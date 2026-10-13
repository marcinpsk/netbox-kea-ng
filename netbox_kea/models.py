# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-FileCopyrightText: 2023 Devon Mar <devon-mar@users.noreply.github.com>
# SPDX-License-Identifier: Apache-2.0
from collections.abc import Mapping
from contextvars import Context, ContextVar, copy_context
from dataclasses import astuple, dataclass
from dataclasses import field as dataclass_field
from functools import partial, reduce
from operator import or_
from pathlib import Path
from typing import TypeVar, cast, get_args

from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import connection, models
from django.urls import reverse
from django.utils.crypto import salted_hmac
from netbox.constants import CENSOR_TOKEN, CENSOR_TOKEN_CHANGED
from netbox.models import NetBoxModel
from netbox.models.features import ChangeLoggingMixin, JobsMixin

from . import branching
from .constants import STALE_CLEANUP_MODES, Family
from .kea import KeaClient
from .leases import AllocationKind
from .reservations import MAX_IDENTITY_LENGTH


@dataclass(frozen=True)
class KeaConnection:
    """The Server settings that select the Kea endpoint and authenticate to it, for one address family."""

    url: str
    username: str | None
    password: str | None = dataclass_field(repr=False)
    verify: bool | str
    client_cert: str | None
    client_key: str | None
    send_service: bool

    def fingerprint(self) -> str:
        """Return a keyed digest of these settings; it holds passwords, so it is never a plain hash."""
        return salted_hmac("netbox_kea.KeaConnection", repr(astuple(self)), algorithm="sha256").hexdigest()


class Server(JobsMixin, NetBoxModel):
    """A Kea DHCP server instance managed through the Kea Control API."""

    name = models.CharField(unique=True, max_length=255)
    ca_url = models.CharField(
        verbose_name="CA / Server URL",
        max_length=255,
        help_text="Default endpoint URL (Kea Control Agent or single DHCP daemon).",
    )
    ca_username = models.CharField(
        blank=True,
        default="",
        max_length=255,
        verbose_name="CA Username",
        help_text="Username for the Kea Control Agent (or default for all daemons).",
    )
    ca_password = models.CharField(
        blank=True,
        default="",
        max_length=255,
        verbose_name="CA Password",
        help_text="Password for the Kea Control Agent (or default for all daemons).",
    )
    dhcp4_username = models.CharField(
        blank=True,
        default="",
        max_length=255,
        verbose_name="DHCPv4 Username",
        help_text="Username for the DHCPv4 daemon. Only used when DHCPv4 URL is configured; falls back to CA credentials otherwise.",
    )
    dhcp4_password = models.CharField(
        blank=True,
        default="",
        max_length=255,
        verbose_name="DHCPv4 Password",
        help_text="Password for the DHCPv4 daemon. Only used when DHCPv4 URL is configured; falls back to CA credentials otherwise.",
    )
    dhcp6_username = models.CharField(
        blank=True,
        default="",
        max_length=255,
        verbose_name="DHCPv6 Username",
        help_text="Username for the DHCPv6 daemon. Only used when DHCPv6 URL is configured; falls back to CA credentials otherwise.",
    )
    dhcp6_password = models.CharField(
        blank=True,
        default="",
        max_length=255,
        verbose_name="DHCPv6 Password",
        help_text="Password for the DHCPv6 daemon. Only used when DHCPv6 URL is configured; falls back to CA credentials otherwise.",
    )
    ssl_verify = models.BooleanField(
        default=True,
        verbose_name="SSL Verification",
        help_text="Enable SSL certificate verification. Disable with caution!",
    )
    client_cert_path = models.CharField(
        max_length=4096,
        blank=True,
        default="",
        verbose_name="Client Certificate",
        help_text="Optional client certificate.",
    )
    client_key_path = models.CharField(
        max_length=4096,
        blank=True,
        default="",
        verbose_name="Private Key",
        help_text="Optional client key.",
    )
    ca_file_path = models.CharField(
        max_length=4096,
        blank=True,
        default="",
        verbose_name="CA File Path",
        help_text="The specific CA certificate file to use for SSL verification.",
    )
    dhcp6 = models.BooleanField(verbose_name="DHCPv6", default=True)
    dhcp4 = models.BooleanField(verbose_name="DHCPv4", default=True)
    dhcp4_url = models.CharField(
        verbose_name="DHCPv4 URL",
        max_length=255,
        blank=True,
        default="",
        help_text="Direct URL for the DHCPv4 daemon. Overrides Server URL for DHCPv4 connections.",
    )
    dhcp6_url = models.CharField(
        verbose_name="DHCPv6 URL",
        max_length=255,
        blank=True,
        default="",
        help_text="Direct URL for the DHCPv6 daemon. Overrides Server URL for DHCPv6 connections.",
    )
    has_control_agent = models.BooleanField(
        verbose_name="Has Control Agent",
        default=True,
        help_text=(
            "Enable if connecting via kea-ctrl-agent. Disable when connecting directly to DHCP daemon endpoints."
        ),
    )
    ipam_first_complete_at: models.DateTimeField = models.DateTimeField(
        null=True,
        blank=True,
        editable=False,
        help_text="When every enabled IPAM workflow first completed its initial observation.",
    )
    ipam_initial_observations: models.JSONField = models.JSONField(default=dict, editable=False)

    sync_enabled = models.BooleanField(
        verbose_name="IPAM Sync Enabled",
        default=True,
        help_text="Include this server in the periodic Kea→NetBox IPAM sync job.",
    )
    sync_leases_enabled = models.BooleanField(
        verbose_name="Sync Leases",
        default=True,
        help_text=(
            "Sync current DHCP address leases as NetBox IP Addresses for this server. With Sync Prefixes also on,"
            " sync current DHCPv6 delegated-prefix leases as NetBox Prefixes."
        ),
    )
    sync_reservations_enabled = models.BooleanField(
        verbose_name="Sync Reservations",
        default=True,
        help_text="Sync DHCP reservations as NetBox IP Addresses for this server.",
    )
    sync_prefixes_enabled = models.BooleanField(
        verbose_name="Sync Prefixes",
        default=True,
        help_text=(
            "Sync Kea subnets as NetBox IP Prefixes for this server. With Sync Leases also on,"
            " sync current DHCPv6 delegated-prefix leases as NetBox Prefixes."
        ),
    )
    sync_ip_ranges_enabled = models.BooleanField(
        verbose_name="Sync IP Ranges",
        default=True,
        help_text="Sync Kea pools as NetBox IP Ranges for this server.",
    )
    sync_deprecate_prefixes_and_ranges: models.BooleanField = models.BooleanField(
        verbose_name="Deprecate stale Prefixes and IP Ranges",
        default=False,
        help_text="Deprecate an owned Prefix or IP Range when this server drops its last ownership link as stale. Never delete it.",
    )
    sync_dhcp_plugin_enabled = models.BooleanField(
        verbose_name="Sync to DHCP plugin",
        default=False,
        help_text=(
            "When the NetBox DHCP plugin (netbox_dhcp) is installed, allow importing this "
            "server's Kea data tier (subnets, pools, host reservations) into the DHCP plugin's "
            "models. Note: Kea shared-networks are a different concept and are NOT imported as "
            "DHCP-plugin Shared Networks (their member subnets are imported individually). "
            "Has no effect if the plugin is absent or the global DHCP Plugin Integration switch is off."
        ),
    )
    persist_config = models.BooleanField(
        verbose_name="Persist configuration",
        default=True,
        help_text=(
            "When enabled, Kea's configuration file is automatically saved "
            "(config-write) after each change so modifications survive a "
            "Kea daemon restart. Disable if Kea configuration is managed externally "
            "(e.g. Ansible, Puppet) or if you manage persistence manually."
        ),
    )
    sync_vrf = models.ForeignKey(
        to="ipam.VRF",
        # PROTECT, not SET_NULL: from a branch, SET_NULL would null main's row (ADR 0007).
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
        verbose_name="Sync VRF",
        help_text=(
            "VRF to assign when syncing subnets as Prefixes, pools as IP Ranges, and leases and reservations as IP Addresses. "
            "Leave blank for the global VRF."
        ),
    )

    class Meta:
        ordering = ("name",)
        permissions = [
            ("bulk_delete_lease_from_server", "Can bulk delete DHCP leases from server"),
        ]

    def save(self, force_insert=False, force_update=False, using=None, update_fields=None) -> None:
        """Keep workflow-owned receipts out of an ordinary existing Server edit."""
        if (not self._state.adding or force_update) and not force_insert and update_fields is None:
            deferred = self.get_deferred_fields()
            update_fields = {
                field.name
                for field in self._meta.concrete_fields
                if not field.primary_key
                and field.attname not in deferred
                and field.name not in {"ipam_initial_observations", "ipam_first_complete_at"}
            }
        super().save(force_insert=force_insert, force_update=force_update, using=using, update_fields=update_fields)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        """Return the detail URL for this server."""
        return reverse("plugins:netbox_kea:server", args=[self.pk])

    @property
    def docs_url(self) -> str | None:
        """Suppress NetBox's Help button, which this package ships no page for.

        NetBoxModel builds the URL from the app label unconditionally, so the button
        renders for a plugin model too and lands on a 404.
        """
        return None

    def kea_connection(self, version: Family | None = None) -> KeaConnection:
        """Return the endpoint and credentials for *version*: its own URL when set, else the CA URL."""
        if version == 4 and self.dhcp4_url:
            url = self.dhcp4_url
            username = self.dhcp4_username or self.ca_username or None
            password = self.dhcp4_password or self.ca_password or None
        elif version == 6 and self.dhcp6_url:
            url = self.dhcp6_url
            username = self.dhcp6_username or self.ca_username or None
            password = self.dhcp6_password or self.ca_password or None
        else:
            url = self.ca_url
            username = self.ca_username or None
            password = self.ca_password or None
        return KeaConnection(
            url=url,
            username=username,
            password=password,
            verify=self.ca_file_path or self.ssl_verify,
            client_cert=self.client_cert_path or None,
            client_key=self.client_key_path or None,
            send_service=self.has_control_agent,
        )

    def get_client(self, version: Family | None = None) -> KeaClient:
        """Return a configured KeaClient, targeting the protocol-specific URL and credentials when available.

        The ``service`` command argument is sent only when this server is fronted by
        a Control Agent (``has_control_agent``), which routes commands to daemons by
        service. When connecting directly to a DHCP daemon (``has_control_agent`` is
        False) ``service`` is dropped, because Kea 3.2.0+ rejects a ``service`` that
        does not match the daemon the request lands on. ``has_control_agent`` is the
        single source of truth here: a protocol-specific ``dhcp{4,6}_url`` may itself
        point at a per-protocol Control Agent (before Kea 3.1.8) or a bare daemon socket
        (Kea 3.0+), so the routing decision follows the flag, not the URL.

        The client is bound to the branch that is active now, so it refuses each Kea write
        command in a branch, also from a clone in a worker thread (ADR 0007). Each write command
        that it sends rotates the records generation of the display cache (ADR 0009).

        Args:
            version: DHCP protocol version (4 or 6). When provided and a protocol-specific
                URL is configured, that URL and its corresponding per-protocol credentials
                (with per-field CA fallback) are used. If no protocol-specific URL is
                configured, ``ca_url`` and CA-level credentials are always used.

        """
        # Imported here: display_cache imports this module.
        from . import display_cache

        connection = self.kea_connection(version)
        config = KeaClientConfig.get()
        return KeaClient(
            url=connection.url,
            username=connection.username,
            password=connection.password,
            verify=connection.verify,
            client_cert=connection.client_cert,
            client_key=connection.client_key,
            timeout=config.kea_timeout,
            persist_config=self.persist_config,
            send_service=connection.send_service,
            max_unpaged_leases=config.lease_query_max_unpaged_leases or None,
            write_guard=branching.bind(),
            on_write=partial(display_cache.rotate_after_write, self),
        )

    def clean(self) -> None:
        """Validate the local Server configuration."""
        super().clean()

        if self.dhcp4 is False and self.dhcp6 is False:
            raise ValidationError({"dhcp6": "At least one of DHCPv4 and DHCPv6 needs to be enabled."})

        if (self.client_cert_path and not self.client_key_path) or (not self.client_cert_path and self.client_key_path):
            raise ValidationError(
                {"client_cert_path": "Client certificate and client private key must be used together."}
            )

        if self.client_cert_path and not Path(self.client_cert_path).is_file():
            raise ValidationError({"client_cert_path": "Client certificate doesn't exist."})
        if self.client_key_path and not Path(self.client_key_path).is_file():
            raise ValidationError({"client_key_path": "Client private key doesn't exist."})

        if self.ca_file_path and not self.ssl_verify:
            raise ValidationError({"ca_file_path": "Cannot specify a CA file when SSL verification is disabled."})

    def to_objectchange(self, action: str):
        """Censor all password fields in NetBox change log entries."""
        objectchange = super().to_objectchange(action)

        password_fields = ("ca_password", "dhcp4_password", "dhcp6_password")

        prechange_data = objectchange.prechange_data or {}
        original_pre_passwords = {f: prechange_data.get(f) for f in password_fields}
        # Censor a set password only. An unset one is "" and must stay "", or the change
        # log tells an operator a password exists where none does.
        for field in password_fields:
            if prechange_data.get(field):
                prechange_data[field] = CENSOR_TOKEN

        if post_data := objectchange.postchange_data:
            for field in password_fields:
                post_password = post_data.get(field)
                if post_password:
                    post_data[field] = (
                        CENSOR_TOKEN_CHANGED if post_password != original_pre_passwords[field] else CENSOR_TOKEN
                    )

        return objectchange


def require_persisted_server(server: Server) -> int:
    """Return the pk of *server*. A Snapshot and a display cache key belong to a saved Server."""
    if server.pk is None:
        raise ValueError("A Kea Snapshot requires a persisted Server.")
    return server.pk


_Singleton = TypeVar("_Singleton", bound="SettingsSingleton")


class SettingsSingleton(ChangeLoggingMixin):
    """A settings row that operators edit on the Settings page without a restart (ADR 0010).

    Exactly one row exists (pk=1 always): a migration creates it, ``save()`` keeps pk=1 and ``delete()`` is
    disabled. A save in a request writes an ObjectChange.
    """

    class Meta:
        abstract = True

    def save(self, *args, **kwargs) -> None:
        """Force pk=1 so only one row can ever exist."""
        self.pk = 1
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Prevent deletion of the singleton row."""
        raise TypeError(f"{type(self).__name__} singleton cannot be deleted.")

    @classmethod
    def get(cls: type[_Singleton]) -> _Singleton:
        """Return the singleton row. A migration creates it, so a missing row raises ``DoesNotExist``.

        In a context from ``PinnedSettings.context()`` it returns the pinned row, and it raises ``RuntimeError`` for a
        model that is not pinned there, because a worker thread opens no database connection.
        """
        pinned = _pinned_settings.get()
        if pinned is None:
            return cls.objects.get(pk=1)
        if cls not in pinned:
            raise RuntimeError(f"{cls.__name__} is not pinned for this worker thread, which reads no database.")
        return cast(_Singleton, pinned[cls])


class SyncConfig(SettingsSingleton):
    """Singleton configuration for the Kea→NetBox IPAM sync job."""

    interval_minutes = models.PositiveIntegerField(
        verbose_name="Sync Interval (minutes)",
        default=5,
        validators=[MinValueValidator(1), MaxValueValidator(1440)],
        help_text=(
            "How often the background sync job runs (minutes). Range 1–1440. A change applies after the next run."
        ),
    )
    sync_enabled = models.BooleanField(
        verbose_name="Sync Enabled (global)",
        default=True,
        help_text="Global switch. Clear it to stop the sync for all Servers, whatever the Server setting.",
    )
    sync_max_leases_per_server: models.PositiveIntegerField = models.PositiveIntegerField(
        verbose_name="Max Leases per Server",
        default=50000,
        help_text="The most leases that one sync run reads from one Server. 0 means no limit.",
    )
    stale_ip_cleanup: models.CharField = models.CharField(
        verbose_name="Stale IP Cleanup",
        max_length=16,
        choices=[(mode, mode.capitalize()) for mode in STALE_CLEANUP_MODES],
        default="remove",
        help_text=(
            "What the sync does with an IP address when the last link of every Server to it goes:"
            " Remove deletes it, Deprecate sets its status to Deprecated, None keeps it."
        ),
    )
    sync_leases_enabled = models.BooleanField(
        verbose_name="Sync Leases",
        default=True,
        help_text=(
            "Sync current Kea address leases to NetBox IPAM as IP addresses. With Prefix sync also on,"
            " sync current DHCPv6 delegated-prefix leases as Prefixes."
        ),
    )
    sync_reservations_enabled = models.BooleanField(
        verbose_name="Sync Reservations",
        default=True,
        help_text="Sync Kea reservations to NetBox IPAM as reserved IP addresses.",
    )
    sync_prefixes_enabled = models.BooleanField(
        verbose_name="Sync Prefixes",
        default=True,
        help_text=(
            "Sync Kea subnets to NetBox IPAM as IP Prefixes. With lease sync also on,"
            " sync current DHCPv6 delegated-prefix leases as Prefixes."
        ),
    )
    sync_ip_ranges_enabled = models.BooleanField(
        verbose_name="Sync IP Ranges",
        default=True,
        help_text="Sync Kea pools to NetBox IPAM as IP Ranges.",
    )

    class Meta:
        app_label = "netbox_kea"
        verbose_name = "Sync Configuration"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(interval_minutes__gte=1) & models.Q(interval_minutes__lte=1440),
                name="syncconfig_interval_minutes_range",
            ),
            models.CheckConstraint(
                condition=models.Q(stale_ip_cleanup__in=STALE_CLEANUP_MODES),
                name="syncconfig_stale_ip_cleanup_mode",
            ),
        ]

    def __str__(self) -> str:
        return "Sync Configuration"


class KeaClientConfig(SettingsSingleton):
    """Singleton configuration of the Kea client that each ``Server.get_client()`` call builds."""

    kea_timeout: models.PositiveIntegerField = models.PositiveIntegerField(
        verbose_name="Kea Timeout (seconds)",
        default=30,
        validators=[MinValueValidator(1)],
        help_text="How long each Kea request can take (seconds). At least 1. A change applies to the next request.",
    )
    lease_query_max_unpaged_leases: models.PositiveIntegerField = models.PositiveIntegerField(
        verbose_name="Max Unpaged Leases",
        default=1000,
        help_text=(
            "Refuse an unpaged Subnet lease query when the Kea lease statistics count more leases than this."
            " 0 disables the check."
        ),
    )

    class Meta:
        app_label = "netbox_kea"
        verbose_name = "Kea Client Configuration"
        constraints = [
            models.CheckConstraint(condition=models.Q(kea_timeout__gte=1), name="keaclientconfig_kea_timeout_min"),
        ]

    def __str__(self) -> str:
        return "Kea Client Configuration"


class DhcpIntegrationConfig(SettingsSingleton):
    """Singleton configuration of the integration with the NetBox DHCP plugin (``netbox_dhcp``)."""

    enabled: models.BooleanField = models.BooleanField(
        verbose_name="Integration Enabled (global)",
        default=True,
        help_text=(
            "Global switch. Clear it to stop the DHCP plugin integration for all Servers, whatever the Server setting."
        ),
    )

    class Meta:
        app_label = "netbox_kea"
        verbose_name = "DHCP Plugin Integration"

    def __str__(self) -> str:
        return "DHCP Plugin Integration"


class DisplayCacheConfig(SettingsSingleton):
    """Singleton TTLs of the display cache, one for each read kind (ADR 0009). 0 turns off caching for that kind.

    ``display_cache`` keys each entry on ``last_updated``, so a save makes every existing entry unreachable.
    """

    configuration_ttl: models.PositiveIntegerField = models.PositiveIntegerField(
        verbose_name="Configuration TTL (seconds)",
        default=300,
        help_text=(
            "How long a page shows a cached Server configuration and Subnet list (seconds)."
            " 0 turns off caching for them."
        ),
    )
    reservations_ttl: models.PositiveIntegerField = models.PositiveIntegerField(
        verbose_name="Reservations TTL (seconds)",
        default=300,
        help_text="How long a page shows cached Reservations (seconds). 0 turns off caching for them.",
    )
    leases_ttl: models.PositiveIntegerField = models.PositiveIntegerField(
        verbose_name="Leases TTL (seconds)",
        default=30,
        help_text=(
            "How long a page shows cached Leases (seconds). 0 turns off caching for them."
            " The Lease pages do not use the cache yet."
        ),
    )
    status_ttl: models.PositiveIntegerField = models.PositiveIntegerField(
        verbose_name="Utilization and Status TTL (seconds)",
        default=15,
        help_text=(
            "How long a page shows cached utilization and daemon status (seconds). 0 turns off caching for them."
            " These pages do not use the cache yet."
        ),
    )

    class Meta:
        app_label = "netbox_kea"
        verbose_name = "Display Cache"

    def __str__(self) -> str:
        return "Display Cache"

    def save(self, *args, **kwargs) -> None:
        """Write ``last_updated`` on every save, also a save with ``update_fields``, because the cache keys hold it."""
        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            kwargs["update_fields"] = {*update_fields, "last_updated"}
        super().save(*args, **kwargs)


# Settings rows read on a request thread for its worker threads; None outside such a worker context.
_pinned_settings: ContextVar[Mapping[type[SettingsSingleton], SettingsSingleton] | None] = ContextVar(
    "pinned_settings", default=None
)


@dataclass(frozen=True)
class PinnedSettings:
    """Settings rows read on the request thread, so that worker threads open no database connection."""

    rows: Mapping[type[SettingsSingleton], SettingsSingleton]

    @classmethod
    def read(cls, *models: type[SettingsSingleton]) -> "PinnedSettings":
        """Read the row of each model now, on the calling thread."""
        return cls({model: model.get() for model in models})

    def context(self) -> Context:
        """Return a copy of the current context in which ``SettingsSingleton.get()`` returns these rows only.

        Make one for each worker task: a context can run in one thread at a time.
        """
        context = copy_context()
        context.run(_pinned_settings.set, self.rows)
        return context


class KeaDhcpLink(ChangeLoggingMixin):
    """Maps a Kea object identity to the netbox-plugin-dhcp (``netbox_dhcp``) record imported from it.

    Kea's ``subnet-id`` is unique only per ``(server, protocol)`` — overlaps across
    servers and between the v4/v6 daemons are normal — but ``netbox_dhcp``'s
    ``Subnet.subnet_id`` is a single *global* unique namespace (and its auto-allocator
    hands out a global ``max+1``).  Kea's id therefore cannot be stored there.  This
    link holds the authoritative ``(server, family, kea_subnet_id)`` identity and points
    — via a ``GenericForeignKey`` so there is no hard migration dependency on
    ``netbox_dhcp`` being installed — at the imported DHCP-plugin object.  It is the
    match key for idempotent re-import and the future home for accept/lock + drift state.

    A Global Reservation has no ``subnet-id``, and ``netbox_dhcp`` derives a
    ``HostReservation``'s family from its Subnet, so a Global row carries no family of
    its own.  ``kea_identity`` holds that missing half of the identity here, which keeps
    the DHCPv4 and DHCPv6 Reservations of one identifier on separate rows.

    Exactly one identity kind is set per row, so the two partial unique constraints
    together cover every link and no row can escape both.
    """

    server = models.ForeignKey(
        to="netbox_kea.Server",
        on_delete=models.CASCADE,
        related_name="dhcp_plugin_links",
    )
    family = models.PositiveSmallIntegerField(
        help_text="IP family of the linked object (4 or 6).",
    )
    kea_subnet_id = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Kea subnet-id for subnet links; null for objects without a Kea subnet-id.",
    )
    # NULL is a distinct state here, not "empty": it means Kea identifies this link by
    # subnet-id. keadhcplink_one_identity_kind requires NULL or a value greater than "",
    # so "" would satisfy neither branch. Do not collapse it to a blank default.
    kea_identity = models.CharField(  # noqa: DJ001
        max_length=MAX_IDENTITY_LENGTH,
        null=True,
        blank=True,
        help_text=(
            "Normalized 'identifier-type:value' for a Global Reservation link; "
            "null for objects Kea identifies by subnet-id."
        ),
    )
    object_type = models.ForeignKey(
        to="contenttypes.ContentType",
        on_delete=models.CASCADE,
        related_name="+",
    )
    object_id = models.PositiveBigIntegerField()
    sys4_object = GenericForeignKey("object_type", "object_id")
    created = models.DateTimeField(auto_now_add=True)
    last_synced = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "netbox_kea"
        verbose_name = "DHCP Import Mapping"
        constraints = [
            models.UniqueConstraint(
                fields=["object_type", "object_id"],
                name="keadhcplink_unique_sys4_object",
            ),
            models.UniqueConstraint(
                fields=["server", "family", "kea_subnet_id"],
                name="keadhcplink_unique_subnet_identity",
                condition=models.Q(kea_subnet_id__isnull=False),
            ),
            models.UniqueConstraint(
                fields=["server", "family", "kea_identity"],
                name="keadhcplink_unique_reservation_identity",
                condition=models.Q(kea_identity__isnull=False),
            ),
            models.CheckConstraint(
                condition=models.Q(kea_subnet_id__isnull=False, kea_identity__isnull=True)
                | models.Q(kea_subnet_id__isnull=True, kea_identity__isnull=False, kea_identity__gt=""),
                name="keadhcplink_one_identity_kind",
            ),
        ]

    def __str__(self) -> str:
        key = f"subnet-id={self.kea_subnet_id}" if self.kea_identity is None else self.kea_identity
        return f"{self.server} v{self.family} {key} → {self.object_type_id}:{self.object_id}"


# One sequence gives every link confirmation and every phase cutoff number (ADR 0006); migration 0019 creates it.
CONFIRMATION_SEQUENCE = "netbox_kea_ipam_ownership_confirmation"


def next_confirmation_number() -> int:
    """Take the next number of the confirmation sequence, for a link confirmation or a phase cutoff."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT nextval(%s)", [CONFIRMATION_SEQUENCE])
        (number,) = cursor.fetchone()
    return number


class IPAMOwnershipSource(models.TextChoices):
    """The Kea source through which a Server owns a NetBox object."""

    LEASE = "lease", "Lease"
    RESERVATION = "reservation", "Reservation"
    SUBNET = "subnet", "Subnet"
    POOL = "pool", "Pool"
    DELEGATED_PREFIX = "delegated-prefix", "Delegated prefix"
    LEASE_PREFIX = "lease-prefix", "Delegated-prefix lease"


OWNED_OBJECT_KEYS = ("ip_address", "prefix", "ip_range")


def _only_key(key: str) -> models.Q:
    return models.Q(**{f"{other}__isnull": other != key for other in OWNED_OBJECT_KEYS})


class IPAMOwnershipLink(models.Model):
    """IPAM Ownership (ADR 0006): one Server and family synchronized one IP address, Prefix or IP Range from one source.

    The row stays in main (ADR 0007). In a branch, a delete that reaches a link is refused before any write.
    """

    server: models.ForeignKey = models.ForeignKey(
        to="netbox_kea.Server",
        on_delete=models.CASCADE,
        related_name="ipam_ownership_links",
    )
    # The key column of server; the type check runs without the Django plugin, which would add it.
    server_id: int
    family: models.PositiveSmallIntegerField = models.PositiveSmallIntegerField(
        choices=[(family, f"IPv{family}") for family in get_args(Family)]
    )
    source: models.CharField = models.CharField(max_length=16, choices=IPAMOwnershipSource.choices)
    ip_address: models.ForeignKey = models.ForeignKey(
        to="ipam.IPAddress",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="kea_ownership_links",
    )
    prefix: models.ForeignKey = models.ForeignKey(
        to="ipam.Prefix",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="kea_ownership_links",
    )
    ip_range: models.ForeignKey = models.ForeignKey(
        to="ipam.IPRange",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="kea_ownership_links",
    )
    facts: models.JSONField = models.JSONField(
        null=True,
        blank=True,
        help_text="The facts that the owner last reported for the object; null for a link without facts.",
    )
    confirmation: models.BigIntegerField = models.BigIntegerField(
        help_text="The confirmation sequence number that a run took when it last confirmed the link.",
    )
    adopted: models.BooleanField = models.BooleanField(default=False)
    allocation_kind: models.CharField = models.CharField(
        max_length=16,
        blank=True,
        default="",
        choices=[(kind, kind.replace("-", " ").capitalize()) for kind in get_args(AllocationKind)],
        help_text=(
            "For a lease link: the allocation kind of the lease that the link came from;"
            " empty when it is unknown (a DHCPv6 lease link from before the kind was recorded)."
        ),
    )
    stale_mark: models.BigIntegerField = models.BigIntegerField(
        null=True,
        blank=True,
        help_text="The cutoff number of the cleanup that kept this last link as stale; null when it is not stale.",
    )

    class Meta:
        app_label = "netbox_kea"
        verbose_name = "IPAM ownership link"
        constraints = [
            models.CheckConstraint(
                condition=reduce(or_, (_only_key(key) for key in OWNED_OBJECT_KEYS)),
                name="ipamownershiplink_one_object",
            ),
            models.CheckConstraint(
                condition=models.Q(family__in=get_args(Family)),
                name="ipamownershiplink_family",
            ),
            models.CheckConstraint(
                condition=models.Q(source__in=IPAMOwnershipSource.values),
                name="ipamownershiplink_source",
            ),
            models.CheckConstraint(
                condition=models.Q(allocation_kind="") | models.Q(source=IPAMOwnershipSource.LEASE),
                name="ipamownershiplink_allocation_kind",
            ),
            *(
                models.UniqueConstraint(
                    fields=["server", "family", "source", key],
                    condition=models.Q(**{f"{key}__isnull": False}),
                    name=f"ipamownershiplink_unique_{key}",
                )
                for key in OWNED_OBJECT_KEYS
            ),
        ]

    def __str__(self) -> str:
        return f"{self.server} IPv{self.family} {self.source} → {self.owned_object}"

    @property
    def owned_object(self) -> models.Model:
        """Return the IP address, Prefix or IP Range that the link names."""
        return next(obj for key in OWNED_OBJECT_KEYS if (obj := getattr(self, key)) is not None)
