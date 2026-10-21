# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import dataclasses
import ipaddress
import json
import math
from dataclasses import dataclass, replace
from typing import Any, Literal, cast

import yaml

from .constants import Family, IPAddressValue
from .dhcp_options import (
    DHCPOption,
    DHCPOptionConflict,
    DHCPOptionIdentity,
    option_identity,
    parse_dhcp_option,
    parse_option_client_classes,
)
from .reservations import (
    MAX_BOOT_FILE_NAME_LENGTH,
    MAX_SERVER_HOSTNAME_LENGTH,
    NEXT_SERVER_RULE,
    ExcludedPrefix,
    IdentifierType,
    InSubnetReservationScope,
    IPv4Reservation,
    IPv6Reservation,
    Reservation,
    ReservationIdentity,
    parse_client_classes,
    parse_next_server,
    reservation_identifier_types,
    reservation_record_data,
)
from .subnet_catalogue import SubnetIdentity

TransferFormat = Literal["yaml", "json"]
_DOCUMENT_FIELDS = frozenset({"version", "reservations"})
_RECORD_FIELDS = frozenset(
    {
        "family",
        "scope",
        "identity",
        "addresses",
        "delegated_prefixes",
        "hostname",
        "options",
        "client_classes",
        "next_server",
        "server_hostname",
        "boot_file_name",
        "excluded_prefixes",
        "user_context",
    }
)
_SCOPE_FIELDS = frozenset({"type", "subnet"})
_GLOBAL_SCOPE_FIELDS = frozenset({"type"})
_SUBNET_FIELDS = frozenset({"cidr"})
_IDENTITY_FIELDS = frozenset({"type", "value"})
_OPTION_FIELDS = frozenset(
    {"code", "name", "space", "data", "csv_format", "always_send", "never_send", "client_classes"}
)
_EXCLUDED_PREFIX_FIELDS = frozenset({"delegated_prefix", "excluded_prefix"})

#: Largest transfer document the parser reads. Every caller is bounded by this,
#: not only the file upload the import form accepts.
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024


class ReservationTransferError(ValueError):
    """The transfer document cannot be decoded."""


@dataclass(frozen=True)
class ReservationTransferDiagnostic:
    """One error at an exact transfer document position."""

    code: str
    message: str
    source_position: str


@dataclass(frozen=True)
class ReservationImportProposal:
    """One validated In-Subnet Reservation ready for subnet resolution."""

    family: Family
    subnet_cidr: str
    identity: ReservationIdentity
    addresses: tuple[IPAddressValue, ...]
    delegated_prefixes: tuple[ipaddress.IPv6Network, ...]
    hostname: str
    options: tuple[DHCPOption, ...]
    client_classes: tuple[str, ...] = ()
    next_server: ipaddress.IPv4Address | None = None
    server_hostname: str = ""
    boot_file_name: str = ""
    excluded_prefixes: tuple[ExcludedPrefix, ...] = ()
    # The document copies the opaque user-context of an exported Reservation; it is not part of the compared value.
    user_context: Any = dataclasses.field(default=None, compare=False)


@dataclass(frozen=True)
class ReservationTransferResult:
    """All valid proposals or all document diagnostics, never both."""

    proposals: tuple[ReservationImportProposal, ...]
    diagnostics: tuple[ReservationTransferDiagnostic, ...]


def resolve_import_proposal(proposal: ReservationImportProposal, subnet: SubnetIdentity) -> Reservation:
    """Bind a validated proposal to one live-verified Subnet Identity."""
    if str(subnet.network) != proposal.subnet_cidr or subnet.network.version != proposal.family:
        raise ValueError("The live Subnet Identity does not match the import proposal.")
    seen: set[DHCPOptionIdentity] = set()
    for option in proposal.options:
        identity = option_identity(option, proposal.family)
        if identity in seen:
            raise DHCPOptionConflict(f"DHCP Option '{option.name or option.code}' is duplicated.")
        seen.add(identity)
    scope = InSubnetReservationScope(subnet)
    if proposal.family == 4:
        return IPv4Reservation(
            scope=scope,
            identity=proposal.identity,
            addresses=cast(tuple[ipaddress.IPv4Address, ...], proposal.addresses),
            hostname=proposal.hostname,
            options=proposal.options,
            client_classes=proposal.client_classes,
            next_server=proposal.next_server,
            server_hostname=proposal.server_hostname,
            boot_file_name=proposal.boot_file_name,
            user_context=proposal.user_context,
        )
    return IPv6Reservation(
        scope=scope,
        identity=proposal.identity,
        addresses=cast(tuple[ipaddress.IPv6Address, ...], proposal.addresses),
        delegated_prefixes=proposal.delegated_prefixes,
        hostname=proposal.hostname,
        options=proposal.options,
        client_classes=proposal.client_classes,
        excluded_prefixes=proposal.excluded_prefixes,
        user_context=proposal.user_context,
    )


def export_reservation_document(records: tuple[Reservation, ...], format_name: str) -> str:
    """Export normalized Reservation records in one explicit format."""
    document = {
        "version": 1,
        "reservations": [reservation_record_data(record, include_subnet_id=False) for record in records],
    }
    if format_name == "json":
        return json.dumps(document, indent=2) + "\n"
    if format_name == "yaml":
        return yaml.safe_dump(document, sort_keys=False)
    raise ReservationTransferError("The transfer format must be YAML or JSON.")


class _NoAliasLoader(yaml.SafeLoader):
    """Safe loader that refuses YAML aliases.

    An alias is a shared reference, so a document inside MAX_DOCUMENT_BYTES can still
    expand into a graph whose traversal is unbounded. Rejecting aliases keeps the byte
    cap a real bound on parser work.
    """

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            raise ReservationTransferError("The transfer document must not use YAML aliases.")
        return super().compose_node(parent, index)

    def flatten_mapping(self, node: Any) -> None:
        """Reject repeated merge keys before the safe loader removes them."""
        merge_seen = False
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                if merge_seen:
                    raise ReservationTransferError("The transfer document contains duplicate key '<<'.")
                merge_seen = True
        super().flatten_mapping(node)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        """Construct a safe mapping and reject repeated keys."""
        mapping = super().construct_mapping(node, deep=deep)
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in keys:
                raise ReservationTransferError(f"The transfer document contains duplicate key {key!r}.")
            keys.add(key)
        return mapping


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReservationTransferError(f"The transfer document contains duplicate key {key!r}.")
        result[key] = value
    return result


def _load_document(document: str, format_name: str) -> Any:
    if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ReservationTransferError(
            f"The transfer document must not exceed {MAX_DOCUMENT_BYTES // (1024 * 1024)} MB."
        )
    try:
        if format_name == "json":
            return json.loads(document, object_pairs_hook=_unique_json_object)
        if format_name == "yaml":
            return yaml.load(document, Loader=_NoAliasLoader)  # noqa: S506  # _NoAliasLoader extends SafeLoader
    except ReservationTransferError:
        raise  # Loader guards already report precise errors.
    except (yaml.YAMLError, RecursionError, ValueError) as exc:
        # json.loads raises a plain ValueError for an oversized integer literal, not
        # JSONDecodeError, and the caller only handles ReservationTransferError.
        raise ReservationTransferError("The transfer document is not valid syntax for the selected format.") from exc
    raise ReservationTransferError("The transfer format must be YAML or JSON.")


def _diagnostic(code: str, message: str, position: str) -> ReservationTransferDiagnostic:
    return ReservationTransferDiagnostic(code=code, message=message, source_position=position)


def _report_unknown_fields(
    value: dict[Any, Any],
    allowed: frozenset[str],
    position: str,
    diagnostics: list[ReservationTransferDiagnostic],
) -> None:
    for field in value:
        if isinstance(field, str) and field in allowed:
            continue
        if isinstance(field, str):
            field_position = f"{position}.{field}" if position else field
        else:
            field_position = f"{position or '$'}[{field!r}]"
        diagnostics.append(
            _diagnostic(
                "unknown-field",
                "The field is not part of the Reservation Transfer Document schema.",
                field_position,
            )
        )


def _parse_family(value: Any, position: str, diagnostics: list[ReservationTransferDiagnostic]) -> Family | None:
    # bool is an int subclass and 4.0 == 4, so equality alone accepts both.
    if not isinstance(value, int) or isinstance(value, bool) or value not in (4, 6):
        diagnostics.append(_diagnostic("invalid-family", "Family must be 4 or 6.", position))
        return None
    return cast(Family, value)


def _parse_scope(
    value: Any,
    family: Family | None,
    position: str,
    diagnostics: list[ReservationTransferDiagnostic],
) -> str | None:
    if not isinstance(value, dict):
        diagnostics.append(_diagnostic("invalid-scope", "Scope must be an object.", position))
        return None
    scope_type = value.get("type")
    _report_unknown_fields(
        value,
        _GLOBAL_SCOPE_FIELDS if scope_type == "global" else _SCOPE_FIELDS,
        position,
        diagnostics,
    )
    if scope_type == "global":
        diagnostics.append(
            _diagnostic(
                "unsupported-scope",
                "Import does not support Global Reservation Scope.",
                f"{position}.type",
            )
        )
        return None
    if scope_type != "in-subnet":
        diagnostics.append(_diagnostic("invalid-scope", "Scope type must be in-subnet or global.", f"{position}.type"))
        return None
    subnet = value.get("subnet")
    if isinstance(subnet, dict):
        _report_unknown_fields(subnet, _SUBNET_FIELDS, f"{position}.subnet", diagnostics)
    cidr = subnet.get("cidr") if isinstance(subnet, dict) else None
    if not isinstance(cidr, str):
        diagnostics.append(
            _diagnostic("invalid-subnet", "The subnet CIDR must be a canonical network.", f"{position}.subnet.cidr")
        )
        return None
    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except (TypeError, ValueError):
        diagnostics.append(
            _diagnostic("invalid-subnet", "The subnet CIDR must be a canonical network.", f"{position}.subnet.cidr")
        )
        return None
    if family is not None and network.version != family:
        diagnostics.append(
            _diagnostic("invalid-subnet", "The subnet CIDR must use the Reservation family.", f"{position}.subnet.cidr")
        )
        return None
    return str(network)


def _parse_identity(
    value: Any,
    family: Family | None,
    position: str,
    diagnostics: list[ReservationTransferDiagnostic],
) -> ReservationIdentity | None:
    if not isinstance(value, dict):
        diagnostics.append(_diagnostic("invalid-identity", "Identity must be an object.", position))
        return None
    _report_unknown_fields(value, _IDENTITY_FIELDS, position, diagnostics)
    identifier_type = value.get("type")
    identifier_value = value.get("value")
    if not isinstance(identifier_type, str) or not isinstance(identifier_value, str):
        diagnostics.append(_diagnostic("invalid-identity", "The Reservation Identity is invalid.", f"{position}.value"))
        return None
    try:
        identity = ReservationIdentity(cast(IdentifierType, identifier_type), identifier_value)
    except (TypeError, ValueError):
        diagnostics.append(_diagnostic("invalid-identity", "The Reservation Identity is invalid.", f"{position}.value"))
        return None
    if family is not None and identity.identifier_type not in reservation_identifier_types(family):
        diagnostics.append(
            _diagnostic("invalid-identity", "The Identity type is not valid for this family.", f"{position}.type")
        )
        return None
    return identity


def _parse_addresses(
    value: Any,
    family: Family | None,
    subnet_cidr: str | None,
    position: str,
    diagnostics: list[ReservationTransferDiagnostic],
) -> tuple[IPAddressValue, ...] | None:
    if not isinstance(value, list):
        diagnostics.append(_diagnostic("invalid-addresses", "Addresses must be a list.", position))
        return None
    subnet = ipaddress.ip_network(subnet_cidr) if subnet_cidr is not None else None
    parsed: list[IPAddressValue] = []
    seen: set[IPAddressValue] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, str):
            diagnostics.append(_diagnostic("invalid-address", "The address is invalid.", f"{position}[{index}]"))
            continue
        try:
            address = ipaddress.ip_address(raw)
        except (TypeError, ValueError):
            diagnostics.append(_diagnostic("invalid-address", "The address is invalid.", f"{position}[{index}]"))
            continue
        if family is not None and address.version != family:
            diagnostics.append(
                _diagnostic("invalid-address", "The address must use the Reservation family.", f"{position}[{index}]")
            )
        elif subnet is not None and address not in subnet:
            diagnostics.append(
                _diagnostic(
                    "out-of-subnet-address",
                    "The address must belong to the selected In-Subnet Scope.",
                    f"{position}[{index}]",
                )
            )
        elif address in seen:
            diagnostics.append(_diagnostic("duplicate-address", "The address is duplicated.", f"{position}[{index}]"))
        else:
            seen.add(address)
            parsed.append(address)
    if family == 4 and len(parsed) > 1:
        diagnostics.append(_diagnostic("invalid-addresses", "DHCPv4 permits at most one address.", position))
    return tuple(parsed)


def _parse_prefixes(
    value: Any,
    family: Family | None,
    position: str,
    diagnostics: list[ReservationTransferDiagnostic],
) -> tuple[ipaddress.IPv6Network, ...] | None:
    if not isinstance(value, list):
        diagnostics.append(_diagnostic("invalid-prefixes", "Delegated prefixes must be a list.", position))
        return None
    if family == 4 and value:
        diagnostics.append(_diagnostic("invalid-prefixes", "DHCPv4 does not support delegated prefixes.", position))
        return None
    parsed: list[ipaddress.IPv6Network] = []
    seen: set[ipaddress.IPv6Network] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, str):
            diagnostics.append(
                _diagnostic("invalid-prefix", "The delegated prefix is invalid.", f"{position}[{index}]")
            )
            continue
        try:
            prefix = ipaddress.IPv6Network(raw, strict=True)
        except (TypeError, ValueError):
            diagnostics.append(
                _diagnostic("invalid-prefix", "The delegated prefix is invalid.", f"{position}[{index}]")
            )
            continue
        if prefix in seen:
            diagnostics.append(
                _diagnostic("duplicate-prefix", "The delegated prefix is duplicated.", f"{position}[{index}]")
            )
        else:
            seen.add(prefix)
            parsed.append(prefix)
    return tuple(parsed)


def _parse_options(
    value: Any,
    position: str,
    diagnostics: list[ReservationTransferDiagnostic],
    family: Family | None,
) -> tuple[DHCPOption, ...] | None:
    if not isinstance(value, list):
        diagnostics.append(_diagnostic("invalid-options", "Options must be a list.", position))
        return None
    parsed: list[DHCPOption] = []
    seen: set[DHCPOptionIdentity] = set()
    for index, entry in enumerate(value):
        option_position = f"{position}[{index}]"
        raw = entry
        if isinstance(entry, dict):
            _report_unknown_fields(entry, _OPTION_FIELDS, option_position, diagnostics)
            raw = {
                "code": entry.get("code"),
                "name": entry.get("name"),
                "space": entry.get("space"),
                "data": entry.get("data", ""),
                "csv-format": entry.get("csv_format"),
                "always-send": entry.get("always_send"),
                "never-send": entry.get("never_send"),
            }
        try:
            option = parse_dhcp_option(raw)
            if isinstance(entry, dict):
                option = replace(option, client_classes=parse_option_client_classes(entry.get("client_classes", [])))
        except ValueError:
            diagnostics.append(_diagnostic("invalid-option", "The DHCP Option is invalid.", option_position))
            continue
        identity = option_identity(option, family) if family is not None else None
        if identity in seen:
            diagnostics.append(_diagnostic("duplicate-option", "The DHCP Option is duplicated.", option_position))
        else:
            if identity is not None:
                seen.add(identity)
            parsed.append(option)
    return tuple(parsed)


def _parse_client_classes(
    value: Any, position: str, diagnostics: list[ReservationTransferDiagnostic]
) -> tuple[str, ...] | None:
    try:
        return parse_client_classes(value)
    except ValueError as exc:
        diagnostics.append(_diagnostic("invalid-client-classes", str(exc), position))
        return None


def _parse_boot_fields(
    raw: dict[Any, Any], family: Family | None, base: str, diagnostics: list[ReservationTransferDiagnostic]
) -> tuple[ipaddress.IPv4Address | None, str, str] | None:
    """Return the next server, server hostname and boot file name of one record; null and "" set none."""
    valid = True
    next_server = None
    value = raw.get("next_server")
    if value is not None:
        try:
            if family == 6:
                raise ValueError("DHCPv6 Reservations have no next server.")
            next_server = parse_next_server(value)
        except ValueError as exc:
            message = str(exc) if family == 6 else f"{NEXT_SERVER_RULE} Use null for none."
            diagnostics.append(_diagnostic("invalid-boot-field", message, f"{base}.next_server"))
            valid = False
    texts: list[str] = []
    for key, label, limit in (
        ("server_hostname", "server hostname", MAX_SERVER_HOSTNAME_LENGTH),
        ("boot_file_name", "boot file name", MAX_BOOT_FILE_NAME_LENGTH),
    ):
        text = raw.get(key, "")
        if family == 6 and text != "":
            message = f"DHCPv6 Reservations have no {label}."
        elif not isinstance(text, str) or len(text) > limit:
            message = f"The {label} must be a string of at most {limit} characters."
        else:
            texts.append(text)
            continue
        diagnostics.append(_diagnostic("invalid-boot-field", message, f"{base}.{key}"))
        valid = False
    return (next_server, texts[0], texts[1]) if valid else None


def _parse_excluded_prefixes(
    value: Any,
    family: Family | None,
    prefixes: tuple[ipaddress.IPv6Network, ...] | None,
    position: str,
    diagnostics: list[ReservationTransferDiagnostic],
) -> tuple[ExcludedPrefix, ...] | None:
    """Return the excluded prefix of each delegated prefix that has one, in the order of the delegated prefixes."""
    if value is None:
        return ()
    if not isinstance(value, list) or (family == 4 and value):
        message = "Excluded prefixes must be a list." if family != 4 else "DHCPv4 does not support excluded prefixes."
        diagnostics.append(_diagnostic("invalid-excluded-prefixes", message, position))
        return None
    pairs: dict[ipaddress.IPv6Network, ExcludedPrefix] = {}
    valid = True
    for index, entry in enumerate(value):
        entry_position = f"{position}[{index}]"
        if isinstance(entry, dict):
            _report_unknown_fields(entry, _EXCLUDED_PREFIX_FIELDS, entry_position, diagnostics)
        try:
            texts = [entry.get(key) if isinstance(entry, dict) else None for key in sorted(_EXCLUDED_PREFIX_FIELDS)]
            if not all(isinstance(text, str) for text in texts):
                raise ValueError("An excluded prefix entry needs two prefixes.")
            pair = ExcludedPrefix(*(ipaddress.IPv6Network(text, strict=True) for text in texts))
            if prefixes is not None and pair.delegated not in prefixes:
                raise ValueError("The delegated prefix is not one of the Reservation.")
        except ValueError:
            diagnostics.append(
                _diagnostic(
                    "invalid-excluded-prefix",
                    "An excluded prefix must be a longer prefix inside one delegated prefix of the Reservation.",
                    entry_position,
                )
            )
            valid = False
            continue
        if pair.delegated in pairs:
            diagnostics.append(
                _diagnostic(
                    "duplicate-excluded-prefix", "The delegated prefix already has an excluded prefix.", entry_position
                )
            )
            valid = False
            continue
        pairs[pair.delegated] = pair
    if not valid or prefixes is None:
        return None
    return tuple(pairs[prefix] for prefix in prefixes if prefix in pairs)


def _is_json_data(value: Any) -> bool:
    """Return whether *value* is JSON data that Kea can store; YAML can also hold dates, sets and other keys."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                return False
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, float):
            if not math.isfinite(item):
                return False
        elif item is not None and not isinstance(item, str | int):
            return False
    return True


def _parse_record(
    raw: Any,
    index: int,
    diagnostics: list[ReservationTransferDiagnostic],
    expected_family: int | None,
) -> tuple[ReservationImportProposal | None, tuple[Family, str, str, str] | None]:
    base = f"reservations[{index}]"
    if not isinstance(raw, dict):
        diagnostics.append(_diagnostic("invalid-record", "A Reservation must be an object.", base))
        return None, None
    _report_unknown_fields(raw, _RECORD_FIELDS, base, diagnostics)
    family = _parse_family(raw.get("family"), f"{base}.family", diagnostics)
    if family is not None and expected_family is not None and family != expected_family:
        diagnostics.append(
            _diagnostic(
                "wrong-family",
                f"This import accepts only DHCPv{expected_family} Reservations.",
                f"{base}.family",
            )
        )
    subnet_cidr = _parse_scope(raw.get("scope"), family, f"{base}.scope", diagnostics)
    identity = _parse_identity(raw.get("identity"), family, f"{base}.identity", diagnostics)
    addresses = _parse_addresses(raw.get("addresses"), family, subnet_cidr, f"{base}.addresses", diagnostics)
    prefixes = _parse_prefixes(raw.get("delegated_prefixes"), family, f"{base}.delegated_prefixes", diagnostics)
    hostname = raw.get("hostname")
    if not isinstance(hostname, str):
        diagnostics.append(_diagnostic("invalid-hostname", "Hostname must be a string.", f"{base}.hostname"))
        hostname = None
    options = _parse_options(raw.get("options"), f"{base}.options", diagnostics, family)
    client_classes = _parse_client_classes(raw.get("client_classes", []), f"{base}.client_classes", diagnostics)
    boot = _parse_boot_fields(raw, family, base, diagnostics)
    excluded = _parse_excluded_prefixes(
        raw.get("excluded_prefixes"), family, prefixes, f"{base}.excluded_prefixes", diagnostics
    )
    user_context = raw.get("user_context")
    if not _is_json_data(user_context):
        diagnostics.append(
            _diagnostic("invalid-user-context", "The user context must be JSON data.", f"{base}.user_context")
        )
    duplicate_key = (
        (family, subnet_cidr, identity.identifier_type, identity.value)
        if family is not None and subnet_cidr is not None and identity is not None
        else None
    )
    if (
        family is None
        or subnet_cidr is None
        or identity is None
        or addresses is None
        or prefixes is None
        or hostname is None
        or options is None
        or client_classes is None
        or boot is None
        or excluded is None
    ):
        return None, duplicate_key
    return (
        ReservationImportProposal(
            family=family,
            subnet_cidr=subnet_cidr,
            identity=identity,
            addresses=addresses,
            delegated_prefixes=prefixes,
            hostname=hostname,
            options=options,
            client_classes=client_classes,
            next_server=boot[0],
            server_hostname=boot[1],
            boot_file_name=boot[2],
            excluded_prefixes=excluded,
            user_context=user_context,
        ),
        duplicate_key,
    )


def parse_reservation_document(
    document: str,
    format_name: str,
    *,
    expected_family: int | None = None,
) -> ReservationTransferResult:
    """Validate a complete transfer document before returning any proposal."""
    raw = _load_document(document, format_name)
    diagnostics: list[ReservationTransferDiagnostic] = []
    if not isinstance(raw, dict):
        return ReservationTransferResult(
            (), (_diagnostic("invalid-document", "Document root must be an object.", "$"),)
        )
    _report_unknown_fields(raw, _DOCUMENT_FIELDS, "", diagnostics)
    version = raw.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        diagnostics.append(_diagnostic("invalid-version", "Document version must be 1.", "version"))
    records = raw.get("reservations")
    if not isinstance(records, list):
        diagnostics.append(_diagnostic("invalid-reservations", "Reservations must be a list.", "reservations"))
        return ReservationTransferResult((), tuple(diagnostics))
    parsed_records = [
        (index, *_parse_record(entry, index, diagnostics, expected_family)) for index, entry in enumerate(records)
    ]
    seen: dict[tuple[Family, str, str, str], int] = {}
    for index, _proposal, duplicate_key in parsed_records:
        if duplicate_key is None:
            continue
        if duplicate_key in seen:
            diagnostics.append(
                _diagnostic(
                    "duplicate-reservation",
                    "The Reservation Identity and Scope are duplicated.",
                    f"reservations[{index}].identity",
                )
            )
        else:
            seen[duplicate_key] = index
    if diagnostics:
        return ReservationTransferResult((), tuple(diagnostics))
    return ReservationTransferResult(
        tuple(proposal for _, proposal, _ in parsed_records if proposal is not None),
        (),
    )
