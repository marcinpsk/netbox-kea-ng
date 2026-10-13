# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Tests for SettingsView, SyncJobsView, ServerSyncStatusView, ServerSyncNowView, ServerSyncToggleView."""

import uuid
from datetime import timedelta
from unittest.mock import patch

from bs4 import BeautifulSoup
from django.test import TestCase, skipUnlessDBFeature
from django.urls import reverse
from django.utils import timezone

from netbox_kea.integrations import dhcp_plugin
from netbox_kea.ipam_reconciliation import _get_stale_cleanup_mode
from netbox_kea.models import DhcpIntegrationConfig, KeaClientConfig, Server, SyncConfig
from netbox_kea.tests.utils import (
    User,
    _get_with_writes,
    _grant,
    _make_db_server,
    _sync_page_urls,
    with_kea_client_config,
)

_MAKE_JOB_NO_DATA = object()  # sentinel: caller did not pass data at all


def _make_job(*, name="Kea IPAM Sync", object_id=None, object_type=None, data=_MAKE_JOB_NO_DATA, delta_seconds=0):
    """Create a real Job row in the test DB.

    Pass ``data=None`` explicitly to store a NULL data field (exercises the
    ``isinstance(job.data, dict)`` guard in ``get_recent_jobs_for_servers``).
    Omitting *data* defaults to ``{}``.

    ``delta_seconds`` shifts the stored ``created`` timestamp backwards so that
    ordering tests are reliable.  Because ``Job.created`` is ``auto_now_add``
    Django silently ignores the field in ``create()``, so we back-fill it via
    a raw ``update()`` call which bypasses that restriction.
    """
    from core.models import Job

    job = Job.objects.create(
        name=name,
        object_type=object_type,
        object_id=object_id,
        status="completed",
        data={} if data is _MAKE_JOB_NO_DATA else data,
        job_id=uuid.uuid4(),
    )
    if delta_seconds:
        Job.objects.filter(pk=job.pk).update(created=timezone.now() - timedelta(seconds=delta_seconds))
        job.refresh_from_db(fields=["created"])
    return job


def _section_data(slug: str, values: dict[str, object]) -> dict[str, object]:
    """Return the POST data of a Settings section, as a browser sends it: a checkbox that is off is left out."""
    data: dict[str, object] = {"section": slug}
    for name, value in values.items():
        if value is not False:
            data[f"{slug}-{name}"] = "on" if value is True else value
    return data


def _defaults(model, *names: str) -> dict[str, object]:
    return {name: model._meta.get_field(name).default for name in names}


def _sync_settings(**values) -> dict[str, object]:
    """Return the POST data of the Sync section; a field that *values* leaves out has its default value."""
    return _section_data("sync", {**_defaults(SyncConfig, "sync_max_leases_per_server", "stale_ip_cleanup"), **values})


def _kea_client_settings(**values) -> dict[str, object]:
    """Return the POST data of the Kea Client section; a field that *values* leaves out has its default value."""
    return _section_data(
        "kea-client", {**_defaults(KeaClientConfig, "kea_timeout", "lease_query_max_unpaged_leases"), **values}
    )


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestSyncJobsView(TestCase):
    """GET /plugins/kea/sync-jobs/: the jobs only, with a link to the Settings page."""

    def setUp(self):
        self.user = User.objects.create_superuser("synctest", "s@s.com", "pass")
        self.client.force_login(self.user)
        _make_db_server(name="kea-a")
        _make_db_server(name="kea-b")

    def test_get_returns_200(self):
        response = self.client.get(reverse("plugins:netbox_kea:sync_jobs"))
        self.assertEqual(response.status_code, 200)

    def test_get_contains_server_names(self):
        response = self.client.get(reverse("plugins:netbox_kea:sync_jobs"))
        self.assertContains(response, "kea-a")
        self.assertContains(response, "kea-b")

    def test_get_links_to_the_settings_page_and_shows_no_settings_form(self):
        response = self.client.get(reverse("plugins:netbox_kea:sync_jobs"))
        self.assertContains(response, f'href="{reverse("plugins:netbox_kea:settings")}"')
        self.assertNotContains(response, "interval_minutes")

    def test_the_page_accepts_no_post(self):
        response = self.client.post(reverse("plugins:netbox_kea:sync_jobs"), {"interval_minutes": 10})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(SyncConfig.get().interval_minutes, 5)

    def test_get_without_login_redirects(self):
        self.client.logout()
        response = self.client.get(reverse("plugins:netbox_kea:sync_jobs"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])


class TestSettingsView(TestCase):
    """GET and POST /plugins/kea/settings/ as a superuser."""

    def setUp(self):
        self.user = User.objects.create_superuser("settings-admin", "a@a.com", "pass")
        self.client.force_login(self.user)
        self.url = reverse("plugins:netbox_kea:settings")

    def test_get_shows_the_stored_values(self):
        SyncConfig.objects.filter(pk=1).update(interval_minutes=13, sync_leases_enabled=False)
        page = BeautifulSoup(self.client.get(self.url).content, "html.parser")
        self.assertEqual(page.find(id="id_sync-interval_minutes")["value"], "13")
        self.assertFalse(page.find(id="id_sync-sync_leases_enabled").has_attr("checked"))
        self.assertTrue(page.find(id="id_sync-sync_reservations_enabled").has_attr("checked"))
        self.assertIsNotNone(page.select_one('form[method="post"] button[type="submit"]'))

    def test_get_shows_each_section_in_a_card_with_its_anchor(self):
        page = BeautifulSoup(self.client.get(self.url).content, "html.parser")
        for slug, title in (("sync", "Sync Configuration"), ("kea-client", "Kea Client Configuration")):
            with self.subTest(section=slug):
                card = page.find(id=slug)
                self.assertIn("card", card["class"])
                self.assertEqual(card.find(class_="card-header").get_text(strip=True), title)

    def test_post_saves_every_field_and_redirects(self):
        response = self.client.post(
            self.url,
            _sync_settings(
                interval_minutes=10,
                sync_enabled=True,
                sync_prefixes_enabled=True,
                sync_max_leases_per_server=7,
                stale_ip_cleanup="deprecate",
            ),
            follow=True,
        )
        self.assertRedirects(response, self.url)
        self.assertContains(response, "Sync Configuration saved.")
        config = SyncConfig.get()
        self.assertEqual(config.interval_minutes, 10)
        self.assertEqual(config.sync_max_leases_per_server, 7)
        self.assertEqual(config.stale_ip_cleanup, "deprecate")
        self.assertTrue(config.sync_enabled)
        self.assertTrue(config.sync_prefixes_enabled)
        self.assertFalse(config.sync_leases_enabled)
        self.assertFalse(config.sync_reservations_enabled)
        self.assertFalse(config.sync_ip_ranges_enabled)

    def test_the_next_periodic_run_schedules_the_posted_interval(self):
        """The interval reaches the job only through the page: the job row was scheduled with another one."""
        from core.models import Job

        from netbox_kea.jobs import KeaIpamSyncJob

        job = Job.objects.create(
            name=KeaIpamSyncJob.name, status="scheduled", scheduled=timezone.now(), interval=5, job_id=uuid.uuid4()
        )
        response = self.client.post(self.url, _sync_settings(interval_minutes=37))
        self.assertEqual(response.status_code, 302)

        KeaIpamSyncJob.handle(job)

        successors = Job.objects.filter(name=KeaIpamSyncJob.name).exclude(pk=job.pk)
        self.assertEqual(list(successors.values_list("interval", flat=True)), [37])

    def test_a_save_records_one_change_with_the_old_and_new_values(self):
        from core.models import ObjectChange
        from django.contrib.contenttypes.models import ContentType

        SyncConfig.objects.filter(pk=1).update(interval_minutes=7)
        self.client.post(self.url, _sync_settings(interval_minutes=21, sync_enabled=True))

        changes = ObjectChange.objects.filter(
            changed_object_type=ContentType.objects.get_for_model(SyncConfig), changed_object_id=1
        )
        self.assertEqual([change.action for change in changes], ["update"])
        change = changes.get()
        self.assertIsNotNone(change.prechange_data, "the view must snapshot the row before it changes it")
        self.assertEqual(change.prechange_data["interval_minutes"], 7)
        self.assertEqual(change.postchange_data["interval_minutes"], 21)

    def test_the_change_detail_page_links_to_no_missing_change_log_route(self):
        """NetBox links the object's change log under get_absolute_url; the Settings page has none."""
        from core.models import ObjectChange

        self.client.post(self.url, _sync_settings(interval_minutes=21, sync_enabled=True))
        change = ObjectChange.objects.get()

        response = self.client.get(reverse("core:objectchange", args=[change.pk]))

        self.assertContains(response, "Sync Configuration")
        hrefs = [link["href"] for link in BeautifulSoup(response.content, "html.parser").find_all("a", href=True)]
        self.assertEqual([href for href in hrefs if href.startswith(self.url) and href.endswith("changelog/")], [])

    def test_the_change_log_api_lists_a_settings_change(self):
        """NetBox serializes each changed object for the change log API, so SyncConfig needs a serializer."""
        from rest_framework.test import APIClient

        self.client.post(self.url, _sync_settings(interval_minutes=21, sync_enabled=True))
        api = APIClient(raise_request_exception=False)
        api.force_authenticate(user=self.user)

        response = api.get(reverse("core-api:objectchange-list"))

        self.assertEqual(response.status_code, 200, response.content[:300])
        (change,) = response.json()["results"]
        self.assertEqual(change["changed_object"], {"id": 1, "display": "Sync Configuration"})

    def test_post_does_not_touch_the_job_registry(self):
        """Only the rqworker reads the registry, so the web process must not write it."""
        from netbox.registry import registry

        from netbox_kea.jobs import KeaIpamSyncJob

        before = dict(registry["system_jobs"][KeaIpamSyncJob])
        self.client.post(self.url, _sync_settings(interval_minutes=15, sync_enabled=True))
        self.assertEqual(registry["system_jobs"][KeaIpamSyncJob], before)

    def test_post_invalid_interval_shows_the_error_and_changes_nothing(self):
        for interval in (0, 1441):
            with self.subTest(interval=interval):
                response = self.client.post(self.url, _sync_settings(interval_minutes=interval, sync_enabled=False))
                self.assertEqual(response.status_code, 200)
                (entry,) = [shown for shown in response.context["sections"] if shown.section.slug == "sync"]
                self.assertIn("interval_minutes", entry.form.errors)
                self.assertEqual(entry.form["interval_minutes"].value(), str(interval))
                self.assertEqual(SyncConfig.get().interval_minutes, 5)
                self.assertTrue(SyncConfig.get().sync_enabled)

    def test_a_posted_stale_ip_cleanup_mode_reaches_the_next_sync_without_a_restart(self):
        self.assertEqual(_get_stale_cleanup_mode(), "remove")

        self.assertEqual(
            self.client.post(self.url, _sync_settings(interval_minutes=5, stale_ip_cleanup="none")).status_code, 302
        )

        self.assertEqual(_get_stale_cleanup_mode(), "none")

    def test_post_invalid_sync_limits_show_the_error_and_change_nothing(self):
        before = SyncConfig.get()
        for field, value in (("sync_max_leases_per_server", -1), ("stale_ip_cleanup", "delete")):
            with self.subTest(field=field, value=value):
                response = self.client.post(self.url, _sync_settings(**{field: value}))
                self.assertEqual(response.status_code, 200)
                (entry,) = [shown for shown in response.context["sections"] if shown.section.slug == "sync"]
                self.assertIn(field, entry.form.errors)
                config = SyncConfig.get()
                self.assertEqual(
                    (config.sync_max_leases_per_server, config.stale_ip_cleanup),
                    (before.sync_max_leases_per_server, before.stale_ip_cleanup),
                )

    def test_post_to_an_unknown_section_is_a_bad_request(self):
        response = self.client.post(self.url, {"section": "unknown", "sync-interval_minutes": 9})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(SyncConfig.get().interval_minutes, 5)

    def test_post_without_syncconfig_row_raises(self):
        """A missing row is a server error, not a message that hides it."""
        SyncConfig.objects.all().delete()
        with self.assertRaises(SyncConfig.DoesNotExist):
            self.client.post(self.url, _sync_settings(interval_minutes=10, sync_enabled=True))
        self.assertFalse(SyncConfig.objects.exists())
        response = self.client.get(reverse("plugins:netbox_kea:server_list"))
        self.assertEqual(list(response.context["messages"]), [])

    def test_get_without_login_redirects(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])


class TestSettingsPermissions(TestCase):
    """Each section needs its model's view permission to show, and its change permission to save."""

    def setUp(self):
        self.user = User.objects.create_user("settings-user")
        self.client.force_login(self.user)
        self.url = reverse("plugins:netbox_kea:settings")
        self.link = f'href="{self.url}"'
        self.menu_link = f'href="{self.url}#'

    def test_a_viewer_sees_the_values_read_only_without_a_submit_control(self):
        _grant([SyncConfig], ["view"], user=self.user)
        SyncConfig.objects.filter(pk=1).update(interval_minutes=13)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        page = BeautifulSoup(response.content, "html.parser")
        interval = page.find(id="id_sync-interval_minutes")
        self.assertEqual(interval["value"], "13")
        self.assertTrue(interval.has_attr("disabled"))
        self.assertTrue(page.find(id="id_sync-sync_enabled").has_attr("disabled"))
        self.assertIsNone(page.select_one('form[method="post"]'))
        self.assertEqual(page.select('.page-body [type="submit"]'), [])

    def test_a_viewer_post_is_refused_and_changes_nothing(self):
        _grant([SyncConfig], ["view"], user=self.user)

        response = self.client.post(self.url, _sync_settings(interval_minutes=30, sync_enabled=False))

        self.assertEqual(response.status_code, 403)
        config = SyncConfig.get()
        self.assertEqual((config.interval_minutes, config.sync_enabled), (5, True))

    def test_a_post_without_the_view_permission_is_refused_and_changes_nothing(self):
        from core.models import ObjectChange

        _grant([SyncConfig], ["change"], user=self.user)
        for interval in (30, 0):
            with self.subTest(interval=interval):
                response = self.client.post(self.url, _sync_settings(interval_minutes=interval, sync_enabled=False))

                self.assertEqual(response.status_code, 403)
                config = SyncConfig.get()
                self.assertEqual((config.interval_minutes, config.sync_enabled), (5, True))
                self.assertFalse(ObjectChange.objects.exists())

    def test_a_user_with_view_and_change_saves(self):
        _grant([SyncConfig], ["view", "change"], user=self.user)

        response = self.client.post(self.url, _sync_settings(interval_minutes=30, sync_enabled=True))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(SyncConfig.get().interval_minutes, 30)

    def test_a_user_who_can_view_no_section_gets_403_and_no_menu_item(self):
        _grant([Server], ["view"], user=self.user)

        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.url, _sync_settings(interval_minutes=30)).status_code, 403)
        self.assertEqual(SyncConfig.get().interval_minutes, 5)
        home = self.client.get(reverse("home"))
        self.assertContains(home, f'href="{reverse("plugins:netbox_kea:server_list")}"')
        self.assertNotContains(home, self.menu_link)
        self.assertNotContains(self.client.get(reverse("plugins:netbox_kea:sync_jobs")), self.link)

    def test_a_viewer_gets_the_menu_item_and_the_sync_jobs_link(self):
        _grant([SyncConfig, Server], ["view"], user=self.user)

        self.assertContains(self.client.get(reverse("home")), f'{self.menu_link}sync"')
        self.assertContains(self.client.get(reverse("plugins:netbox_kea:sync_jobs")), self.link)

    def test_each_section_has_a_menu_item_for_a_user_who_can_view_that_section(self):
        """The Settings menu group holds one item per section, so a new section gets its item and its permission."""
        from netbox_kea.views.settings_page import SECTIONS

        for section in SECTIONS:
            with self.subTest(section=section.slug):
                user = User.objects.create_user(f"settings-only-{section.slug}")
                _grant([section.model], ["view"], user=user)
                self.client.force_login(user)
                menu = BeautifulSoup(self.client.get(reverse("home")).content, "html.parser")
                items = {link["href"]: link.get_text(strip=True) for link in menu.select(f'a[href^="{self.url}#"]')}
                self.assertEqual(items, {f"{self.url}#{section.slug}": section.menu_text})

    def test_the_server_sync_tab_links_to_settings_only_for_a_user_who_can_view_them(self):
        server = _make_db_server()
        tab = reverse("plugins:netbox_kea:server_sync_status", args=[server.pk])
        _grant([Server], ["view"], user=self.user)
        _grant([SyncConfig], ["change"], user=self.user)

        self.assertNotContains(self.client.get(tab), self.link)
        _grant([SyncConfig], ["view"], user=self.user)
        self.assertContains(self.client.get(tab), self.link)


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestSyncPagesWriteNothingOnGet(TestCase):
    """A GET of a sync page reads the migrated SyncConfig row and writes no row."""

    def setUp(self):
        self.client.force_login(User.objects.create_superuser("readonly", "r@r.com", "pass"))
        self.server = _make_db_server()

    def test_sync_page_get_writes_no_row(self):
        for url in _sync_page_urls(self.server):
            with self.subTest(url=url):
                response, writes = _get_with_writes(self.client, url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(writes, [])


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestServerSyncStatusView(TestCase):
    """GET /plugins/kea/servers/{pk}/sync-status/"""

    def setUp(self):
        self.user = User.objects.create_superuser("synctest2", "s2@s.com", "pass")
        self.client.force_login(self.user)
        self.server = _make_db_server()

    def test_get_returns_200(self):
        url = reverse("plugins:netbox_kea:server_sync_status", args=[self.server.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_get_shows_server_name(self):
        url = reverse("plugins:netbox_kea:server_sync_status", args=[self.server.pk])
        response = self.client.get(url)
        self.assertContains(response, self.server.name)

    def test_get_contains_jobs_list_link(self):
        url = reverse("plugins:netbox_kea:server_sync_status", args=[self.server.pk])
        response = self.client.get(url)
        self.assertContains(response, f"object_id={self.server.pk}")

    def test_can_change_server_true_for_superuser(self):
        """can_change_server is True for superuser via object-level restrict check."""
        url = reverse("plugins:netbox_kea:server_sync_status", args=[self.server.pk])
        response = self.client.get(url)
        self.assertTrue(response.context["can_change_server"])


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestServerSyncNowView(TestCase):
    """POST /plugins/kea/servers/{pk}/sync-now/"""

    def setUp(self):
        self.user = User.objects.create_superuser("synctest3", "s3@s.com", "pass")
        self.client.force_login(self.user)
        self.server = _make_db_server()

    def test_post_enqueues_job_and_redirects(self):
        url = reverse("plugins:netbox_kea:server_sync_now", args=[self.server.pk])
        with patch("netbox_kea.views.sync_jobs.KeaIpamSyncJob", autospec=True) as MockJob:
            response = self.client.post(url)
        MockJob.enqueue.assert_called_once_with(instance=self.server, user=self.user, server_pk=self.server.pk)
        self.assertRedirects(
            response,
            reverse("plugins:netbox_kea:server_sync_status", args=[self.server.pk]) + "?family=4",
            fetch_redirect_response=False,
        )

    def test_post_without_permission_returns_403(self):
        restricted = User.objects.create_user("noperm", "n@n.com", "pass")
        self.client.force_login(restricted)
        url = reverse("plugins:netbox_kea:server_sync_now", args=[self.server.pk])
        response = self.client.post(url)
        self.assertEqual(response.status_code, 403)

    def test_post_enqueue_exception_shows_error_message(self):
        url = reverse("plugins:netbox_kea:server_sync_now", args=[self.server.pk])
        with patch("netbox_kea.views.sync_jobs.KeaIpamSyncJob", autospec=True) as MockJob:
            MockJob.enqueue.side_effect = RuntimeError("queue full")
            response = self.client.post(url, follow=True)
        self.assertContains(response, "internal error")


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestServerSyncToggleView(TestCase):
    """POST /plugins/kea/servers/{pk}/sync-toggle/"""

    def setUp(self):
        self.user = User.objects.create_superuser("synctest4", "s4@s.com", "pass")
        self.client.force_login(self.user)
        self.server = _make_db_server()

    def test_post_toggles_sync_enabled_true_to_false(self):
        self.assertTrue(self.server.sync_enabled)
        url = reverse("plugins:netbox_kea:server_sync_toggle", args=[self.server.pk])
        self.client.post(url)
        self.server.refresh_from_db()
        self.assertFalse(self.server.sync_enabled)

    def test_toggle_change_record_keeps_the_previous_sync_state(self):
        from core.models import ObjectChange
        from django.contrib.contenttypes.models import ContentType

        url = reverse("plugins:netbox_kea:server_sync_toggle", args=[self.server.pk])
        response = self.client.post(url)
        self.assertEqual(response.status_code, 302)
        change = ObjectChange.objects.get(
            changed_object_type=ContentType.objects.get_for_model(self.server),
            changed_object_id=self.server.pk,
            action="update",
        )
        self.assertIsNotNone(change.prechange_data)
        self.assertIs(change.prechange_data["sync_enabled"], True)
        self.assertIs(change.postchange_data["sync_enabled"], False)

    def test_post_toggles_sync_enabled_false_to_true(self):
        self.server.sync_enabled = False
        self.server.save(update_fields=["sync_enabled"])
        url = reverse("plugins:netbox_kea:server_sync_toggle", args=[self.server.pk])
        self.client.post(url)
        self.server.refresh_from_db()
        self.assertTrue(self.server.sync_enabled)

    def test_post_redirects_to_sync_status_tab(self):
        url = reverse("plugins:netbox_kea:server_sync_toggle", args=[self.server.pk])
        response = self.client.post(url)
        self.assertRedirects(
            response,
            reverse("plugins:netbox_kea:server_sync_status", args=[self.server.pk]) + "?family=4",
            fetch_redirect_response=False,
        )

    def test_post_without_permission_returns_403(self):
        restricted = User.objects.create_user("noperm_toggle", "nt@nt.com", "pass")
        self.client.force_login(restricted)
        url = reverse("plugins:netbox_kea:server_sync_toggle", args=[self.server.pk])
        response = self.client.post(url)
        self.assertEqual(response.status_code, 403)


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestSyncJobsViewAllowedServerPks(TestCase):
    """allowed_server_pks in SyncJobsView context is permission-filtered."""

    def setUp(self):
        self.server = _make_db_server(name="restricted-server")

    def test_superuser_sees_server_in_allowed_pks(self):
        su = User.objects.create_superuser("su_allowed", "su@a.com", "pass")
        self.client.force_login(su)
        response = self.client.get(reverse("plugins:netbox_kea:sync_jobs"))
        self.assertIn(self.server.pk, response.context["allowed_server_pks"])

    def test_user_without_change_perm_has_empty_allowed_pks(self):
        user = User.objects.create_user("ro_user", "ro@a.com", "pass")
        self.client.force_login(user)
        # Read-only user must still be logged in (login is enforced by the view)
        # but since they have no perms they would be redirected; to test the
        # context we give them view (but not change) permission.
        from django.contrib.auth.models import Permission

        view_perm = Permission.objects.get(codename="view_server", content_type__app_label="netbox_kea")
        user.user_permissions.add(view_perm)
        response = self.client.get(reverse("plugins:netbox_kea:sync_jobs"))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.server.pk, response.context["allowed_server_pks"])


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestServerSyncToggleViewErrorHandling(TestCase):
    """ServerSyncToggleView.post wraps save() in try/except."""

    def setUp(self):
        self.user = User.objects.create_superuser("synctest5", "s5@s.com", "pass")
        self.client.force_login(self.user)
        self.server = _make_db_server()

    def test_post_db_error_shows_error_message_and_redirects(self):
        from unittest.mock import patch

        from django.db import DatabaseError

        url = reverse("plugins:netbox_kea:server_sync_toggle", args=[self.server.pk])
        with patch.object(self.server.__class__, "save", side_effect=DatabaseError("disk full")):
            with patch("netbox_kea.views.sync_jobs.get_object_or_404", return_value=self.server, autospec=True):
                response = self.client.post(url, follow=True)
        self.assertContains(response, "internal error")
        self.assertRedirects(
            response,
            reverse("plugins:netbox_kea:server_sync_status", args=[self.server.pk]) + "?family=4",
            fetch_redirect_response=False,
            target_status_code=200,
        )


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestMigrationsApplied(TestCase):
    """Regression tests: DB columns/tables from new migrations must exist.

    These catch the scenario where the plugin is updated but ``manage.py migrate``
    has not been run (observed as ProgrammingError on combined/sync-jobs pages).
    """

    def setUp(self):
        self.user = User.objects.create_superuser("migtest", "m@m.com", "pass")
        self.client.force_login(self.user)
        _make_db_server(name="mig-server")

    def test_server_sync_enabled_column_accessible(self):
        """Regression: migration 0006 must have added sync_enabled to Server."""
        from netbox_kea.models import Server

        count = Server.objects.filter(sync_enabled=True).count()
        self.assertIsInstance(count, int)

    def test_syncconfig_table_accessible(self):
        """Regression: migration 0005 must have created netbox_kea_syncconfig table."""
        count = SyncConfig.objects.count()
        self.assertIsInstance(count, int)

    def test_combined_view_does_not_500(self):
        """Regression: /plugins/kea/combined/ must not raise ProgrammingError."""
        response = self.client.get(reverse("plugins:netbox_kea:combined"))
        self.assertNotEqual(response.status_code, 500)

    def test_sync_jobs_view_does_not_500(self):
        """Regression: /plugins/kea/sync-jobs/ must not raise ProgrammingError."""
        response = self.client.get(reverse("plugins:netbox_kea:sync_jobs"))
        self.assertNotEqual(response.status_code, 500)

    def test_server_supports_job_assignment(self):
        """Regression: migration 0008 must enable Job assignment to Server (JobsMixin)."""
        from netbox.models.features import has_feature

        from netbox_kea.models import Server

        self.assertTrue(has_feature(Server, "jobs"), "Server must have the 'jobs' feature (JobsMixin)")


@with_kea_client_config(lease_query_max_unpaged_leases=0)
class TestGetRecentJobsForServers(TestCase):
    """Unit tests for get_recent_jobs_for_servers helper."""

    def setUp(self):
        from django.contrib.contenttypes.models import ContentType

        from netbox_kea.models import Server

        self.server_a = _make_db_server(name="server-a")
        self.server_b = _make_db_server(name="server-b")
        self.ct = ContentType.objects.get_for_model(Server)

    def test_returns_empty_list_for_server_with_no_jobs(self):
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        result = get_recent_jobs_for_servers([self.server_a.pk])
        self.assertEqual(result[self.server_a.pk], [])

    def test_returns_bound_job_for_server(self):
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        job = _make_job(object_id=self.server_a.pk, object_type=self.ct)
        result = get_recent_jobs_for_servers([self.server_a.pk])
        self.assertEqual(len(result[self.server_a.pk]), 1)
        self.assertEqual(result[self.server_a.pk][0].pk, job.pk)

    def test_returns_unbound_periodic_job_attributed_via_summary(self):
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        job = _make_job(data={"summary": [{"pk": self.server_a.pk, "name": "server-a"}]})
        result = get_recent_jobs_for_servers([self.server_a.pk])
        self.assertEqual(len(result[self.server_a.pk]), 1)
        self.assertEqual(result[self.server_a.pk][0].pk, job.pk)

    def test_periodic_job_shown_even_when_bound_jobs_fill_limit(self):
        """Core regression: periodic (unbound) jobs must appear even when limit bound jobs exist."""
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        # Create 3 bound manual jobs (older)
        for i in range(3, 0, -1):
            _make_job(object_id=self.server_a.pk, object_type=self.ct, delta_seconds=i * 100)

        # Create 1 periodic job (newer than all bound jobs)
        periodic = _make_job(
            data={"summary": [{"pk": self.server_a.pk}]},
            delta_seconds=10,  # very recent
        )

        result = get_recent_jobs_for_servers([self.server_a.pk], limit=3)
        pks = [j.pk for j in result[self.server_a.pk]]
        self.assertIn(periodic.pk, pks, "Periodic job must appear even when limit bound jobs fill the slot")

    def test_most_recent_job_returned_first(self):
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        old = _make_job(object_id=self.server_a.pk, object_type=self.ct, delta_seconds=200)
        new = _make_job(object_id=self.server_a.pk, object_type=self.ct, delta_seconds=10)
        result = get_recent_jobs_for_servers([self.server_a.pk], limit=5)
        pks = [j.pk for j in result[self.server_a.pk]]
        self.assertEqual(pks[0], new.pk)
        self.assertEqual(pks[1], old.pk)

    def test_limit_respected(self):
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        for i in range(5):
            _make_job(object_id=self.server_a.pk, object_type=self.ct, delta_seconds=i * 10)
        result = get_recent_jobs_for_servers([self.server_a.pk], limit=2)
        self.assertEqual(len(result[self.server_a.pk]), 2)

    def test_multiple_servers_independent(self):
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        job_a = _make_job(object_id=self.server_a.pk, object_type=self.ct)
        job_b = _make_job(object_id=self.server_b.pk, object_type=self.ct)
        result = get_recent_jobs_for_servers([self.server_a.pk, self.server_b.pk])
        self.assertEqual(result[self.server_a.pk][0].pk, job_a.pk)
        self.assertEqual(result[self.server_b.pk][0].pk, job_b.pk)

    def test_unbound_job_summary_none_does_not_raise(self):
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        _make_job(data={"summary": None})
        # Should not raise, server gets no jobs
        result = get_recent_jobs_for_servers([self.server_a.pk])
        self.assertEqual(result[self.server_a.pk], [])

    def test_unbound_job_missing_data_does_not_raise(self):
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        _make_job(data=None)
        result = get_recent_jobs_for_servers([self.server_a.pk])
        self.assertEqual(result[self.server_a.pk], [])

    def test_unknown_server_pk_returns_empty(self):
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        result = get_recent_jobs_for_servers([999999])
        self.assertEqual(result[999999], [])

    def test_deduplication_when_job_attributed_to_two_pks(self):
        """An unbound job covering two servers must not be double-counted per server."""
        from netbox_kea.views.sync_jobs import get_recent_jobs_for_servers

        job = _make_job(
            data={"summary": [{"pk": self.server_a.pk}, {"pk": self.server_b.pk}]},
        )
        result = get_recent_jobs_for_servers([self.server_a.pk, self.server_b.pk])
        # Each server sees the job exactly once
        self.assertEqual(len([j for j in result[self.server_a.pk] if j.pk == job.pk]), 1)
        self.assertEqual(len([j for j in result[self.server_b.pk] if j.pk == job.pk]), 1)


@with_kea_client_config(lease_query_max_unpaged_leases=0)
@skipUnlessDBFeature("supports_json_field_contains")
class TestGetAllJobsForServer(TestCase):
    """Unit tests for get_all_jobs_for_server helper (used by per-server Jobs tab)."""

    def setUp(self):
        from django.contrib.contenttypes.models import ContentType

        from netbox_kea.models import Server

        self.server_a = _make_db_server(name="server-a")
        self.server_b = _make_db_server(name="server-b")
        self.ct = ContentType.objects.get_for_model(Server)

    def test_includes_bound_jobs(self):
        from netbox_kea.views.sync_jobs import get_all_jobs_for_server

        job = _make_job(object_id=self.server_a.pk, object_type=self.ct)
        pks = list(get_all_jobs_for_server(self.server_a.pk).values_list("pk", flat=True))
        self.assertIn(job.pk, pks)

    def test_includes_unbound_periodic_jobs(self):
        from netbox_kea.views.sync_jobs import get_all_jobs_for_server

        job = _make_job(data={"summary": [{"pk": self.server_a.pk, "name": "server-a"}]})
        pks = list(get_all_jobs_for_server(self.server_a.pk).values_list("pk", flat=True))
        self.assertIn(job.pk, pks)

    def test_excludes_unrelated_periodic_jobs(self):
        from netbox_kea.views.sync_jobs import get_all_jobs_for_server

        # periodic job referencing only server_b
        _make_job(data={"summary": [{"pk": self.server_b.pk}]})
        pks = list(get_all_jobs_for_server(self.server_a.pk).values_list("pk", flat=True))
        self.assertEqual(pks, [])

    def test_excludes_jobs_with_different_name(self):
        from netbox_kea.views.sync_jobs import get_all_jobs_for_server

        _make_job(name="Some Other Job", object_id=self.server_a.pk, object_type=self.ct)
        _make_job(name="Some Other Job", data={"summary": [{"pk": self.server_a.pk}]})
        pks = list(get_all_jobs_for_server(self.server_a.pk).values_list("pk", flat=True))
        self.assertEqual(pks, [])

    def test_orders_newest_first(self):
        from netbox_kea.views.sync_jobs import get_all_jobs_for_server

        old = _make_job(object_id=self.server_a.pk, object_type=self.ct, delta_seconds=200)
        new = _make_job(data={"summary": [{"pk": self.server_a.pk}]}, delta_seconds=10)
        pks = list(get_all_jobs_for_server(self.server_a.pk).values_list("pk", flat=True))
        self.assertEqual(pks[0], new.pk)
        self.assertEqual(pks[1], old.pk)


@with_kea_client_config(lease_query_max_unpaged_leases=0)
@skipUnlessDBFeature("supports_json_field_contains")
class TestServerJobsView(TestCase):
    """Tests for the per-server Jobs tab override (includes periodic jobs)."""

    def setUp(self):
        from django.contrib.contenttypes.models import ContentType

        from netbox_kea.models import Server

        self.user = User.objects.create_superuser("jobstest", "j@j.com", "pass")
        self.client.force_login(self.user)
        self.server = _make_db_server(name="server-jobs")
        self.ct = ContentType.objects.get_for_model(Server)

    def test_jobs_tab_url_resolves_to_override(self):
        """The plugin must replace NetBox's auto-registered jobs view."""
        from netbox.registry import registry

        from netbox_kea.views.sync_jobs import ServerJobsView

        entries = [e for e in registry["views"]["netbox_kea"]["server"] if e["name"] == "jobs"]
        self.assertEqual(len(entries), 1, "Exactly one 'jobs' view must be registered for Server")
        self.assertIs(entries[0]["view"], ServerJobsView)

    def test_jobs_tab_renders_bound_job(self):
        bound = _make_job(object_id=self.server.pk, object_type=self.ct)
        url = reverse("plugins:netbox_kea:server_jobs", args=[self.server.pk])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, f"/core/jobs/{bound.pk}/")

    def test_jobs_tab_renders_periodic_job(self):
        """Regression: periodic (object_id=NULL) jobs must appear on the Jobs tab."""
        periodic = _make_job(data={"summary": [{"pk": self.server.pk, "name": "server-jobs"}]})
        url = reverse("plugins:netbox_kea:server_jobs", args=[self.server.pk])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, f"/core/jobs/{periodic.pk}/")

    def test_jobs_tab_excludes_unrelated_periodic_job(self):
        other = _make_db_server(name="other-server")
        _make_job(data={"summary": [{"pk": other.pk}]})
        url = reverse("plugins:netbox_kea:server_jobs", args=[self.server.pk])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        # Table should be empty (no link to any /core/jobs/N/)
        # Use a strict check: no rendered job rows
        from netbox_kea.views.sync_jobs import get_all_jobs_for_server

        self.assertEqual(get_all_jobs_for_server(self.server.pk).count(), 0)

    def test_jobs_tab_returns_403_without_view_job_permission(self):
        """Users without core.view_job must receive 403 even on direct URL access."""
        from django.contrib.auth.models import Permission

        # Create a regular user (non-superuser) with no permissions
        unprivileged = User.objects.create_user("noperm", "n@n.com", "pass")
        # Grant basic NetBox plugin access so the login doesn't fail before our check
        view_server_perm = Permission.objects.get(codename="view_server")
        unprivileged.user_permissions.add(view_server_perm)
        self.client.force_login(unprivileged)

        url = reverse("plugins:netbox_kea:server_jobs", args=[self.server.pk])
        r = self.client.get(url)
        self.assertEqual(r.status_code, 403)


class TestKeaClientSettingsView(TestCase):
    """The Kea Client section of the Settings page, as a superuser."""

    def setUp(self):
        self.user = User.objects.create_superuser("kea-client-admin", "k@k.com", "pass")
        self.client.force_login(self.user)
        self.url = reverse("plugins:netbox_kea:settings")

    def test_get_shows_the_stored_values(self):
        KeaClientConfig.objects.filter(pk=1).update(kea_timeout=12, lease_query_max_unpaged_leases=0)

        page = BeautifulSoup(self.client.get(self.url).content, "html.parser")

        section = page.find(id="kea-client")
        self.assertEqual(section.find(id="id_kea-client-kea_timeout")["value"], "12")
        self.assertEqual(section.find(id="id_kea-client-lease_query_max_unpaged_leases")["value"], "0")
        self.assertIsNotNone(section.select_one('form[method="post"] button[type="submit"]'))

    def test_a_posted_timeout_reaches_the_next_get_client_without_a_restart(self):
        server = _make_db_server()
        before = server.get_client(version=4)
        self.assertEqual((before.timeout, before.max_unpaged_leases), (30, 1000))

        response = self.client.post(
            self.url, _kea_client_settings(kea_timeout=10, lease_query_max_unpaged_leases=250), follow=True
        )

        self.assertRedirects(response, self.url)
        self.assertContains(response, "Kea Client Configuration saved.")
        after = Server.objects.get(pk=server.pk).get_client(version=4)
        self.assertEqual((after.timeout, after.max_unpaged_leases), (10, 250))
        self.assertEqual(before.timeout, 30, "a client keeps the timeout it was built with")

    def test_post_invalid_values_show_the_error_and_change_nothing(self):
        for field, value in (
            ("kea_timeout", 0),
            ("kea_timeout", -1),
            ("kea_timeout", "soon"),
            ("lease_query_max_unpaged_leases", -1),
        ):
            with self.subTest(field=field, value=value):
                response = self.client.post(self.url, _kea_client_settings(**{field: value}))
                self.assertEqual(response.status_code, 200)
                (entry,) = [shown for shown in response.context["sections"] if shown.section.slug == "kea-client"]
                self.assertIn(field, entry.form.errors)
                config = KeaClientConfig.get()
                self.assertEqual((config.kea_timeout, config.lease_query_max_unpaged_leases), (30, 1000))

    def test_a_save_records_one_change_that_the_change_log_api_lists(self):
        from core.models import ObjectChange
        from django.contrib.contenttypes.models import ContentType
        from rest_framework.test import APIClient

        self.client.post(self.url, _kea_client_settings(kea_timeout=45))

        change = ObjectChange.objects.get(
            changed_object_type=ContentType.objects.get_for_model(KeaClientConfig), changed_object_id=1
        )
        self.assertEqual(change.action, "update")
        self.assertEqual((change.prechange_data["kea_timeout"], change.postchange_data["kea_timeout"]), (30, 45))
        api = APIClient(raise_request_exception=False)
        api.force_authenticate(user=self.user)
        response = api.get(reverse("core-api:objectchange-list"))
        self.assertEqual(response.status_code, 200, response.content[:300])
        (listed,) = response.json()["results"]
        self.assertEqual(listed["changed_object"], {"id": 1, "display": "Kea Client Configuration"})

    def test_the_singleton_cannot_be_deleted(self):
        with self.assertRaisesMessage(TypeError, "KeaClientConfig singleton cannot be deleted."):
            KeaClientConfig.get().delete()
        self.assertTrue(KeaClientConfig.objects.filter(pk=1).exists())


class TestDhcpIntegrationSettingsView(TestCase):
    """The DHCP Plugin section of the Settings page holds the global switch. It shows only with netbox_dhcp."""

    def setUp(self):
        self.user = User.objects.create_superuser("dhcp-integration-admin", "d@d.com", "pass")
        self.client.force_login(self.user)
        self.url = reverse("plugins:netbox_kea:settings")

    def _slugs(self) -> list[str]:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        return [shown.section.slug for shown in response.context["sections"]]

    def test_a_save_turns_the_integration_off_and_the_change_log_api_lists_it(self):
        from core.models import ObjectChange
        from django.contrib.contenttypes.models import ContentType
        from rest_framework.test import APIClient

        with patch.object(dhcp_plugin, "is_available", return_value=True, autospec=True):
            page = BeautifulSoup(self.client.get(self.url).content, "html.parser")
            response = self.client.post(self.url, _section_data("dhcp-integration", {"enabled": False}), follow=True)

        self.assertTrue(page.find(id="dhcp-integration").find(id="id_dhcp-integration-enabled").has_attr("checked"))
        self.assertRedirects(response, self.url)
        self.assertContains(response, "DHCP Plugin Integration saved.")
        self.assertIs(DhcpIntegrationConfig.get().enabled, False)
        change = ObjectChange.objects.get(
            changed_object_type=ContentType.objects.get_for_model(DhcpIntegrationConfig), changed_object_id=1
        )
        self.assertEqual((change.prechange_data["enabled"], change.postchange_data["enabled"]), (True, False))
        api = APIClient(raise_request_exception=False)
        api.force_authenticate(user=self.user)
        listed = api.get(reverse("core-api:objectchange-list"))
        self.assertEqual(listed.status_code, 200, listed.content[:300])
        (entry,) = listed.json()["results"]
        self.assertEqual(entry["changed_object"], {"id": 1, "display": "DHCP Plugin Integration"})

    def test_without_the_dhcp_plugin_the_section_is_hidden_and_a_post_is_refused(self):
        with patch.object(dhcp_plugin, "is_available", return_value=True, autospec=True):
            self.assertIn("dhcp-integration", self._slugs())
        with patch.object(dhcp_plugin, "is_available", return_value=False, autospec=True):
            self.assertEqual(self._slugs(), ["sync", "kea-client"])
            response = self.client.post(self.url, _section_data("dhcp-integration", {"enabled": False}))

        self.assertEqual(response.status_code, 400)
        self.assertIs(DhcpIntegrationConfig.get().enabled, True)

    def test_without_the_dhcp_plugin_the_settings_menu_has_no_dhcp_plugin_item(self):
        from netbox_kea import navigation

        def menu_texts():
            return [item.link_text for item in navigation._settings_items()]

        with patch.object(dhcp_plugin, "is_available", return_value=True, autospec=True):
            self.assertEqual(menu_texts(), ["Sync", "Kea Client", "DHCP Plugin"])
        with patch.object(dhcp_plugin, "is_available", return_value=False, autospec=True):
            self.assertEqual(menu_texts(), ["Sync", "Kea Client"])


class TestKeaClientSettingsPermissions(TestCase):
    """The Kea Client section shows with view_keaclientconfig and saves with change_keaclientconfig as well."""

    def setUp(self):
        self.user = User.objects.create_user("kea-client-user")
        self.client.force_login(self.user)
        self.url = reverse("plugins:netbox_kea:settings")

    def _shown_sections(self) -> list[str]:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        return [shown.section.slug for shown in response.context["sections"]]

    def test_each_section_shows_only_with_its_own_view_permission(self):
        _grant([KeaClientConfig], ["view", "change"], user=self.user)
        self.assertEqual(self._shown_sections(), ["kea-client"])
        _grant([SyncConfig], ["view"], user=self.user)
        self.assertEqual(self._shown_sections(), ["sync", "kea-client"])

    def test_a_viewer_sees_the_values_read_only_without_a_submit_control(self):
        _grant([KeaClientConfig], ["view"], user=self.user)
        KeaClientConfig.objects.filter(pk=1).update(kea_timeout=12)

        page = BeautifulSoup(self.client.get(self.url).content, "html.parser")

        timeout = page.find(id="id_kea-client-kea_timeout")
        self.assertEqual(timeout["value"], "12")
        self.assertTrue(timeout.has_attr("disabled"))
        self.assertTrue(page.find(id="id_kea-client-lease_query_max_unpaged_leases").has_attr("disabled"))
        self.assertIsNone(page.select_one('form[method="post"]'))

    def test_a_post_without_both_permissions_is_refused_and_changes_nothing(self):
        for actions in (["view"], ["change"]):
            with self.subTest(actions=actions):
                user = User.objects.create_user(f"kea-client-{'-'.join(actions)}")
                _grant([KeaClientConfig], actions, user=user)
                _grant([SyncConfig], ["view", "change"], user=user)
                self.client.force_login(user)

                response = self.client.post(self.url, _kea_client_settings(kea_timeout=10))

                self.assertEqual(response.status_code, 403)
                self.assertEqual(KeaClientConfig.get().kea_timeout, 30)

    def test_a_user_with_view_and_change_saves(self):
        _grant([KeaClientConfig], ["view", "change"], user=self.user)

        response = self.client.post(self.url, _kea_client_settings(kea_timeout=10))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(KeaClientConfig.get().kea_timeout, 10)
