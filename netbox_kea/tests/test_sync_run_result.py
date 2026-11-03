# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The Sync Run Result: the writer, the reader and the jobs of a Server, through the real job and real Job rows."""

from django.contrib.contenttypes.models import ContentType
from django.test import SimpleTestCase, TestCase

from netbox_kea import sync_run_result
from netbox_kea.ipam_reconciliation import SyncReport
from netbox_kea.jobs import KeaIpamSyncJob
from netbox_kea.models import Server
from netbox_kea.sync_run_result import SyncCounts, SyncRunResult, SyncRunState, jobs_of, latest

from .test_jobs import _LEASE4, _patch_kea
from .utils import _make_db_server, run_results, stored_job, with_sync_config

_REPORT = SyncReport(created=2, updated=3, errors=1, prefix_errors=4, conflicts={"10.0.0.9", "10.0.0.8"})
_REPORT.waiting_objects.update({("ipaddress", 1), ("prefix", 2)})


def _bound(server: Server) -> dict:
    return {"object_type": ContentType.objects.get_for_model(Server), "object_id": server.pk}


@with_sync_config(stale_ip_cleanup="none")
class RealJobTest(TestCase):
    """The job writes each entry through the module, and the module reads it back."""

    def test_a_periodic_run_records_a_synced_result_for_each_server_and_belongs_to_each(self):
        flags = {"dhcp6": False, "sync_prefixes_enabled": False, "sync_ip_ranges_enabled": False}
        first = _make_db_server(name="first", **flags)
        second = _make_db_server(name="second", ca_url="https://second.example.invalid", **flags)
        job = stored_job([])

        with _patch_kea(leases4=[_LEASE4]):
            KeaIpamSyncJob(job).run()

        job.refresh_from_db()
        results = run_results(job)
        self.assertEqual(
            [(r.server_pk, r.server_name, r.state) for r in results],
            [
                (first.pk, "first", SyncRunState.SYNCED),
                (second.pk, "second", SyncRunState.SYNCED),
            ],
        )
        self.assertEqual(results[0].counts, SyncCounts(1, 0, 0, 0, 0, (), 0, 0, 0, 0, 0))
        self.assertEqual([entry["state"] for entry in job.data["summary"]], ["synced", "synced"])
        self.assertEqual(list(jobs_of(first.pk)), [job])
        self.assertEqual(latest(second.pk), (job, results[1]))

    def test_a_run_now_job_records_the_result_of_its_server(self):
        server = _make_db_server(name="run-now", dhcp6=False)
        job = stored_job([], **_bound(server))

        with _patch_kea():
            KeaIpamSyncJob(job).run(server_pk=server.pk)

        job.refresh_from_db()
        (result,) = run_results(job)
        self.assertEqual((result.server_pk, result.state), (server.pk, SyncRunState.SYNCED))
        self.assertEqual(latest(server.pk), (job, result))


class WriterReaderTest(TestCase):
    """Each state reads back as it was written; the other keys of the job data stay."""

    def test_each_state_reads_back_as_written(self):
        results = [
            SyncRunResult.synced(1, "synced", _REPORT),
            SyncRunResult(2, "skipped", SyncRunState.SKIPPED),
            SyncRunResult(3, "interrupted", SyncRunState.INTERRUPTED),
            SyncRunResult(4, "unknown", SyncRunState.UNKNOWN),
        ]
        job = stored_job(results)
        job.refresh_from_db()

        self.assertEqual(run_results(job), results)
        self.assertEqual(
            results[0].counts,
            SyncCounts(2, 3, 1, 4, 2, ("10.0.0.8", "10.0.0.9"), 0, 0, 0, 2, 0),
        )

    def test_the_conflict_sample_names_the_first_conflicts_and_counts_the_rest(self):
        conflicts = {f"10.0.1.{index}" for index in range(sync_run_result.CONFLICT_SAMPLE_SIZE + 3)}
        counts = SyncCounts.from_report(SyncReport(conflicts=conflicts))
        self.assertEqual(counts.conflict_sample, tuple(sorted(conflicts)[: sync_run_result.CONFLICT_SAMPLE_SIZE]))
        self.assertEqual((counts.conflicts, counts.conflicts_truncated), (len(conflicts), 3))

    def test_the_writer_keeps_the_other_keys_of_the_job_data(self):
        job = stored_job([], data={"other": 1})
        job.refresh_from_db()
        self.assertEqual(job.data["other"], 1)


class StateCountsTest(SimpleTestCase):
    def test_only_a_synced_result_has_counts(self):
        counts = SyncCounts.from_report(_REPORT)
        for state in (SyncRunState.SKIPPED, SyncRunState.INTERRUPTED, SyncRunState.UNKNOWN):
            with self.subTest(state=state), self.assertRaises(ValueError):
                SyncRunResult(1, "name", state, counts)
        with self.assertRaises(ValueError):
            SyncRunResult(1, "name", SyncRunState.SYNCED)


class ReaderSchemaTest(TestCase):
    """The reader input here is the subject: entries that the writer of this version does not write."""

    def _read(self, data) -> dict[int, SyncRunResult]:
        job = stored_job([])
        job.data = data
        job.save(update_fields=["data"])
        job.refresh_from_db()
        return sync_run_result.read(job)

    def test_entries_of_older_versions_read_as_unknown(self):
        legacy = {
            "interrupted": {"name": "a", "pk": 1},
            "skipped": {"name": "a", "pk": 1, "ipam_skipped": True},
            "counts": {"name": "a", "pk": 1, "created": 1, "updated": 0, "errors": 0},
        }
        for shape, entry in legacy.items():
            with self.subTest(shape=shape):
                self.assertEqual(self._read({"summary": [entry]}), {1: SyncRunResult(1, "a", SyncRunState.UNKNOWN)})

    def test_entries_that_do_not_match_the_schema_read_as_unknown(self):
        synced = sync_run_result._entry(SyncRunResult.synced(1, "a", _REPORT))
        broken = {
            "unknown state": {"pk": 1, "name": "a", "state": "done"},
            "state not a string": {"pk": 1, "name": "a", "state": ["synced"]},
            "no name": {"pk": 1, "state": "skipped"},
            "extra key": {"pk": 1, "name": "a", "state": "skipped", "created": 1},
            "synced without counts": {"pk": 1, "name": "a", "state": "synced"},
            "count not an integer": {**synced, "created": "1"},
            "count a boolean": {**synced, "errors": True},
            "sample not a list": {**synced, "conflict_sample": "10.0.0.8"},
            "sample item not a string": {**synced, "conflict_sample": [8]},
        }
        for case, entry in broken.items():
            with self.subTest(case=case):
                self.assertEqual(self._read({"summary": [entry]})[1].state, SyncRunState.UNKNOWN)

    def test_two_entries_of_one_server_read_as_unknown(self):
        entry = {"pk": 1, "name": "a", "state": "skipped"}
        self.assertEqual(self._read({"summary": [entry, entry]})[1].state, SyncRunState.UNKNOWN)

    def test_an_entry_without_an_integer_pk_is_not_attributed(self):
        for entry in ({"name": "a", "state": "skipped"}, {"pk": "1"}, {"pk": True}, ["pk", 1], None):
            with self.subTest(entry=entry):
                self.assertEqual(self._read({"summary": [entry]}), {})

    def test_job_data_without_a_list_of_entries_has_no_results(self):
        for data in (None, {}, {"summary": None}, {"summary": {"pk": 1}}):
            with self.subTest(data=data):
                self.assertEqual(self._read(data), {})


class JobsOfTest(TestCase):
    """One query finds the bound and the periodic jobs of a Server, newest first."""

    def setUp(self):
        self.server = _make_db_server(name="server-a")
        self.other = _make_db_server(name="server-b")

    def _skipped(self, *servers: Server) -> list[SyncRunResult]:
        return [SyncRunResult(server.pk, server.name, SyncRunState.SKIPPED) for server in servers]

    def test_a_bound_and_a_periodic_job_both_belong_to_the_server_newest_first(self):
        bound = stored_job([], delta_seconds=200, **_bound(self.server))
        periodic = stored_job(self._skipped(self.server), delta_seconds=10)
        self.assertEqual(list(jobs_of(self.server.pk)), [periodic, bound])

    def test_a_newer_periodic_job_comes_before_older_bound_jobs(self):
        for seconds in (300, 200, 100):
            stored_job([], delta_seconds=seconds, **_bound(self.server))
        periodic = stored_job(self._skipped(self.server), delta_seconds=10)
        self.assertEqual(jobs_of(self.server.pk).first(), periodic)

    def test_a_periodic_job_of_two_servers_belongs_to_each_once(self):
        job = stored_job(self._skipped(self.server, self.other))
        self.assertEqual(list(jobs_of(self.server.pk)), [job])
        self.assertEqual(list(jobs_of(self.other.pk)), [job])

    def test_jobs_of_another_server_or_another_name_do_not_belong(self):
        stored_job(self._skipped(self.other))
        stored_job([], **_bound(self.other))
        stored_job(self._skipped(self.server), name="Some Other Job")
        stored_job([], name="Some Other Job", **_bound(self.server))
        self.assertEqual(list(jobs_of(self.server.pk)), [])
        self.assertEqual(latest(self.server.pk), (None, None))

    def test_a_bound_job_without_an_entry_of_its_server_has_no_result(self):
        job = stored_job([], **_bound(self.server))
        self.assertEqual(latest(self.server.pk), (job, None))
