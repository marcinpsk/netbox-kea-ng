# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-catalogue-mutation-outside-config-write. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
# The bad cases are the read-only views that entered a mutation scope (F4 of the 2026-11-05 review).
from netbox_kea import subnet_catalogue
from netbox_kea.subnet_catalogue import CatalogueUnavailable, mutation


def bad_row_sync_reads_its_target_in_a_mutation_scope(server, subnet_id):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with subnet_catalogue.mutation(server, 4) as scope:
        return scope.find_by_id(subnet_id)


def bad_import_check_finds_each_cidr_in_a_mutation_scope(instance, proposals):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with mutation(instance, 4) as scope:
        try:
            return [scope.find_by_cidr(proposal.subnet_cidr) for proposal in proposals]
        except CatalogueUnavailable:
            return None


def bad_scope_kept_for_later(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    scope = subnet_catalogue.mutation(server, 6)
    return scope


def ok_row_sync_reads_its_target_without_a_scope(server, subnet_id):
    # ok: kea-catalogue-mutation-outside-config-write
    return subnet_catalogue.read_verified(server, 4).find_by_id(subnet_id)


def ok_check_reads_the_subnet_list_only(server, subnet_id):
    # ok: kea-catalogue-mutation-outside-config-write
    return subnet_catalogue.read_identity(server, 4).find_by_id(subnet_id)


def ok_another_mutation_name(form):
    # ok: kea-catalogue-mutation-outside-config-write
    return form.mutation(4)
