# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-catalogue-mutation-outside-config-write. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).
# The bad cases are the read-only views that entered a mutation scope (F4 of the 2026-11-05 review).
import netbox_kea.subnet_catalogue
from netbox_kea import subnet_catalogue
from netbox_kea import subnet_catalogue as catalogue
from netbox_kea.subnet_catalogue import CatalogueUnavailable, mutation
from netbox_kea.subnet_catalogue import mutation as mutate

from inventory import subnet_catalogue as inventory_catalogue
from inventory.subnet_catalogue import mutation as inventory_mutate

from .. import subnet_catalogue as relative_catalogue
from ..subnet_catalogue import mutation as relative_mutate


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


def bad_fully_qualified_call(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with netbox_kea.subnet_catalogue.mutation(server, 4) as scope:
        return scope.find_by_id(20)


def bad_module_alias(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with catalogue.mutation(server, 4) as scope:
        return scope.find_by_id(20)


def bad_name_alias(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with mutate(server, 4) as scope:
        return scope.find_by_id(20)


def bad_relative_module_alias(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with relative_catalogue.mutation(server, 4) as scope:
        return scope.find_by_id(20)


def bad_relative_name_alias(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with relative_mutate(server, 4) as scope:
        return scope.find_by_id(20)


def bad_relative_module(server):
    from .. import subnet_catalogue

    # ruleid: kea-catalogue-mutation-outside-config-write
    with subnet_catalogue.mutation(server, 4) as scope:
        return scope.find_by_id(20)


def bad_relative_name(server):
    from .subnet_catalogue import mutation

    # ruleid: kea-catalogue-mutation-outside-config-write
    with mutation(server, 4) as scope:
        return scope.find_by_id(20)


def ok_row_sync_reads_its_target_without_a_scope(server, subnet_id):
    # ok: kea-catalogue-mutation-outside-config-write
    return subnet_catalogue.read_verified(server, 4).find_by_id(subnet_id)


def ok_check_reads_the_subnet_list_only(server, subnet_id):
    # ok: kea-catalogue-mutation-outside-config-write
    return subnet_catalogue.read_identity(server, 4).find_by_id(subnet_id)


def ok_another_mutation_name(form):
    # ok: kea-catalogue-mutation-outside-config-write
    return form.mutation(4)


def ok_foreign_module_alias(server):
    # ok: kea-catalogue-mutation-outside-config-write
    return inventory_catalogue.mutation(server, 4)


def ok_foreign_name_alias(server):
    # ok: kea-catalogue-mutation-outside-config-write
    return inventory_mutate(server, 4)


def ok_local_receiver(subnet_catalogue):
    # ok: kea-catalogue-mutation-outside-config-write
    return subnet_catalogue.mutation(4)


def ok_parameter_hides_the_name(mutation):
    # ok: kea-catalogue-mutation-outside-config-write
    return mutation(4)


def ok_parameter_hides_the_relative_alias(relative_mutate):
    # ok: kea-catalogue-mutation-outside-config-write
    return relative_mutate(4)
