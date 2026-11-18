# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-catalogue-mutation-outside-config-write: a call to a parameter before a function-local
# import of the same name uses the parameter. No module-level import binds a name here.
# Intentionally contains rule-violating code; excluded from ruff (see pyproject exclude).


def check_module(subnet_catalogue, server):
    # ok: kea-catalogue-mutation-outside-config-write
    subnet_catalogue.mutation(server, 4)
    from .. import subnet_catalogue

    # ruleid: kea-catalogue-mutation-outside-config-write
    with subnet_catalogue.mutation(server, 4) as scope:
        return scope


def check_module_alias(scope_module, server):
    # ok: kea-catalogue-mutation-outside-config-write
    scope_module.mutation(server, 4)
    from . import subnet_catalogue as scope_module

    # ruleid: kea-catalogue-mutation-outside-config-write
    with scope_module.mutation(server, 4) as scope:
        return scope


def check_name(mutation, server):
    # ok: kea-catalogue-mutation-outside-config-write
    mutation(server, 4)
    from ..subnet_catalogue import mutation

    # ruleid: kea-catalogue-mutation-outside-config-write
    with mutation(server, 4) as scope:
        return scope


def check_name_alias(open_scope, server):
    # ok: kea-catalogue-mutation-outside-config-write
    open_scope(server, 4)
    from .subnet_catalogue import mutation as open_scope

    # ruleid: kea-catalogue-mutation-outside-config-write
    with open_scope(server, 4) as scope:
        return scope
