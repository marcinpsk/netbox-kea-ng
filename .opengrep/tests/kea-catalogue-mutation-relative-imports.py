# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-catalogue-mutation-outside-config-write: module-level one-dot imports, and a nested
# function that imports the name of an outer parameter again. No absolute import binds a name here.
# Intentionally contains rule-violating code; excluded from ruff (see pyproject exclude).
from . import subnet_catalogue
from . import subnet_catalogue as one_dot_catalogue
from .subnet_catalogue import mutation
from .subnet_catalogue import mutation as one_dot_mutate


def bad_one_dot_module(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with subnet_catalogue.mutation(server, 4) as scope:
        return scope.find_by_id(20)


def bad_one_dot_module_alias(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with one_dot_catalogue.mutation(server, 4) as scope:
        return scope.find_by_id(20)


def bad_one_dot_name(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with mutation(server, 4) as scope:
        return scope.find_by_id(20)


def bad_one_dot_name_alias(server):
    # ruleid: kea-catalogue-mutation-outside-config-write
    with one_dot_mutate(server, 4) as scope:
        return scope.find_by_id(20)


def bad_nested_import_of_the_parameter_name(mutation):
    def read(server):
        from ..subnet_catalogue import mutation

        # ruleid: kea-catalogue-mutation-outside-config-write
        with mutation(server, 4) as scope:
            return scope.find_by_id(20)

    return read


def bad_nested_import_of_the_parameter_alias(one_dot_mutate):
    def read(server):
        from .subnet_catalogue import mutation as one_dot_mutate

        # ruleid: kea-catalogue-mutation-outside-config-write
        with one_dot_mutate(server, 4) as scope:
            return scope.find_by_id(20)

    return read


def bad_nested_import_of_the_parameter_module(subnet_catalogue):
    def read(server):
        from .. import subnet_catalogue

        # ruleid: kea-catalogue-mutation-outside-config-write
        with subnet_catalogue.mutation(server, 4) as scope:
            return scope.find_by_id(20)

    return read


def bad_nested_import_of_the_parameter_module_alias(one_dot_catalogue):
    def read(server):
        from . import subnet_catalogue as one_dot_catalogue

        # ruleid: kea-catalogue-mutation-outside-config-write
        with one_dot_catalogue.mutation(server, 4) as scope:
            return scope.find_by_id(20)

    return read


def ok_nested_function_uses_the_parameter(mutation):
    def read(server):
        # ok: kea-catalogue-mutation-outside-config-write
        return mutation(server, 4)

    return read


def ok_nested_function_uses_the_module_parameter(subnet_catalogue):
    def read(server):
        # ok: kea-catalogue-mutation-outside-config-write
        return subnet_catalogue.mutation(server, 4)

    return read
