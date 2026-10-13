# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-catalogue-absence-without-consistency. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).


def bad_unknown_subnet(catalogue, catalogue_notice):
    # ruleid: kea-catalogue-absence-without-consistency
    if catalogue_notice is not None and not catalogue.configuration_complete:
        return catalogue_notice
    raise LookupError


class BadSnapshot:
    def address_qualifying_suffix(self, address):
        # ruleid: kea-catalogue-absence-without-consistency
        if not self.configuration_complete:
            raise LookupError
        return self.global_qualifying_suffix


def good_unknown_subnet(catalogue, catalogue_notice):
    # ok: kea-catalogue-absence-without-consistency
    if catalogue_notice is not None and not catalogue.configuration_confirms_absence:
        return catalogue_notice
    raise LookupError


class GoodSnapshot:
    @property
    def unavailable(self):
        # ok: kea-catalogue-absence-without-consistency
        return not (self.identity_complete or self.configuration_complete) or not self.consistent

    @property
    def configuration_confirms_absence(self):
        # ok: kea-catalogue-absence-without-consistency
        return self.configuration_complete and self.consistent
