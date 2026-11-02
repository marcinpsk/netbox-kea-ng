# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass

from netbox_kea import kea_paths


def skip_options(summary, family, parent_path, options):
    for opt in options:
        # ruleid: kea-option-path-outside-planned-options
        summary.record(kea_paths.option(parent_path, opt, family))


def upsert_options(planned_set, family, parent_path):
    for opt in planned_set.options:
        # ruleid: kea-option-path-outside-planned-options
        path = kea_paths.option(parent_path, opt, family)
        print(path)


@dataclass(frozen=True)
class PlannedOptions:
    owner: object
    options: tuple
    keys: tuple

    def paths(self, family):
        owner_path = self.owner.path(family)
        return tuple(
            # ok: kea-option-path-outside-planned-options
            key.path(family) if key is not None else kea_paths.option(owner_path, option, family)
            for option, key in zip(self.options, self.keys, strict=True)
        )


def other_paths(parent_path, family, index):
    # ok: kea-option-path-outside-planned-options
    return kea_paths.option_entry(parent_path, index), kea_paths.option_collection(parent_path)
