# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Rename the Reservation delegated prefix source from ``delegated-prefix`` to ``reservation-prefix`` (ADR 0006)."""

import importlib

from django.db import migrations, models

_0030 = importlib.import_module("netbox_kea.migrations.0030_keadhcplink_unbounded_identity")
_0031 = importlib.import_module("netbox_kea.migrations.0031_keadhcplink_wide_subnet_id")

OLD = "delegated-prefix"
NEW = "reservation-prefix"


def _rename(apps, schema_editor, old, new):
    """Rename the source *old* to *new* in each link and each completion receipt, without an ObjectChange."""
    alias = schema_editor.connection.alias
    apps.get_model("netbox_kea", "IPAMOwnershipLink").objects.using(alias).filter(source=old).update(source=new)
    servers = apps.get_model("netbox_kea", "Server").objects.using(alias)
    stored = servers.exclude(ipam_initial_observations={}).values_list("pk", "ipam_initial_observations")
    for pk, observations in stored:
        renamed = {
            workflow: {
                **receipt,
                "sources": [[family, new if source == old else source] for family, source in receipt["sources"]],
            }
            for workflow, receipt in observations.items()
        }
        if renamed != observations:
            servers.filter(pk=pk).update(ipam_initial_observations=renamed)


def rename_forward(apps, schema_editor):
    """Give each link and receipt the new source name."""
    _rename(apps, schema_editor, OLD, NEW)


def rename_back(apps, schema_editor):
    """Give each link and receipt the source name of the schema before this migration."""
    _rename(apps, schema_editor, NEW, OLD)


# netbox_kea tables stay in main (ADR 0007), but branch migrate fakes every plugin migration.
fake_on_branch = True


class Migration(migrations.Migration):
    dependencies = [
        ('netbox_kea', '0031_keadhcplink_wide_subnet_id'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='ipamownershiplink',
            name='ipamownershiplink_source',
        ),
        # NetBox leaves choices out of deconstruct(), so makemigrations never writes the choices of this AlterField.
        migrations.AlterField(
            model_name='ipamownershiplink',
            name='source',
            field=models.CharField(
                choices=[
                    ('lease', 'Lease'),
                    ('reservation', 'Reservation'),
                    ('subnet', 'Subnet'),
                    ('pool', 'Pool'),
                    ('reservation-prefix', 'Reservation delegated prefix'),
                    ('lease-prefix', 'Delegated-prefix lease'),
                    ('pd-pool', 'Delegated-prefix Pool'),
                ],
                max_length=18,
            ),
        ),
        migrations.RunPython(rename_forward, rename_back),
        migrations.AddConstraint(
            model_name='ipamownershiplink',
            constraint=models.CheckConstraint(
                condition=models.Q(
                    (
                        "source__in",
                        ["lease", "reservation", "subnet", "pool", "reservation-prefix", "lease-prefix", "pd-pool"],
                    )
                ),
                name='ipamownershiplink_source',
            ),
        ),
        # A reverse runs these first, so the refusals of 0031 and 0030 come before this migration reverses.
        migrations.RunPython(migrations.RunPython.noop, _0031.refuse_wide_subnet_ids),
        migrations.RunPython(migrations.RunPython.noop, _0030.refuse_long_identities),
    ]
