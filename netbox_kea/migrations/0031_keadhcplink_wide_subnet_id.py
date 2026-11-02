# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Let a DHCP Import Mapping hold every Kea subnet ID, up to MAX_SUBNET_ID."""

import importlib

from django.db import migrations, models

_0030 = importlib.import_module("netbox_kea.migrations.0030_keadhcplink_unbounded_identity")

# netbox_kea tables stay in main (ADR 0007), and KeaDhcpLink follows its targets into branches (ADR 0008),
# but branch migrate fakes every plugin migration.
fake_on_branch = True


class Migration(migrations.Migration):
    dependencies = [
        ('netbox_kea', '0030_keadhcplink_unbounded_identity'),
    ]

    operations = [
        migrations.AlterField(
            model_name='keadhcplink',
            name='kea_subnet_id',
            field=models.PositiveBigIntegerField(blank=True, help_text='Kea subnet-id of the source object or of its Subnet; null for a global source.', null=True),
        ),
        # A reverse runs this first, so 0030's refusal comes before the narrowing above (no release ends at 0030).
        migrations.RunPython(migrations.RunPython.noop, _0030.refuse_long_identities),
    ]
