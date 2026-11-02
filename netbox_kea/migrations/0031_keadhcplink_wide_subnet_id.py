# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Let a DHCP Import Mapping hold every Kea subnet ID, up to MAX_SUBNET_ID."""

import importlib

from django.db import migrations, models
from django.db.migrations.exceptions import IrreversibleError

_0030 = importlib.import_module("netbox_kea.migrations.0030_keadhcplink_unbounded_identity")

# The highest subnet ID that the PositiveIntegerField before this migration holds.
_PREVIOUS_SUBNET_ID_MAX = 2_147_483_647


def refuse_wide_subnet_ids(apps, schema_editor):
    """Refuse the reverse while a mapping holds a subnet ID that the older column cannot hold."""
    KeaDhcpLink = apps.get_model("netbox_kea", "KeaDhcpLink")
    links = KeaDhcpLink.objects.using(schema_editor.connection.alias)
    count = links.filter(kea_subnet_id__gt=_PREVIOUS_SUBNET_ID_MAX).count()
    if count:
        raise IrreversibleError(
            f"DHCP Import Mappings hold a subnet ID greater than {_PREVIOUS_SUBNET_ID_MAX} ({count} in all), and the "
            "schema before this migration cannot hold one. Nothing changed."
        )

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
        migrations.RunPython(migrations.RunPython.noop, refuse_wide_subnet_ids),
        # A reverse runs this first, so 0030's refusal comes before the narrowing above (no release ends at 0030).
        migrations.RunPython(migrations.RunPython.noop, _0030.refuse_long_identities),
    ]
