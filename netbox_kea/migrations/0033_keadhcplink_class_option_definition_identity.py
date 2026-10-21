# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Widen the DHCP Import Mapping identity for an Option Definition of a client class: "class:space:code"."""

from django.db import migrations, models

# netbox_kea tables stay in main, so branch migrate fakes this migration (ADR 0007).
fake_on_branch = True


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_kea", "0032_dhcpimportentry_removal_reasons"),
    ]

    operations = [
        migrations.AlterField(
            model_name="keadhcplink",
            name="kea_identity",
            field=models.CharField(
                blank=True,
                help_text="Identity of the source object in its Subnet or globally; null for a Subnet or family source.",
                max_length=517,
                null=True,
            ),
        ),
    ]
