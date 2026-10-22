# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Add the setting that runs the scheduled DHCP Import with the periodic sync job. It is off."""

from django.db import migrations, models

# netbox_kea tables stay in main, so branch migrate fakes this migration (ADR 0007).
fake_on_branch = True


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_kea", "0033_keadhcplink_class_option_definition_identity"),
    ]

    operations = [
        migrations.AddField(
            model_name="dhcpintegrationconfig",
            name="scheduled_import_enabled",
            field=models.BooleanField(
                default=False,
                help_text="The periodic sync job also runs the DHCP Import of each Server that has 'Sync to DHCP plugin' on.",
                verbose_name="Scheduled Import",
            ),
        ),
    ]
