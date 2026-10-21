# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Let the DHCP Import own the Prefixes of delegated-prefix Pools through the source pd-pool (ADR 0006)."""

from django.db import migrations, models

# netbox_kea tables stay in main, so branch migrate fakes this migration (ADR 0007).
fake_on_branch = True


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_kea", "0034_dhcpintegrationconfig_scheduled_import_enabled"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="ipamownershiplink",
            name="ipamownershiplink_source",
        ),
        migrations.AddConstraint(
            model_name="ipamownershiplink",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ("source__in", ["lease", "reservation", "subnet", "pool", "delegated-prefix", "lease-prefix", "pd-pool"])
                ),
                name="ipamownershiplink_source",
            ),
        ),
    ]
