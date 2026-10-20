# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Add the reasons of a DHCP Import removal that was suppressed or blocked."""

from django.db import migrations, models

# netbox_kea tables stay in main, so branch migrate fakes this migration (ADR 0007).
fake_on_branch = True


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_kea", "0031_dhcp_import_server_mapping"),
    ]

    operations = [
        migrations.AlterField(
            model_name="dhcpimportentry",
            name="reason",
            field=models.CharField(
                blank=True,
                choices=[
                    ('plugin_gap', 'The DHCP plugin cannot hold it'),
                    ('subnet_id_clash', 'Another Server or family holds this Subnet ID'),
                    ('not_in_scope', 'Not in scope'),
                    ('inherited_from_shared_network', 'Inherited from a Shared Network'),
                    ('no_matching_interface', 'No matching interface'),
                    ('invalid_kea_data', 'Invalid Kea data'),
                    ('no_plugin_home', 'No DHCP plugin field by design'),
                    ('parent_not_imported', 'Its parent object was not imported'),
                    ('ipam_ownership', 'IPAM ownership kept the IPAM object unchanged'),
                    ('write_failed', 'The write failed'),
                    ('read_failed', 'Kea could not be read in full'),
                    ('incomplete_observation', 'Kea was not observed in full, so removal was suppressed'),
                    ('removal_blocked', 'Other rows still depend on it, so it was not removed'),
                ],
                max_length=32,
            ),
        ),
    ]
