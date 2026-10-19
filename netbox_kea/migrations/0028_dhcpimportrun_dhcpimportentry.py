# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Add the stored result of each DHCP Import run: the run and one entry per Kea fact."""

import django.db.models.deletion
from django.db import migrations, models


# netbox_kea tables stay in main, so branch migrate fakes this migration (ADR 0007).
fake_on_branch = True


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_kea', '0027_displaycacheconfig'),
    ]

    operations = [
        migrations.CreateModel(
            name='DhcpImportRun',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('trigger', models.CharField(choices=[('manual', 'Manual'), ('scheduled', 'Scheduled')], max_length=16)),
                ('started', models.DateTimeField()),
                ('finished', models.DateTimeField()),
                (
                    'server',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='dhcp_import_runs',
                        to='netbox_kea.server',
                    ),
                ),
            ],
            options={
                'verbose_name': 'DHCP Import run',
                'ordering': ('-started', '-pk'),
                'indexes': [models.Index(fields=['server', '-started'], name='dhcpimportrun_server_started')],
            },
        ),
        migrations.CreateModel(
            name='DhcpImportEntry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('family', models.PositiveSmallIntegerField()),
                (
                    'kind',
                    models.CharField(
                        choices=[
                            ('server', 'Global configuration'),
                            ('option_definition', 'Option Definition'),
                            ('client_class', 'Client class'),
                            ('shared_network', 'Shared Network'),
                            ('subnet', 'Subnet'),
                            ('pool', 'Pool'),
                            ('reservation', 'Reservation'),
                            ('option', 'DHCP Option'),
                        ],
                        max_length=32,
                    ),
                ),
                (
                    'outcome',
                    models.CharField(
                        choices=[
                            ('created', 'Created'),
                            ('updated', 'Updated'),
                            ('removed', 'Removed'),
                            ('unsupported', 'Unsupported'),
                            ('skipped', 'Skipped'),
                            ('not_imported', 'Not imported'),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    'reason',
                    models.CharField(
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
                        ],
                        max_length=32,
                    ),
                ),
                ('kea_path', models.TextField()),
                ('detail', models.TextField(blank=True)),
                (
                    'run',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='entries',
                        to='netbox_kea.dhcpimportrun',
                    ),
                ),
            ],
            options={
                'verbose_name': 'DHCP Import entry',
                'verbose_name_plural': 'DHCP Import entries',
                'ordering': ('pk',),
            },
        ),
    ]
