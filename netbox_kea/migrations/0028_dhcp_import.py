# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Add the DHCP Import run results, the DHCP Import Mapping kinds and identities, the scheduled import switch and the PD Pool links."""

import django.db.models.deletion
from django.db import migrations, models


def backfill_kind(apps, schema_editor):
    """Set the kind of each mapping that a release before the kind column wrote: a Subnet or a Global Reservation."""
    KeaDhcpLink = apps.get_model("netbox_kea", "KeaDhcpLink")
    links = KeaDhcpLink.objects.using(schema_editor.connection.alias)
    links.filter(kea_subnet_id__isnull=False).update(kind="subnet")
    links.filter(kea_subnet_id__isnull=True).update(kind="reservation")


def remove_unheld_links(apps, schema_editor):
    """Remove the mappings that the schema before the kind column cannot hold. The next import adopts their rows."""
    KeaDhcpLink = apps.get_model("netbox_kea", "KeaDhcpLink")
    KeaDhcpLink.objects.using(schema_editor.connection.alias).exclude(
        models.Q(kind="subnet") | models.Q(kind="reservation", kea_subnet_id__isnull=True)
    ).delete()


def remove_family_links(apps, schema_editor):
    """Remove the family mappings, which the schema before this migration cannot hold."""
    KeaDhcpLink = apps.get_model("netbox_kea", "KeaDhcpLink")
    KeaDhcpLink.objects.using(schema_editor.connection.alias).filter(kind="server").delete()


# netbox_kea tables stay in main (ADR 0007), and KeaDhcpLink follows its targets into branches (ADR 0008),
# but branch migrate fakes every plugin migration.
fake_on_branch = True


class Migration(migrations.Migration):
    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
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
        migrations.RemoveConstraint(
            model_name='keadhcplink',
            name='keadhcplink_unique_subnet_identity',
        ),
        migrations.RemoveConstraint(
            model_name='keadhcplink',
            name='keadhcplink_unique_reservation_identity',
        ),
        migrations.RemoveConstraint(
            model_name='keadhcplink',
            name='keadhcplink_one_identity_kind',
        ),
        migrations.AddField(
            model_name='keadhcplink',
            name='kind',
            field=models.CharField(max_length=32, null=True),
        ),
        migrations.RunPython(backfill_kind, remove_unheld_links),
        migrations.AlterField(
            model_name='keadhcplink',
            name='kind',
            field=models.CharField(max_length=32),
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.UniqueConstraint(condition=models.Q(('kea_identity__isnull', True), ('kea_subnet_id__isnull', False)), fields=('server', 'family', 'kind', 'kea_subnet_id'), name='keadhcplink_unique_subnet_source'),
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.UniqueConstraint(condition=models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', False)), fields=('server', 'family', 'kind', 'kea_subnet_id', 'kea_identity'), name='keadhcplink_unique_in_subnet_source'),
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.UniqueConstraint(condition=models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', True)), fields=('server', 'family', 'kind', 'kea_identity'), name='keadhcplink_unique_global_source'),
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('kind', 'shared_network'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'subnet'), ('kea_identity__isnull', True), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'pool'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'reservation'), models.Q(models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', False)), models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', True)), _connector='OR'), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'client_class'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'option_definition'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), _connector='OR'), name='keadhcplink_kind_identity'),
        ),
        migrations.AddField(
            model_name="dhcpimportentry",
            name="capability",
            field=models.CharField(
                blank=True,
                choices=[
                    ('shared_network_optional_prefix', 'Shared Network without one enclosing Prefix (#88 gap 1)'),
                    ('subnet_id_per_server', 'Subnet ID unique per DHCP server (#88 gap 2)'),
                    ('name_per_server', 'Name unique per DHCP server (#88 gap 3)'),
                    ('server_family', 'DHCP server address family (#88 gap 4)'),
                    ('flex_id_identifier', 'flex-id Reservation identifier (#88 gap 5)'),
                    ('user_context', 'User context (#88 gap 6)'),
                    ('option_spaces', 'Kea option space names (#88 gap 7)'),
                    ('option_code_16_bit', 'DHCPv6 option codes above 255 (#88 gap 8)'),
                    ('option_without_definition', 'DHCP Option without an Option Definition (#88 gap 9)'),
                    ('server_id_fields', 'Full server-id (#88 gap 10)'),
                    ('relay_address_list', 'Relay address list (#88 gap 11)'),
                    ('dhcp4o6_subnet_selection', 'DHCPv4-over-DHCPv6 Subnet selection (#88 gap 12)'),
                    ('address_registration', 'Address registration (#88 gap 13)'),
                    ('stash_agent_options', 'Stashed relay agent options (#88 gap 14)'),
                ],
                max_length=40,
            ),
        ),
        migrations.RemoveConstraint(
            model_name='keadhcplink',
            name='keadhcplink_kind_identity',
        ),
        migrations.RunPython(migrations.RunPython.noop, remove_family_links),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.UniqueConstraint(condition=models.Q(('kea_identity__isnull', True), ('kea_subnet_id__isnull', True)), fields=('server', 'family', 'kind'), name='keadhcplink_unique_family_source'),
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('kind', 'server'), ('kea_identity__isnull', True), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'shared_network'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'subnet'), ('kea_identity__isnull', True), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'pool'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'reservation'), models.Q(models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', False)), models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', True)), _connector='OR'), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'client_class'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'option_definition'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), _connector='OR'), name='keadhcplink_kind_identity'),
        ),
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
        migrations.AddField(
            model_name="dhcpintegrationconfig",
            name="scheduled_import_enabled",
            field=models.BooleanField(
                default=False,
                help_text="The periodic sync job also runs the DHCP Import of each Server that has 'Sync to DHCP plugin' on.",
                verbose_name="Scheduled Import",
            ),
        ),
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
        migrations.RemoveConstraint(
            model_name='keadhcplink',
            name='keadhcplink_kind_identity',
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('kind', 'server'), ('kea_identity__isnull', True), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'shared_network'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'subnet'), ('kea_identity__isnull', True), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'pool'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'pd_pool'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'reservation'), models.Q(models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', False)), models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', True)), _connector='OR'), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'client_class'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'option_definition'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), _connector='OR'), name='keadhcplink_kind_identity'),
        ),
    ]
