# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Let a DHCP Import Mapping map a DHCP Option, and order mapping confirmations by the confirmation sequence (ADR 0006)."""

from django.db import migrations, models


def remove_option_links(apps, schema_editor):
    """Remove the Option mappings that the schema before this migration cannot hold. The next import adopts their rows."""
    KeaDhcpLink = apps.get_model("netbox_kea", "KeaDhcpLink")
    KeaDhcpLink.objects.using(schema_editor.connection.alias).filter(kind="option").delete()


# netbox_kea tables stay in main (ADR 0007), and KeaDhcpLink follows its targets into branches (ADR 0008),
# but branch migrate fakes every plugin migration.
fake_on_branch = True


class Migration(migrations.Migration):
    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('netbox_kea', '0028_dhcp_import'),
    ]

    operations = [
        migrations.AddField(
            model_name='keadhcplink',
            name='options_mapped',
            field=models.BooleanField(default=False, help_text='Whether the import has mapped the DHCP Options of the object; until then it adopts unmapped ones.'),
        ),
        migrations.RemoveConstraint(
            model_name='keadhcplink',
            name='keadhcplink_kind_identity',
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('kind', 'server'), ('kea_identity__isnull', True), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'shared_network'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'subnet'), ('kea_identity__isnull', True), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'pool'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'pd_pool'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'reservation'), models.Q(models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', False)), models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', True)), _connector='OR'), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'client_class'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'option_definition'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'option'), models.Q(models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', False)), models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', True)), _connector='OR'), models.Q(('kea_identity', ''), _negated=True)), _connector='OR'), name='keadhcplink_kind_identity'),
        ),
        # 0 is below every number of the sequence, so an existing mapping is older than every cutoff.
        migrations.AddField(
            model_name='keadhcplink',
            name='confirmation',
            field=models.BigIntegerField(blank=True, default=0, help_text='The confirmation sequence number that a writer took when it last confirmed the mapping.'),
            preserve_default=False,
        ),
        migrations.RemoveField(
            model_name='keadhcplink',
            name='last_synced',
        ),
        # NetBox leaves choices out of deconstruct(), so makemigrations never writes this AlterField.
        migrations.AlterField(
            model_name='dhcpimportentry',
            name='capability',
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
                    ('kea_option_data', 'DHCP Option data in each form that Kea accepts (#88 gap 17)'),
                ],
                max_length=40,
            ),
        ),
        migrations.RunPython(migrations.RunPython.noop, remove_option_links),
    ]
