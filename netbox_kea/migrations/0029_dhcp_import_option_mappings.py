# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Let a DHCP Import Mapping map a DHCP Option, and order mapping confirmations by the confirmation sequence (ADR 0006)."""

from django.db import migrations, models


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
    ]
