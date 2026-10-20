# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Let a DHCP Import Mapping map the global configuration of one family: a source with neither identity column."""

from django.db import migrations, models

# KeaDhcpLink follows its targets into branches (ADR 0008), but branch migrate fakes every plugin migration.
fake_on_branch = True


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('netbox_kea', '0030_dhcpimportentry_capability'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='keadhcplink',
            name='keadhcplink_kind_identity',
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.UniqueConstraint(condition=models.Q(('kea_identity__isnull', True), ('kea_subnet_id__isnull', True)), fields=('server', 'family', 'kind'), name='keadhcplink_unique_family_source'),
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('kind', 'server'), ('kea_identity__isnull', True), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'shared_network'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'subnet'), ('kea_identity__isnull', True), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'pool'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', False), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'reservation'), models.Q(models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', False)), models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', True)), _connector='OR'), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'client_class'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), models.Q(('kind', 'option_definition'), ('kea_identity__isnull', False), ('kea_subnet_id__isnull', True), models.Q(('kea_identity', ''), _negated=True)), _connector='OR'), name='keadhcplink_kind_identity'),
        ),
    ]
