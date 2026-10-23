# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Order DHCP Import Mapping confirmations by the confirmation sequence (ADR 0006), in place of a wall-clock time."""

from django.db import migrations, models

# KeaDhcpLink follows its targets into branches (ADR 0008), but branch migrate fakes every plugin migration.
fake_on_branch = True


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_kea', '0037_keadhcplink_option'),
    ]

    operations = [
        # 0 is below every number of the sequence, so an existing mapping is older than every cutoff.
        migrations.AddField(
            model_name='keadhcplink',
            name='confirmation',
            field=models.BigIntegerField(default=0, help_text='The confirmation sequence number that a writer took when it last confirmed the mapping.'),
            preserve_default=False,
        ),
        migrations.RemoveField(
            model_name='keadhcplink',
            name='last_synced',
        ),
    ]
