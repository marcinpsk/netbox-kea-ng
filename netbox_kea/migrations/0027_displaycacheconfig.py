# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Add the display cache settings row with the default TTLs (ADR 0009, ADR 0010).

No PLUGINS_CONFIG key ever held a TTL, so the row keeps the model defaults.
"""

from django.db import migrations, models


# netbox_kea tables stay in main, so branch migrate fakes this migration (ADR 0007).
fake_on_branch = True


def create_row(apps, schema_editor):
    alias = schema_editor.connection.alias
    apps.get_model("netbox_kea", "DisplayCacheConfig").objects.using(alias).create(pk=1)


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_kea', '0026_dhcpintegrationconfig'),
    ]

    operations = [
        migrations.CreateModel(
            name='DisplayCacheConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('configuration_ttl', models.PositiveIntegerField(default=300)),
                ('reservations_ttl', models.PositiveIntegerField(default=300)),
                ('leases_ttl', models.PositiveIntegerField(default=30)),
                ('status_ttl', models.PositiveIntegerField(default=15)),
            ],
            options={
                'verbose_name': 'Display Cache',
            },
        ),
        migrations.RunPython(create_row, migrations.RunPython.noop),
    ]
