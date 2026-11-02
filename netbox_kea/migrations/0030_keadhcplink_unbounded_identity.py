# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Let a DHCP Import Mapping hold an identity of any length: its source constraints index the digest (ADR 0013)."""

import django.db.models.functions.text
from django.db import migrations, models
from django.db.migrations.exceptions import IrreversibleError
from django.db.models.functions import Length

# The longest identity that the schema before this migration holds.
_PREVIOUS_IDENTITY_LENGTH = 517


def refuse_long_identities(apps, schema_editor):
    """Refuse the reverse while a mapping holds an identity that the older column cannot hold."""
    KeaDhcpLink = apps.get_model("netbox_kea", "KeaDhcpLink")
    links = KeaDhcpLink.objects.using(schema_editor.connection.alias)
    count = links.annotate(identity_length=Length("kea_identity")).filter(
        identity_length__gt=_PREVIOUS_IDENTITY_LENGTH
    ).count()
    if count:
        raise IrreversibleError(
            f"DHCP Import Mappings hold an identity longer than {_PREVIOUS_IDENTITY_LENGTH} characters ({count} in "
            "all), and the schema before this migration cannot hold one. Nothing changed."
        )


# netbox_kea tables stay in main (ADR 0007), and KeaDhcpLink follows its targets into branches (ADR 0008),
# but branch migrate fakes every plugin migration.
fake_on_branch = True


class Migration(migrations.Migration):
    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('netbox_kea', '0029_dhcp_import_option_mappings'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='keadhcplink',
            name='keadhcplink_unique_in_subnet_source',
        ),
        migrations.RemoveConstraint(
            model_name='keadhcplink',
            name='keadhcplink_unique_global_source',
        ),
        migrations.AlterField(
            model_name='keadhcplink',
            name='kea_identity',
            field=models.TextField(blank=True, help_text='Identity of the source object in its Subnet or globally; null for a Subnet or family source.', null=True),
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.UniqueConstraint(models.F('server'), models.F('family'), models.F('kind'), models.F('kea_subnet_id'), django.db.models.functions.text.MD5('kea_identity'), condition=models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', False)), name='keadhcplink_unique_in_subnet_source'),
        ),
        migrations.AddConstraint(
            model_name='keadhcplink',
            constraint=models.UniqueConstraint(models.F('server'), models.F('family'), models.F('kind'), django.db.models.functions.text.MD5('kea_identity'), condition=models.Q(('kea_identity__isnull', False), ('kea_subnet_id__isnull', True)), name='keadhcplink_unique_global_source'),
        ),
        # A reverse runs the last operation first, so its refusal comes before any schema change.
        migrations.RunPython(migrations.RunPython.noop, refuse_long_identities),
    ]
