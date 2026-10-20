# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Give each DHCP Import Mapping the kind of its Kea source, and keep one unique constraint per identity shape."""

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


# KeaDhcpLink follows its targets into branches (ADR 0008), but a branch made before this migration keeps the old
# columns: branch migrate fakes this migration, and the mapping lifecycle refuses that branch.
fake_on_branch = True


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('netbox_kea', '0028_dhcpimportrun_dhcpimportentry'),
    ]

    operations = [
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
    ]
