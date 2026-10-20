# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Record the DHCP Plugin Capability that an unsupported DHCP Import entry needs."""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_kea", "0029_dhcp_import_mapping_kind"),
    ]

    operations = [
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
                    ("user_context", "User context (#88 gap 6)"),
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
    ]
