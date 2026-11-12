# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
def views(request, pk, server, user):
    # ruleid: kea-server-permission-outside-server-scope
    servers = Server.objects.restrict(request.user, "view")
    # ruleid: kea-server-permission-outside-server-scope
    found = Server.objects.restrict(request.user, "change").filter(pk=pk).exists()
    # ruleid: kea-server-permission-outside-server-scope
    one = models.Server.objects.restrict(user, "view").get(pk=pk)
    # ruleid: kea-server-permission-outside-server-scope
    page = get_object_or_404(Server.objects.restrict(user, "view"), pk=pk)
    # ruleid: kea-server-permission-outside-server-scope
    page = get_object_or_404(Server, pk=pk)
    # ruleid: kea-server-permission-outside-server-scope
    page = get_object_or_404(Server.objects.all(), pk=pk)
    # ruleid: kea-server-permission-outside-server-scope
    allowed = request.user.has_perm("netbox_kea.change_server")
    # ruleid: kea-server-permission-outside-server-scope
    allowed = cast(PermissionsMixin, request.user).has_perm("netbox_kea.change_server", obj=server)
    # ruleid: kea-server-permission-outside-server-scope
    allowed = user.has_perm("netbox_kea.bulk_delete_lease_from_server")
    # ruleid: kea-server-permission-outside-server-scope
    allowed = user.has_perm(perm="netbox_kea.change_server", obj=server)
    # ok: kea-server-permission-outside-server-scope
    allowed = user.has_perm("netbox_kea.bulk_delete_lease_from_server", obj=server)
    # ok: kea-server-permission-outside-server-scope
    allowed = user.has_perm(perm="netbox_kea.bulk_delete_lease_from_server", obj=server)
    # ok: kea-server-permission-outside-server-scope
    allowed = cast(PermissionsMixin, request.user).has_perm("netbox_kea.bulk_delete_lease_from_server", obj=server)
    # ok: kea-server-permission-outside-server-scope
    allowed = user.has_perm("core.view_job")
    # ok: kea-server-permission-outside-server-scope
    allowed = user.has_perm("netbox_kea.view_syncconfig")
    # ok: kea-server-permission-outside-server-scope
    ip = get_object_or_404(IPAddress.objects.restrict(user, "view"), pk=pk)
    # ok: kea-server-permission-outside-server-scope
    rows = IPAddress.objects.restrict(user, "view")
    # ok: kea-server-permission-outside-server-scope
    servers = permitted_servers(user, "change")
    # ok: kea-server-permission-outside-server-scope
    locked = Server.objects.select_for_update().get(pk=server.pk)
    # ok: kea-server-permission-outside-server-scope
    page = get_object_or_404(ServerSwitch, pk=pk)
