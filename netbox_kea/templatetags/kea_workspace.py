# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Render the shared workspace shell around native Server object pages."""

from urllib.parse import urlsplit, urlunsplit

from django import template
from django.http import QueryDict
from django.urls import reverse
from netbox.views import generic
from utilities.templatetags.tabs import model_view_tabs

from ..views._base import safe_return_url
from ..views.server_scope import request_access, selected_family
from ..views.workspace import WORKSPACE_SECTIONS, server_context, with_return_url

register = template.Library()


@register.simple_tag(takes_context=True)
def workspace_url(context, url):
    """Retain the validated previous workspace on a local navigation control."""
    return with_return_url(url, safe_return_url(context["request"], ""))


@register.inclusion_tag("netbox_kea/inc/workspace_return_field.html", takes_context=True)
def workspace_return_field(context):
    """Retain the validated previous workspace when a search form submits."""
    return {"workspace_return_url": safe_return_url(context["request"], "")}


@register.inclusion_tag("netbox_kea/inc/workspace_shell.html", takes_context=True)
def server_workspace(context, server, out_of_band=False):
    """Render the same scope bar as combined pages for one saved Server, with its native object tabs."""
    if not server or not server.pk:
        return {"workspace_oob": out_of_band}
    workspace = server_context(context["request"], server)
    object_tabs = _object_tabs(context, server, workspace["workspace_family"])
    if any(tab["is_active"] for tab in object_tabs):
        # A native tab page, such as the Journal, is not one of the workspace sections.
        workspace["workspace_section"] = None
    return {**workspace, "workspace_object_tabs": object_tabs, "workspace_oob": out_of_band}


def _object_tabs(context, server, family) -> list[dict]:
    """Return the native tabs that follow the workspace sections, such as Journal, Changelog and Jobs."""
    workspace_tabs = {section.native_tab for section in WORKSPACE_SECTIONS.values() if section.native_tab}
    return_url = safe_return_url(context["request"], "")
    tabs = []
    for tab in model_view_tabs(context, server)["tabs"]:
        if tab["name"] in workspace_tabs:
            continue
        url = urlsplit(tab["url"])
        query = QueryDict(url.query, mutable=True)
        query["family"] = str(family)
        tabs.append({**tab, "url": with_return_url(urlunsplit(url._replace(query=query.urlencode())), return_url)})
    return tabs


@register.simple_tag(takes_context=True)
def server_control_urls(context, server):
    """Supply native controls on plain views, for this Server and not only the model, and their selected-family URLs."""
    request = context["request"]
    view = generic.ObjectView()
    if "actions" not in context and hasattr(view, "get_permitted_actions"):
        actions = view.get_permitted_actions(request.user, model=server)
        context["actions"] = request_access(request, server).permitted_actions(actions)
    family = selected_family(request, server)
    urls = [reverse(f"plugins:netbox_kea:server_{action}", args=[server.pk]) for action in ("edit", "delete")]
    return [(url, with_return_url(f"{url}?family={family}", safe_return_url(request, ""))) for url in urls]


@register.simple_tag(takes_context=True)
def enabled_family(context, server):
    """Return the family and the URL of the first family that *server* serves, or None."""
    workspace = server_context(context["request"], server)
    return next(
        (
            (family, url)
            for family, url in workspace["workspace_families"]
            if (server.dhcp4 if family == 4 else server.dhcp6)
        ),
        None,
    )


@register.filter(is_safe=True)
def server_family_controls(controls, urls):
    """Keep the native markup and change only canonical Server action targets."""
    for url, target in urls:
        for attribute in ("href", "hx-get"):
            controls = controls.replace(f'{attribute}="{url}"', f'{attribute}="{target}"')
    return controls
