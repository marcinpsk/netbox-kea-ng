# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Render the shared workspace shell around native Server object pages."""

from urllib.parse import urlsplit, urlunsplit

from django import template
from django.http import QueryDict
from django.urls import reverse
from netbox.views import generic
from utilities.templatetags.tabs import model_view_tabs

from ..views._base import _safe_return_url
from ..views.workspace import server_context, with_return_url

register = template.Library()


@register.simple_tag(takes_context=True)
def workspace_url(context, url):
    """Retain the validated previous workspace on a local navigation control."""
    return with_return_url(url, _safe_return_url(context["request"], ""))


@register.inclusion_tag("netbox_kea/inc/workspace_return_field.html", takes_context=True)
def workspace_return_field(context):
    """Retain the validated previous workspace when a search form submits."""
    return {"workspace_return_url": _safe_return_url(context["request"], "")}


@register.inclusion_tag("netbox_kea/inc/workspace_shell.html", takes_context=True)
def server_workspace(context, server, out_of_band=False):
    """Render the same scope bar as combined pages for one saved Server."""
    workspace = server_context(context["request"], server) if server and server.pk else {}
    return {**workspace, "workspace_oob": out_of_band}


@register.inclusion_tag("netbox_kea/inc/server_object_tabs.html", takes_context=True)
def server_object_tabs(context, server):
    """Preserve native extra tabs after the workspace's six sections."""
    if not server or not server.pk:
        return {"tabs": []}
    tabs = model_view_tabs(context, server)["tabs"]
    workspace_tabs = {"status", "leases4", "subnets4", "reservations4", "option_def4", "sync_status"}
    family = server_context(context["request"], server)["workspace_family"]
    extra_tabs = []
    for tab in tabs:
        if tab["name"] in workspace_tabs:
            continue
        url = urlsplit(tab["url"])
        query = QueryDict(url.query, mutable=True)
        query["family"] = str(family)
        extra_tabs.append(
            {
                **tab,
                "url": with_return_url(
                    urlunsplit(url._replace(query=query.urlencode())), _safe_return_url(context["request"], "")
                ),
            }
        )
    return {"tabs": extra_tabs}


@register.simple_tag(takes_context=True)
def server_control_urls(context, server):
    """Supply native controls on plain views and their selected-family URLs."""
    view = generic.ObjectView()
    if "actions" not in context and hasattr(view, "get_permitted_actions"):
        context["actions"] = view.get_permitted_actions(context["request"].user, model=server)
    family = server_context(context["request"], server)["workspace_family"]
    urls = [reverse(f"plugins:netbox_kea:server_{action}", args=[server.pk]) for action in ("edit", "delete")]
    return [(url, with_return_url(f"{url}?family={family}", _safe_return_url(context["request"], ""))) for url in urls]


@register.filter(is_safe=True)
def server_family_controls(controls, urls):
    """Keep the native markup and change only canonical Server action targets."""
    for url, target in urls:
        for attribute in ("href", "hx-get"):
            controls = controls.replace(f'{attribute}="{url}"', f'{attribute}="{target}"')
    return controls
