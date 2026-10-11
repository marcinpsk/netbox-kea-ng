# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Check that the integration harness serves the installed plugin's static files."""

from pathlib import Path

import requests


def test_workspace_stylesheet_is_served(netbox_url: str, nb_http: requests.Session) -> None:
    response = nb_http.get(f"{netbox_url}/static/netbox_kea/css/workspace.css")

    assert response.status_code == 200
    assert response.headers["Content-Type"].split(";", 1)[0] == "text/css"
    stylesheet = Path(__file__).resolve().parents[1] / "netbox_kea/static/netbox_kea/css/workspace.css"
    assert response.text == stylesheet.read_text()
