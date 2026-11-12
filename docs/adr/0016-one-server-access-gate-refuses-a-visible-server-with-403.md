---
status: accepted
date: 2026-11-12
---

<!--
SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
SPDX-License-Identifier: Apache-2.0
-->

# One Server access gate refuses a visible Server with 403

## Context

Each Server view decided again whether the user may view or change the Server, and which reply a refusal gets.
`_KeaChangeMixin` checked the view and the change permission with two queries and gave 403 for a viewable Server
that the user may not change. `ServerFamilyMixin` then loaded the Server again, and each handler loaded it a third
time. Run Now and the Sync toggle gave 404 to the same user. "Can change" was asked in four ways, and the header Edit
and Delete buttons used NetBox's model-level answer, so a user with a change grant constrained to other Servers saw
Edit and got 404 (issue #292).

NetBox's own object views answer 404 for an object that the user may view but not change, because they restrict the
queryset by the action of the view.

## Decision

Every Server view passes one gate, `ServerAccessMixin` in `views/server_scope.py`. A view names the action of its
handlers in `server_action`: `"view"`, or `"change"` (which needs view too). The gate loads the Server once and
applies one refusal rule. Each action except view needs view too, so `permitted_servers()` gives the Servers that
the user may view and take the action on:

| User | Reply |
| --- | --- |
| Anonymous, and the Server needs a login | The login redirect |
| May not view the Server | 404 |
| May view the Server, may not change (or delete) it, and the view changes (or deletes) it | 403 with one message |

The rule gives 403, not NetBox's 404, for a Server that the user can see. The user can open the Server, so a 404
hides nothing, and it reads as a broken link. A 403 says what is missing.

Four views follow the rule through the same refusal function, `server_access()`, and do not declare
`server_action`:

- Run Now and the Sync toggle, because the branch controls (`branching.mutation_form`) treat each gated change view
  as a change form, and these POST-only actions are not one.
- The Server switch, because it leaves its Server, so the disabled family of that Server does not stop it.
- NetBox's Server edit and delete views, with the change and the delete action, on a route with a `pk`. Their add
  form and the bulk views keep NetBox's check.

Run Now and the Sync toggle need only the change permission on the Server. A user with that permission can switch
the IPAM sync of the Server on, and the scheduled run then makes the same IPAM writes, so an IPAM grant adds no
protection. A Manual Sync keeps the rule of unconstrained IPAM grants (`sync_permissions.py`), because it writes
a record that the operator selects, at once.

## Consequences

- A user who may not view a Server gets 404 on every Server route, also where a NetBox object view gave 403.
- Run Now and the Sync toggle give 403, not 404, to a viewer with a change grant constrained to other Servers.
- The header Edit and Delete buttons, the Server Options link and the Create Reservation links follow the object
  permissions of the Server.
- The Server edit and delete pages give 403, not NetBox's 404, for a viewable Server outside the grant, and 404 for a
  Server that the user may not view, also when the user holds the change or delete grant.
- The OpenGrep rule `kea-server-permission-outside-server-scope` refuses a Server permission read in another module.

## Rejected alternatives

- Give 404 like NetBox: rejected, because the user can see the Server.
- Gate Run Now and the Sync toggle with `server_action = "change"`: rejected, because the branch controls would then
  treat them as change forms.
- Require the manual Sync grants for Run Now: rejected, because the Sync toggle already allows the same writes.
