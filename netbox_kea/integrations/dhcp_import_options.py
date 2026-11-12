# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""The custom Option Definitions and the DHCP Options that the DHCP Import writes to the DHCP plugin.

* Every custom **Option Definition** that Kea declares is written before any DHCP Option, used or not: a global
  ``option-def`` to the ``DHCPServer``, and a client class ``option-def`` to its ``ClientClass``, each through its
  own mapping. A space or a code that the plugin cannot hold is unsupported (:mod:`.dhcp_plugin_capabilities`).
* DHCP **options** (``option-data``) are imported at every scope we model: ``DHCPServer`` (global),
  ``ClientClass``, ``Subnet``, ``Pool``, ``PDPool``, ``HostReservation``. Each binds to the sys4-shipped standard
  ``OptionDefinition`` (by space+code), or to a custom definition of its class or of the daemon. An Option keeps its
  Kea ``client-classes``, so the same definition with other classes is another Option. The mapping of an Option holds
  the source of its parent and its identity (ADR 0014), so a changed class set gives a new Option. An Option that an
  operator adds to a mapped parent has no mapping and stays. An option whose definition the plugin cannot hold is
  unsupported with the capability it needs, and an option whose class has no row is skipped. Neither is fatal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .. import kea_paths
from ..dhcp_options import MAX_ONE_OCTET_OPTION_CODE, DHCPOption
from ..mappers.kea_to_dhcp import OptionDefIntent
from .dhcp_import_mappings import first_mapping, mapped_target, options_mapped, unlinked
from .dhcp_import_plan import OptionDefinitionKey
from .dhcp_import_report import Capability, Kind, Reason
from .dhcp_import_values import Source, user_context_fields
from .dhcp_import_write import NotWritten, RowAdapter, WriteScope, adopt_options, write_row
from .dhcp_plugin_capabilities import PluginCapabilities, plugin_model

if TYPE_CHECKING:
    from .dhcp_import_networks import ClassReferences
    from .dhcp_import_plan import OptionKey, PlannedOptions


def _send_option(opt: DHCPOption) -> str | None:
    """Map Kea ``always-send``/``never-send`` flags to the plugin's single choice."""
    if opt.always_send:
        return "always-send"
    if opt.never_send:
        return "never-send"
    return None


@dataclass(frozen=True)
class CustomDefinitions:
    """The custom Option Definitions that one family of a Server declares, each written once a run before any Option.

    *declared* holds the definitions of the daemon and of each client class. The written store of the run holds the
    row of each definition, or why the run did not write it.
    """

    declared: dict[OptionDefinitionKey, OptionDefIntent]
    # The DHCPServers whose unmapped rows of this family the import adopts (adoption_servers).
    adoption_servers: tuple[int, ...]


@dataclass(frozen=True)
class OptionReferences:
    """What the DHCP Options of one family can reference: the custom Option Definitions and the client classes."""

    definitions: CustomDefinitions
    classes: ClassReferences


def _code_and_space_gap(space: str, code: int, family: int, capabilities: PluginCapabilities) -> NotWritten | None:
    """Return why the DHCP plugin cannot hold an option *code* in *space*, in the order of the parity ledger."""
    if family == 6 and code > MAX_ONE_OCTET_OPTION_CODE and not capabilities.has(Capability.OPTION_CODE_16_BIT):
        detail = (
            f"The installed DHCP plugin cannot hold the option code {code}, which is above {MAX_ONE_OCTET_OPTION_CODE}."
        )
        return NotWritten(Reason.PLUGIN_GAP, detail, Capability.OPTION_CODE_16_BIT)
    if not capabilities.holds_space(space):
        detail = f"The installed DHCP plugin cannot hold the option space {space}."
        return NotWritten(Reason.PLUGIN_GAP, detail, Capability.OPTION_SPACES)
    return None


def _without_definition(opt: DHCPOption, space: str, family: int, capabilities: PluginCapabilities):
    """Return why the DHCP plugin cannot hold *opt*, which has no Option Definition, or ``None`` when it can."""
    if not capabilities.has(Capability.OPTION_WITHOUT_DEFINITION):
        detail = "The DHCP plugin has no Option Definition for it and cannot hold an option without one."
        return NotWritten(Reason.PLUGIN_GAP, detail, Capability.OPTION_WITHOUT_DEFINITION)
    if opt.code is None:
        return NotWritten(Reason.INVALID_KEA_DATA, "No Option Definition gives its name a code.")
    return _code_and_space_gap(space, opt.code, family, capabilities)


def _option_definition_fields(
    obj, def_intent: OptionDefIntent, family: int, parent_field: dict, capabilities: PluginCapabilities, summary, source
) -> dict:
    """Return the managed fields of a custom Option Definition: all but its name, which stays as created or renamed.

    *parent_field* sets its parent: the DHCPServer or the client class. The plugin refuses a definition with both.
    """
    return {
        "space": def_intent.space,
        "code": def_intent.code,
        "family": family,
        "type": def_intent.type,
        "array": def_intent.array,
        "record_types": list(def_intent.record_types) or None,
        "encapsulate": def_intent.encapsulate,
        "dhcp_server_id": None,
        "client_class_id": None,
        **parent_field,
        **user_context_fields(obj, def_intent.user_context, capabilities, summary, source, "Option Definition"),
    }


def _held_option_definition(held, key: OptionDefinitionKey) -> NotWritten:
    """Return why the run cannot create a definition that another row holds on its parent: the plugin holds one."""
    holder = first_mapping(held)
    parent = "DHCP server" if key.client_class is None else "client class"
    limit = f"The DHCP plugin holds one custom Option Definition for each space and code of a {parent}"
    holder_text = f"the DHCPv{holder.family} import holds it" if holder is not None else "another row holds it"
    return NotWritten(Reason.PLUGIN_GAP, f"{limit}, and {holder_text}.")


@dataclass(frozen=True)
class _OptionDefinitionAdapter(RowAdapter):
    """A custom Option Definition of the daemon or of a client class, written to *parent*: its DHCPServer or class row.

    A space or a code that the plugin cannot hold is unsupported. It adopts an unmapped definition of the same space
    and code that an import created before Option Definitions had a mapping.
    """

    scope: WriteScope
    key: OptionDefinitionKey
    definitions: CustomDefinitions
    parent: Any

    def _same_key(self):
        return plugin_model("OptionDefinition").objects.filter(standard=False, space=self.key.space, code=self.key.code)

    def _held(self):
        """Return the definitions of the space and code of the key on *parent*, mapped or not."""
        if self.key.client_class is not None:
            return self._same_key().filter(client_class=self.parent)
        return self._same_key().filter(dhcp_server=self.parent)

    def blocked(self) -> NotWritten | None:
        """Return why the plugin cannot hold the space or the code of the definition."""
        return _code_and_space_gap(self.key.space, self.key.code, self.scope.family, self.scope.capabilities)

    def adopt(self):
        """Return the unmapped definition of this family that an import wrote before definitions had a mapping."""
        if self.key.client_class is not None:
            adoptable = self._held()
        else:
            adoptable = self._same_key().filter(dhcp_server__in=self.definitions.adoption_servers)
        return unlinked(adoptable.filter(family=self.scope.family)).first()

    def refusal(self) -> NotWritten | None:
        """Return why the definition cannot be created: another row holds its space and code on the parent."""
        held = self._held()
        return _held_option_definition(held, self.key) if held.exists() else None

    def new_row(self):
        """Return a new custom definition with its Kea name."""
        return plugin_model("OptionDefinition")(name=self.definitions.declared[self.key].name, standard=False)

    def fields(self, row) -> dict:
        """Return the managed fields of the definition on its parent."""
        family = self.scope.family
        parent_field = (
            {"client_class_id": self.parent.pk}
            if self.key.client_class is not None
            else {"dhcp_server_id": self.parent.pk}
        )
        source = Source(family, Kind.OPTION_DEFINITION, self.key.path(family))
        intent = self.definitions.declared[self.key]
        return _option_definition_fields(
            row, intent, family, parent_field, self.scope.capabilities, self.scope.summary, source
        )


def write_option_definition(
    scope: WriteScope, definitions: CustomDefinitions, key: OptionDefinitionKey, parent
) -> None:
    """Write the custom Option Definition of *key* to *parent*. The written store of the run keeps the result."""
    write_row(_OptionDefinitionAdapter(scope, key, definitions, parent))


def _declared_key(opt: DHCPOption, space: str, owner: str | None, definitions: CustomDefinitions):
    """Return the key of the custom Option Definition of *opt* that *owner* declares (``None``: the daemon), if any."""
    if opt.code is not None:
        key = OptionDefinitionKey(space, opt.code, owner)
        return key if key in definitions.declared else None
    return next(
        (
            each
            for each, intent in definitions.declared.items()
            if each.client_class == owner and each.space == space and intent.name == opt.name
        ),
        None,
    )


def _without_its_definition(definition: NotWritten) -> NotWritten:
    """Return why the run does not write an Option whose declared definition it did not write.

    The Option keeps a fact that the plugin cannot hold; for any other reason its parent, the definition, was not
    imported.
    """
    detail = f"Its Option Definition is not imported. {definition.detail}".rstrip()
    if definition.reason == Reason.PLUGIN_GAP:
        return NotWritten(Reason.PLUGIN_GAP, detail, definition.capability)
    return NotWritten(Reason.PARENT_NOT_IMPORTED, detail)


def _resolve_option_definition(
    opt: DHCPOption, scope: WriteScope, definitions: CustomDefinitions, class_name: str | None
):
    """Find the ``OptionDefinition`` a Kea ``option-data`` entry refers to.

    As in Kea, a custom definition comes first: one that the client class *class_name* of the option declares, then
    one that the daemon declares. The written store of the run gives its row. A declared definition that the import
    could not write stays the answer. Then the sys4-shipped **standard** definition (by space+code, else space+name).
    A custom definition that Kea does not declare is never used. Returns ``None`` for an option that the plugin holds
    without a definition, or why the option cannot be imported.
    """
    OptionDefinition = plugin_model("OptionDefinition")
    family, capabilities = scope.family, scope.capabilities
    space = opt.space or kea_paths.default_space(family)
    owners = (None,) if class_name is None else (class_name, None)
    for owner in owners:
        key = _declared_key(opt, space, owner, definitions)
        if key is not None:
            written_definition = scope.written.result(key)
            if isinstance(written_definition, NotWritten):
                return _without_its_definition(written_definition)
            return written_definition

    standard = OptionDefinition.objects.filter(standard=True, space=space)
    if opt.code is not None:
        found = standard.filter(code=opt.code).first()
    elif opt.name:
        found = standard.filter(name=opt.name).first()
    else:
        found = None
    return found if found is not None else _without_definition(opt, space, family, capabilities)


def _data_gap(opt: DHCPOption, definition, capabilities: PluginCapabilities) -> NotWritten | None:
    """Return why the run does not write *opt*: the DHCP plugin refuses its data (gap 17), or ``None``.

    Only a ValidationError of the data check of the plugin is a refusal. Another error of the check raises.
    """
    # The probe checks only samples, so the capability does not prove that the plugin accepts this data.
    if definition is None:
        return None
    refusal = capabilities.data_refusal(definition.type, definition.array, definition.record_types, opt.data or "")
    if refusal is None:
        return None
    detail = f"The installed DHCP plugin refuses this form of option data, which Kea accepts: {refusal}"
    return NotWritten(Reason.PLUGIN_GAP, detail, Capability.KEA_OPTION_DATA)


def option_values(
    candidate, opt: DHCPOption, family: int, capabilities: PluginCapabilities, summary, source: Source
) -> dict:
    """Return the managed fields of an Option as the DHCP plugin stores them, after ``Option.clean`` on *candidate*.

    The plugin's clean step normalizes some values, for example the CSV format of a binary option. An option
    without an Option Definition keeps its Kea space and code (gap 9).
    """
    candidate.data = opt.data or ""
    candidate.csv_format = opt.csv_format
    candidate.send_option = _send_option(opt)
    own: dict = {}
    if capabilities.has(Capability.OPTION_WITHOUT_DEFINITION):
        definition = candidate.definition
        own = {
            "space": opt.space or kea_paths.default_space(family),
            "code": definition.code if definition is not None else opt.code,
        }
        for name, value in own.items():
            setattr(candidate, name, value)
    candidate.clean()
    return {
        "definition_id": candidate.definition_id,
        "data": candidate.data,
        "csv_format": candidate.csv_format,
        "send_option": candidate.send_option,
        **own,
        **user_context_fields(candidate, opt.user_context, capabilities, summary, source, "DHCP Option"),
    }


@dataclass(frozen=True)
class _PlannedOption:
    """A Kea option with an Option Definition that the plugin holds, and its key."""

    option: DHCPOption
    key: OptionKey
    space: str
    code: int | None
    definition: Any
    classes: frozenset[int]


def _option_code(row) -> tuple:
    """Return the space and code of the Option *row*: from its definition, or its own fields without one (gap 9)."""
    if row.definition_id is not None:
        return row.definition.space, row.definition.code
    return row.space, row.code


def _paired_rows(planned: list[_PlannedOption], rows: list) -> list:
    """Return the unmapped Option of *rows* that each planned option without a mapped row adopts, or ``None``.

    First a row with the same definition and the same client classes, then an unpaired row with the same definition,
    in order. A row pairs by space and code, not by its definition row. A row that an import wrote before options had
    classes is updated, not duplicated.
    """
    classes = {row.pk: {each.pk for each in row.client_classes.all()} for row in rows}
    codes = {row.pk: _option_code(row) for row in rows}
    free = list(rows)
    paired: list = [None] * len(planned)
    for exact in (True, False):
        for index, item in enumerate(planned):
            if paired[index] is not None:
                continue
            row = next(
                (
                    row
                    for row in free
                    if codes[row.pk] == (item.space, item.code) and (not exact or classes[row.pk] == item.classes)
                ),
                None,
            )
            if row is not None:
                paired[index] = row
                free.remove(row)
    return paired


@dataclass(frozen=True)
class _OptionAdapter(RowAdapter):
    """One DHCP Option of *parent_obj*. The adoption step (:func:`.dhcp_import_write.adopt_options`) maps its row first."""

    scope: WriteScope
    key: OptionKey
    item: _PlannedOption
    parent_obj: Any
    content_type: Any

    def blocked(self) -> NotWritten | None:
        """Return why the plugin refuses the data of the Option, which it still pairs (gap 17)."""
        return _data_gap(self.item.option, self.item.definition, self.scope.capabilities)

    def new_row(self):
        """Return a new Option of the definition, assigned to the parent row."""
        return plugin_model("Option")(
            definition=self.item.definition,
            assigned_object_type=self.content_type,
            assigned_object_id=self.parent_obj.pk,
        )

    def fields(self, row) -> dict:
        """Return the managed fields of the Option, as the clean step of the plugin leaves them."""
        family = self.scope.family
        source = Source(family, Kind.OPTION, self.key.path(family))
        # A new row is its own candidate; a stored row is compared with a clean candidate.
        candidate = row if row.pk is None else self.new_row()
        return option_values(candidate, self.item.option, family, self.scope.capabilities, self.scope.summary, source)

    def relations(self, row) -> dict[str, set[int]]:
        """Return the client classes of the Option."""
        return {"client_classes": set(self.item.classes)}


def upsert_options(scope: WriteScope, parent_obj, planned_set: PlannedOptions, references: OptionReferences) -> None:
    """Upsert DHCP-plugin ``Option`` rows for the options of *planned_set* (:func:`.dhcp_import_plan.planned_options`).

    They are assigned to *parent_obj*, the row of the object of *planned_set*. One Option per Kea option: the same definition
    with other client classes is another Option. Each Option has a DHCP Import Mapping from its key, and a re-import
    finds the row through it. Until the mapping of the object records that its Options are mapped, an Option without
    a mapped row adopts an unmapped Option of *parent_obj* (:func:`_paired_rows`). The adoptions are written before the
    Options, and that record waits only for a failed Option Definition write or a defined client class that this run
    did not import. After that, every unmapped Option is an operator's and stays. The options of a client
    class also resolve its own Option Definitions. An Option whose definition cannot be resolved, whose class has no
    row, or whose data the plugin refuses, is reported and does not stop the import. An Option whose values did not
    change has no entry.
    """
    server, family, summary = scope.server, scope.family, scope.summary
    parent = planned_set.parent
    if parent is None:
        raise ValueError("Only an object with a mapping source can have imported DHCP Options.")
    if not planned_set.options:
        adopt_options(scope, parent, (), mapped=True)
        return
    from django.contrib.contenttypes.models import ContentType

    ct = ContentType.objects.get_for_model(type(parent_obj))
    class_name = planned_set.class_name
    planned: list[_PlannedOption] = []
    pending_dependency = False
    paths = planned_set.paths(family)
    for opt, key, path in zip(planned_set.options, planned_set.keys, paths, strict=True):
        if key is None:
            raise ValueError("A DHCP Option of an object with a mapping source has a key.")
        definition = _resolve_option_definition(opt, scope, references.definitions, class_name)
        if isinstance(definition, NotWritten):
            pending_dependency |= definition.reason == Reason.PARENT_NOT_IMPORTED
            summary.record(definition.entry(family, Kind.OPTION, path))
            summary.warn(f"{path}: {definition.detail}")
            continue
        classes = references.classes.option_classes(opt.client_classes, path, summary)
        if classes is not None:
            space = opt.space or kea_paths.default_space(family)
            code = definition.code if definition is not None else opt.code
            planned.append(_PlannedOption(opt, key, space, code, definition, classes))
        else:
            pending_dependency |= references.classes.has_pending_import(opt.client_classes)
    adopts = not options_mapped(server, family, parent)
    pairing = [item for item in planned if adopts and mapped_target(server, family, item.key.source) is None]
    unmapped = []
    if pairing:
        unmapped = list(
            unlinked(plugin_model("Option").objects.filter(assigned_object_type=ct, assigned_object_id=parent_obj.pk))
            .select_related("definition")
            .prefetch_related("client_classes")
            .order_by("pk")
        )
    adopted = [
        (row, item.key.source)
        for item, row in zip(pairing, _paired_rows(pairing, unmapped), strict=True)
        if row is not None
    ]
    adopt_options(scope, parent, adopted, mapped=not pending_dependency)
    for item in planned:
        write_row(_OptionAdapter(scope, item.key, item, parent_obj, ct))
