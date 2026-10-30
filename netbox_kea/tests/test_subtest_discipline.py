# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Controls for the guard that keeps subTest assertions inside the subTest block."""

import re
import sys
import textwrap

import pytest
import yaml

from netbox_kea.tests.subtest_discipline import TESTS_ROOT, scan_source, scan_tree


def _scan(body):
    return scan_source(textwrap.dedent(body), "test_x.py")


def test_a_read_after_the_block_of_a_name_the_block_assigns_is_reported():
    hits = _scan(
        """
        class T:
            def test_it(self):
                for family in (4, 6):
                    with self.subTest(family=family):
                        outcome = save(family)
                    self.assertEqual(outcome, "applied")
        """
    )
    assert [(hit.lineno, hit.qualname, hit.names) for hit in hits] == [(5, "T.test_it", ("outcome",))]


def test_a_name_bound_by_another_context_manager_of_the_block_is_reported():
    hits = _scan(
        """
        def test_it(self):
            for family in (4, 6):
                with self.subTest(family=family), _import_kea(family) as kea:
                    save(family)
                self.assertEqual(kea.calls, [])
        """
    )
    assert [hit.names for hit in hits] == [("kea",)]


@pytest.mark.parametrize(
    "binding",
    [
        "import outcome",
        "import outcome.sub",
        "from module import value as outcome",
        "def outcome():\n    pass",
        "class outcome:\n    pass",
        "if x:\n    def outcome():\n        pass",
        "match x:\n    case outcome:\n        pass",
        "match x:\n    case int() as outcome:\n        pass",
        "match x:\n    case [*outcome]:\n        pass",
        "match x:\n    case {'value': outcome}:\n        pass",
        "match x:\n    case {**outcome}:\n        pass",
        "try:\n    f(x)\nexcept ValueError as outcome:\n    pass",
    ],
    ids=[
        "import",
        "dotted-import",
        "import-from",
        "def",
        "class",
        "nested-def",
        "match-capture",
        "match-as",
        "match-star",
        "match-mapping-value",
        "match-mapping-rest",
        "except-alias",
    ],
)
def test_an_import_definition_capture_or_alias_in_the_block_is_a_binding(binding):
    source = "def test_it(self):\n    for x in y:\n        with self.subTest(x=x):\n"
    source += textwrap.indent(binding, " " * 12) + "\n        self.assertTrue(outcome)\n"
    assert [hit.names for hit in scan_source(source)] == [("outcome",)]


@pytest.mark.parametrize(
    "after",
    [
        "if outcome:\n    pass",
        "with self.assertRaises(ValueError):\n    check(outcome)",
        "self.assertEqual([row for row in outcome], [])",
        "self.assertEqual([outcome[i] for i in range(2)], [])",
        "self.assertTrue(all(map(lambda v: v in outcome, y)))",
        "outcome += 1",
        "self.assertTrue([1 for outcome.value in [1]])",
    ],
    ids=[
        "if-test",
        "nested-block",
        "comprehension",
        "comprehension-body",
        "lambda-body",
        "augmented",
        "comprehension-target",
    ],
)
def test_a_read_anywhere_in_a_later_statement_is_reported(after):
    source = "def test_it(self):\n    for x in y:\n        with self.subTest(x=x):\n            outcome = f(x)\n"
    source += textwrap.indent(after, " " * 8) + "\n"
    assert [hit.names for hit in scan_source(source)] == [("outcome",)]


@pytest.mark.parametrize(
    "body",
    [
        # The assertions stay inside the block.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
                self.assertTrue(outcome)
        """,
        # A context manager closes first, inside the same subTest.
        """
        for x in y:
            with self.subTest(x=x):
                with stub() as kea:
                    outcome = f(x)
                self.assertEqual(kea.calls, outcome)
        """,
        # A later subTest block assigns the name again before it reads it.
        """
        for x in y:
            with self.subTest(x=x):
                sent = f(x)
            with self.subTest(x=x, step=2):
                sent = g(x)
                self.assertTrue(sent)
        """,
        # The later statement assigns the name before it reads it.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
            outcome = g(x)
            self.assertTrue(outcome)
        """,
        # No loop: the block is the last statement that can fail.
        """
        with self.subTest(x=1):
            outcome = f(1)
        self.assertTrue(outcome)
        """,
        # A name the block reads but does not bind.
        """
        for x in y:
            with self.subTest(x=x):
                f(server)
            self.assertTrue(server)
        """,
        # A context manager before the subTest binds its name before subTest can hide a failure.
        """
        for x in y:
            with nullcontext(1) as outcome, self.subTest(x=x):
                pass
            self.assertTrue(outcome)
        """,
        # A name that the body of a later block assigns before the block can fail.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
            with stub_kea({}) as kea:
                outcome = g(kea)
            self.assertTrue(outcome)
        """,
        # patch() does not swallow an exception from its body.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
            with patch("module.g"):
                outcome = g(x)
            self.assertTrue(outcome)
        """,
        # The other unittest.mock patch forms do not swallow an exception either.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
            with patch.object(module, "g"), mock.patch.dict(env), unittest.mock.patch("module.h"):
                outcome = g(x)
            self.assertTrue(outcome)
        """,
        # The first operand of a short-circuit operator always runs.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
            (outcome := g(x)) and x
            self.assertTrue(outcome)
        """,
        # An if test always runs, so its assignment expression binds the name on both branches.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
            if (outcome := g(x)):
                pass
            self.assertTrue(outcome)
        """,
        # The first operand of a short-circuit operator in an if test always runs.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
            if (outcome := g(x)) and x:
                self.assertTrue(outcome)
            self.assertTrue(outcome)
        """,
        # A context manager expression runs before the body of its block.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
            with nullcontext(outcome := g(x)):
                self.assertTrue(outcome)
            self.assertTrue(outcome)
        """,
        # A comprehension variable belongs to the comprehension.
        """
        for x in y:
            with self.subTest(x=x):
                f([row for row in x])
            self.assertTrue(row)
        """,
        # A later import assigns the name again before it reads it.
        """
        for x in y:
            with self.subTest(x=x):
                outcome = f(x)
            from module import outcome
            self.assertTrue(outcome)
        """,
        # A name assigned in a nested definition belongs to that definition.
        """
        for x in y:
            with self.subTest(x=x):
                def helper():
                    outcome = f(x)
            self.assertTrue(outcome)
        """,
    ],
    ids=[
        "inside",
        "inner-context-manager",
        "rebound-in-next-block",
        "rebound",
        "no-loop",
        "not-bound",
        "earlier-context-manager",
        "rebound-in-later-block",
        "rebound-in-later-patch-block",
        "rebound-in-later-patch-forms-block",
        "first-operand-walrus",
        "if-test-walrus",
        "if-test-first-operand-walrus",
        "context-manager-walrus",
        "comprehension",
        "later-import",
        "definition-local",
    ],
)
def test_nearby_valid_shapes_pass(body):
    source = "def test_it(self, y, row=None, server=None):\n" + textwrap.indent(textwrap.dedent(body), "    ")
    assert scan_source(source) == []


@pytest.mark.parametrize(
    "outer",
    ["with patch('netbox_kea.kea.KeaClient'):", "if x:"],
    ids=["outer-block", "branch"],
)
def test_a_read_after_an_enclosing_block_in_the_loop_is_reported(outer):
    source = textwrap.dedent(
        f"""
        def test_it(self):
            for x in y:
                {outer}
                    with self.subTest(x=x):
                        outcome = f(x)
                self.assertTrue(outcome)
            self.assertTrue(outcome)
        """
    )
    assert [(hit.lineno, hit.names) for hit in scan_source(source)] == [(5, ("outcome",))]


@pytest.mark.parametrize(
    "block",
    [
        "try:\n    {subtest}\nfinally:\n    {read}",
        "try:\n    {subtest}\nexcept ValueError:\n    pass\nelse:\n    {read}",
        "try:\n    {subtest}\nexcept ValueError:\n    pass\nfinally:\n    {read}",
        "try:\n    pass\nexcept ValueError:\n    {subtest}\nfinally:\n    {read}",
        "try:\n    pass\nexcept ValueError:\n    pass\nelse:\n    {subtest}\nfinally:\n    {read}",
        "try:\n    pass\nfinally:\n    {subtest}\n    {read}",
    ],
    ids=["finally", "else", "finally-after-handler", "handler-then-finally", "else-then-finally", "inside-finally"],
)
def test_a_read_in_a_later_clause_of_the_try_statement_is_reported(block):
    body = block.format(subtest="with self.subTest(x=x):\n        outcome = f(x)", read="self.assertTrue(outcome)")
    source = "def test_it(self):\n    for x in y:\n" + textwrap.indent(body, " " * 8) + "\n"
    assert [hit.names for hit in scan_source(source)] == [("outcome",)]


@pytest.mark.parametrize(
    "block",
    [
        # A finally clause that assigns the name before it reads it.
        "try:\n    {subtest}\nfinally:\n    outcome = g(x)\n    self.assertTrue(outcome)",
        # A handler does not run after a failure that subTest records.
        "try:\n    {subtest}\nexcept ValueError:\n    self.assertTrue(outcome)",
        # A finally clause without a subTest before it in the try statement.
        "try:\n    f(x)\nfinally:\n    self.assertTrue(row)",
    ],
    ids=["finally-rebinds", "handler", "no-subtest"],
)
def test_a_later_clause_of_the_try_statement_that_is_valid_passes(block):
    body = block.format(subtest="with self.subTest(x=x):\n        outcome = f(x)")
    source = "def test_it(self, y, row=None):\n    for x in y:\n" + textwrap.indent(body, " " * 8) + "\n"
    assert scan_source(source) == []


@pytest.mark.parametrize(
    "between",
    [
        "def helper():\n    outcome = 1",
        "match x:\n    case 0:\n        outcome = 0",
        "outcome: int",
        "with self.assertRaises(ZeroDivisionError):\n    outcome = 1 / 0",
        "with pytest.raises(ZeroDivisionError):\n    outcome = 1 / 0",
        "with self.assertRaisesMessage(ZeroDivisionError, 'division'):\n    outcome = 1 / 0",
        "with self.subTest(step=2):\n    outcome = g(x)",
        "with suppress(ValueError), nullcontext(g(x)) as outcome:\n    pass",
        "with ignore_errors():\n    outcome = g(x)",
        "with ignore_errors(), stub_kea({}):\n    outcome = g(x)",
        "with errors.patch():\n    outcome = g(x)",
        "x and (outcome := g(x))",
        "if x and (outcome := g(x)):\n    pass",
        "h((outcome := g(x)) if x else None)",
        pytest.param(
            "try:\n    pass\nexcept* ValueError:\n    outcome = 0",
            marks=pytest.mark.skipif(sys.version_info < (3, 11), reason="except* needs Python 3.11"),
        ),
    ],
    ids=[
        "nested-def",
        "match",
        "annotation",
        "assert-raises",
        "pytest-raises",
        "assert-raises-message",
        "subtest",
        "suppressed-target",
        "unlisted-manager",
        "unlisted-manager-first",
        "unlisted-patch-attribute",
        "short-circuit-walrus",
        "if-test-short-circuit-walrus",
        "conditional-walrus",
        "except-star",
    ],
)
def test_an_assignment_that_may_not_run_is_not_a_rebinding(between):
    source = "def test_it(self):\n    for x in y:\n        with self.subTest(x=x):\n            outcome = f(x)\n"
    source += textwrap.indent(between, " " * 8) + "\n        self.assertTrue(outcome)\n"
    assert (3, ("outcome",)) in [(hit.lineno, hit.names) for hit in scan_source(source)]


def test_a_read_in_a_later_context_manager_target_is_reported():
    source = "def test_it(self):\n    for x in y:\n        with self.subTest(x=x):\n            outcome = f(x)\n"
    source += "        with nullcontext(1) as outcome.value:\n            pass\n"
    assert [hit.names for hit in scan_source(source)] == [("outcome",)]


def test_every_name_a_later_statement_reads_is_named():
    source = "def test_it(self):\n    for x in y:\n        with self.subTest(x=x):\n            a, b = f(x)\n"
    source += "        g(b, a)\n"
    assert [str(hit) for hit in scan_source(source, "test_x.py")] == [
        "test_x.py:3: test_it: 'a', 'b' are read after the subTest block that binds them; keep the reads inside the block"
    ]


def test_a_block_in_the_else_clause_of_a_loop_is_not_in_the_loop():
    source = textwrap.dedent(
        """
        def test_it(self):
            for x in y:
                pass
            else:
                with self.subTest(x=1):
                    outcome = f(1)
                self.assertTrue(outcome)
        """
    )
    assert scan_source(source) == []


def test_a_loop_in_an_outer_function_does_not_cover_a_nested_function():
    source = textwrap.dedent(
        """
        def test_it(self):
            for x in y:
                def check():
                    with self.subTest(x=x):
                        outcome = f(x)
                    return outcome
        """
    )
    assert scan_source(source) == []


def test_the_test_tree_has_no_reads_after_a_subtest_block():
    assert scan_tree() == []


def test_scan_tree_reports_a_new_test_module(tmp_path):
    (tmp_path / "test_new.py").write_text(
        "def test_it(self):\n    for x in y:\n        with self.subTest(x=x):\n            v = f(x)\n        g(v)\n"
    )
    assert [str(hit) for hit in scan_tree(tmp_path)] == [
        "test_new.py:3: test_it: 'v' is read after the subTest block that binds it; keep the reads inside the block"
    ]


def test_hook_scans_the_whole_test_tree():
    configuration = yaml.safe_load((TESTS_ROOT.parents[1] / ".pre-commit-config.yaml").read_text())
    hook = next(hook for repo in configuration["repos"] for hook in repo["hooks"] if hook["id"] == "subtest-discipline")
    assert hook["entry"] == "python3 netbox_kea/tests/subtest_discipline.py"
    assert hook["pass_filenames"] is False
    assert re.search(hook["files"], "netbox_kea/tests/new_directory/test_new.py")
    assert re.search(hook["files"], ".pre-commit-config.yaml")
