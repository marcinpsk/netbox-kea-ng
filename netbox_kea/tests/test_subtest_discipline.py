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
            with stub() as kea:
                outcome = g(kea)
            self.assertTrue(outcome)
        """,
        # A comprehension variable belongs to the comprehension.
        """
        for x in y:
            with self.subTest(x=x):
                f([row for row in x])
            self.assertTrue(row)
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
        "comprehension",
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
    "between",
    [
        "def helper():\n    outcome = 1",
        "match x:\n    case 0:\n        outcome = 0",
        "outcome: int",
        "with self.assertRaises(ZeroDivisionError):\n    outcome = 1 / 0",
        "with self.subTest(step=2):\n    outcome = g(x)",
        "with suppress(ValueError), nullcontext(g(x)) as outcome:\n    pass",
        pytest.param(
            "try:\n    pass\nexcept* ValueError:\n    outcome = 0",
            marks=pytest.mark.skipif(sys.version_info < (3, 11), reason="except* needs Python 3.11"),
        ),
    ],
    ids=["nested-def", "match", "annotation", "assert-raises", "subtest", "suppressed-target", "except-star"],
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
