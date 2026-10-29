# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Keep the reads of a looped ``subTest`` block's names inside that block.

When a call in a ``with self.subTest(...)`` block raises, ``subTest`` records the error and
continues. A later statement that reads a name the block did not bind then raises
``NameError``, which stops the loop and hides the real failure. This guard reports a
``subTest`` block inside a loop when a statement after it in the same loop iteration reads a
name that the block binds (by assignment, ``as``, import or definition) before it assigns the name again.

Stdlib only, so it runs as a pre-commit hook without NetBox. Limits: it does not follow reads
after an inner loop, or in a nested ``def`` with its defaults and decorators. An assignment in a branch, loop, ``try`` or
``match``, or in the body of a context manager that can swallow an exception, does not count
as a rebinding. It reads the loads of one statement before its stores, and it does not see
an assignment expression in a comprehension.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard

TESTS_ROOT = Path(__file__).resolve().parent
_DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_COMPOUND = (ast.For, ast.AsyncFor, ast.While, ast.Try, getattr(ast, "TryStar", ast.Try), ast.Match)
# Context managers that can swallow an exception from their body, so its assignments may not run.
_SUPPRESSING = {
    "subTest",
    "assertRaises",
    "assertRaisesRegex",
    "assertRaisesMessage",
    "assertWarns",
    "assertWarnsRegex",
    "assertWarnsMessage",
    "raises",
    "suppress",
}


@dataclass(frozen=True, order=True)
class Violation:
    """A looped subTest block whose names a later statement reads."""

    path: str
    lineno: int
    qualname: str
    names: tuple[str, ...]

    def __str__(self) -> str:
        names = ", ".join(f"'{name}'" for name in self.names)
        verb, pronoun = ("is", "it") if len(self.names) == 1 else ("are", "them")
        return (
            f"{self.path}:{self.lineno}: {self.qualname}: {names} {verb} read after the subTest block that binds"
            f" {pronoun}; keep the reads inside the block"
        )


def _scope_nodes(node: ast.AST):
    """Yield *node* and its descendants in this scope, without nested scopes or comprehensions."""
    yield node
    if isinstance(node, (*_DEFINITIONS, ast.Lambda)):
        return
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _DEFINITIONS):
            # A definition binds its name here; its body is another scope.
            yield child
        elif not isinstance(child, (ast.Lambda, *_COMPREHENSIONS)):
            yield from _scope_nodes(child)
        elif isinstance(child, _COMPREHENSIONS):
            # The first iterable runs in this scope; the rest belongs to the comprehension.
            yield from _scope_nodes(child.generators[0].iter)


def _stores(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for part in _scope_nodes(node):
        if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store):
            names.add(part.id)
        elif isinstance(part, (ast.Import, ast.ImportFrom)):
            names |= {alias.asname or alias.name.split(".")[0] for alias in part.names if alias.name != "*"}
        elif isinstance(part, _DEFINITIONS):
            names.add(part.name)
    return names


def _definite_stores(node: ast.AST) -> set[str]:
    """Return the names *node* stores, without those in a part that a short-circuit operator or a conditional skips."""
    skipped: set[str] = set()
    for part in _scope_nodes(node):
        if isinstance(part, ast.BoolOp):
            skipped |= set().union(*map(_stores, part.values[1:]))
        elif isinstance(part, ast.IfExp):
            skipped |= _stores(part.body) | _stores(part.orelse)
    return _stores(node) - skipped


def _reads(node: ast.AST) -> set[str]:
    """Return the names that *node* reads from this scope, also through lambda and comprehension bodies."""
    if isinstance(node, ast.Name):
        return {node.id} if isinstance(node.ctx, ast.Load) else set()
    if isinstance(node, _DEFINITIONS):
        return set()
    reads = set().union(*map(_reads, ast.iter_child_nodes(node)))
    if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        reads.add(node.target.id)
    elif isinstance(node, _COMPREHENSIONS):
        local = {
            part.id
            for generator in node.generators
            for part in ast.walk(generator.target)
            if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Store)
        }
        reads = (reads - local) | _reads(node.generators[0].iter)
    elif isinstance(node, ast.Lambda):
        reads -= {argument.arg for argument in ast.walk(node.args) if isinstance(argument, ast.arg)}
        reads |= set().union(*map(_reads, node.args.defaults + [d for d in node.args.kw_defaults if d]))
    return reads


def _called(item: ast.withitem) -> str | None:
    """Return the name of the function or method that a context manager item calls."""
    call = item.context_expr
    if isinstance(call, ast.Call):
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        if isinstance(call.func, ast.Name):
            return call.func.id
    return None


def _is_subtest(node: ast.stmt) -> TypeGuard[ast.With | ast.AsyncWith]:
    return isinstance(node, (ast.With, ast.AsyncWith)) and any(_called(item) == "subTest" for item in node.items)


def _first_reads(body: list[ast.stmt], watched: set[str], rebound: set[str]) -> tuple[set[str], set[str]]:
    """Return the watched names *body* reads before it assigns them, and the names it always assigns."""
    reads: set[str] = set()
    for node in body:
        if isinstance(node, (ast.With, ast.AsyncWith)):
            before = rebound
            for item in node.items:
                reads |= (_reads(item.context_expr) & watched) - rebound
                if item.optional_vars is not None:
                    reads |= (_reads(item.optional_vars) & watched) - rebound
                    rebound = rebound | _stores(item.optional_vars)
            inner, assigned = _first_reads(node.body, watched, rebound)
            reads |= inner
            rebound = before if any(_called(item) in _SUPPRESSING for item in node.items) else assigned
        elif isinstance(node, ast.If):
            reads |= (_reads(node.test) & watched) - rebound
            reads_if_true, when_true = _first_reads(node.body, watched, rebound)
            reads_if_false, when_false = _first_reads(node.orelse, watched, rebound)
            reads |= reads_if_true | reads_if_false
            rebound = when_true & when_false
        elif isinstance(node, _COMPOUND):
            reads |= (_reads(node) & watched) - rebound
        elif isinstance(node, _DEFINITIONS):
            rebound = rebound | {node.name}
        else:
            reads |= (_reads(node) & watched) - rebound
            if not (isinstance(node, ast.AnnAssign) and node.value is None):
                rebound = rebound | _definite_stores(node)
    return reads, rebound


class _Scanner(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.scope: list[str] = []
        # The statements after each enclosing statement, up to the innermost loop; None outside a loop.
        self.after: list[list[ast.stmt]] | None = None
        self.hits: list[Violation] = []

    def _block(self, body: list[ast.stmt]) -> None:
        for index, node in enumerate(body):
            if self.after is None:
                self.visit(node)
                continue
            self.after.append(body[index + 1 :])
            if _is_subtest(node):
                self._check(node)
            self.visit(node)
            self.after.pop()

    def generic_visit(self, node: ast.AST) -> None:
        for field, value in ast.iter_fields(node):
            if field in ("body", "orelse", "finalbody") and isinstance(value, list):
                self._block(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)

    def _scoped(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        outer, self.after = self.after, None
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
        self.after = outer

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scoped

    def _loop(self, node: ast.For | ast.AsyncFor | ast.While) -> None:
        outer, self.after = self.after, []
        self._block(node.body)
        self.after = outer
        self._block(node.orelse)

    visit_For = visit_AsyncFor = visit_While = _loop

    def _try(self, node: ast.Try) -> None:
        if self.after is None:
            self.generic_visit(node)
            return
        # The else and finally clauses run after a failure that subTest records in an earlier clause.
        for body, then in ((node.body, node.orelse + node.finalbody), (node.orelse, node.finalbody)):
            self.after.append(then)
            self._block(body)
            self.after.pop()
        self.after.append(node.finalbody)
        for handler in node.handlers:
            self.visit(handler)
        self.after.pop()
        self._block(node.finalbody)

    visit_Try = visit_TryStar = _try

    def _check(self, node: ast.With | ast.AsyncWith) -> None:
        # A context manager before the subTest binds its name before subTest can hide a failure.
        items = node.items[[_called(item) for item in node.items].index("subTest") :]
        bound = set().union(*(_stores(item.optional_vars) for item in items if item.optional_vars))
        bound |= set().union(*map(_stores, node.body))
        later = [statement for rest in reversed(self.after or []) for statement in rest]
        reads, _ = _first_reads(later, bound, set())
        if reads:
            qualname = ".".join(self.scope) or "<module>"
            self.hits.append(Violation(self.path, node.lineno, qualname, tuple(sorted(reads))))


def scan_source(source: str, path: str = "<source>") -> list[Violation]:
    """Return the looped subTest blocks in one module whose names a later statement reads."""
    scanner = _Scanner(path)
    scanner.visit(ast.parse(source, filename=path))
    return sorted(scanner.hits)


def scan_tree(root: Path = TESTS_ROOT) -> list[Violation]:
    """Scan every module under *root*."""
    hits: list[Violation] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" not in path.parts:
            hits.extend(scan_source(path.read_text(encoding="utf-8"), path.relative_to(root).as_posix()))
    return hits


def main(root: Path = TESTS_ROOT) -> int:
    """Print the whole-tree hook result."""
    hits = scan_tree(root)
    for hit in hits:
        print(hit)
    print(f"subtest-discipline: {len(hits)} violation(s)")
    return int(bool(hits))


if __name__ == "__main__":
    sys.exit(main())
