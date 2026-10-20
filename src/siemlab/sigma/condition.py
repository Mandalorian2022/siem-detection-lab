"""Parser for Sigma ``condition`` expressions.

Grammar (lowest to highest precedence)::

    expr     := and_expr ("or" and_expr)*
    and_expr := not_expr ("and" not_expr)*
    not_expr := "not" not_expr | atom
    atom     := "(" expr ")" | quant | NAME
    quant    := ("1" | "any" | "all") "of" (PATTERN | "them")

``PATTERN`` may end in ``*`` to select every detection whose name starts
with the prefix. The parser produces a small AST that is evaluated against
a mapping of detection name to boolean, so each selection is computed once
per event no matter how often the condition references it.
"""
from __future__ import annotations

import fnmatch
import re
from collections.abc import Mapping
from dataclasses import dataclass

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*\-.]+)")


class SigmaConditionError(ValueError):
    """Raised when a condition cannot be parsed or references unknown names."""


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class Not:
    child: Node


@dataclass(frozen=True)
class And:
    children: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    children: tuple[Node, ...]


@dataclass(frozen=True)
class Quant:
    kind: str          # "any" or "all"
    names: tuple[str, ...]


Node = Ref | Not | And | Or | Quant


def tokenize(text: str) -> list[str]:
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise SigmaConditionError(f"unexpected character at {pos}: {text[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]):
        self.t = tokens
        self.i = 0
        self.names = names

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expect: str | None = None) -> str:
        tok = self.peek()
        if tok is None:
            raise SigmaConditionError("unexpected end of condition")
        if expect is not None and tok.lower() != expect:
            raise SigmaConditionError(f"expected {expect!r}, got {tok!r}")
        self.i += 1
        return tok

    def parse(self) -> Node:
        node = self.expr()
        if self.peek() is not None:
            raise SigmaConditionError(f"trailing tokens: {self.t[self.i:]}")
        return node

    def expr(self) -> Node:
        parts = [self.and_expr()]
        while (self.peek() or "").lower() == "or":
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else Or(tuple(parts))

    def and_expr(self) -> Node:
        parts = [self.not_expr()]
        while (self.peek() or "").lower() == "and":
            self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else And(tuple(parts))

    def not_expr(self) -> Node:
        if (self.peek() or "").lower() == "not":
            self.take()
            return Not(self.not_expr())
        return self.atom()

    def atom(self) -> Node:
        tok = self.take()
        low = tok.lower()
        if tok == "(":
            node = self.expr()
            self.take(")")
            return node
        if low in ("1", "any", "all") and (self.peek() or "").lower() == "of":
            self.take("of")
            target = self.take()
            return Quant("all" if low == "all" else "any", self._resolve(target))
        if tok == ")" or low in ("and", "or", "not", "of"):
            raise SigmaConditionError(f"unexpected token {tok!r}")
        if tok not in self.names:
            raise SigmaConditionError(f"condition references unknown detection {tok!r}")
        return Ref(tok)

    def _resolve(self, target: str) -> tuple[str, ...]:
        if target.lower() == "them":
            picked = [n for n in self.names if not n.startswith("_")]
        else:
            picked = [n for n in self.names if fnmatch.fnmatchcase(n, target)]
        if not picked:
            raise SigmaConditionError(f"'{target}' matches no detection")
        return tuple(picked)


def parse_condition(text: str, names: list[str]) -> Node:
    """Parse ``text`` given the detection names defined by the rule."""
    return _Parser(tokenize(text), names).parse()


def evaluate(node: Node, values: Mapping[str, bool]) -> bool:
    if isinstance(node, Ref):
        return values[node.name]
    if isinstance(node, Not):
        return not evaluate(node.child, values)
    if isinstance(node, And):
        return all(evaluate(c, values) for c in node.children)
    if isinstance(node, Or):
        return any(evaluate(c, values) for c in node.children)
    if node.kind == "all":
        return all(values[n] for n in node.names)
    return any(values[n] for n in node.names)


def referenced(node: Node) -> set[str]:
    """Every detection name the condition can read."""
    if isinstance(node, Ref):
        return {node.name}
    if isinstance(node, Not):
        return referenced(node.child)
    if isinstance(node, (And, Or)):
        out: set[str] = set()
        for c in node.children:
            out |= referenced(c)
        return out
    return set(node.names)
