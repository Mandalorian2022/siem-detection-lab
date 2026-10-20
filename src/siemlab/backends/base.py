"""Shared conversion walk: selections -> field expressions, condition AST -> boolean query."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..sigma.condition import And, Node, Not, Or, Quant, Ref
from ..sigma.loader import SigmaRule
from ..sigma.modifiers import COMPARE, TRANSFORMS, expand_for_backend
from ..sigma.pipeline import map_field


class Backend(ABC):
    name = "base"

    # --- product specifics -------------------------------------------------
    @abstractmethod
    def table(self, dataset: str) -> str: ...

    @abstractmethod
    def field_expr(self, field: str, mode: str, value: Any, case_sensitive: bool) -> str: ...

    @abstractmethod
    def exists(self, field: str, want: bool) -> str: ...

    @abstractmethod
    def finish(self, table: str, where: str, rule: SigmaRule) -> str: ...

    and_, or_, not_ = " and ", " or ", "not "

    # --- generic walk -------------------------------------------------------
    def convert(self, rule: SigmaRule) -> str:
        det = {k: v for k, v in rule.detection.items() if k != "condition"}
        parts = {name: self._selection(rule.dataset, d) for name, d in det.items()}
        assert rule.condition is not None
        where = self._cond(rule.condition, parts)
        return self.finish(self.table(rule.dataset), where, rule)

    def _selection(self, dataset: str, definition: Any) -> str:
        if isinstance(definition, dict):
            return self._group([self._item(dataset, k, v) for k, v in definition.items()], self.and_)
        if isinstance(definition, list) and all(isinstance(d, dict) for d in definition):
            return self._group([self._selection(dataset, d) for d in definition], self.or_)
        if isinstance(definition, list):
            return self._group([self.keyword(str(w)) for w in definition], self.or_)
        raise ValueError("unsupported selection")

    def keyword(self, word: str) -> str:
        return f'"{word}"'

    def _item(self, dataset: str, key: str, value: Any) -> str:
        parts = key.split("|")
        field = map_field(dataset, parts[0])
        mods = parts[1:]
        compare = [m for m in mods if m in COMPARE]
        mode = compare[0] if compare else "equals"
        values = value if isinstance(value, list) else [value]
        joiner = self.and_ if "all" in mods else self.or_
        exprs = []
        for v in values:
            if mode == "exists":
                exprs.append(self.exists(field, bool(v)))
            elif isinstance(v, (bool, int, float)) or v is None or mode in ("re", "cidr", "lt", "lte", "gt", "gte"):
                exprs.append(self.field_expr(field, mode, v, "cased" in mods))
            else:
                pats = expand_for_backend([m for m in mods if m in TRANSFORMS], v)
                exprs.append(self._group([self.field_expr(field, mode, p.text, p.case_sensitive or "cased" in mods)
                                          for p in pats], self.or_))
        return self._group(exprs, joiner)

    def _group(self, exprs: list[str], joiner: str) -> str:
        if len(exprs) == 1:
            return exprs[0]
        return "(" + joiner.join(exprs) + ")"

    def _cond(self, node: Node, parts: dict[str, str]) -> str:
        if isinstance(node, Ref):
            return parts[node.name]
        if isinstance(node, Not):
            return self.not_ + "(" + self._cond(node.child, parts) + ")"
        if isinstance(node, And):
            return self._group([self._cond(c, parts) for c in node.children], self.and_)
        if isinstance(node, Or):
            return self._group([self._cond(c, parts) for c in node.children], self.or_)
        if isinstance(node, Quant):
            return self._group([parts[n] for n in node.names],
                               self.and_ if node.kind == "all" else self.or_)
        raise TypeError(node)
