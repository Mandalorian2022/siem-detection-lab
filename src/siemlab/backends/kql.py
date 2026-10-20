"""Kusto Query Language (Microsoft Sentinel / Defender) backend."""
from __future__ import annotations

from typing import Any

from ..sigma.loader import SigmaRule
from .base import Backend

TABLES = {"identity.signin": "SigninLogs", "windows.security": "SecurityEvent",
          "network.dns": "DnsEvents", "network.connection": "NetworkSession"}


def _col(field: str) -> str:
    return "['" + field + "']" if "." in field else field


def _lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


class KqlBackend(Backend):
    name = "kql"

    def table(self, dataset: str) -> str:
        return TABLES.get(dataset, dataset.replace(".", "_"))

    def exists(self, field: str, want: bool) -> str:
        return f"{'isnotempty' if want else 'isempty'}({_col(field)})"

    def field_expr(self, field: str, mode: str, value: Any, case_sensitive: bool) -> str:
        c = _col(field)
        if value is None:
            return f"isempty({c})"
        if mode in ("lt", "lte", "gt", "gte"):
            return f"{c} {{'lt': '<', 'lte': '<=', 'gt': '>', 'gte': '>='}}[mode] {value}".replace(
                "{'lt': '<', 'lte': '<=', 'gt': '>', 'gte': '>='}[mode]",
                {"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}[mode])
        if mode == "re":
            return f"{c} matches regex {_lit(value)}"
        if mode == "cidr":
            return f"ipv4_is_in_range({c}, {_lit(value)})"
        if isinstance(value, (bool, int, float)):
            return f"{c} == {_lit(value)}"
        s = str(value)
        cs = "_cs" if case_sensitive else ""
        if mode == "equals":
            if any(ch in s for ch in "*?"):
                return f"{c} matches regex {_lit(_wild_to_regex(s))}"
            return f"{c} {'==' if case_sensitive else '=~'} {_lit(s)}"
        op = {"contains": "contains", "startswith": "startswith", "endswith": "endswith"}[mode]
        return f"{c} {op}{cs} {_lit(s)}"

    def finish(self, table: str, where: str, rule: SigmaRule) -> str:
        return f"{table}\n| where {where}"


def _wild_to_regex(s: str) -> str:
    import re
    out = []
    for ch in s:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return "^" + "".join(out) + "$"
