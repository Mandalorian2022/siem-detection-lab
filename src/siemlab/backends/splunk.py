"""Splunk SPL backend."""
from __future__ import annotations

from typing import Any

from ..sigma.loader import SigmaRule
from .base import Backend

SOURCETYPES = {"identity.signin": 'sourcetype="azure:signin"',
               "windows.security": 'sourcetype="WinEventLog:Security"',
               "network.dns": 'sourcetype="dns"', "network.connection": 'sourcetype="netflow"'}


def _q(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


class SplunkBackend(Backend):
    name = "splunk"
    and_, or_, not_ = " AND ", " OR ", "NOT "

    def table(self, dataset: str) -> str:
        return SOURCETYPES.get(dataset, f'sourcetype="{dataset}"')

    def exists(self, field: str, want: bool) -> str:
        return f'{field}=*' if want else f'NOT {field}=*'

    def keyword(self, word: str) -> str:
        return _q(word)

    def field_expr(self, field: str, mode: str, value: Any, case_sensitive: bool) -> str:
        if value is None:
            return f'NOT {field}=*'
        if mode in ("lt", "lte", "gt", "gte"):
            return f'{field}{ {"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}[mode] }{value}'
        if mode == "re":
            return f'| regex {field}={_q(value)}'
        if mode == "cidr":
            return f'{field}={_q(value)}'
        if isinstance(value, (bool, int, float)):
            return f'{field}={_q(value)}'
        s = str(value)
        if mode == "contains":
            s = f"*{s}*"
        elif mode == "startswith":
            s = f"{s}*"
        elif mode == "endswith":
            s = f"*{s}"
        return f'{field}={_q(s)}'

    def finish(self, table: str, where: str, rule: SigmaRule) -> str:
        # a regex item cannot live inside the base search; hoist it to a pipe stage
        if "| regex " in where:
            base, _, rx = where.partition("| regex ")
            base = base.strip().rstrip("(").strip()
            where = (base + " " if base else "") + "| regex " + rx.rstrip(")")
            return f"{table} {where}"
        return f"{table} {where}"
