"""Evaluate Sigma detection rules and correlation rules over an event stream.

Detection rules are applied per event, routed by dataset so a rule only
sees the log source it was written for. Correlation rules then consume the
matches of the rules they reference, in dependency order, so a correlation
may build on another correlation (for example "brute force, then a
successful logon for the same account").
"""
from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from typing import Any

from ..model import Match, parse_ts
from .loader import SigmaCorrelation, SigmaRule, SigmaRuleError
from .pipeline import map_field

AnyRule = SigmaRule | SigmaCorrelation


class SigmaEngine:
    def __init__(self, rules: Iterable[AnyRule]):
        self.rules: list[AnyRule] = list(rules)
        self.by_ref: dict[str, AnyRule] = {}
        for r in self.rules:
            self.by_ref[r.id] = r
            if r.name:
                if r.name in self.by_ref and self.by_ref[r.name] is not r:
                    raise SigmaRuleError(f"duplicate rule name {r.name!r}")
                self.by_ref[r.name] = r
        self.detections = [r for r in self.rules if isinstance(r, SigmaRule)]
        self.correlations = self._ordered_correlations()
        self.by_dataset: dict[str, list[SigmaRule]] = defaultdict(list)
        for d in self.detections:
            self.by_dataset[d.dataset].append(d)
        # rules feeding a correlation with generate: false do not alert on their own
        self.suppressed: set[str] = set()
        for c in self.correlations:
            if not c.generate:
                self.suppressed |= {self.by_ref[ref].id for ref in c.rules}

    def _ordered_correlations(self) -> list[SigmaCorrelation]:
        corrs = {r.id: r for r in self.rules if isinstance(r, SigmaCorrelation)}
        for c in corrs.values():
            for ref in c.rules:
                if ref not in self.by_ref:
                    raise SigmaRuleError(f"{c.path}: correlation references unknown rule {ref!r}")
        order: list[SigmaCorrelation] = []
        state: dict[str, int] = {}

        def visit(c: SigmaCorrelation) -> None:
            if state.get(c.id) == 2:
                return
            if state.get(c.id) == 1:
                raise SigmaRuleError(f"correlation cycle through {c.title!r}")
            state[c.id] = 1
            for ref in c.rules:
                dep = self.by_ref[ref]
                if isinstance(dep, SigmaCorrelation):
                    visit(dep)
            state[c.id] = 2
            order.append(c)
        for c in corrs.values():
            visit(c)
        return order

    def alerting_rules(self) -> list[AnyRule]:
        return [r for r in self.rules if r.id not in self.suppressed]

    # --- evaluation ------------------------------------------------------
    def run(self, events: Iterable[dict]) -> dict[str, list[Match]]:
        """Return rule id -> matches, for every rule (alerting or not)."""
        stream = sorted(((parse_ts(e["@timestamp"]), e) for e in events), key=lambda t: t[0])
        out: dict[str, list[Match]] = {r.id: [] for r in self.rules}
        for ts, ev in stream:
            for rule in self.by_dataset.get(ev.get("event.dataset", ""), ()):
                if rule.matches(ev):
                    out[rule.id].append(Match(rule.id, ts, ts, (ev["event.id"],), event=ev))
        for corr in self.correlations:
            out[corr.id] = self._correlate(corr, out)
        return out

    def _value(self, ref_rule: AnyRule, m: Match, sigma_field: str) -> Any:
        if isinstance(ref_rule, SigmaRule):
            assert m.event is not None
            return m.event.get(map_field(ref_rule.dataset, sigma_field))
        return m.group.get(sigma_field)

    def _inputs(self, corr: SigmaCorrelation, results: dict[str, list[Match]]):
        """(ts, rule_ref, match, group_key) for every referenced match, time-ordered."""
        rows = []
        for ref in corr.rules:
            rule = self.by_ref[ref]
            for m in results[rule.id]:
                key = tuple(self._value(rule, m, g) for g in corr.group_by)
                if any(k is None for k in key):
                    continue
                rows.append((m.ts, ref, rule, m, key))
        rows.sort(key=lambda r: r[0])
        return rows

    def _emit(self, corr: SigmaCorrelation, key: tuple, window: Iterable[Match]) -> Match:
        ms = list(window)
        evidence = tuple(dict.fromkeys(e for m in ms for e in m.evidence))
        group = dict(zip(corr.group_by, key, strict=True))
        return Match(corr.id, min(m.first_ts for m in ms), max(m.ts for m in ms), evidence, group)

    def _passes(self, corr: SigmaCorrelation, n: int) -> bool:
        return n > corr.threshold if corr.op == "gt" else n >= corr.threshold

    def _correlate(self, corr: SigmaCorrelation, results: dict[str, list[Match]]) -> list[Match]:
        rows = self._inputs(corr, results)
        span = corr.timespan
        fired: list[Match] = []
        if corr.type == "event_count":
            windows: dict[tuple, deque] = defaultdict(deque)
            for ts, _ref, _rule, m, key in rows:
                w = windows[key]
                w.append(m)
                while w and ts - w[0].ts > span:
                    w.popleft()
                if self._passes(corr, len(w)):
                    fired.append(self._emit(corr, key, w))
                    w.clear()
        elif corr.type == "value_count":
            assert corr.count_field is not None
            vwin: dict[tuple, deque] = defaultdict(deque)
            for ts, _ref, rule, m, key in rows:
                v = self._value(rule, m, corr.count_field)
                if v is None:
                    continue
                w = vwin[key]
                w.append((m, v))
                while w and ts - w[0][0].ts > span:
                    w.popleft()
                if self._passes(corr, len({val for _, val in w})):
                    fired.append(self._emit(corr, key, (mm for mm, _ in w)))
                    w.clear()
        else:
            ordered = corr.type == "temporal_ordered"
            last: dict[tuple, dict[str, Match]] = defaultdict(dict)
            for ts, ref, _rule, m, key in rows:
                seen = last[key]
                seen[ref] = m
                for r in [r for r, mm in seen.items() if ts - mm.ts > span]:
                    del seen[r]
                if len(seen) < len(corr.rules):
                    continue
                if ordered:
                    times = [seen[r].ts for r in corr.rules]
                    if times != sorted(times) or ref != corr.rules[-1]:
                        continue
                fired.append(self._emit(corr, key, seen.values()))
                seen.clear()
        return fired
