"""Run the whole detection pipeline over an event file.

enrich -> Sigma rules and correlations -> behavioural analytics -> alerts
-> incidents. Alerts carry the entities the incident engine links on and
the evidence event ids the evaluator uses for attribution.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from .analytics import ANALYTICS
from .enrich import Enricher
from .incidents import Incident, build_incidents
from .model import LEVEL_RISK, Alert, Match, fmt_ts, parse_ts
from .sigma import SigmaEngine, SigmaRule, load_rules
from .sigma.loader import SigmaCorrelation
from .sigma.pipeline import map_field
from .simulate.world import World

ENTITY_FIELDS = ("user.name", "host.name", "source.ip", "destination.ip")


def read_events(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _tags(tags: Iterable[str]) -> tuple[list[str], list[str]]:
    tactics = sorted(t[len("attack."):] for t in tags
                     if t.startswith("attack.") and not t[len("attack."):].startswith("t"))
    techniques = sorted(t[len("attack."):].upper() for t in tags
                        if t.startswith("attack.t"))
    return tactics, techniques


def _alert_id(rule_id: str, m: Match) -> str:
    raw = f"{rule_id}|{m.first_ts}|{m.ts}|{','.join(m.evidence[:5])}"
    return "al-" + hashlib.sha1(raw.encode()).hexdigest()[:12]


def _entities_from_match(m: Match, rule: SigmaRule | SigmaCorrelation | None) -> dict[str, str]:
    ents: dict[str, str] = {}
    if m.event is not None:
        for f in ENTITY_FIELDS:
            if m.event.get(f):
                ents[f] = str(m.event[f])
    if isinstance(rule, SigmaCorrelation):
        for k, v in m.group.items():
            dataset = "identity.signin" if any(x in k for x in ("User", "IpAddress")) else "windows.security"
            ents[map_field(dataset, k)] = str(v)
    else:
        for f in ENTITY_FIELDS:
            if m.group.get(f):
                ents[f] = str(m.group[f])
    return ents


def _summary(m: Match) -> str:
    extra = {k: v for k, v in m.group.items() if k not in ENTITY_FIELDS}
    return ", ".join(f"{k}={v}" for k, v in extra.items())


class Pipeline:
    def __init__(self, rules_dir: Path, world: World):
        self.world = world
        self.engine = SigmaEngine(load_rules(rules_dir))
        self.enricher = Enricher(world)
        self.analytics = [cls(world) for cls in ANALYTICS]

    def catalogue(self) -> list[dict]:
        """Every alerting detection with its metadata, for the report."""
        out = []
        for r in self.engine.alerting_rules():
            if r.custom.get("x-building-block"):
                continue
            tac, tech = _tags(r.tags)
            out.append({"id": r.id, "name": r.name or r.id, "title": r.title, "level": r.level,
                        "kind": r.kind, "tactics": tac, "techniques": tech,
                        "description": r.description.strip()})
        for a in self.analytics:
            tac, tech = _tags(a.meta.tags)
            out.append({"id": a.meta.id, "name": a.meta.name, "title": a.meta.title,
                        "level": a.meta.level, "kind": "analytic", "tactics": tac,
                        "techniques": tech, "description": a.meta.description})
        return out

    def run(self, events: list[dict]) -> tuple[list[Alert], list[Incident], list[dict]]:
        enriched = [self.enricher.enrich(e) for e in events]
        for ev in enriched:
            ts = parse_ts(ev["@timestamp"])
            for a in self.analytics:
                a.observe(ev, ts)
        results = self.engine.run(enriched)

        alerts: list[Alert] = []
        for r in self.engine.alerting_rules():
            if r.custom.get("x-building-block"):
                continue
            tac, tech = _tags(r.tags)
            for m in results[r.id]:
                alerts.append(Alert(
                    _alert_id(r.id, m), r.name or r.id, r.title, r.level, LEVEL_RISK[r.level],
                    "sigma-correlation" if r.kind == "correlation" else "sigma", tac, tech,
                    fmt_ts(m.first_ts), fmt_ts(m.ts), _entities_from_match(m, r),
                    list(m.evidence), _summary(m)))
        for a in self.analytics:
            tac, tech = _tags(a.meta.tags)
            for m in a.finish():
                alerts.append(Alert(
                    _alert_id(a.meta.id, m), a.meta.name, a.meta.title, a.meta.level,
                    LEVEL_RISK[a.meta.level], "analytic", tac, tech, fmt_ts(m.first_ts),
                    fmt_ts(m.ts), _entities_from_match(m, None), list(m.evidence), _summary(m)))
        alerts.sort(key=lambda x: (x.first_seen, x.rule_id))
        incidents = build_incidents(alerts, self.world)
        return alerts, incidents, enriched


def write_alerts(path: Path, alerts: list[Alert]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a.to_dict(), separators=(",", ":")) + "\n")


def write_incidents(path: Path, incidents: list[Incident]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([i.to_dict() for i in incidents], f, indent=1)
