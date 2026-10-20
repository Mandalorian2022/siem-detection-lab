"""Risk-based incident correlation.

Alerts rarely arrive labelled with the campaign they belong to. What they
do carry are entities: an account, a host, a source address, a destination.
This module links alerts that share an entity within a time window, with
one extra edge the directory provides, identity -> workstation, so a cloud
sign-in alert for a user and a network alert for that user's laptop land in
the same incident. Each incident accumulates risk from its alerts, with
diminishing returns for the same rule firing repeatedly, so an incident
built from six different detections outranks one rule firing six times.

Generic entities are deliberately excluded from linking: the corporate
egress address, the jump host and the monitoring server appear in so many
alerts that joining on them would collapse everything into one blob.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import asdict, dataclass, field

from .model import Alert, parse_ts

LINK_WINDOW_S = 24 * 3600
LINK_FIELDS = ("user.name", "host.name", "source.ip", "destination.ip")
REPEAT_DECAY = 0.5          # second firing of the same rule counts half, third a quarter
SEVERITY_FLOOR = {"critical": 90, "high": 60, "medium": 35, "low": 15}


@dataclass
class Incident:
    incident_id: str
    severity: str
    risk: int
    first_seen: str
    last_seen: str
    entities: dict[str, list[str]]
    alert_ids: list[str]
    rules: list[str]
    tactics: list[str]
    techniques: list[str]
    title: str = ""
    evidence_count: int = 0
    alerts: list[dict] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("alerts")
        return d


class _DSU:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def _severity(risk: int) -> str:
    for name, floor in SEVERITY_FLOOR.items():
        if risk >= floor:
            return name
    return "informational"


def _title(inc: Incident) -> str:
    who = inc.entities.get("user.name") or inc.entities.get("host.name") or \
        inc.entities.get("source.ip") or ["unknown"]
    return f"{len(inc.rules)} detection(s) on {', '.join(who[:2])}" + \
        (f" and {len(who) - 2} more" if len(who) > 2 else "")


def build_incidents(alerts: list[Alert], world) -> list[Incident]:
    users = {u.name: u for u in world.users}
    generic = {world.office_egress, *(h.ip for h in world.hosts if h.name in ("jump01", "mon01"))}
    generic |= {"jump01", "mon01"}

    keys: list[list[tuple[str, str]]] = []
    for a in alerts:
        ks = []
        for f in LINK_FIELDS:
            v = a.entities.get(f)
            if v and v not in generic:
                ks.append((f, v))
        u = a.entities.get("user.name")
        if u in users and users[u].workstation not in generic:
            ks.append(("host.name", users[u].workstation))
        h = a.entities.get("host.name")
        if h and h not in generic:
            owner = next((u.name for u in world.users if u.workstation == h and u.kind == "human"), None)
            if owner:
                ks.append(("user.name", owner))
        keys.append(ks)

    order = sorted(range(len(alerts)), key=lambda i: parse_ts(alerts[i].first_seen))
    dsu = _DSU(len(alerts))
    last_seen_at: dict[tuple[str, str], tuple[float, int]] = {}
    for i in order:
        t = parse_ts(alerts[i].first_seen)
        for k in keys[i]:
            prev = last_seen_at.get(k)
            if prev and t - prev[0] <= LINK_WINDOW_S:
                dsu.union(prev[1], i)
            last_seen_at[k] = (t, i)

    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(alerts)):
        groups[dsu.find(i)].append(i)

    incidents: list[Incident] = []
    for members in groups.values():
        ms = sorted(members, key=lambda i: parse_ts(alerts[i].first_seen))
        seen_rule: dict[str, int] = defaultdict(int)
        risk = 0.0
        ents: dict[str, set[str]] = defaultdict(set)
        tactics: set[str] = set()
        techs: set[str] = set()
        evidence = 0
        for i in ms:
            a = alerts[i]
            risk += a.risk * (REPEAT_DECAY ** seen_rule[a.rule_id])
            seen_rule[a.rule_id] += 1
            for f, v in a.entities.items():
                ents[f].add(v)
            tactics.update(a.tactics)
            techs.update(a.techniques)
            evidence += len(a.evidence)
        risk_i = min(100, int(round(risk)))
        iid = "inc-" + hashlib.sha1(",".join(alerts[i].alert_id for i in ms).encode()).hexdigest()[:10]
        inc = Incident(iid, _severity(risk_i), risk_i, alerts[ms[0]].first_seen,
                       max(alerts[i].last_seen for i in ms),
                       {f: sorted(v) for f, v in ents.items()},
                       [alerts[i].alert_id for i in ms], sorted({alerts[i].rule_id for i in ms}),
                       sorted(tactics), sorted(techs), evidence_count=evidence,
                       alerts=[alerts[i].to_dict() for i in ms])
        inc.title = _title(inc)
        incidents.append(inc)
    incidents.sort(key=lambda x: (-x.risk, x.first_seen))
    return incidents
