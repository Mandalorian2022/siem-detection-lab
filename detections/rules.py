"""Detection rules for the SIEM Detection Lab.

Each rule consumes normalized events and yields Alert objects keyed the
same way the ground-truth labels are, so evaluation is a set comparison.
Rules are intentionally simple and explainable: thresholds and windows
are named constants, not magic numbers buried in logic.

Geo enrichment mirrors what a GeoIP lookup would provide in production.
It is enrichment, not ground truth: the rules never read the labels file.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# --- enrichment: synthetic GeoIP table shared with the generator -----------
from geoip import GEO  # noqa: E402

# --- thresholds (documented, tunable) --------------------------------------
BRUTE_FORCE_FAILS = 8          # failures from one user+src within the window
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
SPRAY_MIN_USERS = 4            # distinct users targeted from one source
SPRAY_WINDOW = timedelta(minutes=15)
TRAVEL_MIN_KM = 1000.0        # min distance to consider "impossible"
TRAVEL_MAX_HOURS = 1.0        # within this time between the two logins
BUSINESS_START, BUSINESS_END = 7, 19  # UTC hours considered on-hours


@dataclass(frozen=True)
class Alert:
    rule: str
    key: tuple
    detail: str = ""
    evidence: tuple = field(default=())

    def key_dict(self) -> dict:
        return dict(self.key)


def _parse(ev: dict) -> datetime:
    return datetime.fromisoformat(ev["timestamp"])


def _haversine_km(a: tuple, b: tuple) -> float:
    r = 6371.0
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


def _normalize(events: list[dict]) -> list[dict]:
    """Bound, de-duplicate, and UTC-order the input defensively."""
    seen, out = set(), []
    for ev in events:
        eid = ev.get("event_id")
        if eid in seen:
            continue
        seen.add(eid)
        out.append(ev)
    out.sort(key=lambda e: e["timestamp"])
    return out


def brute_force(events: list[dict]) -> list[Alert]:
    buckets: dict[tuple, list[dict]] = {}
    for ev in events:
        if ev["outcome"] != "failure":
            continue
        buckets.setdefault((ev["user"], ev["src_ip"]), []).append(ev)
    alerts = []
    for (user, src), evs in buckets.items():
        evs.sort(key=lambda e: e["timestamp"])
        i = 0
        for j in range(len(evs)):
            while _parse(evs[j]) - _parse(evs[i]) > BRUTE_FORCE_WINDOW:
                i += 1
            if j - i + 1 >= BRUTE_FORCE_FAILS:
                alerts.append(Alert(
                    "brute_force", (("user", user), ("src_ip", src)),
                    f"{j - i + 1} failures within window",
                    tuple(e["event_id"] for e in evs[i:j + 1])))
                break
    return alerts


def password_spray(events: list[dict]) -> list[Alert]:
    by_src: dict[str, list[dict]] = {}
    for ev in events:
        if ev["outcome"] != "failure":
            continue
        by_src.setdefault(ev["src_ip"], []).append(ev)
    alerts = []
    for src, evs in by_src.items():
        evs.sort(key=lambda e: e["timestamp"])
        i = 0
        for j in range(len(evs)):
            while _parse(evs[j]) - _parse(evs[i]) > SPRAY_WINDOW:
                i += 1
            users = {e["user"] for e in evs[i:j + 1]}
            if len(users) >= SPRAY_MIN_USERS:
                alerts.append(Alert(
                    "password_spray", (("src_ip", src),),
                    f"{len(users)} distinct users targeted",
                    tuple(e["event_id"] for e in evs[i:j + 1])))
                break
    return alerts


def impossible_travel(events: list[dict]) -> list[Alert]:
    by_user: dict[str, list[dict]] = {}
    for ev in events:
        if ev["outcome"] != "success" or ev["src_ip"] not in GEO:
            continue
        by_user.setdefault(ev["user"], []).append(ev)
    alerts, seen = [], set()
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e["timestamp"])
        for p, q in zip(evs, evs[1:]):
            if p["src_ip"] == q["src_ip"]:
                continue
            dt = (_parse(q) - _parse(p)).total_seconds() / 3600.0
            if dt > TRAVEL_MAX_HOURS:
                continue
            dist = _haversine_km(GEO[p["src_ip"]], GEO[q["src_ip"]])
            if dist >= TRAVEL_MIN_KM and user not in seen:
                seen.add(user)
                alerts.append(Alert(
                    "impossible_travel", (("user", user),),
                    f"{dist:.0f} km in {dt:.2f} h",
                    (p["event_id"], q["event_id"])))
    return alerts


def off_hours_admin(events: list[dict]) -> list[Alert]:
    alerts, seen = [], set()
    for ev in events:
        if not ev.get("privileged") or ev["outcome"] != "success":
            continue
        hour = _parse(ev).hour
        if BUSINESS_START <= hour < BUSINESS_END:
            continue
        key = (("user", ev["user"]), ("host", ev["host"]), ("hour", hour))
        if key in seen:
            continue
        seen.add(key)
        alerts.append(Alert("off_hours_admin", key,
                            "privileged login outside business hours",
                            (ev["event_id"],)))
    return alerts


RULES = [brute_force, password_spray, impossible_travel, off_hours_admin]


def run_all(events: list[dict]) -> list[Alert]:
    events = _normalize(events)
    alerts: list[Alert] = []
    for rule in RULES:
        alerts.extend(rule(events))
    return alerts
