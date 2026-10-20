"""Beacon detection on connection periodicity, evaluated as a stream.

For each (host, external destination) pair that is not allowlisted, the
analytic keeps the gaps between the most recent connections. Once it has a
full window it tests whether the gaps look like a timer:

* the coefficient of variation (std / mean) is low for a timer and high
  for a person, and
* the share of gaps within 15 % of the median is high; this is robust to
  the odd missed callback that would otherwise inflate the variance.

Both must agree. Testing a sliding window rather than the whole history
matters: an implant that beacons for hours and then starts pushing data
out changes its own traffic pattern, and a whole-series statistic would
let the exfiltration hide the beacon that preceded it. The window fires as
soon as the pattern is established, which is also the earliest useful
moment to tell an analyst.
"""
from __future__ import annotations

import statistics
from collections import defaultdict, deque

from ..model import Match
from .base import Analytic, AnalyticMeta

WINDOW = 24                 # connections per test window
MAX_CV = 0.20
MIN_REGULAR_SHARE = 0.80
REGULAR_TOLERANCE = 0.15
MIN_PERIOD_S = 20.0
MAX_PERIOD_S = 3600.0


def is_periodic(gaps: list[float]) -> tuple[bool, dict]:
    mean = statistics.fmean(gaps)
    if not MIN_PERIOD_S <= mean <= MAX_PERIOD_S:
        return False, {}
    cv = statistics.pstdev(gaps) / mean
    med = statistics.median(gaps)
    regular = sum(1 for g in gaps if abs(g - med) <= REGULAR_TOLERANCE * med) / len(gaps)
    ok = cv <= MAX_CV and regular >= MIN_REGULAR_SHARE
    return ok, {"period_s": round(med), "cv": round(cv, 3), "regular_share": round(regular, 2)}


class Beaconing(Analytic):
    meta = AnalyticMeta(
        id="b2e4d3f5-6c7e-4f80-9bac-1d2e3f4a5b6c", name="beaconing",
        title="Periodic connections to an external host", level="high",
        description="A host connects to one external, non-allowlisted address on a near-fixed "
                    "interval, established over a window of two dozen connections.",
        tags=["attack.command_and_control", "attack.t1071.001"],
        falsepositives=["Vendor licence or update checks on a strict schedule",
                        "Monitoring agents reporting to a SaaS not yet allowlisted"])

    def __init__(self, world) -> None:
        super().__init__(world)
        self.recent: dict[tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=WINDOW))
        self.fired: set[tuple[str, str]] = set()
        self.out: list[Match] = []

    def observe(self, ev: dict, ts: float) -> None:
        if ev.get("event.dataset") != "network.connection":
            return
        if ev.get("destination.is_internal") or ev.get("destination.allowlisted"):
            return
        key = (ev["host.name"], ev["destination.ip"])
        if key in self.fired:
            return
        w = self.recent[key]
        w.append((ts, ev["event.id"], int(ev.get("source.bytes", 0))))
        if len(w) < WINDOW:
            return
        gaps = [b[0] - a[0] for a, b in zip(w, list(w)[1:], strict=False)]
        if min(gaps) <= 0:
            return
        ok, stats = is_periodic(gaps)
        if not ok:
            return
        self.fired.add(key)
        self.out.append(self.match(w[0][0], ts, (r[1] for r in w), {
            "host.name": key[0], "destination.ip": key[1], "connections": len(w), **stats,
            "median_bytes_out": int(statistics.median(r[2] for r in w))}))

    def finish(self) -> list[Match]:
        return self.out
