"""Outbound volume to a single new destination.

Sums bytes sent from each host to each external, non-allowlisted address
over a sliding day. Crossing the threshold once per pair raises a finding.
Approved SaaS destinations (backup targets, file sharing) are excluded by
the allowlist rather than by a bigger threshold, because the right fix for
"the backup job fired this" is to record the backup provider, not to raise
the bar for everyone.
"""
from __future__ import annotations

from collections import defaultdict, deque

from ..model import Match
from .base import Analytic, AnalyticMeta

WINDOW_S = 24 * 3600
THRESHOLD_BYTES = 500 * 1024 * 1024


class ExfilVolume(Analytic):
    meta = AnalyticMeta(
        id="d4a6f5b7-8e90-4ba2-9cde-3f4a5b6c7d8e", name="exfil_volume",
        title="Large outbound transfer to a new destination", level="high",
        description="More than 500 MB sent from one host to one external, non-allowlisted "
                    "address within a day.",
        tags=["attack.exfiltration", "attack.t1048"],
        falsepositives=["A new backup or file-sharing provider not yet on the allowlist"])

    def __init__(self, world) -> None:
        super().__init__(world)
        self.win: dict[tuple[str, str], deque] = defaultdict(deque)
        self.total: dict[tuple[str, str], int] = defaultdict(int)
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
        w = self.win[key]
        b = int(ev.get("source.bytes", 0))
        w.append((ts, ev["event.id"], b))
        self.total[key] += b
        while w and ts - w[0][0] > WINDOW_S:
            _, _, old = w.popleft()
            self.total[key] -= old
        if self.total[key] >= THRESHOLD_BYTES:
            self.fired.add(key)
            self.out.append(self.match(w[0][0], ts, (e for _, e, _ in w), {
                "host.name": key[0], "destination.ip": key[1],
                "bytes_out": self.total[key], "connections": len(w)}))

    def finish(self) -> list[Match]:
        return self.out
