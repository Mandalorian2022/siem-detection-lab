"""Domain-generation-algorithm bursts.

Malware that derives its rendezvous domains from a seed resolves many
names that do not exist before it finds one that does. The signal is a
burst of NXDOMAIN answers for names that look random. Randomness is
scored per label: Shannon entropy, digit share, and the longest run of
consonants, which together separate ``k3j9x0qpa2mz`` from ``accounting``.
CDN hostnames are random-looking too, which is why NXDOMAIN is required:
CDN names resolve.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict, deque

from ..model import Match
from .base import Analytic, AnalyticMeta

WINDOW_S = 15 * 60
MIN_RANDOM_NX = 25
RANDOM_SCORE = 0.6
VOWELS = set("aeiouy")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def longest_consonant_run(s: str) -> int:
    best = run = 0
    for ch in s:
        run = run + 1 if ch.isalpha() and ch not in VOWELS else 0
        best = max(best, run)
    return best


def randomness(label: str) -> float:
    """0 (dictionary-like) to 1 (random). Short labels are never random."""
    if len(label) < 8:
        return 0.0
    ent = min(entropy(label) / 4.0, 1.0)                 # 4 bits ~ 16 symbols uniform
    digits = sum(ch.isdigit() for ch in label) / len(label)
    cons = min(longest_consonant_run(label) / 5.0, 1.0)
    return round(0.5 * ent + 0.25 * min(digits * 3, 1.0) + 0.25 * cons, 3)


class DgaBurst(Analytic):
    meta = AnalyticMeta(
        id="c3f5e4a6-7d8f-4a91-8bcd-2e3f4a5b6c7d", name="dga_burst",
        title="Burst of random-looking non-existent domains", level="high",
        description="Many NXDOMAIN answers for random-looking names from one host in fifteen minutes.",
        tags=["attack.command_and_control", "attack.t1568.002"],
        falsepositives=["Browser pre-fetching of typo domains", "Misconfigured search suffixes"])

    def __init__(self, world) -> None:
        super().__init__(world)
        self.win: dict[str, deque] = defaultdict(deque)
        self.fired: dict[str, float] = {}
        self.out: list[Match] = []

    def observe(self, ev: dict, ts: float) -> None:
        if ev.get("event.dataset") != "network.dns" or ev.get("dns.response_code") != "NXDOMAIN":
            return
        if ev.get("dns.question.allowlisted"):
            return
        label = ev["dns.question.name"].split(".")[0]
        score = randomness(label)
        if score < RANDOM_SCORE:
            return
        host = ev["host.name"]
        w = self.win[host]
        w.append((ts, ev["event.id"]))
        while w and ts - w[0][0] > WINDOW_S:
            w.popleft()
        if len(w) >= MIN_RANDOM_NX and ts - self.fired.get(host, -1e12) > WINDOW_S:
            self.fired[host] = ts
            self.out.append(self.match(w[0][0], ts, (e for _, e in w),
                                       {"host.name": host, "nxdomains": len(w)}))

    def finish(self) -> list[Match]:
        return self.out
