"""Shared data model: timestamps, rule matches, and alerts."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

LEVEL_RISK = {"informational": 5, "low": 15, "medium": 35, "high": 60, "critical": 85}


def parse_ts(text: str) -> float:
    """ISO-8601 -> epoch seconds. Accepts a trailing Z on Python 3.10."""
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def fmt_ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Match:
    """One firing of a rule: a single event, or a correlation window."""
    rule_id: str
    first_ts: float
    ts: float
    evidence: tuple[str, ...]
    group: dict[str, Any] = field(default_factory=dict)
    event: dict | None = field(default=None, repr=False)


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    title: str
    level: str
    risk: int
    source: str                       # sigma | sigma-correlation | analytic
    tactics: list[str]
    techniques: list[str]
    first_seen: str
    last_seen: str
    entities: dict[str, str]
    evidence: list[str]
    summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> Alert:
        return Alert(**d)
