"""Common shape for a behavioural analytic.

An analytic is fed enriched events one at a time (``observe``) and is
asked for its findings at the end (``finish``). Keeping the streaming
interface, even where an analytic only needs a batch, means every analytic
could be moved behind a real event pipeline without changing its logic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..model import Match


@dataclass
class AnalyticMeta:
    id: str
    name: str
    title: str
    level: str
    description: str
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)


class Analytic(ABC):
    meta: AnalyticMeta

    def __init__(self, world) -> None:
        self.world = world

    @abstractmethod
    def observe(self, ev: dict, ts: float) -> None: ...

    @abstractmethod
    def finish(self) -> list[Match]: ...

    def match(self, first_ts: float, ts: float, evidence, group: dict) -> Match:
        return Match(self.meta.id, first_ts, ts, tuple(evidence), group)
