"""Behavioural analytics: detections that need state across many events,
which a per-event Sigma rule cannot express."""
from .base import Analytic
from .beaconing import Beaconing
from .dga import DgaBurst
from .exfil import ExfilVolume
from .travel import ImpossibleTravel

ANALYTICS: list[type[Analytic]] = [ImpossibleTravel, Beaconing, DgaBurst, ExfilVolume]

__all__ = ["Analytic", "ANALYTICS", "ImpossibleTravel", "Beaconing", "DgaBurst", "ExfilVolume"]
