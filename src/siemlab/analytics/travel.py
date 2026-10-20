"""Impossible travel between consecutive successful sign-ins.

The textbook version (distance / time > airliner speed) drowns a SOC in
mobile-carrier false positives: a phone's public address geolocates to the
carrier's gateway, often a thousand kilometres from the phone. The rule
here ignores a mobile-address hop that stays inside one country, or is
shorter than ``MOBILE_TOLERANCE_KM``, and still fires on international
jumps, where a carrier gateway cannot explain the gap. That keeps the
documented false positive (a traveller abroad whose phone still homes to
its carrier at home) and drops the daily one (every remote worker's phone).
"""
from __future__ import annotations

import math
from collections import defaultdict

from ..model import Match
from .base import Analytic, AnalyticMeta

MAX_SPEED_KMH = 900.0        # faster than this between two sign-ins is impossible
MIN_DISTANCE_KM = 300.0      # closer than this is GeoIP noise, never travel
MOBILE_TOLERANCE_KM = 1500.0  # a mobile gateway can sit this far from the phone
MAX_GAP_HOURS = 12.0         # beyond this, the speed is low anyway


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


class ImpossibleTravel(Analytic):
    meta = AnalyticMeta(
        id="a1f3c2e4-5b6d-4e7f-8a9b-0c1d2e3f4a5b", name="impossible_travel",
        title="Impossible travel between sign-ins", level="high",
        description="Two successful sign-ins for one identity from places too far apart "
                    "for the time between them, after discounting mobile-carrier geolocation.",
        tags=["attack.initial_access", "attack.t1078.004"],
        falsepositives=["A roaming phone whose carrier gateway is on another continent",
                        "Corporate VPN exits in several countries"])

    def __init__(self, world) -> None:
        super().__init__(world)
        self.last: dict[str, tuple[float, dict]] = {}
        self.fired: dict[str, float] = defaultdict(lambda: -1e12)
        self.out: list[Match] = []

    def observe(self, ev: dict, ts: float) -> None:
        if ev.get("event.dataset") != "identity.signin" or ev.get("event.outcome") != "success":
            return
        if "source.geo.lat" not in ev:
            return
        user = ev["user.name"]
        prev = self.last.get(user)
        self.last[user] = (ts, ev)
        if prev is None:
            return
        pts, pev = prev
        if pev["source.ip"] == ev["source.ip"]:
            return
        hours = (ts - pts) / 3600.0
        if hours <= 0 or hours > MAX_GAP_HOURS:
            return
        km = haversine_km(pev["source.geo.lat"], pev["source.geo.lon"],
                          ev["source.geo.lat"], ev["source.geo.lon"])
        if km < MIN_DISTANCE_KM or km / hours < MAX_SPEED_KMH:
            return
        mobile = "mobile" in (pev.get("source.asn.type"), ev.get("source.asn.type"))
        same_country = pev.get("source.geo.country") == ev.get("source.geo.country")
        if mobile and (same_country or km < MOBILE_TOLERANCE_KM):
            return
        if ts - self.fired[user] < 6 * 3600:        # one alert per user per six hours
            return
        self.fired[user] = ts
        self.out.append(self.match(pts, ts, (pev["event.id"], ev["event.id"]), {
            "user.name": user, "source.ip": ev["source.ip"],
            "distance_km": round(km), "hours": round(hours, 2),
            "from": pev.get("source.geo.city"), "to": ev.get("source.geo.city")}))

    def finish(self) -> list[Match]:
        return self.out
