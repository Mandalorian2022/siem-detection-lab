"""Synthetic GeoIP enrichment table shared by the generator and the rules.

In production this is what a GeoIP provider returns for a source address.
Here it is a fixed, invented table so the lab is fully self-contained and
reproducible. The "near cluster" sits around one metro area; the three
"far" sources sit on other continents to exercise impossible-travel.
"""
from __future__ import annotations

# A metro-area base point; near sources jitter slightly around it and stay
# well under any travel threshold relative to one another.
_NEAR_BASE = (36.17, -115.14)
NEAR_IPS = [f"198.51.100.{n}" for n in range(10, 30)]

GEO: dict[str, tuple[float, float]] = {}
for _i, _ip in enumerate(NEAR_IPS):
    GEO[_ip] = (_NEAR_BASE[0] + (_i % 5) * 0.03,
                _NEAR_BASE[1] - (_i % 7) * 0.03)

# Far sources used by attack scenarios (other continents).
FAR = {
    "203.0.113.5": (40.71, -74.01),   # region B
    "203.0.113.9": (51.51, -0.13),    # region C
    "192.0.2.7":   (35.68, 139.69),   # region D
}
GEO.update(FAR)
