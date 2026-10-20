import random

from hypothesis import given, settings
from hypothesis import strategies as st

from siemlab.analytics.beaconing import Beaconing, is_periodic
from siemlab.analytics.dga import DgaBurst, randomness
from siemlab.analytics.exfil import ExfilVolume
from siemlab.analytics.travel import ImpossibleTravel, haversine_km


def conn(i, ts, host="ws-001", dst="203.0.113.9", bytes_out=500, allow=False, internal=False):
    return {"event.id": f"c{i}", "event.dataset": "network.connection", "host.name": host,
            "destination.ip": dst, "source.bytes": bytes_out, "destination.allowlisted": allow,
            "destination.is_internal": internal}


def signin(i, ts, user, ip, city, lat, lon, country="US", asn="isp"):
    return {"event.id": f"s{i}", "event.dataset": "identity.signin", "event.outcome": "success",
            "user.name": user, "source.ip": ip, "source.geo.city": city, "source.geo.lat": lat,
            "source.geo.lon": lon, "source.geo.country": country, "source.asn.type": asn}


def test_haversine_known_distance():
    assert abs(haversine_km(36.17, -115.14, 51.51, -0.13) - 8400) < 150   # Las Vegas -> London


def test_travel_fires_on_intercontinental_jump(world):
    a = ImpossibleTravel(world)
    a.observe(signin(1, 0, "ana", "1.1.1.1", "Las Vegas", 36.17, -115.14), 0)
    a.observe(signin(2, 1800, "ana", "2.2.2.2", "Singapore", 1.35, 103.82, "SG"), 1800)
    assert len(a.finish()) == 1


def test_travel_ignores_domestic_mobile_hop(world):
    a = ImpossibleTravel(world)
    a.observe(signin(1, 0, "ana", "1.1.1.1", "Seattle", 47.61, -122.33), 0)
    a.observe(signin(2, 600, "ana", "2.2.2.2", "Phoenix", 33.45, -112.07, asn="mobile"), 600)
    assert a.finish() == []


def test_travel_still_fires_for_mobile_abroad(world):
    a = ImpossibleTravel(world)
    a.observe(signin(1, 0, "ana", "1.1.1.1", "London", 51.51, -0.13, "GB"), 0)
    a.observe(signin(2, 900, "ana", "2.2.2.2", "Phoenix", 33.45, -112.07, asn="mobile"), 900)
    assert len(a.finish()) == 1


def test_beacon_detects_jittered_timer(world, rng):
    b = Beaconing(world)
    t = 0.0
    for i in range(40):
        b.observe(conn(i, t), t)
        t += 60 * (1 + rng.uniform(-0.1, 0.1))
    out = b.finish()
    assert len(out) == 1
    assert 50 <= out[0].group["period_s"] <= 70


def test_beacon_ignores_bursty_traffic(world, rng):
    b = Beaconing(world)
    t = 0.0
    for i in range(80):
        b.observe(conn(i, t), t)
        t += rng.expovariate(1 / 60)
    assert b.finish() == []


def test_beacon_ignores_allowlisted_and_internal(world):
    b = Beaconing(world)
    for i in range(40):
        b.observe(conn(i, i * 60.0, allow=True), i * 60.0)
        b.observe(conn(100 + i, i * 60.0, dst="10.10.10.12", internal=True), i * 60.0)
    assert b.finish() == []


def test_beacon_survives_later_exfil(world, rng):
    """A whole-series statistic would miss this; the sliding window must not."""
    b = Beaconing(world)
    t = 0.0
    for i in range(60):
        b.observe(conn(i, t), t)
        t += 120 * (1 + rng.uniform(-0.08, 0.08))
    for i in range(60, 80):
        b.observe(conn(i, t, bytes_out=150_000_000), t)
        t += rng.uniform(30, 300)
    assert len(b.finish()) == 1


@given(st.lists(st.floats(min_value=57, max_value=63), min_size=23, max_size=23))
@settings(max_examples=50)
def test_is_periodic_accepts_tight_jitter(gaps):
    """Any gap sequence within ±5 % of a 60 s timer is periodic, whatever its shape."""
    ok, _ = is_periodic(gaps)
    assert ok


@given(st.lists(st.floats(min_value=20, max_value=3600), min_size=23, max_size=23))
@settings(max_examples=50)
def test_is_periodic_rejects_wide_spread(gaps):
    if max(gaps) > 1.6 * min(gaps):
        ok, _ = is_periodic(gaps)
        if ok:
            # a wide spread can only pass if most gaps still cluster at the median
            med = sorted(gaps)[len(gaps) // 2]
            assert sum(abs(g - med) <= 0.15 * med for g in gaps) / len(gaps) >= 0.8


def test_randomness_scores():
    assert randomness("accounting") < 0.5
    assert randomness("k3j9x0qpa2mzv7") > 0.6
    assert randomness("ab") == 0.0


def test_dga_burst_needs_nxdomain_and_volume(world):
    d = DgaBurst(world)
    r = random.Random(1)

    def q(i, rcode):
        label = "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(14))
        return {"event.id": f"d{i}", "event.dataset": "network.dns", "host.name": "ws-001",
                "dns.question.name": f"{label}.example", "dns.response_code": rcode,
                "dns.question.allowlisted": False}
    for i in range(40):
        d.observe(q(i, "NOERROR"), i * 10.0)          # CDN-like: resolves
    assert d.finish() == []
    d = DgaBurst(world)
    for i in range(40):
        d.observe(q(i, "NXDOMAIN"), i * 10.0)
    assert len(d.finish()) == 1


def test_exfil_sums_over_a_day_and_fires_once(world):
    e = ExfilVolume(world)
    for i in range(12):
        e.observe(conn(i, i * 600.0, bytes_out=100 * 1024 * 1024), i * 600.0)
    out = e.finish()
    assert len(out) == 1
    assert out[0].group["bytes_out"] >= 500 * 1024 * 1024


def test_exfil_window_slides(world):
    e = ExfilVolume(world)
    e.observe(conn(0, 0.0, bytes_out=400 * 1024 * 1024), 0.0)
    e.observe(conn(1, 2 * 86400.0, bytes_out=400 * 1024 * 1024), 2 * 86400.0)
    assert e.finish() == []
