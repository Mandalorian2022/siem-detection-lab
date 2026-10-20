"""Labeled scenarios: adversary behaviour and benign look-alikes.

Every scenario is expressed purely as identity and network telemetry
(sign-ins, logons, DNS, flows). Each one records the ATT&CK techniques it
represents and which detections a well-tuned SOC would expect to fire. The
benign scenarios are the hard part of the exercise: activity that looks
suspicious but is authorised, which is where real false positives come from.

``known_gap`` marks a scenario the rule set is *not* expected to catch,
documented rather than hidden.
"""
from __future__ import annotations

import random
import string
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from . import events as E
from .baseline import local_to_utc
from .world import World


@dataclass
class Scenario:
    id: str
    name: str
    malicious: bool
    techniques: list[str]
    expected: list[str]
    description: str
    entities: dict[str, str] = field(default_factory=dict)
    known_gap: bool = False
    campaign: str | None = None
    stage: int | None = None
    start: float = 0.0
    end: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


Gen = Callable[[World, random.Random], tuple[Scenario, list[dict]]]
REGISTRY: list[Gen] = []


def scenario(fn: Gen) -> Gen:
    REGISTRY.append(fn)
    return fn


def _humans(world: World) -> list:
    return [u for u in world.users if u.kind == "human"]


def _ip(world: World, host: str) -> str:
    return next(h.ip for h in world.hosts if h.name == host)


def _when(world: World, rng: random.Random, lo: float = 9.0, hi: float = 16.0,
          day: int | None = None) -> float:
    d = rng.randint(0, 4) if day is None else day
    return local_to_utc(world, d, rng.uniform(lo, hi))


def _finish(s: Scenario, evs: list[dict]) -> tuple[Scenario, list[dict]]:
    for e in evs:
        e["_scn"] = s.id
    s.start = min(e["_ts"] for e in evs)
    s.end = max(e["_ts"] for e in evs)
    return s, evs


def _random_label(rng: random.Random, n: int, alphabet: str = string.ascii_lowercase) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


# --- adversary behaviour -------------------------------------------------------

@scenario
def password_spray(world, rng):
    ip = rng.choice(world.external_pool["unlisted_hosting"])
    targets = rng.sample(_humans(world), rng.randint(14, 22))
    t = _when(world, rng)
    evs = [E.signin(t + i * rng.uniform(20, 80), u.name, ip, ok=False, mfa="none",
                    auth="singleFactor") for i, u in enumerate(targets)]
    return _finish(Scenario("A01", "password spray from one address", True, ["T1110.003"],
                            ["signin_password_spray"],
                            "One hosting-provider address tries one password against many accounts.",
                            {"source.ip": ip}), evs)


@scenario
def brute_force_then_success(world, rng):
    u = rng.choice(_humans(world))
    ip = rng.choice(world.external_pool["unlisted_hosting"])
    t = _when(world, rng)
    n = rng.randint(14, 30)
    evs = [E.signin(t + i * rng.uniform(6, 14), u.name, ip, ok=False, mfa="none",
                    auth="singleFactor") for i in range(n)]
    tl = evs[-1]["_ts"] + rng.uniform(30, 200)
    evs.append(E.signin(tl, u.name, ip, ok=True, mfa="none", auth="singleFactor"))
    return _finish(Scenario("A02", "brute force then successful sign-in", True,
                            ["T1110.001", "T1078.004"],
                            ["signin_bruteforce_account", "signin_bruteforce_then_success"],
                            "Rapid guessing against one account, ending in a valid sign-in.",
                            {"user.name": u.name, "source.ip": ip}), evs)


@scenario
def slow_distributed_bruteforce(world, rng):
    u = rng.choice(_humans(world))
    ips = rng.sample(world.external_pool["unlisted_hosting"], 14)
    t = _when(world, rng, 6, 10)
    evs = []
    for i in range(rng.randint(28, 36)):
        evs.append(E.signin(t + i * rng.uniform(300, 520), u.name, rng.choice(ips), ok=False,
                            mfa="none", auth="singleFactor"))
    return _finish(Scenario("A03", "slow brute force from rotating addresses", True,
                            ["T1110.001"], ["signin_slow_bruteforce"],
                            "One account, guessed slowly from many addresses to stay under per-IP limits.",
                            {"user.name": u.name}), evs)


@scenario
def distributed_low_rate_spray(world, rng):
    ips = rng.sample(world.external_pool["unlisted_hosting"], 30)
    users = _humans(world)
    t = _when(world, rng, 0, 20)
    evs = []
    for ip in ips:
        for u in rng.sample(users, rng.randint(2, 3)):
            evs.append(E.signin(t + rng.uniform(0, 3 * 3600), u.name, ip, ok=False,
                                mfa="none", auth="singleFactor"))
    return _finish(Scenario("A04", "distributed low-rate spray", True, ["T1110.003"], [],
                            "Thirty addresses, two or three accounts each, spread over three hours. "
                            "No per-address or per-account threshold is crossed; catching it needs "
                            "a tenant-wide failure-rate baseline, which this rule set does not have.",
                            {}, known_gap=True), evs)


@scenario
def mfa_fatigue(world, rng):
    u = rng.choice(_humans(world))
    ip = rng.choice(world.external_pool["unlisted_hosting"])
    t = _when(world, rng, 18, 22)
    evs = []
    n = rng.randint(6, 11)
    for i in range(n):
        evs.append(E.signin(t + i * rng.uniform(40, 90), u.name, ip, ok=False,
                            mfa=rng.choice(["denied", "timeout"]), auth="multiFactor",
                            result=E.RESULT_MFA_DENIED))
    evs.append(E.signin(evs[-1]["_ts"] + rng.uniform(30, 120), u.name, ip, ok=True))
    return _finish(Scenario("A05", "MFA fatigue then approval", True, ["T1621", "T1078.004"],
                            ["signin_mfa_fatigue", "signin_mfa_fatigue_then_success"],
                            "Repeated push prompts with a valid password until the user approves one.",
                            {"user.name": u.name, "source.ip": ip}), evs)


@scenario
def impossible_travel(world, rng):
    u = rng.choice([x for x in _humans(world) if not x.remote])
    far = rng.choice(["Singapore", "Lagos", "Sao Paulo", "Tokyo", "Sydney"])
    ip = rng.choice(world.external_pool[far][:9])
    t = _when(world, rng, 10, 14)
    evs = [E.signin(t, u.name, world.office_egress, ok=True, app="Outlook", mfa="none",
                    auth="singleFactor"),
           E.signin(t + rng.uniform(900, 2400), u.name, ip, ok=True, app="Files")]
    return _finish(Scenario("A06", "session from another continent", True, ["T1078.004"],
                            ["impossible_travel"],
                            f"A sign-in from {far} minutes after one from the office.",
                            {"user.name": u.name, "source.ip": ip}), evs)


@scenario
def anonymizer_signin(world, rng):
    u = rng.choice(_humans(world))
    ip = rng.choice([i for i, v in world.intel.items() if v["category"] == "anonymizer"])
    t = _when(world, rng, 0, 23)
    evs = [E.signin(t, u.name, ip, ok=True, app="Files")]
    return _finish(Scenario("A07", "sign-in through an anonymising proxy", True,
                            ["T1090.003", "T1078.004"], ["signin_anonymizer_success"],
                            "A valid sign-in from an address threat intel lists as an anonymiser.",
                            {"user.name": u.name, "source.ip": ip}), evs)


@scenario
def privileged_new_country(world, rng):
    u = rng.choice([x for x in world.users if x.kind == "admin"])
    city = rng.choice(["Frankfurt", "Amsterdam", "London"])
    ip = rng.choice(world.external_pool[city][:9])
    t = _when(world, rng, 1, 5)
    evs = [E.signin(t, u.name, ip, ok=True, app="Portal")]
    return _finish(Scenario("A08", "admin sign-in from a new country", True, ["T1078.004"],
                            ["signin_privileged_new_country"],
                            "A privileged identity signs in from a country it has never used.",
                            {"user.name": u.name, "source.ip": ip}), evs)


@scenario
def offhours_privileged_logon(world, rng):
    u = rng.choice([x for x in world.users if x.kind == "admin"])
    t = _when(world, rng, 2.0, 4.5)
    evs = [E.logon(t, "dc01", u.name, _ip(world, "ws-007"), ok=True, logon_type=10)]
    return _finish(Scenario("A09", "privileged logon at 3 a.m. without a change", True,
                            ["T1078.002"], ["win_privileged_logon_offhours"],
                            "An admin account logs on interactively to a domain controller at night, "
                            "from a workstation, with no approved change.",
                            {"user.name": u.name, "host.name": "dc01"}), evs)


@scenario
def internal_logon_spray(world, rng):
    src = rng.choice(_humans(world))
    src_ip = _ip(world, src.workstation)
    servers = [h.name for h in world.hosts if h.role == "server"]
    t = _when(world, rng)
    evs = [E.logon(t + i * rng.uniform(10, 40), srv, rng.choice(["adm-ortiz", "adm-kim"]),
                   src_ip, ok=False) for i, srv in enumerate(rng.sample(servers, 7))]
    return _finish(Scenario("A10", "failed logons across many servers from one workstation",
                            True, ["T1110.003", "T1021"], ["win_failed_logons_many_hosts"],
                            "A workstation tries admin credentials against seven servers in minutes.",
                            {"source.ip": src_ip, "host.name": src.workstation}), evs)


@scenario
def rdp_from_internet(world, rng):
    ip = rng.choice(world.external_pool["unlisted_hosting"])
    t = _when(world, rng, 0, 23)
    evs = [E.logon(t, "web01", "adm-patel", ip, ok=True, logon_type=10)]
    return _finish(Scenario("A11", "remote desktop logon from the internet", True,
                            ["T1133", "T1021.001"], ["win_rdp_from_external"],
                            "An interactive remote logon to a server straight from a public address.",
                            {"host.name": "web01", "source.ip": ip}), evs)


def _beacon(world, rng, host, dst, t, hours, period, jitter, scn):
    evs = []
    ip = _ip(world, host)
    end = t + hours * 3600
    while t < end:
        evs.append(E.conn(t, host, ip, dst, bytes_out=rng.randint(300, 700),
                          bytes_in=rng.randint(200, 1500), duration=0.4, scn=scn))
        t += period * (1 + rng.uniform(-jitter, jitter))
    return evs


@scenario
def c2_beaconing(world, rng):
    h = rng.choice(_humans(world)).workstation
    dst = rng.choice(world.external_pool["unlisted_hosting"])
    evs = _beacon(world, rng, h, dst, _when(world, rng, 9, 12), rng.uniform(3, 5),
                  rng.choice([60, 90, 120]), 0.08, "A12")
    return _finish(Scenario("A12", "periodic callbacks to an unknown host", True,
                            ["T1071.001"], ["beaconing"],
                            "A workstation connects to one external address on a near-fixed interval.",
                            {"host.name": h, "destination.ip": dst}), evs)


@scenario
def dga_burst(world, rng):
    h = rng.choice(_humans(world)).workstation
    t = _when(world, rng)
    tlds = ["example", "test", "invalid"]
    evs = [E.dns(t + i * rng.uniform(5, 25), h, _ip(world, h),
                 f"{_random_label(rng, rng.randint(12, 20), string.ascii_lowercase + string.digits)}"
                 f".{rng.choice(tlds)}", rcode="NXDOMAIN") for i in range(rng.randint(35, 60))]
    return _finish(Scenario("A13", "burst of algorithmically generated domains", True,
                            ["T1568.002"], ["dga_burst"],
                            "Dozens of random-looking domains, nearly all non-existent, in minutes.",
                            {"host.name": h}), evs)


@scenario
def dns_tunnel_like(world, rng):
    h = rng.choice(_humans(world)).workstation
    t = _when(world, rng)
    evs = [E.dns(t + i * rng.uniform(1, 6), h, _ip(world, h),
                 f"{_random_label(rng, 48, '0123456789abcdef')}.{_random_label(rng, 6)}.data-relay.example",
                 qtype="TXT") for i in range(rng.randint(120, 220))]
    return _finish(Scenario("A14", "high-volume long-label TXT queries", True, ["T1071.004"],
                            ["dns_long_label_query"],
                            "Many TXT lookups with long hex labels under one domain.",
                            {"host.name": h}), evs)


@scenario
def large_upload(world, rng):
    u = rng.choice(_humans(world))
    h = u.workstation
    dst = rng.choice(world.external_pool["unlisted_hosting"])
    t = _when(world, rng, 12, 19)
    total = rng.randint(1_200_000_000, 2_500_000_000)
    chunks = rng.randint(8, 15)
    evs = [E.conn(t + i * rng.uniform(120, 260), h, _ip(world, h), dst,
                  bytes_out=total // chunks, bytes_in=40_000, duration=rng.uniform(60, 200))
           for i in range(chunks)]
    return _finish(Scenario("A15", "gigabytes uploaded to a new destination", True, ["T1048"],
                            ["exfil_volume"],
                            "A workstation that normally uploads kilobytes sends gigabytes to one host.",
                            {"host.name": h, "destination.ip": dst}), evs)


@scenario
def intel_destination(world, rng):
    h = rng.choice(_humans(world)).workstation
    ip = rng.choice([i for i, v in world.intel.items() if v["category"] == "c2"])
    dom = rng.choice([d for d, v in world.intel.items() if v["type"] == "domain"])
    t = _when(world, rng)
    evs = [E.dns(t, h, _ip(world, h), dom),
           E.conn(t + 0.5, h, _ip(world, h), ip, bytes_out=1200, bytes_in=5000)]
    return _finish(Scenario("A16", "contact with a known-bad domain and address", True,
                            ["T1071"], ["dns_query_intel_domain", "net_conn_intel_destination"],
                            "A lookup of a listed domain followed by a connection to a listed address.",
                            {"host.name": h}), evs)


# --- benign look-alikes ---------------------------------------------------------

@scenario
def typo_burst(world, rng):
    u = rng.choice(_humans(world))
    t = _when(world, rng, 8, 9.5)
    evs = [E.signin(t + i * 9, u.name, u.home_ip if u.remote else world.office_egress,
                    ok=False, mfa="none", auth="singleFactor") for i in range(5)]
    evs.append(E.signin(t + 70, u.name, evs[0]["source.ip"], ok=True))
    return _finish(Scenario("B01", "five typos then success", False, [], [],
                            "A user fights caps lock. Nothing should fire.",
                            {"user.name": u.name}), evs)


@scenario
def mobile_carrier_geo(world, rng):
    u = rng.choice([x for x in _humans(world) if not x.remote])
    t = _when(world, rng)
    evs = [E.signin(t, u.name, world.office_egress, ok=True, app="Portal", mfa="none",
                    auth="singleFactor"),
           E.signin(t + rng.uniform(300, 900), u.name, u.mobile_ip, ok=True, app="Outlook",
                    mfa="none", auth="singleFactor")]
    return _finish(Scenario("B02", "phone geolocates to the next state", False, [], [],
                            "Office sign-in, then the user's phone via a carrier that geolocates "
                            "to Phoenix. Mobile carrier addresses are handled by the travel analytic.",
                            {"user.name": u.name}), evs)


@scenario
def approved_change(world, rng):
    u = rng.choice([x for x in world.users if x.kind == "admin"])
    day = rng.randint(0, 3)
    t = local_to_utc(world, day, rng.uniform(22.5, 23.5))
    world.change_windows.append({"user": u.name, "host": "db01", "start": t - 1800,
                                 "end": t + 7200, "ticket": f"CHG{rng.randint(10000, 99999)}"})
    evs = [E.logon(t, "db01", u.name, _ip(world, "jump01"), ok=True, logon_type=10)]
    return _finish(Scenario("B03", "night maintenance under an approved change", False, [], [],
                            "An admin works at night inside an approved change window.",
                            {"user.name": u.name, "host.name": "db01"}), evs)


@scenario
def emergency_fix(world, rng):
    u = rng.choice([x for x in world.users if x.kind == "admin"])
    t = _when(world, rng, 1.5, 3.0)
    evs = [E.logon(t, "app01", u.name, _ip(world, "jump01"), ok=True, logon_type=10)]
    return _finish(Scenario("B04", "emergency fix without a ticket", False, [],
                            ["win_privileged_logon_offhours"],
                            "An on-call admin fixes an outage at 2 a.m. and files the change later. "
                            "The alert is correct to fire: a benign true positive.",
                            {"user.name": u.name, "host.name": "app01"}), evs)


@scenario
def stale_credential_script(world, rng):
    t = _when(world, rng, 9, 11)
    servers = [h.name for h in world.hosts if h.role == "server"]
    evs = [E.logon(t + i * rng.uniform(5, 30), srv, "adm-reyes", _ip(world, "jump01"), ok=False)
           for i, srv in enumerate(rng.sample(servers, 7))]
    return _finish(Scenario("B05", "inventory script with an expired password", False, [],
                            ["win_failed_logons_many_hosts"],
                            "A scheduled inventory script on the jump host still has the old "
                            "admin password and fails on every server.",
                            {"user.name": "adm-reyes", "host.name": "jump01"}), evs)


@scenario
def new_backup_provider(world, rng):
    day = rng.randint(2, 4)
    t = local_to_utc(world, day, 1.3)
    dst = rng.choice(world.external_pool["unlisted_hosting"])
    evs = [E.conn(t + i * 600, "fs01", _ip(world, "fs01"), dst, bytes_out=900_000_000,
                  bytes_in=2_000_000, duration=580) for i in range(4)]
    return _finish(Scenario("B06", "first night on a new backup provider", False, [],
                            ["exfil_volume"],
                            "Backups move to a provider that is not on the allowlist yet.",
                            {"host.name": "fs01", "destination.ip": dst}), evs)


@scenario
def vendor_license_check(world, rng):
    dst = rng.choice(world.external_pool["unlisted_hosting"])
    evs = _beacon(world, rng, "app01", dst, local_to_utc(world, 0, 0.5), 96, 300, 0.003, "B07")
    return _finish(Scenario("B07", "vendor licence check every five minutes", False, [],
                            ["beaconing"],
                            "An application server phones its vendor on a strict schedule. "
                            "Indistinguishable from a beacon until the destination is allowlisted.",
                            {"host.name": "app01", "destination.ip": dst}), evs)


@scenario
def antivirus_dns(world, rng):
    hosts = rng.sample(_humans(world), 10)
    evs = []
    for u in hosts:
        t = _when(world, rng)
        for i in range(rng.randint(5, 15)):
            evs.append(E.dns(t + i * rng.uniform(2, 60), u.workstation, _ip(world, u.workstation),
                             f"{_random_label(rng, 48, '0123456789abcdef')}.av-lookup.example",
                             qtype="TXT"))
    return _finish(Scenario("B08", "antivirus reputation lookups over DNS", False, [], [],
                            "The endpoint agent checks file hashes with long TXT lookups. "
                            "Its domain is allowlisted in the tunnel rule.",
                            {}), evs)


@scenario
def roaming_traveller(world, rng):
    u = rng.choice([x for x in _humans(world) if x.department == "sales"] or _humans(world))
    t = _when(world, rng, 3, 7)
    london = rng.choice(world.external_pool["London"][:9])
    evs = [E.signin(t, u.name, london, ok=True, app="Portal"),
           E.signin(t + rng.uniform(600, 1800), u.name, u.mobile_ip, ok=True, app="Outlook",
                    mfa="none", auth="singleFactor")]
    return _finish(Scenario("B09", "traveller in London, phone still homes to Phoenix", False,
                            [], ["impossible_travel"],
                            "Laptop signs in from a London hotel; the roaming phone's carrier "
                            "address still geolocates to Phoenix. A classic travel false positive.",
                            {"user.name": u.name}), evs)


# --- multi-stage campaign ------------------------------------------------------

def campaign_account_takeover(world: World, rng: random.Random) -> list[tuple[Scenario, list[dict]]]:
    """Spray, MFA fatigue, attacker session, then endpoint callbacks and exfiltration.

    Stages share one victim identity and that identity's workstation, so an
    incident engine that links identities to their assets can rebuild the
    whole chain from alerts raised by unrelated rules.
    """
    victim = rng.choice([u for u in _humans(world) if not u.remote])
    ws, ws_ip = victim.workstation, _ip(world, victim.workstation)
    spray_ip = rng.choice(world.external_pool["unlisted_hosting"])
    att_ip = rng.choice(world.external_pool["Frankfurt"][:9])
    c2 = rng.choice(world.external_pool["unlisted_hosting"])
    day = rng.randint(1, 3)
    t = local_to_utc(world, day, rng.uniform(6.5, 7.5))
    out = []

    def stage(n, name, techs, expected, desc, evs, ents):
        s = Scenario(f"C01.{n}", name, True, techs, expected, desc, ents,
                     campaign="C01", stage=n)
        out.append(_finish(s, evs))

    others = rng.sample([u for u in _humans(world) if u.name != victim.name], 11)
    spray = [E.signin(t + i * rng.uniform(30, 70), u.name, spray_ip, ok=False, mfa="none",
                      auth="singleFactor") for i, u in enumerate(others + [victim])]
    stage(1, "spray that includes the victim", ["T1110.003"], ["signin_password_spray"],
          "The spray finds the victim's password (the attempt fails only at MFA later).",
          spray, {"source.ip": spray_ip})

    t2 = spray[-1]["_ts"] + rng.uniform(1800, 3600)
    fat = [E.signin(t2 + i * rng.uniform(40, 80), victim.name, att_ip, ok=False,
                    mfa=rng.choice(["denied", "timeout"]), result=E.RESULT_MFA_DENIED)
           for i in range(rng.randint(6, 9))]
    fat.append(E.signin(fat[-1]["_ts"] + rng.uniform(40, 100), victim.name, att_ip, ok=True))
    stage(2, "MFA fatigue until approval", ["T1621", "T1078.004"],
          ["signin_mfa_fatigue", "signin_mfa_fatigue_then_success"],
          "Push prompts from Frankfurt until the victim taps approve.", fat,
          {"user.name": victim.name, "source.ip": att_ip})

    t3 = local_to_utc(world, day, rng.uniform(9.0, 9.5))
    sess = [E.signin(t3, victim.name, world.office_egress, ok=True, app="Outlook", mfa="none",
                     auth="singleFactor"),
            E.signin(t3 + rng.uniform(600, 1500), victim.name, att_ip, ok=True, app="Files",
                     mfa="none", auth="singleFactor")]
    stage(3, "attacker session alongside the real user", ["T1078.004"], ["impossible_travel"],
          "The victim at the office and the attacker in Frankfurt use the account together.",
          sess, {"user.name": victim.name})

    t4 = sess[-1]["_ts"] + rng.uniform(1200, 2400)
    beac = _beacon(world, rng, ws, c2, t4, 3.0, 120, 0.1, None)
    stage(4, "workstation starts calling back", ["T1071.001"], ["beaconing"],
          "The victim's workstation begins periodic callbacks to a hosting address.",
          beac, {"host.name": ws, "destination.ip": c2})

    t5 = t4 + rng.uniform(1800, 3600)
    dom = rng.choice([d for d, v in world.intel.items() if v["type"] == "domain"])
    lookup = [E.dns(t5, ws, ws_ip, dom)]
    stage(5, "lookup of a listed domain", ["T1071"], ["dns_query_intel_domain"],
          "The workstation resolves a domain threat intel already knows.", lookup,
          {"host.name": ws})

    t6 = t4 + 3 * 3600 - rng.uniform(1800, 2400)
    exf = [E.conn(t6 + i * rng.uniform(100, 200), ws, ws_ip, c2, bytes_out=160_000_000,
                  bytes_in=30_000, duration=150) for i in range(rng.randint(8, 12))]
    stage(6, "staged data leaves over the callback channel", ["T1048"], ["exfil_volume"],
          "Over a gigabyte goes out to the callback address.", exf,
          {"host.name": ws, "destination.ip": c2})
    return out


def generate_scenarios(world: World, rng: random.Random) -> list[tuple[Scenario, list[dict]]]:
    out = [gen(world, rng) for gen in REGISTRY]
    out.extend(campaign_account_takeover(world, rng))
    return out
