"""The simulated organisation: identities, hosts, IP geography, threat intel.

``World`` is what an identity provider, a CMDB, a GeoIP database and a
threat-intel feed would give a SOC. Detection may use it as enrichment
context. It never contains ground truth about which activity is malicious.

All addresses are from RFC 1918 (internal) and RFC 5737 documentation
ranges (external), so nothing here refers to a real network.
"""
from __future__ import annotations

import ipaddress
import random
from dataclasses import asdict, dataclass, field

FIRST = ["ana", "ben", "carla", "dev", "eli", "fatima", "gus", "hana", "ivan", "jade",
         "kofi", "lena", "marco", "nina", "omar", "priya", "quinn", "rosa", "sam", "tara",
         "uma", "victor", "wen", "xena", "yusuf", "zoe", "alma", "bruno", "chen", "dina",
         "emil", "farah", "gabe", "hugo", "iris", "jonah", "kira", "leo", "maya", "noah"]
LAST = ["ortiz", "kim", "nguyen", "patel", "smith", "garcia", "khan", "lopez", "chen",
        "silva", "reyes", "tanaka", "brown", "ali", "rossi", "novak", "haddad", "park",
        "costa", "meyer"]
DEPTS = ["finance", "engineering", "sales", "hr", "operations", "research"]

# city -> (lat, lon, country, offset into 198.51.100.0/24 in /28 blocks)
CITIES: dict[str, tuple[float, float, str]] = {
    "Las Vegas": (36.17, -115.14, "US"), "Phoenix": (33.45, -112.07, "US"),
    "Denver": (39.74, -104.99, "US"), "Seattle": (47.61, -122.33, "US"),
    "Austin": (30.27, -97.74, "US"), "Chicago": (41.88, -87.63, "US"),
    "New York": (40.71, -74.01, "US"), "Toronto": (43.65, -79.38, "CA"),
    "London": (51.51, -0.13, "GB"), "Frankfurt": (50.11, 8.68, "DE"),
    "Amsterdam": (52.37, 4.90, "NL"), "Singapore": (1.35, 103.82, "SG"),
    "Sydney": (-33.87, 151.21, "AU"), "Sao Paulo": (-23.55, -46.63, "BR"),
    "Lagos": (6.52, 3.38, "NG"), "Tokyo": (35.68, 139.69, "JP"),
}
OFFICE_CITY = "Las Vegas"
UTC_OFFSET_HOURS = -8     # the organisation's local time for business-hours logic


@dataclass
class User:
    name: str
    department: str
    privileged: bool
    home_city: str
    remote: bool
    workstation: str
    home_ip: str
    mobile_ip: str
    known_countries: list[str]
    kind: str = "human"          # human | admin | service


@dataclass
class Host:
    name: str
    ip: str
    role: str                    # workstation | server


@dataclass
class World:
    seed: int
    users: list[User]
    hosts: list[Host]
    geo: dict[str, dict]                     # ip -> {city, country, lat, lon, asn_type}
    intel: dict[str, dict]                   # indicator -> {type, category}
    allowlists: dict[str, list[str]]
    change_windows: list[dict]               # {user, host, start, end} approved changes
    office_egress: str
    utc_offset_hours: int = UTC_OFFSET_HOURS
    external_pool: dict[str, list[str]] = field(default_factory=dict)

    def user(self, name: str) -> User:
        return next(u for u in self.users if u.name == name)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @staticmethod
    def from_dict(d: dict) -> World:
        d = dict(d)
        d["users"] = [User(**u) for u in d["users"]]
        d["hosts"] = [Host(**h) for h in d["hosts"]]
        return World(**d)


def _block(net: str, index: int, size: int = 16) -> list[str]:
    base = ipaddress.ip_network(net)
    start = int(base.network_address) + index * size
    return [str(ipaddress.ip_address(start + i)) for i in range(1, size - 1)]


def build_world(seed: int, n_users: int = 36) -> World:
    rng = random.Random(seed)
    geo: dict[str, dict] = {}
    pool: dict[str, list[str]] = {}

    # 198.51.100.0/24: residential / office / mobile addresses, one /28 per city
    for i, (city, (lat, lon, cc)) in enumerate(CITIES.items()):
        ips = _block("198.51.100.0/24", i)
        pool[city] = ips
        for j, ip in enumerate(ips):
            asn = "mobile" if j >= 10 else "isp"
            geo[ip] = {"city": city, "country": cc, "lat": lat, "lon": lon, "asn_type": asn}
    office_egress = pool[OFFICE_CITY][0]
    geo[office_egress]["asn_type"] = "corporate"

    # 203.0.113.0/24: hosting providers; parts are listed in threat intel
    hosting_cities = ["Frankfurt", "Amsterdam", "Singapore", "Lagos", "Sao Paulo", "Tokyo",
                      "London", "Toronto"]
    for i, city in enumerate(hosting_cities):
        lat, lon, cc = CITIES[city]
        for ip in _block("203.0.113.0/24", i, 32):
            geo[ip] = {"city": city, "country": cc, "lat": lat, "lon": lon, "asn_type": "hosting"}
    pool["hosting"] = [ip for ip, g in geo.items() if g["asn_type"] == "hosting"]

    # 192.0.2.0/24: SaaS and CDN services the company uses (allowlisted)
    saas = [f"192.0.2.{i}" for i in range(10, 60)]
    for ip in saas:
        geo[ip] = {"city": "Seattle", "country": "US", "lat": 47.61, "lon": -122.33,
                   "asn_type": "hosting"}
    pool["saas"] = saas
    pool["cdn"] = [f"192.0.2.{i}" for i in range(100, 140)]
    for ip in pool["cdn"]:
        geo[ip] = {"city": "Los Angeles", "country": "US", "lat": 34.05, "lon": -118.24,
                   "asn_type": "hosting"}

    hosting = pool["hosting"]
    rng.shuffle(hosting)
    intel: dict[str, dict] = {}
    for ip in hosting[:10]:
        intel[ip] = {"type": "ip", "category": "anonymizer"}
    for ip in hosting[10:16]:
        intel[ip] = {"type": "ip", "category": "c2"}
    for d in ("update-check.bad.example", "cdn-sync.bad.example", "telemetry.bad.example"):
        intel[d] = {"type": "domain", "category": "c2"}
    pool["unlisted_hosting"] = hosting[16:]

    users: list[User] = []
    names = rng.sample([f"{f}.{ln}" for f in FIRST for ln in LAST], n_users)
    remote_cities = ["Denver", "Seattle", "Austin", "Phoenix", "Chicago"]
    for i, nm in enumerate(names):
        remote = rng.random() < 0.3
        city = rng.choice(remote_cities) if remote else OFFICE_CITY
        users.append(User(
            name=nm, department=rng.choice(DEPTS), privileged=False, home_city=city,
            remote=remote, workstation=f"ws-{i + 1:03d}",
            home_ip=pool[city][1 + i % 9], mobile_ip=pool["Phoenix"][10 + i % 4],
            known_countries=["US"]))
    for nm in ("adm-ortiz", "adm-kim", "adm-patel", "adm-reyes"):
        users.append(User(nm, "it", True, OFFICE_CITY, False, "jump01",
                          pool[OFFICE_CITY][2], pool["Phoenix"][12], ["US"], "admin"))
    for nm in ("svc-backup", "svc-scanner", "svc-monitor"):
        users.append(User(nm, "it", nm == "svc-backup", OFFICE_CITY, False, "app01",
                          office_egress, office_egress, ["US"], "service"))

    hosts = [Host(u.workstation, f"10.10.1.{i + 10}", "workstation")
             for i, u in enumerate(users) if u.kind == "human"]
    for j, nm in enumerate(("dc01", "fs01", "app01", "db01", "jump01", "mon01", "mail01", "web01")):
        hosts.append(Host(nm, f"10.10.10.{j + 10}", "server"))

    allowlists = {
        "saas_destinations": ["192.0.2.0/26"],
        "dns_suffixes": ["corp.example", "av-lookup.example", "cdn.example", "saas.example"],
        "beacon_destinations": ["192.0.2.0/26"],
        "service_accounts_legacy_auth": ["svc-scanner"],
        "vpn_egress": [office_egress],
    }
    return World(seed=seed, users=users, hosts=hosts, geo=geo, intel=intel,
                 allowlists=allowlists, change_windows=[], office_egress=office_egress,
                 external_pool=pool)
