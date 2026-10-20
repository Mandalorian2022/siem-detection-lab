"""Enrichment: add the context a SOC would join onto raw telemetry.

Rules stay simple and portable when the context they need is already on
the event: the organisation's local hour, whether the identity is
privileged, where an address geolocates, whether threat intel lists it,
whether a destination is an approved SaaS service, and whether a
privileged logon falls inside an approved change window.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone

from .model import parse_ts
from .simulate.world import World

_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _PRIVATE)


class Enricher:
    def __init__(self, world: World):
        self.world = world
        self.users = {u.name: u for u in world.users}
        self.tz = timezone(timedelta(hours=world.utc_offset_hours))
        self.saas = [ipaddress.ip_network(n) for n in world.allowlists["saas_destinations"]]
        self.suffixes = tuple(world.allowlists["dns_suffixes"])
        self.legacy_ok = set(world.allowlists["service_accounts_legacy_auth"])
        self.changes = world.change_windows

    def _allowlisted(self, ip: str | None) -> bool:
        if not ip or is_internal(ip):
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.saas)

    def _in_change(self, user: str, host: str, ts: float) -> bool:
        return any(c["user"] == user and c["host"] == host and c["start"] <= ts <= c["end"]
                   for c in self.changes)

    def enrich(self, ev: dict) -> dict:
        e = dict(ev)
        ts = parse_ts(e["@timestamp"])
        local = datetime.fromtimestamp(ts, tz=self.tz)
        e["time.local_hour"] = local.hour
        e["time.local_weekday"] = local.strftime("%a")

        u = self.users.get(e.get("user.name", ""))
        if u is not None:
            e["user.privileged"] = u.privileged
            e["user.kind"] = u.kind
            e["user.department"] = u.department
            e["user.workstation"] = u.workstation
            e["user.legacy_auth_allowed"] = u.name in self.legacy_ok

        for side in ("source", "destination"):
            ip = e.get(f"{side}.ip")
            if not ip:
                continue
            e[f"{side}.is_internal"] = is_internal(ip)
            g = self.world.geo.get(ip)
            if g:
                e[f"{side}.geo.city"] = g["city"]
                e[f"{side}.geo.country"] = g["country"]
                e[f"{side}.geo.lat"] = g["lat"]
                e[f"{side}.geo.lon"] = g["lon"]
                e[f"{side}.asn.type"] = g["asn_type"]
            ti = self.world.intel.get(ip)
            e[f"{side}.ti.category"] = ti["category"] if ti else None
        if "destination.ip" in e:
            e["destination.allowlisted"] = self._allowlisted(e["destination.ip"])

        if e.get("event.dataset") == "identity.signin" and u is not None:
            country = e.get("source.geo.country")
            e["source.geo.known_for_user"] = country in u.known_countries if country else None

        q = e.get("dns.question.name")
        if q:
            ti = self.world.intel.get(q)
            e["dns.question.ti_category"] = ti["category"] if ti else None
            e["dns.question.allowlisted"] = q.endswith(self.suffixes)

        if e.get("event.dataset") == "windows.security" and u is not None and u.privileged:
            e["change.approved"] = self._in_change(u.name, e.get("host.name", ""), ts)
        return e

    def stream(self, events: Iterable[dict]) -> Iterator[dict]:
        for ev in events:
            yield self.enrich(ev)
