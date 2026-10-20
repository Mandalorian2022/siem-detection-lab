"""Benign background activity for a five-day working week.

The baseline is deliberately not "clean": people mistype passwords, phones
sign in through mobile carriers that geolocate to another state, a
monitoring server polls everything on a fixed schedule, endpoints check in
with SaaS services periodically, CDNs serve random-looking hostnames, and a
backup job moves a lot of data at night. A detection that cannot live with
this traffic would not survive a real SOC.
"""
from __future__ import annotations

import random
import string
from datetime import datetime, timezone

from . import events as E
from .world import World

WEEK_START = datetime(2026, 3, 2, tzinfo=timezone.utc).timestamp()   # a Monday
DAY = 86400.0
DAYS = 5

COMMON_DOMAINS = [
    "mail.saas.example", "docs.saas.example", "chat.saas.example", "files.saas.example",
    "calendar.saas.example", "login.saas.example", "www.news-daily.example",
    "search.example", "maps.example", "weather.example", "intranet.corp.example",
    "hr.corp.example", "wiki.corp.example", "git.corp.example", "tickets.corp.example",
    "fonts.cdn.example", "static.cdn.example", "video.streaming.example",
    "shop.retail.example", "bank.finance.example",
]


def local_to_utc(world: World, day: int, local_hour: float) -> float:
    return WEEK_START + day * DAY + (local_hour - world.utc_offset_hours) * 3600


def _host_ip(world: World, name: str) -> str:
    return next(h.ip for h in world.hosts if h.name == name)


def _cdn_name(rng: random.Random) -> str:
    label = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(12))
    return f"{label}.cdn.example"


def generate_baseline(world: World, rng: random.Random) -> list[dict]:
    out: list[dict] = []
    pool = world.external_pool
    saas, cdn = pool["saas"], pool["cdn"]
    servers = [h.name for h in world.hosts if h.role == "server"]

    for day in range(DAYS):
        for u in world.users:
            if u.kind == "service":
                continue
            start = rng.gauss(8.3, 0.6)
            end = max(start + 6, rng.gauss(17.2, 0.7))
            ws = u.workstation
            ws_ip = _host_ip(world, ws)
            egress = u.home_ip if u.remote else world.office_egress
            t0 = local_to_utc(world, day, start)
            t1 = local_to_utc(world, day, end)

            # cloud sign-ins: one interactive with MFA, then token refreshes
            if rng.random() < 0.22:          # a typo or two, then success
                for k in range(rng.randint(1, 3)):
                    out.append(E.signin(t0 + 8 * k, u.name, egress, ok=False, mfa="none",
                                        auth="singleFactor"))
            out.append(E.signin(t0 + 40, u.name, egress, ok=True))
            for _ in range(rng.randint(2, 5)):
                out.append(E.signin(rng.uniform(t0, t1), u.name, egress, ok=True,
                                    app=rng.choice(["Outlook", "Portal", "Files"]),
                                    mfa="none", auth="singleFactor"))
            if rng.random() < 0.18:          # phone on a mobile carrier
                out.append(E.signin(rng.uniform(t0, t1), u.name, u.mobile_ip, ok=True,
                                    app="Outlook", mfa="none", auth="singleFactor"))

            # Windows logons: interactive at the desk, network logons to file/mail servers
            if u.kind == "human":
                out.append(E.logon(t0 + 5, ws, u.name, ws_ip, ok=True, logon_type=2))
                for _ in range(rng.randint(5, 14)):
                    srv = rng.choice(["fs01", "mail01", "app01"])
                    out.append(E.logon(rng.uniform(t0, t1), srv, u.name, ws_ip, ok=True))
                if rng.random() < 0.08:
                    out.append(E.logon(rng.uniform(t0, t1), "fs01", u.name, ws_ip, ok=False))
            else:                             # admins work from the jump host
                jump_ip = _host_ip(world, "jump01")
                out.append(E.logon(t0 + 5, "jump01", u.name, world.office_egress, ok=True,
                                   logon_type=10))
                for _ in range(rng.randint(4, 10)):
                    out.append(E.logon(rng.uniform(t0, t1), rng.choice(servers), u.name,
                                       jump_ip, ok=True, logon_type=rng.choice([3, 10])))

            # DNS and the connections that follow it
            src_host, src_ip = (ws, ws_ip) if u.kind == "human" else ("jump01", _host_ip(world, "jump01"))
            for _ in range(rng.randint(70, 150)):
                t = rng.uniform(t0, t1)
                q = _cdn_name(rng) if rng.random() < 0.15 else rng.choice(COMMON_DOMAINS)
                out.append(E.dns(t, src_host, src_ip, q))
                if not q.endswith("corp.example"):
                    dst = rng.choice(cdn if "cdn" in q else saas)
                    out.append(E.conn(t + 0.2, src_host, src_ip, dst,
                                      bytes_out=int(rng.lognormvariate(8.5, 1.0)),
                                      bytes_in=int(rng.lognormvariate(11, 1.3)),
                                      duration=rng.uniform(0.2, 30)))
            if rng.random() < 0.05:           # a legitimate large upload to the file SaaS
                out.append(E.conn(rng.uniform(t0, t1), src_host, src_ip, rng.choice(saas[:30]),
                                  bytes_out=rng.randint(200_000_000, 900_000_000),
                                  bytes_in=200_000, duration=rng.uniform(200, 900)))

        # endpoints check in with the (allowlisted) management SaaS every 15 minutes
        for h in world.hosts:
            if h.role != "workstation":
                continue
            t = WEEK_START + day * DAY + rng.uniform(0, 900)
            while t < WEEK_START + (day + 1) * DAY:
                out.append(E.conn(t, h.name, h.ip, saas[5], bytes_out=900, bytes_in=1400,
                                  duration=0.3))
                t += 900 + rng.uniform(-5, 5)

        # monitoring server polls every server once a minute (internal, very regular)
        mon_ip = _host_ip(world, "mon01")
        for minute in range(0, 1440, 1):
            t = WEEK_START + day * DAY + minute * 60
            for srv in ("dc01", "fs01", "app01", "db01", "mail01", "web01"):
                if rng.random() < 0.15:       # keep volume sane: sample the polling
                    out.append(E.conn(t + rng.uniform(0, 0.5), "mon01", mon_ip,
                                      _host_ip(world, srv), port=5666, bytes_out=300,
                                      bytes_in=600, duration=0.05))

        # service accounts: scanner mails over legacy auth, backup runs at night
        for _ in range(rng.randint(3, 8)):
            out.append(E.signin(local_to_utc(world, day, rng.uniform(8, 17)), "svc-scanner",
                                world.office_egress, ok=True, app="IMAP", mfa="none",
                                auth="singleFactor"))
        tb = local_to_utc(world, day, 1.0 + rng.uniform(0, 0.2))
        out.append(E.logon(tb, "fs01", "svc-backup", _host_ip(world, "app01"), ok=True,
                           logon_type=5))
        out.append(E.conn(tb + 60, "fs01", _host_ip(world, "fs01"), saas[40],
                          bytes_out=rng.randint(3_000_000_000, 5_000_000_000),
                          bytes_in=5_000_000, duration=2400))
    return out
