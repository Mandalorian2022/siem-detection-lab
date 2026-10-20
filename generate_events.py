#!/usr/bin/env python3
"""Synthetic authentication-event generator for the SIEM Detection Lab.

Produces authentication events for a small fleet of generic hosts and
users, mixes in benign "near-miss" activity, and injects labeled attack
scenarios. A real intrusion often trips more than one detection, so each
scenario is labeled with every rule it is expected to fire, which lets the
evaluator score multi-signal detections honestly.

Ground-truth labels are written to a SEPARATE file and never appear in the
detection input. Everything here is synthetic: no real hosts, users,
addresses, or logs.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import random

from geoip import NEAR_IPS

HOSTS = [f"host{i:02d}" for i in range(1, 13)]
STD_USERS = [
    "alice", "bob", "carol", "dave", "erin", "frank",
    "grace", "heidi", "ivan", "judy", "mallory", "trent",
]
ADMIN_USERS = ["root", "svc-backup", "netadmin"]
ALL_USERS = STD_USERS + ADMIN_USERS

# one stable home source per user (unique, all in the near cluster) so the
# baseline never trips impossible-travel or shared-source spray
HOME_IP = {u: NEAR_IPS[i] for i, u in enumerate(ALL_USERS)}

NY, LONDON, TOKYO = "203.0.113.5", "203.0.113.9", "192.0.2.7"
BUSINESS_START, BUSINESS_END = 7, 19  # UTC hours treated as on-hours


@dataclass
class Event:
    event_id: str
    timestamp: str
    host: str
    user: str
    src_ip: str
    outcome: str
    method: str
    privileged: bool


class Gen:
    def __init__(self, seed: int, start: datetime):
        self.r = random.Random(seed)
        self.t = start
        self.n = 0
        self.events: list[Event] = []
        self.attacks: list[dict] = []
        self.benign_anomalies: list[dict] = []

    def _id(self) -> str:
        self.n += 1
        return f"e{self.n:06d}"

    def _emit(self, *, host, user, src_ip, outcome, method, privileged,
              when) -> Event:
        ev = Event(self._id(), when.astimezone(timezone.utc).isoformat(),
                   host, user, src_ip, outcome, method, privileged)
        self.events.append(ev)
        return ev

    def _label(self, type_, key, event_ids):
        self.attacks.append({"type": type_, "key": key,
                            "event_ids": event_ids})

    # -- rule-safe baseline -------------------------------------------------
    def background(self, count: int):
        for _ in range(count):
            self.t += timedelta(seconds=self.r.randint(5, 240))
            user = self.r.choice(ALL_USERS)
            priv = user in ADMIN_USERS
            on_hours = BUSINESS_START <= self.t.hour < BUSINESS_END
            if priv and not on_hours:
                continue  # admins only act on-hours in the baseline
            outcome = "success" if self.r.random() > 0.05 else "failure"
            self._emit(host=self.r.choice(HOSTS), user=user,
                       src_ip=HOME_IP[user], outcome=outcome,
                       method="pubkey" if self.r.random() > 0.3 else "password",
                       privileged=priv, when=self.t)

    # -- labeled attack scenarios -------------------------------------------
    def brute_force(self, user, src_ip, *, fails=12, with_travel=False,
                    off_hours=False, host="host03"):
        priv = user in ADMIN_USERS
        if off_hours:
            self.t += timedelta(hours=self.r.randint(5, 10))
            self.t = self.t.replace(hour=23, minute=self.r.randint(0, 20))
        else:
            self.t += timedelta(minutes=self.r.randint(3, 20))

        ids = []
        if with_travel:
            # a normal login from home shortly before the attacker's success,
            # which makes the attacker's success an impossible-travel event
            self.t += timedelta(minutes=self.r.randint(10, 20))
            prior = self._emit(host=host, user=user, src_ip=HOME_IP[user],
                               outcome="success", method="pubkey",
                               privileged=priv, when=self.t)
            ids.append(prior.event_id)

        base = self.t + timedelta(minutes=self.r.randint(2, 6))
        burst = []
        for _ in range(fails):
            base += timedelta(seconds=self.r.randint(2, 9))
            burst.append(self._emit(host=host, user=user, src_ip=src_ip,
                                    outcome="failure", method="password",
                                    privileged=priv, when=base).event_id)
        base += timedelta(seconds=5)
        success = self._emit(host=host, user=user, src_ip=src_ip,
                            outcome="success", method="password",
                            privileged=priv, when=base)
        self.t = base
        self._label("brute_force", {"user": user, "src_ip": src_ip},
                    burst + [success.event_id])
        if with_travel:
            self._label("impossible_travel", {"user": user},
                        [ids[0], success.event_id])
        if off_hours and priv:
            self._label("off_hours_admin",
                       {"user": user, "host": host,
                        "hour": base.astimezone(timezone.utc).hour},
                        [success.event_id])

    def password_spray(self, src_ip, users, per=3):
        self.t += timedelta(minutes=self.r.randint(3, 20))
        ids, base = [], self.t
        for u in users:
            for _ in range(per):
                base += timedelta(seconds=self.r.randint(10, 40))
                ids.append(self._emit(host="host07", user=u, src_ip=src_ip,
                                      outcome="failure", method="password",
                                      privileged=u in ADMIN_USERS,
                                      when=base).event_id)
        self.t = base
        self._label("password_spray", {"src_ip": src_ip}, ids)

    def impossible_travel(self, user, ip_home, ip_far):
        self.t += timedelta(minutes=self.r.randint(3, 20))
        a = self._emit(host="host01", user=user, src_ip=ip_home,
                       outcome="success", method="pubkey",
                       privileged=user in ADMIN_USERS, when=self.t)
        self.t += timedelta(minutes=self.r.randint(8, 25))
        b = self._emit(host="host05", user=user, src_ip=ip_far,
                       outcome="success", method="pubkey",
                       privileged=user in ADMIN_USERS, when=self.t)
        self._label("impossible_travel", {"user": user},
                    [a.event_id, b.event_id])

    def off_hours_admin(self, user, host="host02"):
        self.t += timedelta(hours=self.r.randint(5, 10))
        self.t = self.t.replace(hour=self.r.choice([1, 2, 3, 23]))
        ev = self._emit(host=host, user=user, src_ip=HOME_IP[user],
                        outcome="success", method="password",
                        privileged=True, when=self.t)
        self._label("off_hours_admin",
                   {"user": user, "host": host,
                    "hour": self.t.astimezone(timezone.utc).hour},
                    [ev.event_id])

    # -- benign near-misses (labeled benign, measure false positives) -------
    def fat_finger(self, user):
        self.t += timedelta(minutes=self.r.randint(3, 20))
        base = self.t
        for _ in range(self.r.randint(3, 4)):
            base += timedelta(seconds=self.r.randint(8, 30))
            self._emit(host="host03", user=user, src_ip=HOME_IP[user],
                       outcome="failure", method="password",
                       privileged=False, when=base)
        base += timedelta(seconds=20)
        self._emit(host="host03", user=user, src_ip=HOME_IP[user],
                   outcome="success", method="password", privileged=False,
                   when=base)
        self.t = base
        self.benign_anomalies.append(
            {"type": "brute_force",
             "key": {"user": user, "src_ip": HOME_IP[user]}})

    def admin_onhours(self, user, host="host02"):
        self.t += timedelta(minutes=self.r.randint(3, 20))
        self.t = self.t.replace(hour=self.r.choice([9, 11, 14, 16]))
        ev = self._emit(host=host, user=user, src_ip=HOME_IP[user],
                        outcome="success", method="pubkey", privileged=True,
                        when=self.t)
        self.benign_anomalies.append(
            {"type": "off_hours_admin",
             "key": {"user": user, "host": host,
                     "hour": self.t.astimezone(timezone.utc).hour}})


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--events-out", default="data/events.jsonl")
    ap.add_argument("--labels-out", default="data/labels.json")
    args = ap.parse_args()

    g = Gen(args.seed, datetime(2026, 3, 2, 8, 0, tzinfo=timezone.utc))
    g.background(400)
    g.brute_force("bob", NY, with_travel=True)          # brute + travel
    g.background(120)
    g.password_spray(TOKYO, ["alice", "carol", "dave", "erin", "grace"])
    g.background(120)
    g.impossible_travel("judy", HOME_IP["judy"], TOKYO)
    g.background(120)
    g.off_hours_admin("svc-backup")
    g.background(80)
    g.fat_finger("frank")                                # benign near-miss
    g.admin_onhours("netadmin")                          # benign near-miss
    g.background(120)
    g.brute_force("root", LONDON, off_hours=True)        # brute + off-hours
    g.background(80)

    evs = sorted(g.events, key=lambda e: e.timestamp)
    with open(args.events_out, "w") as f:
        for e in evs:
            f.write(json.dumps(asdict(e)) + "\n")

    labels = {"attacks": g.attacks, "benign_anomalies": g.benign_anomalies,
              "generated_at": datetime.now(timezone.utc).isoformat(),
              "event_count": len(evs)}
    with open(args.labels_out, "w") as f:
        json.dump(labels, f, indent=2)

    print(f"wrote {len(evs)} events -> {args.events_out}")
    print(f"wrote {len(g.attacks)} attack labels, "
          f"{len(g.benign_anomalies)} benign near-misses -> {args.labels_out}")


if __name__ == "__main__":
    main()
