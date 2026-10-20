#!/usr/bin/env python3
"""Run the detection rules over an event stream and persist alerts.

Input:  JSON-lines events (no labels).
Output: alerts as JSON and as a SQLite evidence table.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone

from detections.rules import run_all

MAX_EVENTS = 5_000_000  # defensive input bound


def load_events(path: str) -> list[dict]:
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if len(events) >= MAX_EVENTS:
                raise SystemExit(f"input exceeds MAX_EVENTS={MAX_EVENTS}")
            events.append(json.loads(line))
    return events


def write_sqlite(path: str, alerts) -> None:
    con = sqlite3.connect(path)
    con.execute("DROP TABLE IF EXISTS alerts")
    con.execute(
        "CREATE TABLE alerts (rule TEXT, key_json TEXT, detail TEXT, "
        "evidence_json TEXT, created_utc TEXT)")
    now = datetime.now(timezone.utc).isoformat()
    con.executemany(
        "INSERT INTO alerts VALUES (?,?,?,?,?)",
        [(a.rule, json.dumps(a.key_dict()), a.detail,
          json.dumps(list(a.evidence)), now) for a in alerts])
    con.commit()
    con.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", default="data/events.jsonl")
    ap.add_argument("--alerts-out", default="data/alerts.json")
    ap.add_argument("--sqlite-out", default="data/evidence.sqlite")
    args = ap.parse_args()

    events = load_events(args.events)
    alerts = run_all(events)

    with open(args.alerts_out, "w") as f:
        json.dump([{"rule": a.rule, "key": a.key_dict(),
                    "detail": a.detail, "evidence": list(a.evidence)}
                   for a in alerts], f, indent=2)
    write_sqlite(args.sqlite_out, alerts)

    by_rule: dict[str, int] = {}
    for a in alerts:
        by_rule[a.rule] = by_rule.get(a.rule, 0) + 1
    print(f"processed {len(events)} events, {len(alerts)} alerts")
    for rule, n in sorted(by_rule.items()):
        print(f"  {rule}: {n}")


if __name__ == "__main__":
    main()
