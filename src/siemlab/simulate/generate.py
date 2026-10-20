"""Compose baseline and scenarios into an event stream plus separate truth.

Outputs (in ``out_dir``):

* ``events.jsonl`` - the telemetry, time-ordered, with no labels in it
* ``world.json``   - org context (directory, geo, intel, allowlists, changes)
* ``truth.json``   - scenario metadata and the event -> scenario mapping

Detection reads the first two. Only evaluation reads the third.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

from ..model import fmt_ts
from .baseline import generate_baseline
from .scenarios import generate_scenarios
from .world import build_world


def generate(seed: int, out_dir: Path) -> dict:
    rng = random.Random(seed)
    world = build_world(seed)
    events = generate_baseline(world, rng)
    scenarios = []
    for scn, evs in generate_scenarios(world, rng):
        scenarios.append(scn)
        events.extend(evs)

    events.sort(key=lambda e: e["_ts"])
    event_scenario: dict[str, str] = {}
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "events.jsonl", "w", encoding="utf-8") as f:
        for i, e in enumerate(events, 1):
            eid = f"e{i:07d}"
            if e.get("_scn"):
                event_scenario[eid] = e["_scn"]
            row = {"@timestamp": fmt_ts(e["_ts"]), "event.id": eid}
            row.update({k: v for k, v in e.items() if not k.startswith("_")})
            f.write(json.dumps(row, separators=(",", ":")) + "\n")

    with open(out_dir / "world.json", "w", encoding="utf-8") as f:
        json.dump(world.to_dict(), f, indent=1)
    truth = {"seed": seed, "scenarios": [s.to_dict() for s in scenarios],
             "event_scenario": event_scenario}
    with open(out_dir / "truth.json", "w", encoding="utf-8") as f:
        json.dump(truth, f, indent=1)
    return {"events": len(events), "scenarios": len(scenarios),
            "labeled_events": len(event_scenario)}
