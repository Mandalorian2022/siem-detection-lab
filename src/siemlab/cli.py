"""Command-line entry point: ``siemlab <command>``.

    generate   build a synthetic week (events, world, ground truth)
    validate   load every rule and report problems, exit 1 on any
    run        enrich, detect, correlate; write alerts and incidents
    evaluate   score alerts against ground truth; write the report
    export     translate Sigma detection rules to a SIEM query language
    all        generate -> run -> evaluate
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .evaluate import evaluate, load_truth
from .report import html_page, markdown
from .runner import Pipeline, read_events, write_alerts, write_incidents
from .sigma import SigmaRule, SigmaRuleError, load_rules
from .sigma.engine import SigmaEngine
from .simulate import generate
from .simulate.world import World

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES = ROOT / "rules"


def _world(build: Path) -> World:
    with open(build / "world.json", encoding="utf-8") as f:
        return World.from_dict(json.load(f))


def cmd_generate(a: argparse.Namespace) -> int:
    stats = generate(a.seed, a.build)
    print(f"generated {stats['events']:,} events, {stats['scenarios']} scenarios "
          f"({stats['labeled_events']} labeled events) -> {a.build}")
    return 0


def cmd_validate(a: argparse.Namespace) -> int:
    try:
        rules = load_rules(a.rules)
        engine = SigmaEngine(rules)
    except SigmaRuleError as e:
        print(f"INVALID: {e}")
        return 1
    n_det = sum(1 for r in rules if r.kind == "detection")
    n_cor = len(rules) - n_det
    problems = []
    for r in rules:
        if r.kind == "detection" and not r.custom.get("x-building-block") and not r.tags:
            problems.append(f"{r.title}: no ATT&CK tags")
        if r.level in ("high", "critical") and not r.description.strip():
            problems.append(f"{r.title}: high-severity rule without a description")
    for p in problems:
        print("WARN", p)
    print(f"OK: {n_det} detection rules, {n_cor} correlation rules, "
          f"{len(engine.alerting_rules())} alerting, {len(engine.suppressed)} building blocks")
    return 0


def cmd_run(a: argparse.Namespace) -> int:
    world = _world(a.build)
    pipe = Pipeline(a.rules, world)
    events = read_events(a.build / "events.jsonl")
    alerts, incidents, _ = pipe.run(events)
    write_alerts(a.build / "alerts.jsonl", alerts)
    write_incidents(a.build / "incidents.json", incidents)
    with open(a.build / "catalogue.json", "w", encoding="utf-8") as f:
        json.dump(pipe.catalogue(), f, indent=1)
    by_rule: dict[str, int] = {}
    for al in alerts:
        by_rule[al.rule_id] = by_rule.get(al.rule_id, 0) + 1
    print(f"{len(events):,} events -> {len(alerts)} alerts -> {len(incidents)} incidents")
    for k, v in sorted(by_rule.items()):
        print(f"  {k:36s} {v}")
    return 0


def cmd_evaluate(a: argparse.Namespace) -> int:
    from .model import Alert
    with open(a.build / "alerts.jsonl", encoding="utf-8") as f:
        alerts = [Alert.from_dict(json.loads(line)) for line in f if line.strip()]
    with open(a.build / "incidents.json", encoding="utf-8") as f:
        inc_dicts = json.load(f)
    from .incidents import Incident
    incidents = [Incident(**{**d, "alerts": []}) for d in inc_dicts]
    amap = {x.alert_id: x for x in alerts}
    for i in incidents:
        i.alerts = [amap[x].to_dict() for x in i.alert_ids]
    with open(a.build / "catalogue.json", encoding="utf-8") as f:
        catalogue = json.load(f)
    truth = load_truth(a.build / "truth.json")
    with open(a.build / "events.jsonl", encoding="utf-8") as f:
        n_events = sum(1 for _ in f)
    rep = evaluate(alerts, incidents, truth, catalogue, n_events)
    with open(a.build / "report.json", "w", encoding="utf-8") as f:
        json.dump(rep.to_dict(), f, indent=1)
    with open(a.build / "report.md", "w", encoding="utf-8") as f:
        f.write(markdown(rep, catalogue))
    with open(a.build / "report.html", "w", encoding="utf-8") as f:
        f.write(html_page(rep, catalogue, inc_dicts))
    o = rep.overall
    print(f"precision {o['precision']}  recall {o['recall']}  baseline FP {rep.noise['baseline_alerts']}  "
          f"known gaps {o['known_gaps']}  median TTD {o['median_time_to_detect_s']}s")
    print(f"campaign: {len(rep.campaign['stages_in_largest_incident'])}/{rep.campaign['stages']} "
          f"stages in one incident")
    missed = [s for s in rep.scenarios if s.missed and not s.known_gap]
    for s in missed:
        print(f"  MISSED {s.id} {s.name}: {s.missed}")
    if a.strict and (missed or rep.noise["baseline_alerts"]):
        return 1
    return 0


def cmd_export(a: argparse.Namespace) -> int:
    from .backends import BACKENDS
    rules = load_rules(a.rules)
    backend = BACKENDS[a.backend]()
    for r in rules:
        if not isinstance(r, SigmaRule):
            continue
        print(f"// {r.title} [{r.level}]")
        print(backend.convert(r))
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="siemlab", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--build", type=Path, default=Path("build"), help="working directory")
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="rule directory")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate").add_argument("--seed", type=int, default=7)
    sub.add_parser("validate")
    sub.add_parser("run")
    sub.add_parser("evaluate").add_argument(
        "--strict", action="store_true", help="exit 1 on a miss or a baseline false positive")
    sub.add_parser("export").add_argument("--backend", choices=["kql", "splunk"], default="kql")
    al = sub.add_parser("all")
    al.add_argument("--seed", type=int, default=7)
    al.add_argument("--strict", action="store_true")
    a = p.parse_args(argv)
    if a.cmd == "all":
        return cmd_generate(a) or cmd_validate(a) or cmd_run(a) or cmd_evaluate(a)
    return {"generate": cmd_generate, "validate": cmd_validate, "run": cmd_run,
            "evaluate": cmd_evaluate, "export": cmd_export}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
