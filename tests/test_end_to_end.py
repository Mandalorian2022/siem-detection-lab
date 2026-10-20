"""Generate, run, evaluate on two seeds. This is the test that keeps the README honest."""
import json
from pathlib import Path

import pytest

from siemlab.evaluate import evaluate, load_truth
from siemlab.incidents import build_incidents
from siemlab.runner import Pipeline, read_events
from siemlab.simulate import generate
from siemlab.simulate.world import World


@pytest.fixture(scope="module", params=[7, 23])
def run(request, tmp_path_factory, rules_dir):
    build = tmp_path_factory.mktemp(f"seed{request.param}")
    generate(request.param, build)
    with open(build / "world.json", encoding="utf-8") as f:
        world = World.from_dict(json.load(f))
    pipe = Pipeline(rules_dir, world)
    events = read_events(build / "events.jsonl")
    alerts, incidents, _ = pipe.run(events)
    report = evaluate(alerts, incidents, load_truth(build / "truth.json"), pipe.catalogue(), len(events))
    return build, world, alerts, incidents, report


def test_labels_never_reach_the_event_stream(run):
    build = run[0]
    text = Path(build / "events.jsonl").read_text(encoding="utf-8")
    assert "_scn" not in text and "malicious" not in text
    assert "expected" not in Path(build / "world.json").read_text(encoding="utf-8")


def test_every_expected_detection_fires(run):
    report = run[4]
    missed = [(s.id, s.missed) for s in report.scenarios if s.missed and not s.known_gap]
    assert not missed, missed
    assert report.overall["recall"] == 1.0


def test_no_alert_on_plain_baseline(run):
    report = run[4]
    assert report.noise["baseline_alerts"] == 0, [a["rule_id"] for a in report.baseline_false_positives]


def test_silent_benign_scenarios_stay_silent(run):
    report = run[4]
    noisy = [s.id for s in report.scenarios if not s.malicious and not s.expected and s.fired]
    assert not noisy, noisy


def test_known_gap_is_really_a_gap(run):
    report = run[4]
    gaps = [s for s in report.scenarios if s.known_gap]
    assert gaps
    for g in gaps:
        assert not g.fired, f"{g.id} is documented as a gap but fired {g.fired}; update the docs"


def test_campaign_lands_mostly_in_one_incident(run):
    report = run[4]
    assert report.campaign["stages_detected"] == report.campaign["stages"]
    assert len(report.campaign["stages_in_largest_incident"]) >= report.campaign["stages"] - 1
    assert report.campaign["largest_incident_risk"] >= 90


def test_incident_risk_has_diminishing_returns(run):
    world, alerts = run[1], run[2]
    incidents = build_incidents(alerts, world)
    for inc in incidents:
        assert inc.risk <= 100
        assert inc.severity in ("critical", "high", "medium", "low", "informational")
    assert incidents == sorted(incidents, key=lambda i: (-i.risk, i.first_seen))


def test_alerts_are_deterministic(run, rules_dir):
    build, world, alerts = run[0], run[1], run[2]
    again, _, _ = Pipeline(rules_dir, world).run(read_events(build / "events.jsonl"))
    assert [a.alert_id for a in again] == [a.alert_id for a in alerts]
