"""Every shipped rule must load, be referenced correctly, carry ATT&CK tags, and export."""
import re

from siemlab.backends import BACKENDS
from siemlab.sigma import SigmaEngine, SigmaRule, load_rules

ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z_]+)$")


def test_rules_load_and_resolve(rules_dir):
    rules = load_rules(rules_dir)
    eng = SigmaEngine(rules)
    assert len(rules) >= 15
    assert len(eng.alerting_rules()) >= 10


def test_every_rule_is_well_formed(rules_dir):
    for r in load_rules(rules_dir):
        assert r.description.strip(), r.title
        assert r.tags, r.title
        assert all(ATTACK_TAG.match(t) for t in r.tags), (r.title, r.tags)
        assert r.name and re.match(r"^[a-z][a-z0-9_]+$", r.name), r.title
        assert r.status in ("stable", "experimental", "test")


def test_building_blocks_never_alert(rules_dir):
    eng = SigmaEngine(load_rules(rules_dir))
    blocks = [r for r in eng.rules if r.custom.get("x-building-block")]
    assert blocks
    for b in blocks:
        assert b.level == "informational"
    # every building block must be consumed by at least one correlation
    consumed = {eng.by_ref[ref].id for r in eng.correlations for ref in r.rules}
    for b in blocks:
        assert b.id in consumed, f"{b.title} is a building block nothing uses"


def test_backends_export_every_detection_rule(rules_dir):
    rules = [r for r in load_rules(rules_dir) if isinstance(r, SigmaRule)]
    for name, cls in BACKENDS.items():
        b = cls()
        for r in rules:
            q = b.convert(r)
            assert q.strip(), (name, r.title)
            # the mapped field names, not the Sigma ones, must appear
            if "ResultType" in str(r.detection):
                assert "identity.result_code" in q or "identity" in q


def test_kql_shape(rules_dir):
    rule = next(r for r in load_rules(rules_dir) if r.name == "win_rdp_from_external")
    q = BACKENDS["kql"]().convert(rule)
    assert q.startswith("SecurityEvent\n| where ")
    assert "event.code" in q and "'4624'" in q
    assert "not (" in q and "corporate" in q


def test_splunk_shape(rules_dir):
    rule = next(r for r in load_rules(rules_dir) if r.name == "win_privileged_logon_offhours")
    q = BACKENDS["splunk"]().convert(rule)
    assert q.startswith('sourcetype="WinEventLog:Security"')
    assert "time.local_hour<6" in q and "time.local_hour>=21" in q
    assert "NOT (" in q
