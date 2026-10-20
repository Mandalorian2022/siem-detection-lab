"""Engine semantics on hand-built events, independent of the simulator."""
import pytest

from siemlab.sigma import SigmaEngine, SigmaRuleError
from siemlab.sigma.loader import build_correlation, build_rule

FAIL = {
    "title": "fail", "id": "11111111-1111-4111-8111-111111111111", "name": "fail",
    "level": "informational", "logsource": {"product": "azure", "service": "signinlogs"},
    "detection": {"selection": {"ResultType": "50126"}, "condition": "selection"},
    "x-building-block": True,
}
OK = {**FAIL, "id": "22222222-2222-4222-8222-222222222222", "name": "ok",
      "detection": {"selection": {"ResultType": "0"}, "condition": "selection"}}


def corr(cid, ctype, rules, group, span, cond=None, generate=False):
    return {"title": cid, "id": cid, "name": cid, "level": "high",
            "correlation": {"type": ctype, "rules": rules, "group-by": group, "timespan": span,
                            "condition": cond or {}, "generate": generate}}


def signin(i, user, ip, ok, minute):
    return {"@timestamp": f"2026-03-02T10:{minute:02d}:00Z", "event.id": f"e{i}",
            "event.dataset": "identity.signin", "user.name": user, "source.ip": ip,
            "identity.result_code": "0" if ok else "50126"}


def test_event_count_window_and_reset():
    c = build_correlation(corr("33333333-3333-4333-8333-333333333333", "event_count", ["fail"],
                               ["UserPrincipalName"], "10m", {"gte": 3}))
    eng = SigmaEngine([build_rule(FAIL), c])
    evs = [signin(i, "ana", "1.1.1.1", False, m) for i, m in enumerate([0, 2, 4, 30, 31, 32])]
    res = eng.run(evs)
    fired = res[c.id]
    assert len(fired) == 2
    assert fired[0].evidence == ("e0", "e1", "e2")
    assert fired[1].evidence == ("e3", "e4", "e5")


def test_event_count_respects_window():
    c = build_correlation(corr("33333333-3333-4333-8333-333333333333", "event_count", ["fail"],
                               ["UserPrincipalName"], "5m", {"gte": 3}))
    eng = SigmaEngine([build_rule(FAIL), c])
    evs = [signin(i, "ana", "1.1.1.1", False, m) for i, m in enumerate([0, 10, 20])]
    assert eng.run(evs)[c.id] == []


def test_value_count_distinct_users():
    c = build_correlation(corr("44444444-4444-4444-8444-444444444444", "value_count", ["fail"],
                               ["IpAddress"], "1h", {"field": "UserPrincipalName", "gte": 3}))
    eng = SigmaEngine([build_rule(FAIL), c])
    same_user = [signin(i, "ana", "1.1.1.1", False, m) for i, m in enumerate(range(5))]
    assert eng.run(same_user)[c.id] == []
    many = [signin(i, u, "1.1.1.1", False, i) for i, u in enumerate(["ana", "ben", "ben", "cy"])]
    assert len(eng.run(many)[c.id]) == 1


def test_temporal_ordered_requires_order():
    bf = build_correlation(corr("55555555-5555-4555-8555-555555555555", "event_count", ["fail"],
                                ["UserPrincipalName", "IpAddress"], "10m", {"gte": 2}))
    seq = build_correlation(corr("66666666-6666-4666-8666-666666666666", "temporal_ordered",
                                 ["55555555-5555-4555-8555-555555555555", "ok"],
                                 ["UserPrincipalName", "IpAddress"], "1h", generate=True))
    eng = SigmaEngine([build_rule(FAIL), build_rule(OK), bf, seq])
    good = [signin(0, "ana", "1.1.1.1", False, 0), signin(1, "ana", "1.1.1.1", False, 1),
            signin(2, "ana", "1.1.1.1", True, 5)]
    assert len(eng.run(good)[seq.id]) == 1
    wrong_order = [signin(0, "ana", "1.1.1.1", True, 0), signin(1, "ana", "1.1.1.1", False, 1),
                   signin(2, "ana", "1.1.1.1", False, 2)]
    assert eng.run(wrong_order)[seq.id] == []
    other_ip = [signin(0, "ana", "1.1.1.1", False, 0), signin(1, "ana", "1.1.1.1", False, 1),
                signin(2, "ana", "9.9.9.9", True, 5)]
    assert eng.run(other_ip)[seq.id] == []


def test_building_blocks_and_generate_flag():
    bf = build_correlation(corr("55555555-5555-4555-8555-555555555555", "event_count", ["fail"],
                                ["UserPrincipalName"], "10m", {"gte": 2}))
    eng = SigmaEngine([build_rule(FAIL), build_rule(OK), bf])
    alerting = {r.name for r in eng.alerting_rules()}
    assert "fail" not in alerting            # referenced by a generate:false correlation
    assert bf.id in {r.id for r in eng.alerting_rules()}


def test_unknown_reference_and_cycle_are_errors():
    with pytest.raises(SigmaRuleError):
        SigmaEngine([build_rule(FAIL), build_correlation(
            corr("77777777-7777-4777-8777-777777777777", "event_count", ["nope"], [], "1m", {"gte": 1}))])
    a = corr("88888888-8888-4888-8888-888888888888", "temporal", ["99999999-9999-4999-8999-999999999999"], [], "1m")
    b = corr("99999999-9999-4999-8999-999999999999", "temporal", ["88888888-8888-4888-8888-888888888888"], [], "1m")
    with pytest.raises(SigmaRuleError):
        SigmaEngine([build_correlation(a), build_correlation(b)])


def test_rule_only_sees_its_dataset():
    r = build_rule(OK)
    eng = SigmaEngine([r])
    wrong = {**signin(0, "ana", "1.1.1.1", True, 0), "event.dataset": "windows.security"}
    assert eng.run([wrong])[r.id] == []
