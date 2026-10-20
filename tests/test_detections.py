"""Unit, property, and end-to-end tests for the detection rules.

Run: python3 -m unittest discover -s tests -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from detections import rules  # noqa: E402


def ev(eid, user, src, outcome, when, priv=False, host="host01",
       method="password"):
    return {"event_id": eid, "timestamp": when.astimezone(timezone.utc).isoformat(),
            "host": host, "user": user, "src_ip": src, "outcome": outcome,
            "method": method, "privileged": priv}


T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


class TestBruteForce(unittest.TestCase):
    def test_fires_above_threshold(self):
        evs = [ev(f"e{i}", "bob", "203.0.113.5", "failure",
                  T0 + timedelta(seconds=i * 10))
               for i in range(rules.BRUTE_FORCE_FAILS)]
        alerts = rules.brute_force(evs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].key_dict(),
                         {"user": "bob", "src_ip": "203.0.113.5"})

    def test_quiet_below_threshold(self):
        evs = [ev(f"e{i}", "bob", "203.0.113.5", "failure",
                  T0 + timedelta(seconds=i * 10))
               for i in range(rules.BRUTE_FORCE_FAILS - 1)]
        self.assertEqual(rules.brute_force(evs), [])

    def test_window_bounded(self):
        # failures spread far apart must not accumulate into one alert
        evs = [ev(f"e{i}", "bob", "203.0.113.5", "failure",
                  T0 + timedelta(minutes=i * 2))
               for i in range(rules.BRUTE_FORCE_FAILS)]
        self.assertEqual(rules.brute_force(evs), [])


class TestSpray(unittest.TestCase):
    def test_fires_on_many_users(self):
        evs = []
        for u in range(rules.SPRAY_MIN_USERS):
            evs.append(ev(f"e{u}", f"user{u}", "192.0.2.7", "failure",
                          T0 + timedelta(seconds=u * 30)))
        alerts = rules.password_spray(evs)
        self.assertEqual(len(alerts), 1)

    def test_quiet_single_user(self):
        evs = [ev(f"e{i}", "alice", "192.0.2.7", "failure",
                  T0 + timedelta(seconds=i * 30)) for i in range(10)]
        self.assertEqual(rules.password_spray(evs), [])


class TestTravel(unittest.TestCase):
    def test_fires_far_and_fast(self):
        evs = [ev("a", "judy", "198.51.100.10", "success", T0),
               ev("b", "judy", "192.0.2.7", "success",
                  T0 + timedelta(minutes=20))]
        self.assertEqual(len(rules.impossible_travel(evs)), 1)

    def test_quiet_same_region(self):
        evs = [ev("a", "judy", "198.51.100.10", "success", T0),
               ev("b", "judy", "198.51.100.12", "success",
                  T0 + timedelta(minutes=20))]
        self.assertEqual(rules.impossible_travel(evs), [])

    def test_quiet_enough_time(self):
        evs = [ev("a", "judy", "198.51.100.10", "success", T0),
               ev("b", "judy", "192.0.2.7", "success",
                  T0 + timedelta(hours=12))]
        self.assertEqual(rules.impossible_travel(evs), [])


class TestOffHours(unittest.TestCase):
    def test_fires_off_hours_privileged(self):
        evs = [ev("a", "root", "198.51.100.10", "success",
                  T0.replace(hour=2), priv=True)]
        self.assertEqual(len(rules.off_hours_admin(evs)), 1)

    def test_quiet_on_hours(self):
        evs = [ev("a", "root", "198.51.100.10", "success",
                  T0.replace(hour=12), priv=True)]
        self.assertEqual(rules.off_hours_admin(evs), [])

    def test_quiet_unprivileged(self):
        evs = [ev("a", "alice", "198.51.100.10", "success",
                  T0.replace(hour=2), priv=False)]
        self.assertEqual(rules.off_hours_admin(evs), [])


class TestNormalization(unittest.TestCase):
    def test_dedup_and_order(self):
        evs = [ev("dup", "a", "x", "failure", T0 + timedelta(seconds=30)),
               ev("dup", "a", "x", "failure", T0 + timedelta(seconds=30)),
               ev("e1", "a", "x", "failure", T0)]
        out = rules._normalize(evs)
        self.assertEqual(len(out), 2)
        self.assertLessEqual(out[0]["timestamp"], out[1]["timestamp"])

    def test_determinism(self):
        evs = [ev(f"e{i}", "bob", "203.0.113.5", "failure",
                  T0 + timedelta(seconds=i * 5))
               for i in range(rules.BRUTE_FORCE_FAILS)]
        first = [(a.rule, a.key) for a in rules.run_all(list(evs))]
        second = [(a.rule, a.key) for a in rules.run_all(list(reversed(evs)))]
        self.assertEqual(sorted(map(str, first)), sorted(map(str, second)))


class TestEndToEnd(unittest.TestCase):
    def test_pipeline_recall_and_no_false_positives(self):
        with tempfile.TemporaryDirectory() as d:
            evp = os.path.join(d, "events.jsonl")
            lbp = os.path.join(d, "labels.json")
            alp = os.path.join(d, "alerts.json")
            sqp = os.path.join(d, "ev.sqlite")
            env = {**os.environ, "PYTHONPATH": ROOT}
            subprocess.run([sys.executable, "generate_events.py",
                            "--events-out", evp, "--labels-out", lbp],
                           cwd=ROOT, check=True, env=env,
                           capture_output=True)
            subprocess.run([sys.executable, "detect.py", "--events", evp,
                            "--alerts-out", alp, "--sqlite-out", sqp],
                           cwd=ROOT, check=True, env=env,
                           capture_output=True)
            import evaluate
            with open(alp) as f:
                alerts = json.load(f)
            with open(lbp) as f:
                labels = json.load(f)
            _, totals = evaluate.score(alerts, labels)
            self.assertEqual(totals["FN"], 0, "missed a labeled attack")
            self.assertEqual(totals["FP"], 0, "fired on a benign near-miss")
            self.assertGreaterEqual(totals["TP"], 5)


if __name__ == "__main__":
    unittest.main()
