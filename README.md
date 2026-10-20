# SIEM Detection Lab

A small, self-contained detection-engineering lab. It generates synthetic
authentication logs for a fleet of generic hosts, injects a set of labeled
attack scenarios, runs a set of authored detections over the stream, and
measures the detections against independently generated ground truth.

Everything is synthetic and reproducible. There is no real data here: no
real hosts, accounts, addresses, or logs. The point is to demonstrate a
detection-engineering workflow end to end, not to publish any environment.

## Why it exists

Shipping logs to a SIEM is the easy part. The engineering is in the
detections and the access model around them: writing rules that catch real
attacks without drowning analysts in false positives, proving they work,
and keeping the people who read the data on least privilege. This lab shows
that loop on data that is safe to share.

## What it does

1. **Generate** synthetic auth events plus labeled attacks and labeled
   benign near-misses. Labels are written to a separate file and never
   enter the detection input.
2. **Detect** with four authored rules (below), writing alerts to JSON and
   to a SQLite evidence table.
3. **Evaluate** alerts against ground truth, producing a confusion matrix
   with precision, recall, F1, and false-positive rate.

A real intrusion usually trips more than one rule, so each scenario is
labeled with every detection it is expected to fire. That lets correlated,
multi-signal detections score as correct rather than as false positives.

## Detections

| Rule | Fires on | Key thresholds |
|---|---|---|
| Brute force | many failures, one account, one source, short window | 8 failures / 5 min |
| Password spray | one source, many distinct accounts, one window | 4 users / 15 min |
| Impossible travel | two successful logins, geo-distant, short time | 1000 km / 1 h |
| Off-hours admin | successful privileged login outside business hours | 07:00-19:00 UTC |

Each rule exists twice: as runnable Python in `detections/rules.py` and as
a portable definition in `sigma/`.

## Results on the bundled scenario set

Synthetic data only. The confusion matrix is bounded to the labeled
scenarios in this lab, so these numbers describe this lab and are not a
claim about general detector performance.

| Detection | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| brute_force | 2 | 0 | 0 | 1 | 1.000 | 1.000 | 1.000 |
| password_spray | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| impossible_travel | 2 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| off_hours_admin | 2 | 0 | 0 | 1 | 1.000 | 1.000 | 1.000 |
| **overall** | 7 | 0 | 0 | 2 | 1.000 | 1.000 | 1.000 |

Two of the five injected intrusions were caught by a second rule as well:
the brute-forced account showed impossible travel, and the brute-forced
privileged account also tripped the off-hours rule. The two benign
near-misses (a user mistyping a password, an admin working on-hours) were
correctly left alone.

## Run it

No third-party dependencies. Python 3.11+.

```bash
python3 generate_events.py     # -> data/events.jsonl, data/labels.json
python3 detect.py              # -> data/alerts.json, data/evidence.sqlite
python3 evaluate.py            # -> data/report.md, data/report.html
```

Or all at once:

```bash
./run.sh
```

Run the tests:

```bash
python3 -m unittest discover -s tests -v
```

## Layout

```
generate_events.py   synthetic events + labeled scenarios (labels kept separate)
detect.py            runs the rules, writes alerts to JSON and SQLite
evaluate.py          scores alerts vs ground truth, writes the report
detections/rules.py  the four detections, as code
geoip.py             shared synthetic GeoIP enrichment table
sigma/               the same detections as portable Sigma rules
tests/               unit, property, and end-to-end tests
docs/                least-privilege dashboard and access model
```

## Design notes and honest limits

- **Synthetic and bounded.** The baseline is constructed to be rule-safe
  (unique home sources, admins on-hours), so every alert is attributable
  to a labeled scenario. This makes the confusion matrix interpretable; it
  also means the numbers reflect these scenarios only.
- **Thresholds are illustrative.** Real tuning depends on an
  environment's own baseline. The thresholds here are named constants, easy
  to change in one place.
- **GeoIP is simulated.** The enrichment table is invented so the lab is
  self-contained. Real GeoIP is noisier, and VPN or proxy egress is a known
  source of impossible-travel false positives.
- **Scope.** This is a teaching and demonstration artifact, not a
  production detection suite.

## Provenance

Built with AI assistance under explicit requirements, with the design
decisions, thresholds, and validation documented here and in the code. The
measured results above are produced by running the code in this
repository.

## License

MIT. See `LICENSE`.
