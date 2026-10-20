# SIEM Detection Lab: Evaluation Report

_Generated 2026-10-20T20:45:07.579129+00:00_

Scope: synthetic data only. The confusion matrix is bounded to the labeled attack and benign near-miss scenarios in this lab. Numbers describe this lab and should not be read as general detector performance.

## Per-detection results

| Detection | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| brute_force | 2 | 0 | 0 | 1 | 1.000 | 1.000 | 1.000 | 0.000 |
| password_spray | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | n/a |
| impossible_travel | 2 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | n/a |
| off_hours_admin | 2 | 0 | 0 | 1 | 1.000 | 1.000 | 1.000 | 0.000 |
| **overall** | 7 | 0 | 0 | 2 | 1.000 | 1.000 | 1.000 | 0.000 |

## How to read this

- **TP**: a labeled attack the rule correctly flagged.
- **FP**: the rule fired on a labeled benign near-miss (for example a user mistyping a password).
- **FN**: a labeled attack the rule missed.
- **TN**: a benign near-miss the rule correctly left alone.

