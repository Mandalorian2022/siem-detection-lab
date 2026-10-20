#!/usr/bin/env python3
"""Score alerts against the independently generated ground-truth labels.

The evaluation universe per detection type is the set of labeled attack
keys (positives) plus labeled benign near-miss keys (negatives). This
bounds the confusion matrix to scenarios we deliberately created, so the
reported numbers describe this lab only and nothing more.
"""
from __future__ import annotations

import argparse
import html
import json
from datetime import datetime, timezone

TYPES = ["brute_force", "password_spray", "impossible_travel",
         "off_hours_admin"]


def _norm(d: dict) -> frozenset:
    return frozenset(d.items())


def score(alerts, labels):
    attacks = {t: set() for t in TYPES}
    benign = {t: set() for t in TYPES}
    for a in labels["attacks"]:
        attacks[a["type"]].add(_norm(a["key"]))
    for b in labels["benign_anomalies"]:
        benign[b["type"]].add(_norm(b["key"]))

    alert_keys = {t: set() for t in TYPES}
    for a in alerts:
        if a["rule"] in alert_keys:
            alert_keys[a["rule"]].add(_norm(a["key"]))

    rows, totals = {}, {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for t in TYPES:
        pos, neg, fired = attacks[t], benign[t], alert_keys[t]
        tp = len(fired & pos)
        fn = len(pos - fired)
        tn = len(neg - fired)
        # anything fired that is not a known attack counts as a false positive
        fp = len(fired - pos)
        rows[t] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn}
        for k in totals:
            totals[k] += rows[t][k]
    return rows, totals


def metrics(c: dict) -> dict:
    tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    f1 = (2 * prec * rec / (prec + rec)
          if prec and rec and (prec + rec) else None)
    return {"precision": prec, "recall": rec, "f1": f1, "fpr": fpr}


def _fmt(x) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def markdown_report(rows, totals) -> str:
    out = ["# SIEM Detection Lab: Evaluation Report", ""]
    out.append(f"_Generated {datetime.now(timezone.utc).isoformat()}_")
    out.append("")
    out.append("Scope: synthetic data only. The confusion matrix is bounded "
               "to the labeled attack and benign near-miss scenarios in this "
               "lab. Numbers describe this lab and should not be read as "
               "general detector performance.")
    out.append("")
    out.append("## Per-detection results")
    out.append("")
    out.append("| Detection | TP | FP | FN | TN | Precision | Recall | F1 | FPR |")
    out.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for t in TYPES:
        c, m = rows[t], metrics(rows[t])
        out.append(f"| {t} | {c['TP']} | {c['FP']} | {c['FN']} | {c['TN']} "
                   f"| {_fmt(m['precision'])} | {_fmt(m['recall'])} "
                   f"| {_fmt(m['f1'])} | {_fmt(m['fpr'])} |")
    m = metrics(totals)
    out.append(f"| **overall** | {totals['TP']} | {totals['FP']} "
               f"| {totals['FN']} | {totals['TN']} | {_fmt(m['precision'])} "
               f"| {_fmt(m['recall'])} | {_fmt(m['f1'])} | {_fmt(m['fpr'])} |")
    out.append("")
    out.append("## How to read this")
    out.append("")
    out.append("- **TP**: a labeled attack the rule correctly flagged.")
    out.append("- **FP**: the rule fired on a labeled benign near-miss "
               "(for example a user mistyping a password).")
    out.append("- **FN**: a labeled attack the rule missed.")
    out.append("- **TN**: a benign near-miss the rule correctly left alone.")
    out.append("")
    return "\n".join(out) + "\n"


def html_report(rows, totals) -> str:
    def row(t, c):
        m = metrics(c)
        return ("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
                "<td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>").format(
            html.escape(t), c["TP"], c["FP"], c["FN"], c["TN"],
            _fmt(m["precision"]), _fmt(m["recall"]), _fmt(m["f1"]),
            _fmt(m["fpr"]))
    body = "\n".join(row(t, rows[t]) for t in TYPES)
    body += "\n" + row("overall", totals)
    return (
        "<!doctype html><meta charset=utf-8>"
        "<title>SIEM Detection Lab report</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;"
        "color:#111}table{border-collapse:collapse}th,td{border:1px solid "
        "#ccc;padding:.4rem .7rem;text-align:right}th:first-child,"
        "td:first-child{text-align:left}caption{text-align:left;"
        "margin-bottom:.6rem;color:#555}</style>"
        "<h1>SIEM Detection Lab: Evaluation Report</h1>"
        "<p>Synthetic data only. Confusion matrix bounded to labeled "
        "scenarios in this lab.</p>"
        "<table><caption>Per-detection results</caption>"
        "<tr><th>Detection</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th>"
        "<th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th></tr>"
        + body + "</table>")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--alerts", default="data/alerts.json")
    ap.add_argument("--labels", default="data/labels.json")
    ap.add_argument("--md-out", default="data/report.md")
    ap.add_argument("--html-out", default="data/report.html")
    args = ap.parse_args()

    with open(args.alerts) as f:
        alerts = json.load(f)
    with open(args.labels) as f:
        labels = json.load(f)

    rows, totals = score(alerts, labels)
    with open(args.md_out, "w") as f:
        f.write(markdown_report(rows, totals))
    with open(args.html_out, "w") as f:
        f.write(html_report(rows, totals))

    m = metrics(totals)
    print("overall:", {k: _fmt(v) for k, v in m.items()})
    print(f"TP={totals['TP']} FP={totals['FP']} "
          f"FN={totals['FN']} TN={totals['TN']}")
    print(f"reports -> {args.md_out}, {args.html_out}")


if __name__ == "__main__":
    main()
