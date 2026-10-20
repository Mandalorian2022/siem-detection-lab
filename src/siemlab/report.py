"""Render the evaluation as Markdown (for the README) and a standalone HTML page."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .evaluate import Report

TACTIC_ORDER = ["initial_access", "persistence", "credential_access", "lateral_movement",
                "command_and_control", "exfiltration"]


def _f(x: float | None, digits: int = 3) -> str:
    return "n/a" if x is None else f"{x:.{digits}f}"


def _secs(x: float | None) -> str:
    if x is None:
        return "n/a"
    if x < 90:
        return f"{x:.0f} s"
    return f"{x / 60:.1f} min"


def markdown(r: Report, catalogue: list[dict]) -> str:
    o = r.overall
    out = ["## Measured results", "",
           f"Seed {r.seed}: {r.events:,} events over five days, {r.alerts} alerts, "
           f"{r.incidents} incidents ({r.alerts_per_day} alerts/day).", ""]
    expected_mal = o["malicious_scenarios"] - o["known_gaps"]
    caught = expected_mal - sum(1 for s in r.scenarios if s.malicious and not s.known_gap and s.missed)
    joined = len(r.campaign["stages_in_largest_incident"])
    out += ["| | Value |", "|---|---:|",
            f"| Attack scenarios detected | {caught} / {expected_mal} (+{o['known_gaps']} documented gap) |",
            f"| Precision / recall (per expected detection) | {_f(o['precision'])} / {_f(o['recall'])} |",
            f"| Alerts raised on plain baseline traffic | {r.noise['baseline_alerts']} |",
            f"| Benign look-alikes that correctly fired (analyst noise) | {o['benign_true_positives']} |",
            f"| Extra detections on attacks beyond the expected rule | {o['extra_detections_on_attacks']} |",
            f"| Median time to detect | {_secs(o['median_time_to_detect_s'])} |",
            f"| Campaign stages joined into one incident | {joined} / {r.campaign['stages']} "
            f"(risk {r.campaign['largest_incident_risk']}) |",
            ""]
    out += ["### Per detection", "",
            "| Detection | Kind | Level | TP | FP | FN | Precision | Recall |",
            "|---|---|---|---:|---:|---:|---:|---:|"]
    kinds = {c["name"]: (c["kind"], c["level"]) for c in catalogue}
    for name, d in r.detections.items():
        kind, level = kinds.get(name, ("?", "?"))
        out.append(f"| `{name}` | {kind} | {level} | {d['tp']} | {d['fp']} | {d['fn']} "
                   f"| {_f(d['precision'])} | {_f(d['recall'])} |")
    out += ["", "### Scenarios", "",
            "| Scenario | Type | Expected | Result | Time to detect |", "|---|---|---|---|---:|"]
    for s in r.scenarios:
        if s.known_gap:
            res = "documented gap"
        elif s.missed:
            res = "MISSED: " + ", ".join(s.missed)
        elif s.unexpected:
            res = "fired + unexpected: " + ", ".join(s.unexpected)
        elif not s.malicious and not s.expected:
            res = "silent (correct)"
        elif not s.malicious:
            res = "fired (benign true positive)"
        else:
            res = "detected"
        exp = ", ".join(f"`{e}`" for e in s.expected) or "nothing"
        out.append(f"| {s.id} {s.name} | {'attack' if s.malicious else 'benign'} | {exp} | {res} "
                   f"| {_secs(s.time_to_detect_s) if s.malicious else ''} |")
    out += ["", "### ATT&CK coverage", ""]
    by_tactic: dict[str, set[str]] = {}
    for c in catalogue:
        for t in c["tactics"]:
            by_tactic.setdefault(t, set()).update(c["techniques"])
    for t in TACTIC_ORDER:
        if t in by_tactic:
            out.append(f"- **{t.replace('_', ' ')}**: " + ", ".join(sorted(by_tactic[t])))
    out.append("")
    return "\n".join(out)


def html_page(r: Report, catalogue: list[dict], incidents: list[dict]) -> str:
    def esc(x) -> str:
        return html.escape(str(x))
    rows = "".join(
        f"<tr><td><code>{esc(n)}</code></td><td>{d['tp']}</td><td>{d['fp']}</td><td>{d['fn']}</td>"
        f"<td>{_f(d['precision'])}</td><td>{_f(d['recall'])}</td></tr>"
        for n, d in r.detections.items())
    scn = "".join(
        f"<tr class='{'gap' if s.known_gap else 'miss' if s.missed else 'ok'}'><td>{esc(s.id)}</td>"
        f"<td>{esc(s.name)}</td><td>{'attack' if s.malicious else 'benign'}</td>"
        f"<td>{esc(', '.join(s.fired) or '—')}</td><td>{esc(', '.join(s.missed) or '')}</td>"
        f"<td>{_secs(s.time_to_detect_s) if s.malicious else ''}</td></tr>" for s in r.scenarios)
    inc = "".join(
        f"<tr><td>{esc(i['incident_id'])}</td><td class='{esc(i['severity'])}'>{esc(i['severity'])}</td>"
        f"<td>{i['risk']}</td><td>{esc(i['title'])}</td><td>{len(i['alert_ids'])}</td>"
        f"<td>{esc(', '.join(i['techniques']))}</td></tr>" for i in incidents[:25])
    o = r.overall
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SIEM Detection Lab report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#1b1f24;background:#fff}}
h1{{font-size:1.5rem}}h2{{font-size:1.15rem;margin-top:2rem}}
table{{border-collapse:collapse;width:100%;font-size:.9rem;margin:.6rem 0}}
th,td{{border:1px solid #d0d7de;padding:.35rem .55rem;text-align:left;vertical-align:top}}
th{{background:#f6f8fa}} td:nth-child(n+2):not(:last-child){{white-space:nowrap}}
.kpi{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.6rem}}
.kpi div{{border:1px solid #d0d7de;border-radius:8px;padding:.6rem .8rem}}
.kpi b{{display:block;font-size:1.4rem}}
tr.miss td{{background:#ffebe9}} tr.gap td{{background:#fff8c5}}
td.critical{{color:#a40e26;font-weight:600}} td.high{{color:#bc4c00;font-weight:600}}
small{{color:#57606a}}
</style></head><body>
<h1>SIEM Detection Lab — evaluation report</h1>
<small>Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · seed {r.seed} · synthetic data only</small>
<div class="kpi">
<div><b>{r.events:,}</b>events</div><div><b>{r.alerts}</b>alerts</div><div><b>{r.incidents}</b>incidents</div>
<div><b>{_f(o['precision'])}</b>precision</div><div><b>{_f(o['recall'])}</b>recall</div>
<div><b>{r.noise['baseline_alerts']}</b>alerts on baseline</div>
<div><b>{_secs(o['median_time_to_detect_s'])}</b>median time to detect</div>
<div><b>{len(r.campaign['stages_in_largest_incident'])}/{r.campaign['stages']}</b>campaign stages in one incident</div>
</div>
<h2>Per detection</h2>
<table><tr><th>Detection</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th></tr>{rows}</table>
<h2>Scenarios</h2>
<table><tr><th>ID</th><th>Scenario</th><th>Type</th><th>Fired</th><th>Missed</th><th>Time to detect</th></tr>{scn}</table>
<h2>Top incidents</h2>
<table><tr><th>Incident</th><th>Severity</th><th>Risk</th><th>Title</th><th>Alerts</th><th>Techniques</th></tr>{inc}</table>
<h2>Raw numbers</h2><pre>{esc(json.dumps({'overall': o, 'campaign': r.campaign, 'noise': r.noise}, indent=1))}</pre>
</body></html>"""
