# SIEM Detection Lab

[![ci](https://github.com/Mandalorian2022/siem-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Mandalorian2022/siem-detection-lab/actions/workflows/ci.yml)

A detection-engineering lab you can run end to end in under a minute: a
from-scratch **Sigma rule engine** with correlation rules, four
**behavioural analytics** that per-event rules cannot express, **risk-based
incident correlation** that rebuilds a multi-stage intrusion from alerts
raised by unrelated rules, and an **evaluation harness** that scores all of
it against labeled ground truth, including the benign look-alikes that
produce real-world false positives.

Everything is synthetic and reproducible: a simulated organisation of
forty identities and a working week of identity and network telemetry,
with no real hosts, accounts, addresses or logs anywhere in the repository.
The numbers below come from running the code here, and CI fails if they
regress.

```bash
pip install -e ".[dev]"
siemlab all --seed 7 --strict      # generate -> validate -> detect -> evaluate
open build/report.html
```

## What it detects

| Detection | Kind | ATT&CK |
|---|---|---|
| Password spray from a single address | correlation (`value_count`) | T1110.003 |
| Brute force against one account, and brute force followed by success | correlation (`event_count` → `temporal_ordered`) | T1110.001, T1078.004 |
| Slow brute force from rotating addresses | correlation, 4 h window | T1110.001 |
| MFA fatigue, and fatigue followed by approval | correlation (`event_count` → `temporal_ordered`) | T1621, T1078.004 |
| Successful sign-in through a known anonymiser | Sigma, threat-intel enrichment | T1090.003 |
| Privileged sign-in from a never-seen country | Sigma, identity enrichment | T1078.004 |
| Impossible travel, mobile-carrier aware | behavioural analytic | T1078.004 |
| Privileged interactive logon out of hours without an approved change | Sigma, change-window enrichment | T1078.002 |
| Failed logons across many hosts from one source | correlation (`value_count`) | T1110.003, T1021 |
| Remote desktop logon to a server from the internet | Sigma | T1133, T1021.001 |
| Periodic connections to an external host (beaconing) | behavioural analytic, sliding window | T1071.001 |
| Burst of random-looking non-existent domains (DGA) | behavioural analytic, entropy scoring | T1568.002 |
| High-volume long-label TXT queries (tunnelling) | correlation over a Sigma building block | T1071.004 |
| Large outbound transfer to a new destination | behavioural analytic | T1048 |
| Threat-intel hits on DNS queries and connections | Sigma | T1071 |

Rules live in [`rules/`](rules) as standard Sigma YAML, including Sigma v2
correlation rules, and export to Sentinel KQL and Splunk SPL with
`siemlab export`.

## What it is tested against

Twenty-two attack scenarios and nine benign look-alikes, plus a six-stage
account-takeover campaign (spray → MFA fatigue → attacker session alongside
the real user → beaconing from the victim's workstation → known-bad lookup →
exfiltration) whose stages share only an identity and that identity's
laptop. The benign set is the point of the exercise:

- a user mistyping a password five times at 8 a.m.,
- a phone whose carrier address geolocates two states away,
- an admin working at 11 p.m. inside an approved change window, and one at
  2 a.m. without a ticket,
- an inventory script holding an expired admin password,
- a nightly backup to a provider nobody allowlisted yet,
- a vendor licence check every five minutes that is statistically a beacon,
- an endpoint agent doing reputation lookups over long TXT queries,
- a traveller in London whose roaming phone still homes to Phoenix.

Some of those should fire and some must not; the ground truth says which.
One attack, a distributed spray of two or three accounts per address across
thirty addresses, is included as a **documented gap**: nothing in this rule
set can see it, and the report says so instead of hiding it.

<!-- results:start -->
## Measured results

Seed 7: 68,281 events over five days, 41 alerts, 21 incidents (8.2 alerts/day).

| | Value |
|---|---:|
| Attack scenarios detected | 21 / 21 (+1 documented gap) |
| Precision / recall (per expected detection) | 1.000 / 1.000 |
| Alerts raised on plain baseline traffic | 0 |
| Benign look-alikes that correctly fired (analyst noise) | 5 |
| Extra detections on attacks beyond the expected rule | 7 |
| Median time to detect | 0 s |
| Campaign stages joined into one incident | 5 / 6 (risk 100) |

### Per detection

| Detection | Kind | Level | TP | FP | FN | Precision | Recall |
|---|---|---|---:|---:|---:|---:|---:|
| `beaconing` | analytic | high | 3 | 0 | 0 | 1.000 | 1.000 |
| `dga_burst` | analytic | high | 1 | 0 | 0 | 1.000 | 1.000 |
| `dns_long_label_query` | correlation | high | 1 | 0 | 0 | 1.000 | 1.000 |
| `dns_query_intel_domain` | detection | high | 2 | 0 | 0 | 1.000 | 1.000 |
| `exfil_volume` | analytic | high | 3 | 0 | 0 | 1.000 | 1.000 |
| `impossible_travel` | analytic | high | 3 | 0 | 0 | 1.000 | 1.000 |
| `net_conn_intel_destination` | detection | high | 1 | 0 | 0 | 1.000 | 1.000 |
| `signin_anonymizer_success` | detection | high | 1 | 0 | 0 | 1.000 | 1.000 |
| `signin_bruteforce_account` | correlation | medium | 1 | 0 | 0 | 1.000 | 1.000 |
| `signin_bruteforce_then_success` | correlation | critical | 1 | 0 | 0 | 1.000 | 1.000 |
| `signin_mfa_fatigue` | correlation | high | 2 | 0 | 0 | 1.000 | 1.000 |
| `signin_mfa_fatigue_then_success` | correlation | critical | 2 | 0 | 0 | 1.000 | 1.000 |
| `signin_password_spray` | correlation | high | 2 | 0 | 0 | 1.000 | 1.000 |
| `signin_privileged_new_country` | detection | high | 1 | 0 | 0 | 1.000 | 1.000 |
| `signin_slow_bruteforce` | correlation | medium | 1 | 0 | 0 | 1.000 | 1.000 |
| `win_failed_logons_many_hosts` | correlation | high | 2 | 0 | 0 | 1.000 | 1.000 |
| `win_privileged_logon_offhours` | detection | medium | 2 | 0 | 0 | 1.000 | 1.000 |
| `win_rdp_from_external` | detection | critical | 1 | 0 | 0 | 1.000 | 1.000 |

### Scenarios

| Scenario | Type | Expected | Result | Time to detect |
|---|---|---|---|---:|
| A01 password spray from one address | attack | `signin_password_spray` | detected | 0 s |
| A02 brute force then successful sign-in | attack | `signin_bruteforce_account`, `signin_bruteforce_then_success` | fired + unexpected: impossible_travel, signin_slow_bruteforce | 0 s |
| A03 slow brute force from rotating addresses | attack | `signin_slow_bruteforce` | detected | 0 s |
| A04 distributed low-rate spray | attack | nothing | documented gap | n/a |
| A05 MFA fatigue then approval | attack | `signin_mfa_fatigue`, `signin_mfa_fatigue_then_success` | fired + unexpected: impossible_travel | 0 s |
| A06 session from another continent | attack | `impossible_travel` | detected | 0 s |
| A07 sign-in through an anonymising proxy | attack | `signin_anonymizer_success` | fired + unexpected: impossible_travel | 0 s |
| A08 admin sign-in from a new country | attack | `signin_privileged_new_country` | fired + unexpected: impossible_travel | 0 s |
| A09 privileged logon at 3 a.m. without a change | attack | `win_privileged_logon_offhours` | detected | 0 s |
| A10 failed logons across many servers from one workstation | attack | `win_failed_logons_many_hosts` | detected | 0 s |
| A11 remote desktop logon from the internet | attack | `win_rdp_from_external` | detected | 0 s |
| A12 periodic callbacks to an unknown host | attack | `beaconing` | detected | 0 s |
| A13 burst of algorithmically generated domains | attack | `dga_burst` | detected | 0 s |
| A14 high-volume long-label TXT queries | attack | `dns_long_label_query` | detected | 0 s |
| A15 gigabytes uploaded to a new destination | attack | `exfil_volume` | detected | 0 s |
| A16 contact with a known-bad domain and address | attack | `dns_query_intel_domain`, `net_conn_intel_destination` | detected | 0 s |
| B01 five typos then success | benign | nothing | silent (correct) |  |
| B02 phone geolocates to the next state | benign | nothing | silent (correct) |  |
| B03 night maintenance under an approved change | benign | nothing | silent (correct) |  |
| B04 emergency fix without a ticket | benign | `win_privileged_logon_offhours` | fired (benign true positive) |  |
| B05 inventory script with an expired password | benign | `win_failed_logons_many_hosts` | fired (benign true positive) |  |
| B06 first night on a new backup provider | benign | `exfil_volume` | fired (benign true positive) |  |
| B07 vendor licence check every five minutes | benign | `beaconing` | fired (benign true positive) |  |
| B08 antivirus reputation lookups over DNS | benign | nothing | silent (correct) |  |
| B09 traveller in London, phone still homes to Phoenix | benign | `impossible_travel` | fired (benign true positive) |  |
| C01.1 spray that includes the victim | attack | `signin_password_spray` | detected | 0 s |
| C01.2 MFA fatigue until approval | attack | `signin_mfa_fatigue`, `signin_mfa_fatigue_then_success` | fired + unexpected: impossible_travel | 0 s |
| C01.3 attacker session alongside the real user | attack | `impossible_travel` | detected | 0 s |
| C01.4 workstation starts calling back | attack | `beaconing` | fired + unexpected: exfil_volume | 0 s |
| C01.5 lookup of a listed domain | attack | `dns_query_intel_domain` | detected | 0 s |
| C01.6 staged data leaves over the callback channel | attack | `exfil_volume` | detected | 0 s |

### ATT&CK coverage

- **initial access**: T1021.001, T1078.004, T1090.003, T1110.001, T1133, T1621
- **persistence**: T1078.002
- **credential access**: T1021, T1078.004, T1110.001, T1110.003, T1621
- **lateral movement**: T1021, T1021.001, T1110.003, T1133
- **command and control**: T1071, T1071.001, T1071.004, T1078.004, T1090.003, T1568.002
- **exfiltration**: T1048, T1071.004
<!-- results:end -->

## Design decisions worth reading

- **Attribution by evidence, not by time window.** An alert counts for a
  scenario only if it cites an event that scenario generated. A rule that
  fires constantly cannot score by accident.
- **Building blocks.** Rules marked `x-building-block: true` never alert;
  they exist to feed correlations. A sign-in failure is not an alert. Ten
  of them from one address in ten minutes is.
- **Allowlists over thresholds.** When the backup job tripped the
  exfiltration analytic, the fix was to record the backup destination, not
  to raise the byte threshold for everyone. The world carries the
  allowlists and change windows a real SOC has to maintain, and the rules
  are only as quiet as that context is complete.
- **Streaming beacon detection.** The periodicity test runs on a sliding
  window of two dozen connections, not the whole history, because an
  implant that beacons for hours and then starts moving data changes its
  own traffic pattern. A whole-series statistic lets the exfiltration hide
  the beacon that preceded it; the window catches the beacon first.
- **Mobile-carrier-aware travel.** Impossible travel ignores a mobile hop
  that stays inside one country, which removes the daily remote-worker
  false positive, and still fires on the traveller abroad whose phone homes
  to a carrier at home, which is listed as a benign true positive because
  an analyst still has to look.
- **Diminishing returns in incident risk.** The same rule firing six times
  is worth less than six different rules firing once. The campaign reaches
  risk 100 from five distinct detections; a noisy single rule cannot.

## Layout

```
rules/                 Sigma detection and correlation rules (identity, windows, network)
src/siemlab/sigma/     Sigma implementation: modifiers, condition parser, pipeline, loader, engine
src/siemlab/analytics/ impossible travel, beaconing, DGA burst, exfiltration volume
src/siemlab/simulate/  the synthetic organisation, benign baseline, labeled scenarios
src/siemlab/enrich.py  GeoIP, threat intel, identity, allowlist and change-window enrichment
src/siemlab/incidents.py  entity-linked, risk-scored incident correlation
src/siemlab/evaluate.py   scoring against ground truth; report.py renders it
src/siemlab/backends/  KQL and SPL export
tests/                 unit, property-based (Hypothesis) and end-to-end on two seeds
docs/                  architecture, evaluation method, how to add a detection
```

## Honest limits

This is a lab. Its recall is measured against scenarios it defines, its
false-positive rate against a baseline it generates, and its thresholds
are illustrative constants with comments rather than values tuned from a
real environment. GeoIP and threat intel are simulated. The point is the
method, the measurement and the discipline of documenting the gap, not a
claim that these fifteen rules would hold up unchanged in production.

## Provenance

Built with AI assistance under explicit requirements. The design
decisions, thresholds, trade-offs and validation are documented in this
README, in `docs/`, and in the rules and code themselves. The measured
results are produced by the code in this repository on every CI run.

## License

MIT. See `LICENSE`.
