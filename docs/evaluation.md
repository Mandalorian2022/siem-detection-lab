# How the numbers are produced, and what they do not mean

## Ground truth

`generate` writes three files. `events.jsonl` and `world.json` are what
detection sees. `truth.json` maps each labeled event id to the scenario
that produced it and lists, per scenario, the detections a tuned SOC
should expect. Nothing in the event stream says which events are
scenario events; a test asserts that.

## Scoring

For every scenario and every detection it expects:

| Outcome | Meaning |
|---|---|
| TP | an alert from that detection cites an event of the scenario |
| FN | none does, and the scenario is not a documented gap |
| benign TP | the scenario is benign, expected the detection, and it fired — the rule is right, the analyst still pays |
| extra | a detection the scenario did not list fired on it (attack scenarios only) — bonus coverage, reported but not scored |
| FP | a detection fired on a benign scenario that did not expect it, **or** on baseline traffic with no scenario at all |

Precision and recall follow. `--strict` makes `evaluate` exit non-zero on
any FN or any baseline alert, and CI runs it on two seeds, so a change
that regresses either fails the build.

A multi-stage campaign is one intrusion. An alert whose evidence falls in
one stage counts for the neighbouring stage that expects the same
detection: an attacker who signs in from Frankfurt at the end of an MFA
fatigue run and is then seen alongside the real user is one travel
event, not two.

## Time to detect

Measured from the scenario's first event to the first evidence event of
the first expected alert. For single-event rules it is zero by
construction; for correlations it is the time to cross the threshold.

## What the numbers do not say

- **They describe this scenario set.** Recall of 1.0 means every
  scenario the lab defines is caught, not that these rules catch every
  attack. The distributed low-rate spray (A04) is in the set precisely
  to show a documented miss.
- **Zero baseline false positives is by construction and by allowlist.**
  The baseline includes the traffic that usually hurts (mobile-carrier
  geolocation, a vendor licence check that looks like a beacon, a
  nightly backup, a script with an expired password, typo bursts at
  8 a.m.), and the rules survive it because the world carries the
  allowlists and change windows a real SOC would have to build. The
  benign look-alike scenarios that *do* fire are the honest measure of
  analyst load.
- **Thresholds are illustrative.** Every threshold is a named constant
  with a comment on why. A real environment tunes them from its own
  baseline.
- **GeoIP and threat intel are simulated.** Real feeds are noisier and
  later.
