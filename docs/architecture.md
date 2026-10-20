# Architecture

```
                 rules/*.yml                      src/siemlab/analytics/
                (Sigma + correlations)           (stateful behavioural logic)
                        |                                   |
 events.jsonl --> enrich.py --> sigma/engine.py -------+----+--> alerts.jsonl
 world.json        |            per-event rules,       |
                   |            windowed correlations   v
                   |                             incidents.py  --> incidents.json
                   |                       (entity-linked, risk-scored)
                   v
            truth.json  (never read before evaluate.py)
                   |
                   v
            evaluate.py --> report.{json,md,html}
```

## Event schema

Events are flat dictionaries with ECS-style dotted keys. Four datasets are
produced by the simulator and consumed by the rules:

| `event.dataset` | Source it imitates | Key fields |
|---|---|---|
| `identity.signin` | cloud identity provider sign-in log | `user.name`, `source.ip`, `identity.result_code`, `identity.mfa_result` |
| `windows.security` | Windows Security log (4624 / 4625) | `host.name`, `user.name`, `source.ip`, `winlog.logon.type` |
| `network.dns` | resolver query log | `host.name`, `dns.question.name`, `dns.question.type`, `dns.response_code` |
| `network.connection` | flow / firewall log | `host.name`, `destination.ip`, `destination.port`, `source.bytes` |

`enrich.py` adds the context a SOC would join on: local time, identity
attributes from the directory, GeoIP, threat-intel verdicts, allowlist
membership, and change-window approval. Rules read the enriched event.

## Sigma implementation

`src/siemlab/sigma/` is a from-scratch implementation of the parts of the
Sigma specification the lab needs:

- **`modifiers.py`** — value matching: wildcards, `contains` / `startswith`
  / `endswith`, `re` with flags, `cidr`, numeric comparisons, `exists`,
  `all`, `cased`, and the transformations `wide`, `base64`, `base64offset`
  and `windash`. `base64offset` is property-tested: for any value and any
  byte alignment, one of the three fragments appears in the encoding.
- **`condition.py`** — a recursive-descent parser for condition
  expressions with correct precedence (`not` > `and` > `or`), parentheses,
  and `1 of` / `any of` / `all of` with wildcard patterns and `them`.
  Selections are evaluated lazily and at most once per event.
- **`pipeline.py`** — the processing pipeline: maps Sigma's generic field
  names (`TargetUserName`, `IpAddress`) onto this schema and resolves a
  rule's `logsource` to a dataset, so a rule is only ever run against the
  log source it was written for.
- **`loader.py`** — YAML loading and validation (UUID ids, levels, unused
  selections, unknown modifiers), multi-document files, and the lab's one
  extension: `x-building-block: true` marks a rule that never alerts on its
  own and exists only to feed correlations.
- **`engine.py`** — runs detection rules per event, then correlation rules
  in dependency order so a correlation can reference another correlation.
  Implements `event_count`, `value_count`, `temporal` and
  `temporal_ordered` with sliding windows keyed by `group-by`.

## Behavioural analytics

Some detections need state across many events and do not fit a per-event
rule: distance between consecutive sign-ins, periodicity of connections,
randomness of domain names over a window, bytes summed over a day. Each
lives in `analytics/` as a class with `observe(event)` and `finish()`,
so it could sit behind a streaming pipeline without changes. Thresholds
are named constants at the top of each file.

## Incidents

`incidents.py` links alerts that share an entity (account, host, source
or destination address) within 24 hours, plus the directory's
identity → workstation edge, into incidents with a union-find. Risk is
the sum of alert risk with diminishing returns per repeated rule, capped
at 100. Generic entities (the corporate egress, the jump host, the
monitoring server) are excluded from linking because they would join
unrelated activity into one blob.

## Evaluation

Attribution is by evidence: an alert belongs to the scenario that produced
any event it cites. This is stricter than overlapping time windows and
cannot be gamed by a rule that fires often. See `docs/evaluation.md`.
