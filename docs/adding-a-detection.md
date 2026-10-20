# Adding a detection

The loop is: write the behaviour, write the rule, prove the rule.

## 1. Add a scenario

In `src/siemlab/simulate/scenarios.py`, add a function decorated with
`@scenario` that returns `(Scenario, events)`. Give it:

- an id (`A17` for an attack, `B10` for a benign look-alike),
- the ATT&CK techniques it represents,
- `expected`: the detection names that should fire, or `[]` for a benign
  scenario that must stay silent,
- `known_gap=True` if you are adding it to document a miss.

Add a benign twin whenever you can think of one. A rule that has never
been run against the thing it is most likely to misfire on is not done.

## 2. Write the rule

**Sigma detection rule** (`rules/<area>/*.yml`): standard Sigma. The
`logsource` must resolve through `sigma/pipeline.py`; add a mapping there
if you are introducing a new dataset. Enriched fields (`user.privileged`,
`source.asn.type`, `change.approved`, ...) can be used directly.

**Correlation rule**: a `correlation:` document referencing other rules
by `name`. Mark the rules it consumes with `x-building-block: true` if
they should not alert on their own.

**Behavioural analytic** (`src/siemlab/analytics/`): subclass `Analytic`,
implement `observe` and `finish`, add it to `ANALYTICS`. Use this only
when the logic genuinely needs state a Sigma rule cannot hold.

Every rule needs `tags` with ATT&CK tactic and technique, a description
that says what it catches *and why the threshold is what it is*, and a
`falsepositives` entry if you know of one.

## 3. Prove it

```bash
siemlab validate
pytest
siemlab --build build all --seed 7 --strict
siemlab --build build all --seed 23 --strict
```

`--strict` fails on a missed expectation or on any alert raised by
baseline traffic. If your rule fires on the baseline, the fix is usually
an allowlist or an enrichment field, not a bigger threshold.

Then read `build/report.md` and confirm the scenario shows the result you
intended, including the benign twin staying silent (or firing, if you
decided that is correct, in which case list the detection in its
`expected` so the report counts it as a benign true positive).

## 4. Export it

```bash
siemlab export --backend kql
siemlab export --backend splunk
```

Detection rules convert to Sentinel KQL and Splunk SPL. Correlation rules
do not: windowing semantics differ per product, and the right target is
the platform's own correlation feature.
