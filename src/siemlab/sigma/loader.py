"""Load Sigma rules and Sigma correlation rules from YAML.

Supports one or more YAML documents per file. A document with a
``detection`` block is a detection rule; one with a ``correlation`` block
is a correlation rule (Sigma specification v2: ``event_count``,
``value_count``, ``temporal`` and ``temporal_ordered``).
"""
from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .condition import Node, evaluate, parse_condition, referenced
from .modifiers import Predicate, build_predicate
from .pipeline import map_field, resolve_dataset

EventPredicate = Callable[[dict], bool]
LEVELS = ("informational", "low", "medium", "high", "critical")
_TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class SigmaRuleError(ValueError):
    pass


class _LazySelections(dict):
    """Evaluate a selection only when the condition actually reads it, once."""

    def __init__(self, preds: dict[str, EventPredicate], event: dict):
        super().__init__()
        self._preds, self._event = preds, event

    def __missing__(self, name: str) -> bool:
        value = self._preds[name](self._event)
        self[name] = value
        return value


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    status: str
    description: str
    tags: list[str]
    logsource: dict
    dataset: str
    detection: dict
    falsepositives: list[str]
    name: str | None
    custom: dict[str, Any]
    path: str
    selections: dict[str, EventPredicate] = field(repr=False, default_factory=dict)
    condition: Node | None = field(repr=False, default=None)

    @property
    def kind(self) -> str:
        return "detection"

    def matches(self, event: dict) -> bool:
        assert self.condition is not None
        return evaluate(self.condition, _LazySelections(self.selections, event))


@dataclass
class SigmaCorrelation:
    id: str
    title: str
    level: str
    status: str
    description: str
    tags: list[str]
    type: str
    rules: list[str]
    group_by: list[str]
    timespan: int
    op: str
    threshold: int
    count_field: str | None
    generate: bool
    falsepositives: list[str]
    name: str | None
    custom: dict[str, Any]
    path: str

    @property
    def kind(self) -> str:
        return "correlation"


def parse_timespan(text: str) -> int:
    m = _TIMESPAN.match(str(text).strip())
    if not m:
        raise SigmaRuleError(f"bad timespan {text!r}")
    return int(m.group(1)) * _UNIT[m.group(2)]


def _item_predicate(dataset: str, key: str, value: Any) -> EventPredicate:
    parts = key.split("|")
    fname, mods = parts[0], parts[1:]
    evkey = map_field(dataset, fname)
    values = value if isinstance(value, list) else [value]
    pred: Predicate = build_predicate(mods, values)
    return lambda ev: pred(ev.get(evkey))


def _keyword_predicate(words: list[Any]) -> EventPredicate:
    preds = [build_predicate(["contains"], [w]) for w in words]

    def check(ev: dict) -> bool:
        vals = [v for v in ev.values() if isinstance(v, str)]
        return any(p(v) for p in preds for v in vals)
    return check


def _compile_selection(dataset: str, definition: Any) -> EventPredicate:
    if isinstance(definition, dict):
        items = [_item_predicate(dataset, k, v) for k, v in definition.items()]
        return lambda ev: all(p(ev) for p in items)
    if isinstance(definition, list):
        if all(isinstance(d, dict) for d in definition):
            subs = [_compile_selection(dataset, d) for d in definition]
            return lambda ev: any(p(ev) for p in subs)
        if all(not isinstance(d, (dict, list)) for d in definition):
            return _keyword_predicate(definition)
    raise SigmaRuleError(f"unsupported selection shape: {type(definition).__name__}")


def _common(doc: dict, path: str) -> dict[str, Any]:
    for req in ("title", "id", "level"):
        if req not in doc:
            raise SigmaRuleError(f"{path}: missing required field {req!r}")
    try:
        uuid.UUID(str(doc["id"]))
    except ValueError as e:
        raise SigmaRuleError(f"{path}: id is not a UUID") from e
    if doc["level"] not in LEVELS:
        raise SigmaRuleError(f"{path}: level must be one of {LEVELS}")
    return {
        "id": str(doc["id"]),
        "title": doc["title"],
        "level": doc["level"],
        "status": doc.get("status", "experimental"),
        "description": doc.get("description", ""),
        "tags": list(doc.get("tags", [])),
        "falsepositives": list(doc.get("falsepositives", [])),
        "name": doc.get("name"),
        "custom": {k: v for k, v in doc.items() if k.startswith("x-")},
        "path": path,
    }


def build_rule(doc: dict, path: str = "<memory>") -> SigmaRule:
    base = _common(doc, path)
    det = dict(doc["detection"])
    cond_text = det.pop("condition", None)
    if cond_text is None:
        raise SigmaRuleError(f"{path}: detection has no condition")
    if isinstance(cond_text, list):
        cond_text = " or ".join(f"({c})" for c in cond_text)
    dataset = resolve_dataset(doc.get("logsource", {}))
    rule = SigmaRule(logsource=dict(doc.get("logsource", {})), dataset=dataset,
                     detection=dict(doc["detection"]), **base)
    rule.selections = {name: _compile_selection(dataset, d) for name, d in det.items()}
    rule.condition = parse_condition(str(cond_text), list(det))
    unused = set(det) - referenced(rule.condition)
    if unused:
        raise SigmaRuleError(f"{path}: selections never used by the condition: {sorted(unused)}")
    return rule


def build_correlation(doc: dict, path: str = "<memory>") -> SigmaCorrelation:
    base = _common(doc, path)
    c = doc["correlation"]
    ctype = c.get("type")
    if ctype not in ("event_count", "value_count", "temporal", "temporal_ordered"):
        raise SigmaRuleError(f"{path}: unsupported correlation type {ctype!r}")
    cond = c.get("condition", {})
    op, threshold, cfield = "gte", len(c.get("rules", [])), None
    if ctype in ("event_count", "value_count"):
        ops = [k for k in cond if k in ("gte", "gt")]
        if len(ops) != 1:
            raise SigmaRuleError(f"{path}: condition needs exactly one of gte/gt")
        op, threshold = ops[0], int(cond[ops[0]])
        cfield = cond.get("field")
        if ctype == "value_count" and not cfield:
            raise SigmaRuleError(f"{path}: value_count needs condition.field")
    return SigmaCorrelation(
        type=ctype, rules=list(c["rules"]), group_by=list(c.get("group-by", [])),
        timespan=parse_timespan(c["timespan"]), op=op, threshold=threshold,
        count_field=cfield, generate=bool(c.get("generate", False)), **base)


def load_file(path: Path) -> list[SigmaRule | SigmaCorrelation]:
    out: list[SigmaRule | SigmaCorrelation] = []
    with open(path, encoding="utf-8") as f:
        for doc in yaml.safe_load_all(f):
            if not doc:
                continue
            if "correlation" in doc:
                out.append(build_correlation(doc, str(path)))
            elif "detection" in doc:
                out.append(build_rule(doc, str(path)))
            else:
                raise SigmaRuleError(f"{path}: document is neither a rule nor a correlation")
    return out


def load_rules(directory: Path) -> list[SigmaRule | SigmaCorrelation]:
    rules: list[SigmaRule | SigmaCorrelation] = []
    for p in sorted(Path(directory).rglob("*.yml")):
        rules.extend(load_file(p))
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise SigmaRuleError(f"duplicate rule ids: {sorted(dupes)}")
    return rules
