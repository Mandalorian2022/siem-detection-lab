"""Value matching for Sigma detection items.

A detection item looks like ``CommandLine|wide|base64offset|contains: IEX``.
This module turns the modifier chain plus the rule value(s) into a single
predicate over the event's field value, following Sigma semantics:

* plain strings match the whole value, case-insensitively, with ``*`` and
  ``?`` wildcards (``\\*`` escapes a literal asterisk);
* a list of values is OR'ed, unless the ``all`` modifier makes it AND;
* transformation modifiers (``wide``, ``base64``, ``base64offset``,
  ``windash``) expand one rule value into one or more concrete patterns;
* encoded patterns (base64) are matched case-sensitively, because base64
  is case-sensitive and folding it would match unrelated text.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

Predicate = Callable[[Any], bool]

TRANSFORMS = {"wide", "utf16le", "utf16be", "utf16", "base64", "base64offset", "windash"}
COMPARE = {"contains", "startswith", "endswith", "re", "cidr", "exists",
           "lt", "lte", "gt", "gte"}
FLAGS = {"all", "i", "m", "s", "cased"}
KNOWN = TRANSFORMS | COMPARE | FLAGS

_DASHES = ("-", "/", "–", "—", "―")


class SigmaModifierError(ValueError):
    """Raised for an unknown or contradictory modifier chain."""


@dataclass(frozen=True)
class Pattern:
    """One concrete string pattern after transformations."""
    text: str
    case_sensitive: bool = False


def _expand(value: str, mods: list[str]) -> list[Pattern]:
    """Apply transformation modifiers in order to produce concrete patterns."""
    raw: list[bytes | str] = [value]
    encoded = False
    for m in mods:
        if m == "windash":
            nxt: list[bytes | str] = []
            for v in raw:
                if not isinstance(v, str) or encoded:
                    raise SigmaModifierError("windash must come before encoding modifiers")
                nxt.extend([v.replace("-", d) for d in _DASHES] if "-" in v else [v])
            raw = nxt
        elif m in ("wide", "utf16le"):
            raw = [v.encode("utf-16-le") if isinstance(v, str) else v for v in raw]
        elif m == "utf16be":
            raw = [v.encode("utf-16-be") if isinstance(v, str) else v for v in raw]
        elif m == "utf16":
            raw = [v.encode("utf-16") if isinstance(v, str) else v for v in raw]
        elif m == "base64":
            raw = [base64.b64encode(v if isinstance(v, bytes) else v.encode()).decode()
                   for v in raw]
            encoded = True
        elif m == "base64offset":
            out: list[bytes | str] = []
            for v in raw:
                out.extend(base64_offsets(v if isinstance(v, bytes) else v.encode()))
            raw = out
            encoded = True
    pats = []
    for v in raw:
        text = v.decode("latin-1") if isinstance(v, bytes) else v
        pats.append(Pattern(text, case_sensitive=encoded))
    return pats


def base64_offsets(value: bytes) -> list[str]:
    """The three base64 renderings of ``value`` at byte offsets 0, 1 and 2.

    Text embedded in a larger base64 blob can start at any byte alignment,
    which changes its encoding. Trimming the characters that depend on the
    unknown neighbours gives three stable substrings, one of which must
    appear in any base64 blob that contains ``value``.
    """
    start = (0, 2, 3)
    end = (None, -3, -2)
    out = []
    for i in range(3):
        enc = base64.b64encode(b" " * i + value)
        out.append(enc[start[i]:end[(len(value) + i) % 3]].decode())
    return out


def _wildcard_regex(pattern: str, anchor_start: bool, anchor_end: bool) -> str:
    """Translate a Sigma wildcard string into a regex body."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    body = "".join(out)
    return ("^" if anchor_start else "") + body + ("$" if anchor_end else "")


def _string_matcher(pat: Pattern, mode: str) -> Predicate:
    text = pat.text
    if mode == "contains":
        text = f"*{text}*"
    elif mode == "startswith":
        text = f"{text}*"
    elif mode == "endswith":
        text = f"*{text}"
    flags = re.DOTALL | (0 if pat.case_sensitive else re.IGNORECASE)
    has_wild = any(ch in text for ch in "*?")
    if not has_wild:
        if pat.case_sensitive:
            return lambda v: v is not None and str(v) == text
        folded = text.casefold()
        return lambda v: v is not None and str(v).casefold() == folded
    rx = re.compile(_wildcard_regex(text, True, True), flags)
    return lambda v: v is not None and rx.match(str(v)) is not None


def _to_number(v: Any) -> float | None:
    if isinstance(v, bool):
        return float(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def build_predicate(mods: Iterable[str], values: list[Any]) -> Predicate:
    """Compile a modifier chain and its rule values into one predicate."""
    mods = list(mods)
    unknown = [m for m in mods if m not in KNOWN]
    if unknown:
        raise SigmaModifierError(f"unsupported modifier(s): {unknown}")
    compare = [m for m in mods if m in COMPARE]
    if len(compare) > 1:
        raise SigmaModifierError(f"conflicting comparison modifiers: {compare}")
    mode = compare[0] if compare else "equals"
    transforms = [m for m in mods if m in TRANSFORMS]
    want_all = "all" in mods

    preds: list[Predicate] = []
    for value in values:
        if mode == "exists":
            preds.append(_exists_pred(bool(value)))
            continue
        if value is None:
            preds.append(_is_empty)
            continue
        if mode in ("lt", "lte", "gt", "gte"):
            limit = _to_number(value)
            if limit is None:
                raise SigmaModifierError(f"numeric modifier {mode} needs a number, got {value!r}")
            op: dict[str, Callable[[float, float], bool]] = {
                "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b,
                "gt": lambda a, b: a > b, "gte": lambda a, b: a >= b}
            fn = op[mode]

            def num_pred(v: Any, fn=fn, limit=limit) -> bool:
                n = _to_number(v)
                return n is not None and fn(n, limit)
            preds.append(num_pred)
            continue
        if mode == "cidr":
            net = ipaddress.ip_network(str(value), strict=False)

            def cidr_pred(v: Any, net=net) -> bool:
                try:
                    return v is not None and ipaddress.ip_address(str(v)) in net
                except ValueError:
                    return False
            preds.append(cidr_pred)
            continue
        if mode == "re":
            flags = 0
            if "i" in mods:
                flags |= re.IGNORECASE
            if "m" in mods:
                flags |= re.MULTILINE
            if "s" in mods:
                flags |= re.DOTALL
            preds.append(_regex_pred(re.compile(str(value), flags)))
            continue
        if isinstance(value, bool):
            preds.append(_bool_pred(value))
            continue
        if isinstance(value, (int, float)):
            preds.append(_number_pred(float(value)))
            continue
        pats = _expand(str(value), transforms)
        if "cased" in mods:
            pats = [Pattern(p.text, True) for p in pats]
        # a transformed value (e.g. windash, base64offset) matches if any variant does
        preds.append(_any_of([_string_matcher(p, mode) for p in pats]))

    if want_all:
        return _all_of(preds)
    if len(preds) == 1:
        return preds[0]
    return _any_of(preds)


def _is_empty(v: Any) -> bool:
    return v is None or v == ""


def _exists_pred(want: bool) -> Predicate:
    def pred(v: Any) -> bool:
        return (not _is_empty(v)) == want
    return pred


def _regex_pred(rx: re.Pattern[str]) -> Predicate:
    def pred(v: Any) -> bool:
        return v is not None and rx.search(str(v)) is not None
    return pred


def _bool_pred(b: bool) -> Predicate:
    def pred(v: Any) -> bool:
        return v is b or str(v).casefold() == str(b).casefold()
    return pred


def _number_pred(n: float) -> Predicate:
    def pred(v: Any) -> bool:
        return v is not None and _to_number(v) == n
    return pred


def _any_of(preds: list[Predicate]) -> Predicate:
    if len(preds) == 1:
        return preds[0]

    def pred(v: Any) -> bool:
        return any(p(v) for p in preds)
    return pred


def _all_of(preds: list[Predicate]) -> Predicate:
    def pred(v: Any) -> bool:
        return all(p(v) for p in preds)
    return pred


def expand_for_backend(mods: Iterable[str], value: Any) -> list[Pattern]:
    """Concrete patterns for one rule value, for query backends."""
    return _expand(str(value), [m for m in mods if m in TRANSFORMS])
