import base64

import pytest
from hypothesis import given
from hypothesis import strategies as st

from siemlab.sigma.modifiers import SigmaModifierError, base64_offsets, build_predicate


def p(mods, *values):
    return build_predicate(mods, list(values))


def test_plain_equals_is_case_insensitive():
    assert p([], "Admin")("admin")
    assert not p([], "Admin")("administrator")


def test_wildcards():
    assert p([], "*.bad.example")("c2.bad.example")
    assert p([], "host??")("host01")
    assert not p([], "host??")("host001")
    assert p([], r"literal\*star")("literal*star")
    assert not p([], r"literal\*star")("literalXstar")


def test_contains_startswith_endswith():
    assert p(["contains"], "evil")("so EVIL much")
    assert p(["startswith"], "svc-")("svc-backup")
    assert not p(["startswith"], "svc-")("x svc-backup")
    assert p(["endswith"], ".example")("a.b.example")


def test_list_is_or_and_all_is_and():
    assert p([], "a", "b")("B")
    assert not p(["contains", "all"], "a", "b")("only a")
    assert p(["contains", "all"], "a", "b")("a and b")


def test_numeric_and_comparisons():
    assert p([], 4624)("4624")
    assert p(["gte"], 21)(21)
    assert p(["lt"], 6)("5")
    assert not p(["lt"], 6)("6")
    assert not p(["lt"], 6)("not a number")


def test_bool_and_null():
    assert p([], True)(True)
    assert p([], True)("true")
    assert not p([], True)(False)
    assert p([], None)(None)
    assert p([], None)("")
    assert not p([], None)("x")


def test_exists():
    assert p(["exists"], True)("anything")
    assert not p(["exists"], True)(None)
    assert p(["exists"], False)(None)


def test_regex_flags():
    assert p(["re"], r"^adm-\w+$")("adm-kim")
    assert not p(["re"], r"^ADM")("adm-kim")
    assert p(["re", "i"], r"^ADM")("adm-kim")


def test_cidr():
    assert p(["cidr"], "10.10.0.0/16")("10.10.1.20")
    assert not p(["cidr"], "10.10.0.0/16")("10.11.1.20")
    assert not p(["cidr"], "10.10.0.0/16")("not-an-ip")


def test_windash_variants():
    pred = p(["windash", "contains"], "-noprofile")
    assert pred("powershell /noprofile")
    assert pred("powershell –noprofile")
    assert not pred("powershell noprofile")


def test_base64_is_case_sensitive_and_wide_encodes_utf16():
    enc = base64.b64encode("Invoke".encode("utf-16-le")).decode()
    assert p(["wide", "base64", "contains"], "Invoke")("xx" + enc + "yy")
    assert not p(["base64", "contains"], "Invoke")(base64.b64encode(b"invoke").decode())


@given(st.binary(min_size=1, max_size=40), st.binary(min_size=0, max_size=12), st.binary(min_size=0, max_size=12))
def test_base64offset_covers_every_alignment(value, prefix, suffix):
    blob = base64.b64encode(prefix + value + suffix).decode()
    assert any(frag in blob for frag in base64_offsets(value))


def test_rejects_unknown_and_conflicting_modifiers():
    with pytest.raises(SigmaModifierError):
        p(["bogus"], "x")
    with pytest.raises(SigmaModifierError):
        p(["contains", "startswith"], "x")
    with pytest.raises(SigmaModifierError):
        p(["base64", "windash"], "a-b")
