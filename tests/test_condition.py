import pytest

from siemlab.sigma.condition import SigmaConditionError, evaluate, parse_condition, referenced

NAMES = ["selection", "filter_vpn", "night", "late", "sel_a", "sel_b"]


def ev(text, **values):
    node = parse_condition(text, NAMES)
    vals = {n: False for n in NAMES}
    vals.update(values)
    return evaluate(node, vals)


def test_precedence_and_before_or():
    assert ev("selection and night or late", late=True)
    assert not ev("selection and (night or late)", late=True)
    assert ev("selection and (night or late)", selection=True, late=True)


def test_not_binds_tightest():
    assert ev("not selection and late", late=True)
    assert not ev("not (selection and late)", selection=True, late=True)
    assert ev("not not selection", selection=True)


def test_quantifiers():
    assert ev("1 of sel_*", sel_b=True)
    assert not ev("all of sel_*", sel_b=True)
    assert ev("all of sel_*", sel_a=True, sel_b=True)
    assert ev("any of them", night=True)


def test_them_excludes_underscore_private_names():
    node = parse_condition("all of them", ["a", "_helper"])
    assert referenced(node) == {"a"}


def test_referenced_names():
    node = parse_condition("selection and not filter_vpn and (night or late)", NAMES)
    assert referenced(node) == {"selection", "filter_vpn", "night", "late"}


@pytest.mark.parametrize("bad", ["selection and", "and selection", "(selection", "selection)",
                                 "unknown_name", "1 of nothing_*", "selection selection",
                                 "selection && late"])
def test_rejects_malformed(bad):
    with pytest.raises(SigmaConditionError):
        parse_condition(bad, NAMES)
