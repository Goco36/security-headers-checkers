"""Tests for checker.evaluate.

Run with:  python -m pytest -v
"""

from hdrcheck.checker import Status, evaluate


def by_header(findings):
    return {f.header: f for f in findings}


def test_all_rules_missing_on_empty_response():
    findings = by_header(evaluate({}))
    assert findings["Strict-Transport-Security"].status == Status.MISSING
    assert findings["Content-Security-Policy"].status == Status.MISSING


def test_header_names_are_case_insensitive():
    findings = by_header(evaluate({"x-content-type-options": "nosniff"}))
    assert findings["X-Content-Type-Options"].status == Status.OK


def test_hsts_with_short_max_age_is_misconfigured():
    findings = by_header(evaluate({"Strict-Transport-Security": "max-age=60"}))
    assert findings["Strict-Transport-Security"].status == Status.MISCONFIGURED


def test_hsts_with_long_max_age_is_ok():
    findings = by_header(evaluate({"Strict-Transport-Security": "max-age=31536000"}))
    assert findings["Strict-Transport-Security"].status == Status.OK


def test_wrong_nosniff_value_is_misconfigured():
    findings = by_header(evaluate({"X-Content-Type-Options": "yes"}))
    assert findings["X-Content-Type-Options"].status == Status.MISCONFIGURED


def test_server_header_is_reported_as_leak():
    findings = by_header(evaluate({"Server": "Apache/2.4.1"}))
    assert findings["Server"].status == Status.LEAK


def test_hsts_with_non_numeric_max_age_is_misconfigured():
    findings = by_header(evaluate({"Strict-Transport-Security": "max-age=²"}))
    assert findings["Strict-Transport-Security"].status == Status.MISCONFIGURED
