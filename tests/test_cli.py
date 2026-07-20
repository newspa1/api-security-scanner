"""Tests for cli.py's --mass-assignment-fields parsing."""

from __future__ import annotations

from apisec.cli import _infer_value_type, _parse_mass_assignment_fields


def test_infer_value_type_bool():
    assert _infer_value_type("true") is True
    assert _infer_value_type("false") is False
    assert _infer_value_type("True") is True  # case-insensitive


def test_infer_value_type_int():
    assert _infer_value_type("999999") == 999999
    assert isinstance(_infer_value_type("999999"), int)


def test_infer_value_type_float():
    assert _infer_value_type("0.01") == 0.01
    assert isinstance(_infer_value_type("0.01"), float)


def test_infer_value_type_falls_back_to_string():
    assert _infer_value_type("premium") == "premium"


def test_parse_mass_assignment_fields_single_pair():
    assert _parse_mass_assignment_fields("subscription_tier=premium") == [
        ("subscription_tier", "premium")
    ]


def test_parse_mass_assignment_fields_multiple_pairs_mixed_types():
    result = _parse_mass_assignment_fields("credit_limit=999999,is_verified=true,tier=gold")
    assert result == [
        ("credit_limit", 999999),
        ("is_verified", True),
        ("tier", "gold"),
    ]


def test_parse_mass_assignment_fields_strips_whitespace():
    assert _parse_mass_assignment_fields(" tenant_id = 42 ") == [("tenant_id", 42)]


def test_parse_mass_assignment_fields_skips_malformed_entries():
    # no "=" -- skipped rather than raising, so one typo doesn't kill the rest
    result = _parse_mass_assignment_fields("valid_field=1,justAWord,another_field=2")
    assert result == [("valid_field", 1), ("another_field", 2)]


def test_parse_mass_assignment_fields_empty_string():
    assert _parse_mass_assignment_fields("") == []
