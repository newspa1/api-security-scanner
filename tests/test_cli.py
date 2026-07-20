"""Tests for cli.py's --mass-assignment-fields parsing."""

from __future__ import annotations

from apisec.cli import _infer_value_type, _parse_fields_file, _parse_mass_assignment_fields


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


# ---- @file support --------------------------------------------------------

def test_parse_fields_file_json_object(tmp_path):
    path = tmp_path / "fields.json"
    path.write_text('{"subscription_tier": "premium", "credit_limit": 999999, "is_verified": true}')
    assert _parse_fields_file(str(path)) == [
        ("subscription_tier", "premium"),
        ("credit_limit", 999999),
        ("is_verified", True),
    ]


def test_parse_fields_file_name_equals_value_lines(tmp_path):
    path = tmp_path / "fields.txt"
    path.write_text("subscription_tier=premium\ncredit_limit=999999\nis_verified=true\n")
    assert _parse_fields_file(str(path)) == [
        ("subscription_tier", "premium"),
        ("credit_limit", 999999),
        ("is_verified", True),
    ]


def test_parse_fields_file_ignores_blank_lines_and_comments(tmp_path):
    path = tmp_path / "fields.txt"
    path.write_text(
        "# fields found by reading the target's own API docs\n"
        "\n"
        "tenant_id=42\n"
        "\n"
        "# this one grants admin on signup\n"
        "is_admin=true\n"
    )
    assert _parse_fields_file(str(path)) == [("tenant_id", 42), ("is_admin", True)]


def test_parse_fields_file_skips_malformed_lines(tmp_path):
    path = tmp_path / "fields.txt"
    path.write_text("valid_field=1\njust a line with no equals sign\nanother_field=2\n")
    assert _parse_fields_file(str(path)) == [("valid_field", 1), ("another_field", 2)]


def test_parse_mass_assignment_fields_at_prefix_reads_json_file(tmp_path):
    path = tmp_path / "fields.json"
    path.write_text('{"tier": "gold"}')
    assert _parse_mass_assignment_fields(f"@{path}") == [("tier", "gold")]


def test_parse_mass_assignment_fields_at_prefix_reads_text_file(tmp_path):
    path = tmp_path / "fields.txt"
    path.write_text("tier=gold\n")
    assert _parse_mass_assignment_fields(f"@{path}") == [("tier", "gold")]


def test_parse_mass_assignment_fields_without_at_prefix_stays_inline():
    # a value that happens to contain "@" mid-string (not as the very first
    # character) must NOT be treated as a file reference
    assert _parse_mass_assignment_fields("email=user@example.com") == [
        ("email", "user@example.com")
    ]
