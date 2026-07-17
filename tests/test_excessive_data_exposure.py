"""Part 2 tests: the hybrid Excessive Data Exposure check.

Each of the three detection layers is unit-tested in isolation (they're pure
functions), then the confidence scoring, then an end-to-end integration test
against the demo API. This is the "correctness" half of the plan's per-part
contract: prove it finds the true positive AND doesn't fire on clean data."""

import pytest

from apisec.checks.excessive_data_exposure import (
    ExcessiveDataExposureCheck,
    _collect_signals,
    _declared_property_names,
    _name_looks_sensitive,
    _severity_for,
    _shannon_entropy,
    _value_looks_secret,
)
from apisec.checks.base import ScanContext, Severity
from apisec.spec_loader import Endpoint


# ---- Layer 1: name heuristic --------------------------------------------------

@pytest.mark.parametrize("name", ["password", "password_hash", "access_token", "ssn", "api_key"])
def test_layer1_flags_sensitive_names(name):
    assert _name_looks_sensitive(name) is True


@pytest.mark.parametrize("name", ["id", "name", "email", "created_at"])
def test_layer1_ignores_innocuous_names(name):
    assert _name_looks_sensitive(name) is False


# ---- Layer 2: value shape + entropy ------------------------------------------

def test_layer2_detects_bcrypt_regardless_of_field_name():
    # The exact blind spot the user raised: a secret under an innocent name.
    assert _value_looks_secret("$2b$12$abcdefghijklmnopqrstuv") == "bcrypt-hash"


def test_layer2_detects_jwt():
    jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123_-"
    assert _value_looks_secret(jwt_like) == "jwt"


def test_layer2_detects_high_entropy_string():
    assert _value_looks_secret("A9f4Q2xZ7bV1kP0wR8sT3mN6") == "high-entropy"


def test_layer2_ignores_normal_values():
    assert _value_looks_secret("Alice") is None
    assert _value_looks_secret("alice@example.com") is None
    assert _value_looks_secret(42) is None


def test_shannon_entropy_ordering():
    assert _shannon_entropy("aaaaaaaa") < _shannon_entropy("A9f4Q2xZ7bV1kP0w")


# ---- Layer 3: schema conformance ---------------------------------------------

def test_layer3_flags_undeclared_field():
    schema = {"type": "object", "properties": {"id": {}, "name": {}}}
    declared = _declared_property_names(schema)
    body = {"id": 1, "name": "Alice", "password_hash": "x"}
    signals = _collect_signals(body, declared)
    hits = {s.path: s.reasons for s in signals}
    assert "undeclared-in-schema" in hits["password_hash"]
    # A declared, innocuous field should not be flagged by Layer 3.
    assert "name" not in hits


def test_layer3_silent_without_schema():
    # No declared schema -> Layer 3 must not guess (returns None -> no undeclared).
    assert _declared_property_names(None) is None
    signals = _collect_signals({"anything": "value"}, None)
    for s in signals:
        assert "undeclared-in-schema" not in s.reasons


# ---- Confidence scoring ------------------------------------------------------

def test_multiple_layers_raise_severity_to_high():
    schema = {"type": "object", "properties": {"id": {}}}
    declared = _declared_property_names(schema)
    # password_hash: sensitive name + bcrypt value + undeclared = 3 reasons.
    body = {"id": 1, "password_hash": "$2b$12$abcdefghijklmnopqrstuv"}
    signals = _collect_signals(body, declared)
    assert _severity_for(signals) == Severity.HIGH


# ---- Integration: against the live demo API ----------------------------------
# Uses the shared `demo_sessions` fixture (tests/conftest.py), which logs the
# two seeded demo users in and hands back TestClient-backed sessions.

def test_integration_finds_password_hash_leak(demo_sessions):
    session_a, _ = demo_sessions
    ctx = ScanContext(base_url="http://testserver", session_a=session_a)
    ep = Endpoint(path="/users/{user_id}", method="GET", operation_id="read_user")
    findings = ExcessiveDataExposureCheck().run(ep, ctx)

    assert len(findings) == 1
    assert findings[0].check_id == "API3:2023"
    assert "password_hash" in findings[0].evidence


def test_integration_me_is_clean(demo_sessions):
    session_a, _ = demo_sessions
    ctx = ScanContext(base_url="http://testserver", session_a=session_a)
    ep = Endpoint(path="/me", method="GET", operation_id="read_me")
    findings = ExcessiveDataExposureCheck().run(ep, ctx)
    assert findings == []  # /me is deliberately clean -> no false positive
