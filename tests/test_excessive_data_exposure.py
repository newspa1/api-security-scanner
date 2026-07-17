"""Part 2 tests: the hybrid Excessive Data Exposure check.

Each of the three detection layers is unit-tested in isolation (they're pure
functions), then the confidence scoring, then an end-to-end integration test
against the demo API. This is the "correctness" half of the plan's per-part
contract: prove it finds the true positive AND doesn't fire on clean data."""

import pytest
from fastapi.testclient import TestClient

from apisec.checks.excessive_data_exposure import (
    ExcessiveDataExposureCheck,
    _collect_signals,
    _declared_property_names,
    _name_looks_sensitive,
    _severity_for,
    _shannon_entropy,
    _value_looks_secret,
)
from apisec.checks.base import Severity
from apisec.scanner import scan


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

@pytest.fixture
def demo_scan():
    from demo_vulnerable_api.app import _reset_state, app

    _reset_state()
    client = TestClient(app)
    token = client.post("/login", json={"username": "alice", "password": "alice-pw"}).json()[
        "access_token"
    ]
    return client, token


def test_integration_finds_password_hash_leak(monkeypatch, demo_scan):
    client, token = demo_scan
    # Point the scanner's requests at the in-process TestClient so no real server
    # is needed. The check calls session.get(url); route it through the client.
    from apisec.checks import excessive_data_exposure as eda

    def fake_get(url, timeout=5, **kwargs):
        path = url.replace("http://testserver", "")
        return client.get(path, headers={"Authorization": f"Bearer {token}"})

    check = eda.ExcessiveDataExposureCheck()

    from apisec.spec_loader import Endpoint

    ep = Endpoint(path="/users/{user_id}", method="GET", operation_id="read_user")
    session = type("S", (), {"get": staticmethod(fake_get)})()
    findings = check.run(ep, "http://testserver", session)

    assert len(findings) == 1
    assert findings[0].check_id == "API3:2023"
    assert "password_hash" in findings[0].evidence


def test_integration_me_is_clean(demo_scan):
    client, token = demo_scan
    from apisec.checks import excessive_data_exposure as eda

    def fake_get(url, timeout=5, **kwargs):
        path = url.replace("http://testserver", "")
        return client.get(path, headers={"Authorization": f"Bearer {token}"})

    ep_type = __import__("apisec.spec_loader", fromlist=["Endpoint"]).Endpoint
    ep = ep_type(path="/me", method="GET", operation_id="read_me")
    session = type("S", (), {"get": staticmethod(fake_get)})()
    findings = eda.ExcessiveDataExposureCheck().run(ep, "http://testserver", session)
    assert findings == []  # /me is deliberately clean -> no false positive
