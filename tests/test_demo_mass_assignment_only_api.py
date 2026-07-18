"""Correctness tests for demo_apps/mass_assignment_only: proves the app has
exactly the one planted bug (PATCH /me applies an undeclared `role` field)
and nothing else, then proves the real scanner (ALL_CHECKS) reports EXACTLY
ONE finding -- Mass Assignment, and nothing from the other three checks."""

from __future__ import annotations

import pytest

from apisec.checks import ALL_CHECKS
from apisec.checks.base import ScanContext
from apisec.spec_loader import extract_endpoints
from demo_apps.mass_assignment_only.app import _reset_state, app


@pytest.fixture
def mass_assignment_only_sessions(sessions_for):
    _reset_state()
    return sessions_for(app, ("alice", "alice-pw"), ("bob", "bob-pw"))


def test_patch_me_applies_undeclared_role_the_one_bug(mass_assignment_only_sessions):
    client, (session_a, _) = mass_assignment_only_sessions
    client.patch("/me", headers=session_a.headers, json={"name": "Alice X", "role": "admin"})
    body = client.get("/me", headers=session_a.headers).json()
    assert body["role"] == "admin"


def test_me_response_is_clean(mass_assignment_only_sessions):
    client, (session_a, _) = mass_assignment_only_sessions
    body = client.get("/me", headers=session_a.headers).json()
    assert "password" not in body


def test_full_scan_finds_exactly_one_mass_assignment_finding(mass_assignment_only_sessions):
    client, (session_a, session_b) = mass_assignment_only_sessions
    spec = client.get("/openapi.json").json()
    endpoints = extract_endpoints(spec)
    ctx = ScanContext(base_url="http://testserver", session_a=session_a, session_b=session_b)

    findings = [f for ep in endpoints for check in ALL_CHECKS for f in check.run(ep, ctx)]

    assert len(findings) == 1
    assert findings[0].check_id == "API3:2023"
    assert findings[0].title == "Mass Assignment"
    assert findings[0].endpoint == "/me"
