"""Correctness tests for demo_apps/mass_assignment_only: proves the app has
exactly the one planted bug (PATCH /me applies an undeclared `role` field)
and nothing else. Whether the REAL scanner agrees and reports exactly one
Mass Assignment finding is covered once, alongside the other three targets,
in test_scan_all_targets.py -- no need to duplicate that here."""

from __future__ import annotations

import pytest

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
