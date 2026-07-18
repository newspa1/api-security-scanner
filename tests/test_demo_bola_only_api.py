"""Correctness tests for demo_bola_only_api: proves the app has exactly the
one planted bug (Bob can read Alice's order) and nothing else, then proves
the real scanner (ALL_CHECKS) reports EXACTLY ONE finding -- BOLA, and
nothing from the other three checks."""

from __future__ import annotations

import pytest

from apisec.checks import ALL_CHECKS
from apisec.checks.base import ScanContext
from apisec.spec_loader import extract_endpoints
from demo_bola_only_api.app import _reset_state, app


@pytest.fixture
def bola_only_sessions(sessions_for):
    _reset_state()
    return sessions_for(app, ("alice", "alice-pw"), ("bob", "bob-pw"))


def test_bob_can_read_alices_order_the_one_bug(bola_only_sessions):
    client, (_, session_b) = bola_only_sessions
    resp = client.get("/orders/1", headers=session_b.headers)  # order 1 is Alice's
    assert resp.status_code == 200


def test_me_response_is_clean(bola_only_sessions):
    client, (session_a, _) = bola_only_sessions
    body = client.get("/me", headers=session_a.headers).json()
    assert "password" not in body


def test_full_scan_finds_exactly_one_bola_finding(bola_only_sessions):
    client, (session_a, session_b) = bola_only_sessions
    spec = client.get("/openapi.json").json()
    endpoints = extract_endpoints(spec)
    ctx = ScanContext(base_url="http://testserver", session_a=session_a, session_b=session_b)

    findings = [f for ep in endpoints for check in ALL_CHECKS for f in check.run(ep, ctx)]

    assert len(findings) == 1
    assert findings[0].check_id == "API1:2023"
    assert findings[0].endpoint == "/orders/{order_id}"
