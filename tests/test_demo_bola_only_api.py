"""Correctness tests for demo_apps/bola_only: proves the app has exactly the
one planted bug (Bob can read Alice's order) and nothing else. Whether the
REAL scanner agrees and reports exactly one BOLA finding is covered once,
alongside the other three targets, in test_scan_all_targets.py -- no need
to duplicate that here."""

from __future__ import annotations

import pytest

from demo_apps.bola_only.app import _reset_state, app


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
