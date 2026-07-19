"""Tests for write_bola.py: the write-based extension of BOLA. Same shape as
test_bola.py -- decision logic against fake sessions with canned responses,
then integration tests against the live demo API with two real identities.
"""

from __future__ import annotations

from apisec.checks.base import ScanContext
from apisec.checks.write_bola import WriteBolaCheck
from apisec.spec_loader import Endpoint, extract_endpoints


# ---- decision logic, using fake sessions with canned responses ---------------

class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeSession:
    """Maps a URL to a canned status code (default 404 for anything unlisted),
    for the PATCH/PUT write this check makes."""

    def __init__(self, status_by_url: dict[str, int], default: int = 404):
        self.status_by_url = status_by_url
        self.default = default

    def request(self, method, url, json=None, timeout=5, **kwargs):
        return _FakeResponse(self.status_by_url.get(url, self.default))


def _id_endpoint(method="PATCH"):
    return Endpoint(path="/things/{id}", method=method, operation_id="update_thing")


def test_no_second_identity_skips_check():
    ctx = ScanContext(base_url="http://x", session_a=_FakeSession({}), session_b=None)
    assert WriteBolaCheck().run(_id_endpoint(), ctx) == []


def test_flags_when_both_identities_can_write_same_id():
    url = "http://x/things/1"
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({url: 200}),
        session_b=_FakeSession({url: 200}),
    )
    findings = WriteBolaCheck().run(_id_endpoint(), ctx)
    assert len(findings) == 1
    assert findings[0].check_id == "API1:2023"
    assert findings[0].severity.value == "critical"  # a write is worse than a read
    assert "id=1" in findings[0].evidence


def test_no_finding_when_b_gets_403_properly_enforced():
    url = "http://x/things/1"
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({url: 200}),
        session_b=_FakeSession({url: 403}),
    )
    assert WriteBolaCheck().run(_id_endpoint(), ctx) == []


def test_no_finding_when_a_finds_no_writable_candidate_id():
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({}, default=404),
        session_b=_FakeSession({}, default=200),
    )
    assert WriteBolaCheck().run(_id_endpoint(), ctx) == []


def test_tries_next_candidate_id_when_first_is_not_writable_by_a():
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/things/1": 404, "http://x/things/2": 200}),
        session_b=_FakeSession({"http://x/things/2": 200}),
    )
    findings = WriteBolaCheck().run(_id_endpoint(), ctx)
    assert len(findings) == 1
    assert "id=2" in findings[0].evidence


def test_get_method_is_skipped():
    ep = Endpoint(path="/things/{id}", method="GET", operation_id="get_thing")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/things/1": 200}),
        session_b=_FakeSession({"http://x/things/1": 200}),
    )
    assert WriteBolaCheck().run(ep, ctx) == []


def test_delete_method_is_skipped():
    # Deliberate scope exclusion -- see write_bola.py's own SCOPE section.
    ep = Endpoint(path="/things/{id}", method="DELETE", operation_id="delete_thing")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/things/1": 200}),
        session_b=_FakeSession({"http://x/things/1": 200}),
    )
    assert WriteBolaCheck().run(ep, ctx) == []


def test_endpoint_without_id_param_is_skipped():
    ep = Endpoint(path="/health", method="PATCH", operation_id="update_health")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/health": 200}),
        session_b=_FakeSession({"http://x/health": 200}),
    )
    assert WriteBolaCheck().run(ep, ctx) == []


# ---- false-positive mitigations: spec-declared public + --public-paths -------

def test_spec_declared_public_endpoint_is_skipped():
    ep = Endpoint(path="/things/{id}", method="PATCH", operation_id="update_thing", security=[])
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/things/1": 200}),
        session_b=_FakeSession({"http://x/things/1": 200}),
    )
    assert WriteBolaCheck().run(ep, ctx) == []


def test_public_paths_allowlist_suppresses_matching_endpoint():
    ep = Endpoint(path="/announcements/{id}", method="PATCH", operation_id="update_announcement")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/announcements/1": 200}),
        session_b=_FakeSession({"http://x/announcements/1": 200}),
        public_paths=["/announcements/*"],
    )
    assert WriteBolaCheck().run(ep, ctx) == []


def test_public_paths_allowlist_does_not_affect_unmatched_endpoints():
    ep = Endpoint(path="/orders/{id}", method="PUT", operation_id="update_order")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/orders/1": 200}),
        session_b=_FakeSession({"http://x/orders/1": 200}),
        public_paths=["/announcements/*"],
    )
    assert len(WriteBolaCheck().run(ep, ctx)) == 1


# ---- integration: against the live demo API, two real identities -------------

def test_integration_write_bola_on_demo_vulnerable_users_endpoint(demo_client, demo_sessions):
    # demo_apps/vulnerable's PATCH /users/{user_id} was planted for Mass
    # Assignment (undeclared fields get applied) but was NEVER given an
    # ownership check either -- a real, previously-uncounted bug this check
    # newly surfaces: bob can write to alice's record just by knowing her
    # id, no different identity check at all. Confirms this check finds a
    # real bug on real (if incidental) target code, not just fakes.
    session_a, session_b = demo_sessions  # alice, bob
    spec = demo_client.get("/openapi.json").json()
    endpoints = extract_endpoints(spec)
    ep = next(e for e in endpoints if e.path == "/users/{user_id}" and e.method == "PATCH")

    ctx = ScanContext(base_url="http://testserver", session_a=session_a, session_b=session_b)
    findings = WriteBolaCheck().run(ep, ctx)

    assert len(findings) == 1
    assert findings[0].check_id == "API1:2023"
    assert findings[0].severity.value == "critical"
