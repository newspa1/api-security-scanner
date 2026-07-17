"""Part 3 tests: two-user auth (ScanContext) + the BOLA check.

Split into: (1) the shared id-substitution helper, (2) the BOLA decision logic
in isolation using fake sessions with canned status codes (no network / no
demo API needed — this is what proves the "2xx-as-user-B => finding" logic
and the 404-vs-403 distinction from the plan), (3) an integration test against
the live demo API with two real identities, and (4) a full-scan regression
check that Part 1/2 findings still work after the ScanContext refactor.
"""

from __future__ import annotations

from apisec.checks.base import ScanContext, concrete_url
from apisec.checks.bola import BolaCheck, _has_id_path_param
from apisec.spec_loader import Endpoint, extract_endpoints


# ---- concrete_url (shared id-substitution helper, used by EDE and BOLA) ------

def test_concrete_url_substitutes_single_param():
    assert concrete_url("/users/{id}", "http://x", "42") == "http://x/users/42"


def test_concrete_url_substitutes_multiple_params():
    assert concrete_url("/a/{x}/b/{y}", "http://x", "9") == "http://x/a/9/b/9"


def test_has_id_path_param():
    assert _has_id_path_param("/users/{id}") is True
    assert _has_id_path_param("/health") is False


# ---- decision logic, using fake sessions with canned responses ---------------

class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeSession:
    """Maps a URL to a canned status code (default 404 for anything unlisted)."""

    def __init__(self, status_by_url: dict[str, int], default: int = 404):
        self.status_by_url = status_by_url
        self.default = default

    def get(self, url, timeout=5, **kwargs):
        return _FakeResponse(self.status_by_url.get(url, self.default))


def _id_endpoint():
    return Endpoint(path="/things/{id}", method="GET", operation_id="get_thing")


def test_no_second_identity_skips_check():
    ctx = ScanContext(base_url="http://x", session_a=_FakeSession({}), session_b=None)
    assert BolaCheck().run(_id_endpoint(), ctx) == []


def test_flags_when_both_identities_can_read_same_id():
    url = "http://x/things/1"
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({url: 200}),
        session_b=_FakeSession({url: 200}),
    )
    findings = BolaCheck().run(_id_endpoint(), ctx)
    assert len(findings) == 1
    assert findings[0].check_id == "API1:2023"
    assert "id=1" in findings[0].evidence


def test_no_finding_when_b_gets_403_properly_enforced():
    url = "http://x/things/1"
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({url: 200}),
        session_b=_FakeSession({url: 403}),
    )
    assert BolaCheck().run(_id_endpoint(), ctx) == []


def test_no_finding_when_a_finds_no_accessible_candidate_id():
    # session_a gets 404 for every candidate id (1..5) -> nothing to test B against.
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({}, default=404),
        session_b=_FakeSession({}, default=200),
    )
    assert BolaCheck().run(_id_endpoint(), ctx) == []


def test_tries_next_candidate_id_when_first_is_not_accessible_to_a():
    # id=1: A gets 404 (wrong guess, not "properly enforced"). id=2: A gets 200,
    # B also gets 200 -> flagged using id=2, proving the id=1 404 didn't stop
    # the scan or get misread as "enforced".
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/things/1": 404, "http://x/things/2": 200}),
        session_b=_FakeSession({"http://x/things/2": 200}),
    )
    findings = BolaCheck().run(_id_endpoint(), ctx)
    assert len(findings) == 1
    assert "id=2" in findings[0].evidence


def test_non_get_method_is_skipped():
    ep = Endpoint(path="/things/{id}", method="PATCH", operation_id="update_thing")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/things/1": 200}),
        session_b=_FakeSession({"http://x/things/1": 200}),
    )
    assert BolaCheck().run(ep, ctx) == []


def test_endpoint_without_id_param_is_skipped():
    ep = Endpoint(path="/health", method="GET", operation_id="health")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/health": 200}),
        session_b=_FakeSession({"http://x/health": 200}),
    )
    assert BolaCheck().run(ep, ctx) == []


# ---- integration: against the live demo API, two real identities -------------

def test_integration_bola_on_users_endpoint(demo_sessions):
    session_a, session_b = demo_sessions  # alice, bob
    ctx = ScanContext(base_url="http://testserver", session_a=session_a, session_b=session_b)
    ep = Endpoint(path="/users/{user_id}", method="GET", operation_id="read_user")

    findings = BolaCheck().run(ep, ctx)

    assert len(findings) == 1
    assert findings[0].check_id == "API1:2023"


def test_integration_bola_on_orders_endpoint(demo_sessions):
    session_a, session_b = demo_sessions
    ctx = ScanContext(base_url="http://testserver", session_a=session_a, session_b=session_b)
    ep = Endpoint(path="/orders/{order_id}", method="GET", operation_id="read_order")

    findings = BolaCheck().run(ep, ctx)

    assert len(findings) == 1
    assert findings[0].check_id == "API1:2023"


def test_integration_full_scan_no_regression(demo_client, demo_sessions):
    """Drives ALL_CHECKS (the ScanContext refactor touched every one of them)
    against the demo API with two identities, confirming BOLA now fires
    alongside the Part 1/2 findings with no regressions from the refactor."""
    from apisec.checks import ALL_CHECKS

    session_a, session_b = demo_sessions
    spec = demo_client.get("/openapi.json").json()
    endpoints = extract_endpoints(spec)
    ctx = ScanContext(base_url="http://testserver", session_a=session_a, session_b=session_b)

    findings = []
    for ep in endpoints:
        for check in ALL_CHECKS:
            findings.extend(check.run(ep, ctx))

    check_ids = {f.check_id for f in findings}
    assert "API1:2023" in check_ids  # BOLA (new this part)
    assert "API2:2023" in check_ids  # Broken Auth (Part 1, no regression)
    assert "API3:2023" in check_ids  # Excessive Data Exposure (Part 2, no regression)
