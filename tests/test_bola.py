"""Part 3 tests: two-user auth (ScanContext) + the BOLA check.

Split into: (1) the shared id-substitution helper, (2) the BOLA decision logic
in isolation using fake sessions with canned status codes (no network / no
demo API needed — this is what proves the "2xx-as-user-B => finding" logic
and the 404-vs-403 distinction from the plan), and (3) integration tests
against the live demo API with two real identities. A full ALL_CHECKS
regression scan (proving no other check broke) lives in
test_scan_all_targets.py, alongside the other demo targets.
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


# ---- false-positive mitigations: spec-declared public + --public-paths -------

def test_spec_declared_public_endpoint_is_skipped():
    # security == [] means the SPEC says no auth is needed here -- even though
    # both fake sessions would "succeed", this must not be flagged.
    ep = Endpoint(path="/things/{id}", method="GET", operation_id="get_thing", security=[])
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/things/1": 200}),
        session_b=_FakeSession({"http://x/things/1": 200}),
    )
    assert BolaCheck().run(ep, ctx) == []


def test_no_security_info_still_runs_normally():
    # security is None (no info at all) -- must NOT be treated like [].
    # Regression guard for the exact bug this feature could have introduced.
    ep = Endpoint(path="/things/{id}", method="GET", operation_id="get_thing", security=None)
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/things/1": 200}),
        session_b=_FakeSession({"http://x/things/1": 200}),
    )
    assert len(BolaCheck().run(ep, ctx)) == 1


def test_public_paths_allowlist_suppresses_matching_endpoint():
    ep = Endpoint(path="/announcements/{id}", method="GET", operation_id="get_announcement")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/announcements/1": 200}),
        session_b=_FakeSession({"http://x/announcements/1": 200}),
        public_paths=["/announcements/*"],
    )
    assert BolaCheck().run(ep, ctx) == []


def test_public_paths_allowlist_does_not_affect_unmatched_endpoints():
    ep = Endpoint(path="/orders/{id}", method="GET", operation_id="get_order")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"http://x/orders/1": 200}),
        session_b=_FakeSession({"http://x/orders/1": 200}),
        public_paths=["/announcements/*"],  # doesn't match /orders/*
    )
    assert len(BolaCheck().run(ep, ctx)) == 1


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


def test_integration_public_items_endpoint_not_flagged(demo_client, demo_sessions):
    """/public/items/{item_id} is genuinely public (openapi_extra security=[]
    in the demo app). Uses the REAL spec extraction, not a hand-built
    Endpoint, so this proves the spec_loader fix end-to-end."""
    session_a, session_b = demo_sessions
    spec = demo_client.get("/openapi.json").json()
    endpoints = extract_endpoints(spec)
    ep = next(e for e in endpoints if e.path == "/public/items/{item_id}")
    assert ep.security == []  # sanity: the spec really does declare this public

    ctx = ScanContext(base_url="http://testserver", session_a=session_a, session_b=session_b)
    assert BolaCheck().run(ep, ctx) == []


def test_integration_announcements_flagged_without_allowlist(demo_sessions):
    """/announcements/{id} requires auth but is intentionally shared -- with
    NO --public-paths configured, this is an expected false positive (the
    honest baseline behavior documented in bola.py)."""
    session_a, session_b = demo_sessions
    ctx = ScanContext(base_url="http://testserver", session_a=session_a, session_b=session_b)
    ep = Endpoint(
        path="/announcements/{announcement_id}", method="GET", operation_id="read_announcement"
    )
    findings = BolaCheck().run(ep, ctx)
    assert len(findings) == 1


def test_integration_announcements_suppressed_with_allowlist(demo_sessions):
    """Same endpoint, same identities -- but with --public-paths declaring it
    intentionally shared, the false positive is suppressed."""
    session_a, session_b = demo_sessions
    ctx = ScanContext(
        base_url="http://testserver",
        session_a=session_a,
        session_b=session_b,
        public_paths=["/announcements/*"],
    )
    ep = Endpoint(
        path="/announcements/{announcement_id}", method="GET", operation_id="read_announcement"
    )
    assert BolaCheck().run(ep, ctx) == []


# A full ALL_CHECKS scan against the vulnerable demo (proving BOLA fires
# alongside Part 1/2's findings with no regression from the ScanContext
# refactor) is covered once, precisely (exact count + exact bug-type
# fingerprint, catching the API3:2023-shared-id case too), alongside the
# other three demo targets, in test_scan_all_targets.py.
