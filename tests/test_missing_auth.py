"""Part 6 tests: the "no authentication required at all" check, distinct
from broken_auth.py's alg=none forgery. Same shape as the other checks' unit
tests: a fake stateful session (no network), then an integration test
against the real demo API.
"""

from __future__ import annotations

from apisec.checks.base import ScanContext
from apisec.checks.missing_auth import MissingAuthCheck
from apisec.spec_loader import Endpoint


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeSession:
    """`request()` distinguishes the two calls this check makes: a plain
    call (default session headers apply, used both directly and as the
    "confirm this id is real" baseline) vs. a call with
    `headers={"Authorization": None}` (the actual no-auth-at-all probe).
    `authed_by_url`/`stripped_by_url` map URL -> status code; unlisted URLs
    default to 404."""

    def __init__(
        self,
        authed_by_url: dict[str, int] | None = None,
        stripped_by_url: dict[str, int] | None = None,
        has_auth_header: bool = True,
    ):
        self.headers = {"Authorization": "Bearer real-token"} if has_auth_header else {}
        self.authed_by_url = authed_by_url or {}
        self.stripped_by_url = stripped_by_url or {}

    def request(self, method, url, headers=None, timeout=5, **kwargs):
        if headers and headers.get("Authorization", "unset") is None:
            return _FakeResponse(self.stripped_by_url.get(url, 404))
        return _FakeResponse(self.authed_by_url.get(url, 404))


def _plain_endpoint():
    return Endpoint(path="/things", method="GET", operation_id="list_things")


def _id_endpoint():
    return Endpoint(path="/things/{id}", method="GET", operation_id="get_thing")


def test_flags_when_endpoint_accepts_no_auth_at_all():
    url = "http://x/things"
    session = _FakeSession(stripped_by_url={url: 200})
    ctx = ScanContext(base_url="http://x", session_a=session)
    findings = MissingAuthCheck().run(_plain_endpoint(), ctx)
    assert len(findings) == 1
    assert findings[0].check_id == "API2:2023"
    assert findings[0].severity.value == "critical"
    assert "no Authorization header" in findings[0].evidence


def test_no_finding_when_auth_is_required():
    url = "http://x/things"
    session = _FakeSession(stripped_by_url={url: 401})
    ctx = ScanContext(base_url="http://x", session_a=session)
    assert MissingAuthCheck().run(_plain_endpoint(), ctx) == []


def test_skips_spec_declared_public_endpoint():
    class _ExplodingSession:
        headers = {"Authorization": "Bearer x"}

        def request(self, *args, **kwargs):
            raise AssertionError("should not make a request for a declared-public endpoint")

    ep = Endpoint(path="/public/thing", method="GET", operation_id="get_thing", security=[])
    ctx = ScanContext(base_url="http://x", session_a=_ExplodingSession())
    assert MissingAuthCheck().run(ep, ctx) == []


def test_skips_public_paths_allowlist():
    class _ExplodingSession:
        headers = {"Authorization": "Bearer x"}

        def request(self, *args, **kwargs):
            raise AssertionError("should not make a request for an allowlisted path")

    ep = Endpoint(path="/announcements/{id}", method="GET", operation_id="get_announcement")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_ExplodingSession(),
        public_paths=["/announcements/*"],
    )
    assert MissingAuthCheck().run(ep, ctx) == []


def test_skips_when_no_authorization_header_configured():
    class _ExplodingSession:
        headers: dict[str, str] = {}

        def request(self, *args, **kwargs):
            raise AssertionError("should not make a request with nothing configured to strip")

    ctx = ScanContext(base_url="http://x", session_a=_ExplodingSession())
    assert MissingAuthCheck().run(_plain_endpoint(), ctx) == []


def test_id_param_endpoint_needs_a_real_accessible_id_first():
    # id=1 doesn't resolve to anything real (404 even WITH auth) -- proves
    # nothing about authentication, so it must not be reported.
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession(authed_by_url={"http://x/things/1": 404}),
    )
    assert MissingAuthCheck().run(_id_endpoint(), ctx) == []


def test_tries_next_candidate_id_when_first_is_not_a_real_resource():
    # id=1: not real (404 even with auth). id=2: real (200 with auth), and
    # also 200 with auth stripped entirely -- flagged, using id=2.
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession(
            authed_by_url={"http://x/things/1": 404, "http://x/things/2": 200},
            stripped_by_url={"http://x/things/2": 200},
        ),
    )
    findings = MissingAuthCheck().run(_id_endpoint(), ctx)
    assert len(findings) == 1
    assert "id=2" in findings[0].evidence


def test_id_param_endpoint_not_flagged_when_auth_enforced():
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession(
            authed_by_url={"http://x/things/1": 200},
            stripped_by_url={"http://x/things/1": 401},
        ),
    )
    assert MissingAuthCheck().run(_id_endpoint(), ctx) == []


# ---- integration: against the live demo API -----------------------------------


def test_integration_no_finding_on_demo_users_endpoint(demo_sessions):
    from apisec.spec_loader import extract_endpoints

    alice, _ = demo_sessions
    spec = alice.client.get("/openapi.json").json()
    endpoints = extract_endpoints(spec)
    ctx = ScanContext(base_url="http://testserver", session_a=alice, all_endpoints=endpoints)

    users_endpoint = next(e for e in endpoints if e.path == "/users/{user_id}" and e.method == "GET")
    assert MissingAuthCheck().run(users_endpoint, ctx) == []
