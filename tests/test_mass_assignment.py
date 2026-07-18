"""Part 4 tests: the Mass Assignment check.

Same shape as the BOLA tests: pure-function unit tests for payload building,
decision-logic tests against a fake stateful session (no network), then an
integration test proving it against the real demo API spec end-to-end.
"""

from __future__ import annotations

from apisec.checks.base import ScanContext
from apisec.checks.mass_assignment import MassAssignmentCheck
from apisec.spec_loader import Endpoint, extract_endpoints

# build_legit_payload is now a shared helper in checks/base.py -- see
# test_checks_base.py for its unit tests.


# ---- decision logic, using a fake stateful session ----------------------------

class _FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}

    def json(self):
        return self._body


class _FakeSession:
    """Simulates a resource with mutable state. `accept_fields=None` means
    every field in a write payload gets applied (a vulnerable handler);
    passing a set simulates a handler that only applies an allowlist of
    fields (a secure handler)."""

    def __init__(self, initial_state, write_status=200, accept_fields=None):
        self.state = dict(initial_state)
        self.write_status = write_status
        self.accept_fields = accept_fields

    def request(self, method, url, json=None, timeout=5, **kwargs):
        if self.write_status >= 400:
            return _FakeResponse(self.write_status)
        payload = json or {}
        if self.accept_fields is None:
            self.state.update(payload)
        else:
            for key, value in payload.items():
                if key in self.accept_fields:
                    self.state[key] = value
        return _FakeResponse(self.write_status, dict(self.state))

    def get(self, url, timeout=5, **kwargs):
        return _FakeResponse(200, dict(self.state))


def _patch_endpoint(schema=None):
    return Endpoint(
        path="/things/{id}", method="PATCH", operation_id="update_thing", request_body_schema=schema
    )


def test_flags_when_injected_field_persists():
    session = _FakeSession({"id": 1, "name": "x"}, accept_fields=None)  # vulnerable
    ctx = ScanContext(base_url="http://x", session_a=session)
    findings = MassAssignmentCheck().run(_patch_endpoint(), ctx)
    assert len(findings) == 1
    assert findings[0].check_id == "API3:2023"
    assert "role" in findings[0].evidence


def test_no_finding_when_write_rejected():
    session = _FakeSession({"id": 1}, write_status=422)  # every write rejected
    ctx = ScanContext(base_url="http://x", session_a=session)
    assert MassAssignmentCheck().run(_patch_endpoint(), ctx) == []


def test_no_finding_when_secure_handler_ignores_extra_fields():
    session = _FakeSession({"id": 1, "name": "x"}, accept_fields={"name"})  # secure
    ctx = ScanContext(base_url="http://x", session_a=session)
    assert MassAssignmentCheck().run(_patch_endpoint(), ctx) == []


def test_declared_field_is_not_treated_as_a_finding():
    # "role" IS in the declared schema -> legitimately writable, must not be
    # reported even though the (vulnerable, accept-everything) handler applies
    # it. Undeclared candidates (e.g. is_admin) still get flagged.
    schema = {"type": "object", "properties": {"role": {"type": "string"}}}
    session = _FakeSession({"id": 1}, accept_fields=None)
    ctx = ScanContext(base_url="http://x", session_a=session)
    findings = MassAssignmentCheck().run(_patch_endpoint(schema), ctx)
    assert len(findings) == 1
    assert "role" not in findings[0].evidence
    assert "is_admin" in findings[0].evidence


def test_get_method_is_skipped():
    ep = Endpoint(path="/things/{id}", method="GET", operation_id="get_thing")
    session = _FakeSession({"id": 1}, accept_fields=None)
    ctx = ScanContext(base_url="http://x", session_a=session)
    assert MassAssignmentCheck().run(ep, ctx) == []


def test_post_method_is_skipped():
    # Documented scope decision: POST (creation) isn't handled -- see the
    # module docstring for why.
    ep = Endpoint(path="/things", method="POST", operation_id="create_thing")
    session = _FakeSession({}, accept_fields=None)
    ctx = ScanContext(base_url="http://x", session_a=session)
    assert MassAssignmentCheck().run(ep, ctx) == []


# ---- id-retry logic, using an id-aware fake session ---------------------------

class _FakeIdAwareSession:
    """Unlike _FakeSession above, this one discriminates by which candidate
    id is in the URL: writes to ids NOT in `accessible_ids` are rejected
    outright (simulating 'not a real/accessible resource for this
    identity'), so the retry loop actually has something to retry past."""

    def __init__(self, accessible_ids, accept_fields=None):
        self.accessible_ids = accessible_ids
        self.accept_fields = accept_fields
        self.state_by_id: dict[str, dict] = {}
        self.write_urls: list[str] = []

    @staticmethod
    def _id_from_url(url: str) -> str:
        return url.rsplit("/", 1)[-1]

    def request(self, method, url, json=None, timeout=5, **kwargs):
        self.write_urls.append(url)
        cid = self._id_from_url(url)
        if cid not in self.accessible_ids:
            return _FakeResponse(403)
        state = self.state_by_id.setdefault(cid, {})
        payload = json or {}
        if self.accept_fields is None:
            state.update(payload)
        else:
            for key, value in payload.items():
                if key in self.accept_fields:
                    state[key] = value
        return _FakeResponse(200, dict(state))

    def get(self, url, timeout=5, **kwargs):
        cid = self._id_from_url(url)
        if cid not in self.accessible_ids:
            return _FakeResponse(404)
        return _FakeResponse(200, dict(self.state_by_id.get(cid, {})))


def test_tries_next_candidate_id_when_first_is_not_writable():
    # id "1" and "2" are not real/accessible resources; "3" is. The baseline
    # legit-only write must skip past 1 and 2 before locking onto 3.
    session = _FakeIdAwareSession(accessible_ids={"3"}, accept_fields=None)
    ctx = ScanContext(base_url="http://x", session_a=session)

    findings = MassAssignmentCheck().run(_patch_endpoint(), ctx)

    assert len(findings) == 1
    assert "id=3" in findings[0].evidence
    assert "role" in findings[0].evidence
    # confirms candidates 1 and 2 really were tried and rejected, not skipped
    assert any(url.endswith("/1") for url in session.write_urls)
    assert any(url.endswith("/2") for url in session.write_urls)


def test_no_finding_when_no_candidate_id_is_ever_writable():
    session = _FakeIdAwareSession(accessible_ids=set(), accept_fields=None)
    ctx = ScanContext(base_url="http://x", session_a=session)
    assert MassAssignmentCheck().run(_patch_endpoint(), ctx) == []


def test_no_finding_when_locked_in_id_has_secure_handler():
    # id "1" is real/writable, but the handler only applies the allowlisted
    # `name` field -- the retry loop correctly locks onto id 1 (no need to
    # try further ids), and the secure handler correctly produces no finding.
    session = _FakeIdAwareSession(accessible_ids={"1"}, accept_fields={"name"})
    ctx = ScanContext(base_url="http://x", session_a=session)
    assert MassAssignmentCheck().run(_patch_endpoint(), ctx) == []


# ---- integration: against the real demo API spec + a live identity -----------

def test_integration_mass_assignment_on_users_endpoint(demo_client, demo_sessions):
    session_a, _ = demo_sessions  # alice; concrete_url defaults to id "1" (her own)
    spec = demo_client.get("/openapi.json").json()
    endpoints = extract_endpoints(spec)
    ep = next(e for e in endpoints if e.path == "/users/{user_id}" and e.method == "PATCH")
    # Sanity: the spec really only declares `name` as writable.
    assert set(ep.request_body_schema.get("properties", {})) == {"name"}

    ctx = ScanContext(base_url="http://testserver", session_a=session_a)
    findings = MassAssignmentCheck().run(ep, ctx)

    assert len(findings) == 1
    assert findings[0].check_id == "API3:2023"
    assert "role" in findings[0].evidence
