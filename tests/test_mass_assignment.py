"""Part 4 tests: the Mass Assignment check.

Same shape as the BOLA tests: pure-function unit tests for payload building,
decision-logic tests against a fake stateful session (no network), then an
integration test proving it against the real demo API spec end-to-end.
"""

from __future__ import annotations

from apisec.checks.base import ScanContext
from apisec.checks.mass_assignment import MassAssignmentCheck, _build_legit_payload
from apisec.spec_loader import Endpoint, extract_endpoints


# ---- _build_legit_payload (pure function) -------------------------------------

def test_build_legit_payload_fills_declared_properties_by_type():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
            "active": {"type": "boolean"},
        },
    }
    payload = _build_legit_payload(schema)
    assert payload == {"name": "apisec-test", "age": 1, "active": True}


def test_build_legit_payload_handles_missing_schema():
    assert _build_legit_payload(None) == {}
    assert _build_legit_payload({}) == {}


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
