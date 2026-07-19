"""Part 4 tests: the Mass Assignment check.

Same shape as the BOLA tests: pure-function unit tests for payload building,
decision-logic tests against a fake stateful session (no network), then an
integration test proving it against the real demo API spec end-to-end.
"""

from __future__ import annotations

from apisec.checks.base import ScanContext, Severity
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


def test_secure_handler_produces_only_a_low_suspected_finding_not_a_high_one():
    # the handler is secure (only "name" is ever applied), but the fake GET
    # response never includes the injected field at all -- indistinguishable,
    # from the outside, from a vulnerable handler that stores it somewhere
    # this same read-back doesn't show. That ambiguity is now reported as a
    # LOW "accepted, not confirmed" finding rather than staying silent (see
    # CONFIDENCE TIERS in mass_assignment.py's module docstring) -- but it
    # must NOT be reported as the HIGH-confidence "confirmed" finding.
    session = _FakeSession({"id": 1, "name": "x"}, accept_fields={"name"})  # secure
    ctx = ScanContext(base_url="http://x", session_a=session)
    findings = MassAssignmentCheck().run(_patch_endpoint(), ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "not confirmed" in findings[0].evidence
    assert "role" in findings[0].evidence


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


def test_explicit_different_value_on_readback_is_clear_not_suspected():
    # the response DOES include "role", but with a value that contradicts
    # what was injected -- real evidence the server is ignoring/overriding
    # it, not silence. Must be excluded entirely (CLEAR), not reported as
    # SUSPECTED just because it wasn't a verbatim match.
    class _OverridesRoleSession:
        def request(self, method, url, json=None, timeout=5, **kwargs):
            return _FakeResponse(200, {"id": 1, "role": "user"})

        def get(self, url, timeout=5, **kwargs):
            return _FakeResponse(200, {"id": 1, "role": "user"})  # never changes

    ctx = ScanContext(base_url="http://x", session_a=_OverridesRoleSession())
    findings = MassAssignmentCheck().run(_patch_endpoint(), ctx)
    assert len(findings) == 1  # the other candidate fields are still SUSPECTED
    assert findings[0].severity == Severity.LOW
    assert findings[0].evidence == (
        "id=1: undeclared field(s) accepted but not confirmed: "
        "is_admin, isAdmin, admin, permissions, status, is_paid, price, "
        "discount_percent, balance"
    )


def test_mixed_confirmed_and_suspected_fields_produce_two_separate_findings():
    # "admin" genuinely persists and reads back; the rest of the candidate
    # fields never show up in the response at all. Should produce one HIGH
    # (confirmed) finding and one separate LOW (suspected) finding, not one
    # finding lumping both confidence levels together.
    class _OnlyAdminSticksSession:
        def __init__(self):
            self.stored_admin = None

        def request(self, method, url, json=None, timeout=5, **kwargs):
            payload = json or {}
            if "admin" in payload:
                self.stored_admin = payload["admin"]
            return _FakeResponse(200, {"id": 1})

        def get(self, url, timeout=5, **kwargs):
            body = {"id": 1}
            if self.stored_admin is not None:
                body["admin"] = self.stored_admin
            return _FakeResponse(200, body)

    ctx = ScanContext(base_url="http://x", session_a=_OnlyAdminSticksSession())
    findings = MassAssignmentCheck().run(_patch_endpoint(), ctx)
    assert len(findings) == 2

    high = next(f for f in findings if f.severity == Severity.HIGH)
    low = next(f for f in findings if f.severity == Severity.LOW)
    assert high.evidence == "id=1: undeclared field(s) accepted and persisted: admin"
    assert low.evidence == (
        "id=1: undeclared field(s) accepted but not confirmed: "
        "role, is_admin, isAdmin, permissions, status, is_paid, price, "
        "discount_percent, balance"
    )


def test_business_logic_field_is_flagged_when_it_persists():
    # "status" is the business-logic-flavored candidate motivated by crAPI's
    # real order-manipulation bug (see mass_assignment.py's module docstring
    # and _CANDIDATE_BUSINESS_LOGIC_FIELDS) -- confirm it's actually wired
    # into the check, not just declared and never used.
    session = _FakeSession({"id": 1, "name": "x"}, accept_fields=None)  # vulnerable
    ctx = ScanContext(base_url="http://x", session_a=session)
    findings = MassAssignmentCheck().run(_patch_endpoint(), ctx)
    assert len(findings) == 1
    assert "status" in findings[0].evidence
    assert "is_paid" in findings[0].evidence


def test_declared_business_logic_field_is_not_treated_as_a_finding():
    # same guarantee as test_declared_field_is_not_treated_as_a_finding, for
    # a business-logic candidate: a schema-declared "price" is legitimately
    # writable and must not be reported, even on a vulnerable handler.
    schema = {"type": "object", "properties": {"price": {"type": "number"}}}
    session = _FakeSession({"id": 1}, accept_fields=None)
    ctx = ScanContext(base_url="http://x", session_a=session)
    findings = MassAssignmentCheck().run(_patch_endpoint(schema), ctx)
    assert len(findings) == 1
    assert "price" not in findings[0].evidence
    assert "status" in findings[0].evidence


def test_get_method_is_skipped():
    ep = Endpoint(path="/things/{id}", method="GET", operation_id="get_thing")
    session = _FakeSession({"id": 1}, accept_fields=None)
    ctx = ScanContext(base_url="http://x", session_a=session)
    assert MassAssignmentCheck().run(ep, ctx) == []


def test_post_secure_create_handler_produces_only_a_low_suspected_finding():
    # same ambiguity as the PATCH/PUT case above, on a creation endpoint:
    # the handler is secure, but there's no way to prove that from outside
    # with this response shape -- LOW/suspected, not HIGH/confirmed, not [].
    ep = Endpoint(path="/things", method="POST", operation_id="create_thing")
    session = _FakeSession({}, accept_fields=set())  # secure: applies nothing extra
    ctx = ScanContext(base_url="http://x", session_a=session)
    findings = MassAssignmentCheck().run(ep, ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "not confirmed" in findings[0].evidence


# ---- POST (creation) support ---------------------------------------------------

def _register_endpoint(schema=None):
    return Endpoint(
        path="/users/v1/register", method="POST", operation_id="register", request_body_schema=schema
    )


def _orders_collection_endpoint(schema=None):
    return Endpoint(
        path="/orders", method="POST", operation_id="create_order", request_body_schema=schema
    )


def _order_item_endpoint():
    return Endpoint(path="/orders/{order_id}", method="GET", operation_id="get_order")


def test_post_flags_when_create_response_reflects_injected_field():
    # /things has no declared schema, so every candidate field is
    # "undeclared"; the fake session echoes whatever it's sent straight
    # back in the response body -- confirmable with no GET at all.
    ep = Endpoint(path="/things", method="POST", operation_id="create_thing")
    session = _FakeSession({}, accept_fields=None)  # vulnerable: echoes everything
    ctx = ScanContext(base_url="http://x", session_a=session)
    findings = MassAssignmentCheck().run(ep, ctx)
    assert len(findings) == 1
    assert "role" in findings[0].evidence
    assert "on creation" in findings[0].evidence


class _FakeCreateThenReadSession:
    """POST returns only a server-generated id (no field reflection); GET
    on the item endpoint returns whatever was actually stored -- simulates
    a create-then-fetch flow where the injected field persisted server-side
    without being echoed in the create response itself."""

    def __init__(self):
        self.next_id = 1
        self.stored_by_id: dict[str, dict] = {}
        self.get_urls: list[str] = []

    def request(self, method, url, json=None, timeout=5, **kwargs):
        item_id = str(self.next_id)
        self.next_id += 1
        self.stored_by_id[item_id] = dict(json or {})
        return _FakeResponse(201, {"id": int(item_id)})

    def get(self, url, timeout=5, **kwargs):
        self.get_urls.append(url)
        body = self.stored_by_id.get(url.rsplit("/", 1)[-1])
        return _FakeResponse(200, body) if body is not None else _FakeResponse(404)


def test_post_flags_via_discovered_id_readback_when_response_does_not_reflect():
    session = _FakeCreateThenReadSession()
    ctx = ScanContext(
        base_url="http://x",
        session_a=session,
        all_endpoints=[_orders_collection_endpoint(), _order_item_endpoint()],
    )
    findings = MassAssignmentCheck().run(_orders_collection_endpoint(), ctx)
    assert len(findings) == 1
    assert "role" in findings[0].evidence
    # confirms it actually read the item endpoint back, not just the create response
    assert len(session.get_urls) > 0


class _FakeClientChosenIdSession:
    """Simulates VAmPI-style registration: the create response has no id at
    all (just a status message) -- the resource's identifier is whatever
    the CALLER supplied in the payload (e.g. `username`), not something the
    server generates. GET-by-that-value returns whatever was stored."""

    def __init__(self, id_field: str):
        self.id_field = id_field
        self.stored: dict[str, dict] = {}
        self.get_urls: list[str] = []

    def request(self, method, url, json=None, timeout=5, **kwargs):
        payload = json or {}
        self.stored[str(payload.get(self.id_field))] = dict(payload)
        return _FakeResponse(200, {"message": "created", "status": "success"})

    def get(self, url, timeout=5, **kwargs):
        self.get_urls.append(url)
        body = self.stored.get(url.rsplit("/", 1)[-1])
        return _FakeResponse(200, body) if body is not None else _FakeResponse(404)


def test_post_flags_via_payload_key_readback_for_client_chosen_id():
    schema = {
        "type": "object",
        "properties": {"username": {"type": "string"}, "password": {"type": "string"}},
    }
    session = _FakeClientChosenIdSession(id_field="username")
    ctx = ScanContext(
        base_url="http://x",
        session_a=session,
        all_endpoints=[
            _register_endpoint(schema),
            Endpoint(path="/users/v1/{username}", method="GET", operation_id="get_user"),
        ],
    )
    findings = MassAssignmentCheck().run(_register_endpoint(schema), ctx)
    assert len(findings) == 1
    assert "admin" in findings[0].evidence
    # confirms it actually resolved the resource via the submitted username,
    # not a server-generated id (there wasn't one)
    assert any(url.endswith("/apisec-test") for url in session.get_urls)


def test_post_low_suspected_finding_when_no_reflection_and_no_readback_possible():
    # response has no id, and there's no sibling GET endpoint at all -- both
    # readback strategies come up empty. The write itself wasn't rejected
    # though, so this is weak evidence worth a LOW finding, not silence.
    class _NoInfoSession:
        def request(self, method, url, json=None, timeout=5, **kwargs):
            return _FakeResponse(200, {"message": "created"})

    ctx = ScanContext(
        base_url="http://x", session_a=_NoInfoSession(), all_endpoints=[_orders_collection_endpoint()]
    )
    findings = MassAssignmentCheck().run(_orders_collection_endpoint(), ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "not confirmed" in findings[0].evidence


def test_post_no_finding_when_create_is_rejected():
    class _RejectingSession:
        def request(self, method, url, json=None, timeout=5, **kwargs):
            return _FakeResponse(422)

    ctx = ScanContext(base_url="http://x", session_a=_RejectingSession())
    assert MassAssignmentCheck().run(_orders_collection_endpoint(), ctx) == []


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


def test_locked_in_id_with_secure_handler_produces_only_a_low_suspected_finding():
    # id "1" is real/writable, but the handler only applies the allowlisted
    # `name` field -- the retry loop correctly locks onto id 1 (no need to
    # try further ids). Same read-back ambiguity as the tests above: LOW,
    # not HIGH, not [].
    session = _FakeIdAwareSession(accessible_ids={"1"}, accept_fields={"name"})
    ctx = ScanContext(base_url="http://x", session_a=session)
    findings = MassAssignmentCheck().run(_patch_endpoint(), ctx)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "id=1" in findings[0].evidence
    assert "not confirmed" in findings[0].evidence


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
