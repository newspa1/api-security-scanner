"""Tests for shared check infrastructure in checks/base.py: build_legit_payload
(moved here from mass_assignment.py, now shared), the id-DISCOVERY machinery
-- create a real resource via a sibling POST, read its real id back -- that
bola.py and mass_assignment.py both try first before falling back to
sequential-integer guessing (concrete_url's default), and the two POST
read-back helpers mass_assignment.py uses to verify a Mass Assignment finding
on a creation endpoint: _item_endpoint_for_collection_path (server-generated
id -> matching item GET) and find_item_endpoint_for_payload (client-chosen id
-> matching item GET via a shared field name).
"""

from __future__ import annotations

import jwt

from apisec.checks.base import (
    ScanContext,
    _candidate_ids_for,
    _collection_path,
    _extract_id_from_response,
    _identity_from_session,
    _item_endpoint_for_collection_path,
    build_legit_payload,
    discover_candidate_fields,
    discover_resource_id,
    find_item_endpoint_for_payload,
)
from apisec.spec_loader import Endpoint


# ---- build_legit_payload -------------------------------------------------------

def test_build_legit_payload_fills_declared_properties_by_type():
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
            "active": {"type": "boolean"},
        },
    }
    payload = build_legit_payload(schema)
    assert payload == {"name": "apisec-test", "age": 1, "active": True}


def test_build_legit_payload_handles_missing_schema():
    assert build_legit_payload(None) == {}
    assert build_legit_payload({}) == {}


# ---- discover_candidate_fields --------------------------------------------------

def _endpoint_with_schemas(path, method, request_schema=None, response_schema=None):
    return Endpoint(
        path=path,
        method=method,
        operation_id="x",
        request_body_schema=request_schema,
        response_schema=response_schema,
    )


def test_discover_candidate_fields_finds_property_from_a_different_endpoints_response():
    # /users/{id} GET's response declares "subscription_tier", which
    # /users/{id} PATCH's own request body never does -- a real,
    # spec-derived candidate, no manual typing.
    endpoints = [
        _endpoint_with_schemas(
            "/users/{id}",
            "GET",
            response_schema={
                "type": "object",
                "properties": {"id": {"type": "integer"}, "subscription_tier": {"type": "string"}},
            },
        ),
        _endpoint_with_schemas("/users/{id}", "PATCH", request_schema={"type": "object", "properties": {}}),
    ]
    result = discover_candidate_fields(endpoints, declared_fields=set())
    assert ("subscription_tier", "apisec-test") in result
    assert ("id", 1) in result  # also discovered, just less interesting


def test_discover_candidate_fields_excludes_fields_already_declared_here():
    endpoints = [
        _endpoint_with_schemas(
            "/users/{id}",
            "GET",
            response_schema={"type": "object", "properties": {"name": {"type": "string"}}},
        ),
    ]
    result = discover_candidate_fields(endpoints, declared_fields={"name"})
    assert result == []


def test_discover_candidate_fields_deduplicates_across_schemas():
    endpoints = [
        _endpoint_with_schemas(
            "/a", "GET", response_schema={"type": "object", "properties": {"tier": {"type": "string"}}}
        ),
        _endpoint_with_schemas(
            "/b", "POST", request_schema={"type": "object", "properties": {"tier": {"type": "string"}}}
        ),
    ]
    result = discover_candidate_fields(endpoints, declared_fields=set())
    assert result.count(("tier", "apisec-test")) == 1


def test_discover_candidate_fields_picks_placeholder_by_type():
    endpoints = [
        _endpoint_with_schemas(
            "/a",
            "GET",
            response_schema={
                "type": "object",
                "properties": {
                    "is_verified": {"type": "boolean"},
                    "balance": {"type": "number"},
                    "count": {"type": "integer"},
                },
            },
        ),
    ]
    result = discover_candidate_fields(endpoints, declared_fields=set())
    assert ("is_verified", True) in result
    assert ("balance", 1.0) in result
    assert ("count", 1) in result


def test_discover_candidate_fields_returns_nothing_when_spec_has_no_schemas():
    endpoints = [Endpoint(path="/health", method="GET", operation_id="health")]
    assert discover_candidate_fields(endpoints, declared_fields=set()) == []


# ---- _collection_path -----------------------------------------------------------

def test_collection_path_strips_trailing_id_segment():
    assert _collection_path("/orders/{order_id}") == "/orders"
    assert _collection_path("/users/{username}") == "/users"


def test_collection_path_none_when_id_is_not_the_last_segment():
    # e.g. PUT /users/{username}/email -- no obvious "create one of these"
    # collection endpoint to correlate with.
    assert _collection_path("/users/{id}/email") is None


def test_collection_path_none_when_no_id_param_at_all():
    assert _collection_path("/health") is None


# ---- _extract_id_from_response ---------------------------------------------------

def test_extract_id_top_level():
    assert _extract_id_from_response({"id": 7, "message": "ok"}) == "7"


def test_extract_id_nested_one_level():
    # common real-world wrapper shape, e.g. crAPI's {"order": {"id": 7}}
    assert _extract_id_from_response({"order": {"id": 7}, "status": "ok"}) == "7"


def test_extract_id_returns_none_when_absent():
    assert _extract_id_from_response({"message": "ok"}) is None


def test_extract_id_ignores_booleans():
    # bool is technically an int subclass in Python -- must not be mistaken
    # for a numeric id.
    assert _extract_id_from_response({"id": True}) is None


def test_extract_id_returns_none_for_non_dict_body():
    assert _extract_id_from_response([1, 2, 3]) is None
    assert _extract_id_from_response("not json") is None


# ---- discover_resource_id, using fake sessions/endpoints (no network) -----------

class _FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}

    def json(self):
        return self._body


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls: list[tuple] = []

    def request(self, method, url, json=None, timeout=5, **kwargs):
        self.calls.append((method, url, json))
        return self.response


def _order_item_endpoint():
    return Endpoint(path="/orders/{order_id}", method="GET", operation_id="get_order")


def _order_collection_endpoint(schema=None):
    return Endpoint(
        path="/orders", method="POST", operation_id="create_order", request_body_schema=schema
    )


def test_discover_resource_id_creates_and_extracts_id():
    session = _FakeSession(_FakeResponse(201, {"id": 42, "message": "created"}))
    ctx = ScanContext(
        base_url="http://x",
        session_a=session,
        all_endpoints=[_order_item_endpoint(), _order_collection_endpoint()],
    )
    assert discover_resource_id(_order_item_endpoint(), ctx) == "42"
    # confirms it POSTed to the collection path, not the item path
    assert session.calls[0][0] == "POST"
    assert session.calls[0][1] == "http://x/orders"


def test_discover_resource_id_none_when_no_sibling_post():
    session = _FakeSession(_FakeResponse(200, {"id": 1}))
    ctx = ScanContext(base_url="http://x", session_a=session, all_endpoints=[_order_item_endpoint()])
    assert discover_resource_id(_order_item_endpoint(), ctx) is None
    assert session.calls == []  # never even attempted a request


def test_discover_resource_id_none_when_post_rejected():
    session = _FakeSession(_FakeResponse(403, {}))
    ctx = ScanContext(
        base_url="http://x",
        session_a=session,
        all_endpoints=[_order_item_endpoint(), _order_collection_endpoint()],
    )
    assert discover_resource_id(_order_item_endpoint(), ctx) is None


def test_discover_resource_id_none_when_response_has_no_id():
    session = _FakeSession(_FakeResponse(200, {"message": "ok, but no id anywhere"}))
    ctx = ScanContext(
        base_url="http://x",
        session_a=session,
        all_endpoints=[_order_item_endpoint(), _order_collection_endpoint()],
    )
    assert discover_resource_id(_order_item_endpoint(), ctx) is None


def test_discover_resource_id_uses_collection_endpoints_own_schema_for_payload():
    schema = {"type": "object", "properties": {"product_id": {"type": "integer"}}}
    session = _FakeSession(_FakeResponse(200, {"id": 9}))
    ctx = ScanContext(
        base_url="http://x",
        session_a=session,
        all_endpoints=[_order_item_endpoint(), _order_collection_endpoint(schema)],
    )
    discover_resource_id(_order_item_endpoint(), ctx)
    assert session.calls[0][2] == {"product_id": 1}  # built from the POST's OWN schema


# ---- _item_endpoint_for_collection_path (reverse of _collection_path) -----------

def test_item_endpoint_for_collection_path_finds_matching_get():
    endpoints = [_order_collection_endpoint(), _order_item_endpoint()]
    found = _item_endpoint_for_collection_path("/orders", endpoints)
    assert found is not None
    assert found.path == "/orders/{order_id}"
    assert found.method == "GET"


def test_item_endpoint_for_collection_path_none_when_no_match():
    assert _item_endpoint_for_collection_path("/orders", [_order_collection_endpoint()]) is None


def test_item_endpoint_for_collection_path_ignores_non_get_methods():
    # a PATCH on /orders/{order_id} doesn't count as the "item GET"
    patch_ep = Endpoint(path="/orders/{order_id}", method="PATCH", operation_id="update_order")
    assert _item_endpoint_for_collection_path("/orders", [patch_ep]) is None


# ---- find_item_endpoint_for_payload (client-chosen id fallback) -----------------

def _user_item_endpoint():
    return Endpoint(path="/users/v1/{username}", method="GET", operation_id="get_user")


def test_find_item_endpoint_for_payload_matches_path_param_to_payload_key():
    payload = {"username": "alice", "password": "hunter2"}
    endpoint, value = find_item_endpoint_for_payload(payload, [_user_item_endpoint()])
    assert endpoint is not None
    assert endpoint.path == "/users/v1/{username}"
    assert value == "alice"


def test_find_item_endpoint_for_payload_none_when_no_key_matches():
    payload = {"email": "alice@example.com"}
    endpoint, value = find_item_endpoint_for_payload(payload, [_user_item_endpoint()])
    assert endpoint is None
    assert value is None


def test_find_item_endpoint_for_payload_skips_multi_param_paths():
    multi_param_ep = Endpoint(path="/users/v1/{username}/orders/{order_id}", method="GET", operation_id="x")
    payload = {"username": "alice"}
    endpoint, value = find_item_endpoint_for_payload(payload, [multi_param_ep])
    assert endpoint is None
    assert value is None


def test_find_item_endpoint_for_payload_ignores_boolean_values():
    # bool is an int subclass -- must not be mistaken for a usable id value
    ep = Endpoint(path="/flags/{enabled}", method="GET", operation_id="get_flag")
    payload = {"enabled": True}
    endpoint, value = find_item_endpoint_for_payload(payload, [ep])
    assert endpoint is None
    assert value is None


# ---- _identity_from_session: pulling a real id out of the scan's own JWT ------

class _SessionWithHeaders:
    def __init__(self, headers):
        self.headers = headers


def _bearer(claims):
    return {"Authorization": f"Bearer {jwt.encode(claims, 'whatever-secret', algorithm='HS256')}"}


def test_identity_from_session_extracts_sub_claim():
    session = _SessionWithHeaders(_bearer({"sub": "alice"}))
    assert _identity_from_session(session) == "alice"


def test_identity_from_session_prefers_username_over_sub():
    # _IDENTITY_CLAIM_KEYS checks "username" before "sub" -- a token with
    # both should use the more specific, human-readable one.
    session = _SessionWithHeaders(_bearer({"sub": "1", "username": "alice"}))
    assert _identity_from_session(session) == "alice"


def test_identity_from_session_handles_numeric_claim():
    session = _SessionWithHeaders(_bearer({"user_id": 42}))
    assert _identity_from_session(session) == "42"


def test_identity_from_session_returns_none_when_no_authorization_header():
    assert _identity_from_session(_SessionWithHeaders({})) is None


def test_identity_from_session_returns_none_for_non_bearer_scheme():
    session = _SessionWithHeaders({"Authorization": "Basic dXNlcjpwYXNz"})
    assert _identity_from_session(session) is None


def test_identity_from_session_returns_none_for_non_jwt_token():
    # an opaque session id / API key, not shaped like a JWT at all
    session = _SessionWithHeaders({"Authorization": "Bearer not-a-real-jwt"})
    assert _identity_from_session(session) is None


def test_identity_from_session_returns_none_when_no_matching_claim_present():
    session = _SessionWithHeaders(_bearer({"exp": 9999999999, "iat": 1}))
    assert _identity_from_session(session) is None


def test_identity_from_session_ignores_boolean_claim_values():
    # bool is an int subclass -- a claim like "id": true must not be
    # mistaken for a usable identifier
    session = _SessionWithHeaders(_bearer({"id": True}))
    assert _identity_from_session(session) is None


# ---- _candidate_ids_for: discovery, then identity, then guessing --------------

def _id_endpoint():
    return Endpoint(path="/orders/{order_id}", method="GET", operation_id="get_order")


class _NoDiscoverySession(_SessionWithHeaders):
    """No sibling POST in all_endpoints -- discover_resource_id() always
    returns None, isolating _candidate_ids_for()'s identity-claim behavior."""


def test_candidate_ids_for_includes_own_identity_before_guessing():
    session = _NoDiscoverySession(_bearer({"sub": "realuser42"}))
    ctx = ScanContext(base_url="http://x", session_a=session, all_endpoints=[_id_endpoint()])
    candidates = _candidate_ids_for(_id_endpoint(), ctx)
    assert candidates == ["realuser42", "1", "2", "3", "4", "5"]


def test_candidate_ids_for_falls_back_to_guessing_without_a_jwt():
    session = _NoDiscoverySession({})  # no Authorization header at all
    ctx = ScanContext(base_url="http://x", session_a=session, all_endpoints=[_id_endpoint()])
    assert _candidate_ids_for(_id_endpoint(), ctx) == ["1", "2", "3", "4", "5"]


def test_candidate_ids_for_does_not_duplicate_identity_already_in_guess_list():
    # a token whose claim happens to be a plain digit already in _CANDIDATE_IDS
    session = _NoDiscoverySession(_bearer({"sub": "3"}))
    ctx = ScanContext(base_url="http://x", session_a=session, all_endpoints=[_id_endpoint()])
    candidates = _candidate_ids_for(_id_endpoint(), ctx)
    assert candidates == ["3", "1", "2", "4", "5"]
    assert candidates.count("3") == 1
