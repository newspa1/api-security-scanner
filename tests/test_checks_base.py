"""Tests for shared check infrastructure in checks/base.py: build_legit_payload
(moved here from mass_assignment.py, now shared) and the id-DISCOVERY
machinery -- create a real resource via a sibling POST, read its real id back
-- that bola.py and mass_assignment.py both try first before falling back to
sequential-integer guessing (concrete_url's default).
"""

from __future__ import annotations

from apisec.checks.base import (
    ScanContext,
    _collection_path,
    _extract_id_from_response,
    build_legit_payload,
    discover_resource_id,
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
