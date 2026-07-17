"""Part 1 correctness test: prove each planted bug in the demo API behaves as
designed. This is the ground truth the scanner checks are later validated
against — if these fail, the demo target is wrong and no scanner result can be
trusted."""

import base64
import json

import jwt
import pytest
from fastapi.testclient import TestClient

from demo_vulnerable_api.app import SECRET_KEY, _reset_state, app


@pytest.fixture
def client():
    _reset_state()  # isolate: restore seed data before each test
    return TestClient(app)


def _token_for(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_alg_none(original_token: str) -> str:
    payload = jwt.decode(original_token, options={"verify_signature": False})
    header = _b64url_no_pad(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url_no_pad(json.dumps(payload).encode())
    return f"{header}.{body}."


def test_login_issues_token(client):
    token = _token_for(client, "alice", "alice-pw")
    assert token.count(".") == 2  # header.payload.signature


def test_broken_auth_alg_none_is_accepted(client):
    # The core Broken Auth bug: a forged, unsigned token is accepted.
    real = _token_for(client, "alice", "alice-pw")
    forged = _forge_alg_none(real)
    resp = client.get("/me", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 200


def test_users_endpoint_leaks_password_hash(client):
    token = _token_for(client, "alice", "alice-pw")
    resp = client.get("/users/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "password_hash" in resp.json()  # Excessive Data Exposure


def test_me_is_clean_no_password_hash(client):
    # /me must NOT leak, so the scanner has exactly one EDE true positive.
    token = _token_for(client, "alice", "alice-pw")
    resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "password_hash" not in resp.json()


def test_bola_user_b_can_read_user_a(client):
    token_b = _token_for(client, "bob", "bob-pw")
    # Bob (id 2) reads Alice's record (id 1) — should be forbidden but isn't.
    resp = client.get("/users/1", headers={"Authorization": f"Bearer {token_b}"})
    assert resp.status_code == 200
    assert resp.json()["username"] == "alice"


def test_bola_user_b_can_read_user_a_order(client):
    token_b = _token_for(client, "bob", "bob-pw")
    resp = client.get("/orders/1", headers={"Authorization": f"Bearer {token_b}"})
    assert resp.status_code == 200
    assert resp.json()["user_id"] == 1  # Alice's order, read by Bob


def test_mass_assignment_applies_undeclared_role(client):
    token = _token_for(client, "alice", "alice-pw")
    resp = client.patch(
        "/users/1",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Alice Updated", "role": "admin"},  # role is undeclared
    )
    assert resp.status_code == 200
    # Read back the full record and confirm the privileged field stuck.
    check = client.get("/users/1", headers={"Authorization": f"Bearer {token}"})
    assert check.json()["role"] == "admin"


def test_openapi_spec_is_served(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    assert "/users/{user_id}" in paths
    # The PATCH body schema should advertise only `name`, not `role`.
    patch_schema = paths["/users/{user_id}"]["patch"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    # schema may be a $ref; resolve if so
    resp_full = resp.json()
    if "$ref" in patch_schema:
        ref_name = patch_schema["$ref"].split("/")[-1]
        patch_schema = resp_full["components"]["schemas"][ref_name]
    assert set(patch_schema.get("properties", {})) == {"name"}
