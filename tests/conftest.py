"""Shared pytest fixtures: route a check's `requests.Session`-shaped calls
through the demo API's in-process FastAPI TestClient, so integration tests
don't need a real server running."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


class TestClientSession:
    """Minimal stand-in for requests.Session, backed by a TestClient. Only
    implements what the checks actually call: .get(), .request(), .headers."""

    def __init__(self, client: TestClient, token: str | None):
        self.client = client
        self.headers: dict[str, str] = {"Authorization": f"Bearer {token}"} if token else {}

    def get(self, url: str, timeout: float = 5, **kwargs):
        return self.request("GET", url, **kwargs)

    def request(self, method: str, url: str, headers: dict | None = None, timeout: float = 5, **kwargs):
        path = url.replace("http://testserver", "")
        merged = dict(self.headers)
        if headers:
            merged.update(headers)
        return self.client.request(method, path, headers=merged, **kwargs)


@pytest.fixture
def demo_client():
    from demo_vulnerable_api.app import _reset_state, app

    _reset_state()
    return TestClient(app)


@pytest.fixture
def demo_sessions(demo_client):
    """(alice_session, bob_session): TestClientSession instances, pre-logged-in
    as the two seeded demo users, ready to plug into a ScanContext as
    session_a / session_b."""

    def _login(username: str, password: str) -> TestClientSession:
        resp = demo_client.post("/login", json={"username": username, "password": password})
        return TestClientSession(demo_client, resp.json()["access_token"])

    return _login("alice", "alice-pw"), _login("bob", "bob-pw")
