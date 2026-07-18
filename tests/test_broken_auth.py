import base64
import json

import jwt

from apisec.checks.base import ScanContext
from apisec.checks.broken_auth import BrokenAuthCheck, _forge_alg_none_token
from apisec.spec_loader import Endpoint


def test_forge_alg_none_preserves_claims_but_strips_signature():
    original = jwt.encode({"user_id": 1, "role": "user"}, "some-secret", algorithm="HS256")

    forged = _forge_alg_none_token(original)

    header_b64, payload_b64, signature = forged.split(".")
    assert signature == ""

    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    assert header["alg"] == "none"
    assert payload == {"user_id": 1, "role": "user"}


def test_forge_alg_none_returns_none_for_garbage_input():
    assert _forge_alg_none_token("not-a-jwt") is None


def test_skips_spec_declared_public_endpoint():
    # A forged token "succeeding" against an endpoint that never required
    # auth in the first place isn't a bypass of anything -- there was no
    # signature check to bypass. The guard must short-circuit BEFORE any
    # request is attempted; assert that with a session that fails loudly if
    # touched at all, not just check the return value.
    class _ExplodingSession:
        headers = {"Authorization": "Bearer x"}

        def request(self, *args, **kwargs):
            raise AssertionError("should not make a request for a declared-public endpoint")

    ep = Endpoint(path="/public/thing", method="GET", operation_id="get_thing", security=[])
    ctx = ScanContext(base_url="http://x", session_a=_ExplodingSession())
    assert BrokenAuthCheck().run(ep, ctx) == []


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeSession:
    """Maps a fixed Authorization header VALUE to a canned status code, so
    the baseline (garbage credential) and forged-token requests can be
    distinguished. `headers` starts with a real, validly-SHAPED JWT (just
    not a real secret) -- _forge_alg_none_token needs actual JWT structure
    to decode, unlike a plain string, or it bails out with None before this
    fake's request() is ever reached."""

    def __init__(self, status_by_auth_value: dict[str, int]):
        real_looking = jwt.encode({"sub": "1"}, "whatever-secret", algorithm="HS256")
        self.headers = {"Authorization": f"Bearer {real_looking}"}
        self.status_by_auth_value = status_by_auth_value

    def request(self, method, url, headers=None, timeout=5, **kwargs):
        auth = (headers or {}).get("Authorization", "")
        # Anything that isn't the exact baseline probe is treated as "the
        # forged token" for this fake, since forging is randomized/opaque.
        key = "baseline" if auth == "Bearer not-a-real-token" else "forged"
        return _FakeResponse(self.status_by_auth_value.get(key, 404))


def test_skips_when_endpoint_has_no_real_auth_check():
    # Found scanning VAmPI (github.com/erev0s/VAmPI): several endpoints
    # accept ANY credential, including garbage, because they never check
    # auth at all. A forged token "succeeding" there is not a bypass.
    ep = Endpoint(path="/no-auth-at-all", method="GET", operation_id="get_thing")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"baseline": 200, "forged": 200}),
    )
    assert BrokenAuthCheck().run(ep, ctx) == []


def test_flags_when_baseline_rejected_but_forged_token_accepted():
    # The real bug: garbage credentials correctly rejected (auth IS
    # enforced), but the forged alg=none token still gets through.
    ep = Endpoint(path="/protected", method="GET", operation_id="get_thing")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"baseline": 401, "forged": 200}),
    )
    findings = BrokenAuthCheck().run(ep, ctx)
    assert len(findings) == 1
    assert findings[0].check_id == "API2:2023"


def test_no_finding_when_both_baseline_and_forged_are_rejected():
    ep = Endpoint(path="/well-defended", method="GET", operation_id="get_thing")
    ctx = ScanContext(
        base_url="http://x",
        session_a=_FakeSession({"baseline": 401, "forged": 401}),
    )
    assert BrokenAuthCheck().run(ep, ctx) == []
