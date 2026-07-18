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
