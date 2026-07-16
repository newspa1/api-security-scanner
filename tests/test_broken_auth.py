import base64
import json

import jwt

from apisec.checks.broken_auth import _forge_alg_none_token


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
