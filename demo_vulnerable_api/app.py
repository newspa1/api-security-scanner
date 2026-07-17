"""Intentionally vulnerable API — the target the scanner is tested against.

Every `# VULNERABLE:` comment marks a deliberate bug, one per scanner check:
  - POST /login .......... issues a JWT whose verification is disabled (accepts
                           alg=none forged tokens)            -> Broken Auth
  - GET  /users/{id} ..... returns password_hash in the body  -> Excessive Data Exposure
  - GET  /users/{id} ..... no ownership check (any user, any id) -> BOLA
  - GET  /orders/{id} .... no ownership check                 -> BOLA
  - PATCH /users/{id} .... applies undeclared fields (e.g. role) -> Mass Assignment

DO NOT deploy this. It exists only so the scanner has something real to catch.
Run it with:  uvicorn demo_vulnerable_api.app:app --reload
"""

from __future__ import annotations

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

SECRET_KEY = "demo-not-a-real-secret"

# In-memory seed data. Two users so BOLA (user B reads user A's objects) is
# testable. `_reset_state()` restores this exactly — used by tests for isolation.
_SEED_USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "password": "alice-pw",
        "password_hash": "$2b$12$demo.hash.for.alice.deadbeefdeadbeefdeadbeef",
        "name": "Alice",
        "email": "alice@example.com",
        "role": "user",
    },
    2: {
        "id": 2,
        "username": "bob",
        "password": "bob-pw",
        "password_hash": "$2b$12$demo.hash.for.bob.cafebabecafebabecafebabe0",
        "name": "Bob",
        "email": "bob@example.com",
        "role": "user",
    },
}
_SEED_ORDERS = {
    1: {"id": 1, "user_id": 1, "item": "Widget", "amount": 42.0},
    2: {"id": 2, "user_id": 2, "item": "Gadget", "amount": 13.5},
}

USERS: dict[int, dict] = {}
ORDERS: dict[int, dict] = {}


def _reset_state() -> None:
    """Restore seed data (deep-ish copy so mutations don't leak across tests)."""
    USERS.clear()
    ORDERS.clear()
    USERS.update({uid: dict(u) for uid, u in _SEED_USERS.items()})
    ORDERS.update({oid: dict(o) for oid, o in _SEED_ORDERS.items()})


_reset_state()

app = FastAPI(title="Demo Vulnerable API", version="1.0.0")


class LoginRequest(BaseModel):
    username: str
    password: str


class UserUpdate(BaseModel):
    # NOTE: only `name` is declared here, so this is the sole field the OpenAPI
    # spec advertises for the PATCH body. The handler below ignores that and
    # applies the raw body — that gap is the mass-assignment vulnerability.
    name: str


def _public_user(user: dict) -> dict:
    """A user view without the raw password. Still leaks password_hash on the
    /users/{id} route on purpose; /me uses this to stay clean."""
    return {k: v for k, v in user.items() if k not in {"password", "password_hash"}}


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ")
    try:
        # VULNERABLE (Broken Auth): signature verification is disabled, so a
        # forged token with alg=none and an empty signature is accepted. An
        # attacker can set `sub` to any user id without knowing the secret.
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256", "none"],
            options={"verify_signature": False},
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid token")
    sub = payload.get("sub")
    user = USERS.get(int(sub)) if sub is not None else None
    if user is None:
        raise HTTPException(status_code=401, detail="unknown user")
    return user


@app.post("/login")
def login(body: LoginRequest) -> dict:
    for user in USERS.values():
        if user["username"] == body.username and user["password"] == body.password:
            token = jwt.encode({"sub": str(user["id"])}, SECRET_KEY, algorithm="HS256")
            return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="bad credentials")


@app.get("/me")
def read_me(current: dict = Depends(get_current_user)) -> dict:
    # Clean view: no password_hash — so the Excessive Data Exposure check should
    # NOT fire here, only on /users/{id}.
    return _public_user(current)


@app.get("/users/{user_id}")
def read_user(user_id: int, current: dict = Depends(get_current_user)) -> dict:
    user = USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    # VULNERABLE (BOLA): no check that `current` is allowed to read `user_id`.
    # VULNERABLE (Excessive Data Exposure): returns the full record including
    # password_hash instead of a curated response model.
    return user


@app.get("/orders/{order_id}")
def read_order(order_id: int, current: dict = Depends(get_current_user)) -> dict:
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    # VULNERABLE (BOLA): any authenticated user can read any order.
    return order


@app.patch("/users/{user_id}")
async def update_user(
    user_id: int,
    body: UserUpdate,  # noqa: ARG001 — declared for the OpenAPI schema only
    request: Request,
    current: dict = Depends(get_current_user),
) -> dict:
    user = USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    raw = await request.json()
    # VULNERABLE (Mass Assignment): blindly copies every field from the request
    # body onto the stored record, including undeclared privileged fields like
    # `role` that the OpenAPI schema never advertised.
    for key, value in raw.items():
        user[key] = value
    return _public_user(user)
