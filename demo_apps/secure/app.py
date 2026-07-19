"""A SECURE sibling of demo_apps/vulnerable -- no planted bugs at all. This is
the control group, proving the scanner doesn't cry wolf on properly-defended
code. Each `# FIXED (vs...)` comment marks the one line that closes the
corresponding bug in the vulnerable demo.

NOT literally zero findings, and that's intentional, not a bug here: Mass
Assignment's SUSPECTED/LOW confidence tier (see mass_assignment.py's module
docstring) fires on `PATCH /me` because its response genuinely has no
role/admin/permissions field to prove OR disprove an injection against --
see tests/test_scan_all_targets.py's "secure" test param for the full
explanation. Every HIGH/CRITICAL-severity check still produces zero here.

Run it with:  uvicorn demo_apps.secure.app:app --port 8001
"""

from __future__ import annotations

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

SECRET_KEY = "demo-not-a-real-secret"

_SEED_USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "password": "alice-pw",
        "name": "Alice",
        "email": "alice@example.com",
    },
    2: {
        "id": 2,
        "username": "bob",
        "password": "bob-pw",
        "name": "Bob",
        "email": "bob@example.com",
    },
}
_SEED_ORDERS = {
    1: {"id": 1, "user_id": 1, "item": "Widget", "amount": 42.0},
    2: {"id": 2, "user_id": 2, "item": "Gadget", "amount": 13.5},
}

USERS: dict[int, dict] = {}
ORDERS: dict[int, dict] = {}


def _reset_state() -> None:
    USERS.clear()
    ORDERS.clear()
    USERS.update({uid: dict(u) for uid, u in _SEED_USERS.items()})
    ORDERS.update({oid: dict(o) for oid, o in _SEED_ORDERS.items()})


_reset_state()

app = FastAPI(title="Demo Secure API", version="1.0.0")


class LoginRequest(BaseModel):
    username: str
    password: str


class MeUpdate(BaseModel):
    name: str


def _public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "name": user["name"],
        "email": user["email"],
    }


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ")
    try:
        # FIXED (vs. Broken Auth in demo_apps/vulnerable): the signature IS
        # verified, and only HS256 is accepted -- a forged alg=none token
        # fails here instead of being silently accepted.
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="invalid token")
    user = USERS.get(int(payload.get("sub", -1)))
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
    # FIXED (vs. Excessive Data Exposure): no password/password_hash returned.
    return _public_user(current)


@app.patch("/me")
def update_me(body: MeUpdate, current: dict = Depends(get_current_user)) -> dict:
    # FIXED (vs. Mass Assignment): only the explicitly declared field is
    # applied. Extra fields in a raw request body are never even looked at,
    # because we read from the validated `body` model, not the raw JSON.
    USERS[current["id"]]["name"] = body.name
    return _public_user(USERS[current["id"]])


@app.get("/orders/{order_id}")
def read_order(order_id: int, current: dict = Depends(get_current_user)) -> dict:
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    # FIXED (vs. BOLA): an explicit ownership check.
    if order["user_id"] != current["id"]:
        raise HTTPException(status_code=403, detail="not your order")
    return order


@app.get("/orders/{order_id}/receipt")
def read_order_receipt(order_id: int, current: dict = Depends(get_current_user)) -> dict:
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    # FIXED (vs. Missing Authentication): requires a valid bearer token,
    # same as every other endpoint here.
    if order["user_id"] != current["id"]:
        raise HTTPException(status_code=403, detail="not your order")
    return {"order_id": order["id"], "item": order["item"], "amount": order["amount"]}
