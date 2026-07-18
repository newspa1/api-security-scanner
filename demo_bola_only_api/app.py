"""An API with EXACTLY ONE planted bug: BOLA on GET /orders/{id}. Auth is
correctly verified (unlike demo_vulnerable_api), responses are clean, and
there's no write endpoint at all -- so scanning this should produce exactly
ONE finding: API1:2023.

Run it with:  uvicorn demo_bola_only_api.app:app --port 8002
"""

from __future__ import annotations

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

SECRET_KEY = "demo-not-a-real-secret"

_SEED_USERS = {
    1: {"id": 1, "username": "alice", "password": "alice-pw", "name": "Alice", "email": "alice@example.com"},
    2: {"id": 2, "username": "bob", "password": "bob-pw", "name": "Bob", "email": "bob@example.com"},
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

app = FastAPI(title="Demo BOLA-Only API", version="1.0.0")


class LoginRequest(BaseModel):
    username: str
    password: str


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
        # Signature verified -- not the bug we're isolating here.
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
    # Clean -- not the bug we're isolating here.
    return _public_user(current)


@app.get("/orders/{order_id}")
def read_order(order_id: int, current: dict = Depends(get_current_user)) -> dict:
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    # THE ONLY PLANTED BUG: no ownership check. Any authenticated user can
    # read any order.
    return order
