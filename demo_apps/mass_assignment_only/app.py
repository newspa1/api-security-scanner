"""An API with EXACTLY ONE planted bug: Mass Assignment on PATCH /me. Auth is
correctly verified, /me's response is clean, and there's no id-addressable
GET endpoint for BOLA to probe at all -- so scanning this should produce
exactly ONE finding: API3:2023 (Mass Assignment).

Run it with:  uvicorn demo_apps.mass_assignment_only.app:app --port 8003
"""

from __future__ import annotations

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

SECRET_KEY = "demo-not-a-real-secret"

_SEED_USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "password": "alice-pw",
        "name": "Alice",
        "email": "alice@example.com",
        "role": "user",
    },
    2: {
        "id": 2,
        "username": "bob",
        "password": "bob-pw",
        "name": "Bob",
        "email": "bob@example.com",
        "role": "user",
    },
}

USERS: dict[int, dict] = {}


def _reset_state() -> None:
    USERS.clear()
    USERS.update({uid: dict(u) for uid, u in _SEED_USERS.items()})


_reset_state()

app = FastAPI(title="Demo Mass-Assignment-Only API", version="1.0.0")


class LoginRequest(BaseModel):
    username: str
    password: str


class MeUpdate(BaseModel):
    # Only `name` is declared -- this is the sole field the OpenAPI schema
    # advertises as writable. The handler below ignores that for the actual
    # write, which is the planted bug.
    name: str


def _public_user(user: dict) -> dict:
    return {k: v for k, v in user.items() if k not in {"password"}}


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


@app.patch("/me")
async def update_me(
    body: MeUpdate,  # noqa: ARG001 -- declared for the OpenAPI schema only
    request: Request,
    current: dict = Depends(get_current_user),
) -> dict:
    raw = await request.json()
    # THE ONLY PLANTED BUG: blindly copies every field from the raw request
    # body, including undeclared ones like `role`, instead of applying only
    # the validated `body.name`.
    for key, value in raw.items():
        USERS[current["id"]][key] = value
    return _public_user(USERS[current["id"]])
