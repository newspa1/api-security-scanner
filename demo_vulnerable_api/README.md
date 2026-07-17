# Demo Vulnerable API

An **intentionally vulnerable** FastAPI app used as the target for testing
`apisec-scanner` end-to-end. Each endpoint contains a deliberate bug matching one
of the scanner's checks. **Do not deploy this anywhere.**

## Run it

```bash
pip install -e ".[dev]"        # from the repo root; installs fastapi + uvicorn
uvicorn demo_vulnerable_api.app:app --reload
```

Then the OpenAPI spec the scanner consumes is served at
`http://localhost:8000/openapi.json`.

Get a token to scan with:

```bash
curl -s -X POST http://localhost:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pw"}'
# -> {"access_token":"eyJ...","token_type":"bearer"}
```

## Seed data

| User | id | username / password | role |
|---|---|---|---|
| A | 1 | `alice` / `alice-pw` | user |
| B | 2 | `bob` / `bob-pw` | user |

Orders: order `1` belongs to user A, order `2` belongs to user B.

## Planted vulnerabilities

| Endpoint | Bug | OWASP check |
|---|---|---|
| `POST /login` + auth | JWT signature verification disabled → `alg=none` forged tokens accepted | Broken Authentication (API2) |
| `GET /users/{id}` | returns `password_hash` in the body | Excessive Data Exposure (API3) |
| `GET /users/{id}` | no ownership check — any user can read any id | BOLA (API1) |
| `GET /orders/{id}` | no ownership check | BOLA (API1) |
| `PATCH /users/{id}` | applies undeclared body fields (e.g. `role`) not in the schema | Mass Assignment (API6) |

`GET /me` is deliberately **clean** (no `password_hash`) so the Excessive Data
Exposure check has exactly one true positive to find (`/users/{id}`).

Each bug is marked with a `# VULNERABLE:` comment in `app.py`.
