# Demo Secure API

The control group: a sibling of `demo_vulnerable_api` with the exact same
shape (same login flow, same seed data, same endpoints) but every bug fixed.
Scanning this should produce **zero findings**.

## Run it

```bash
uvicorn demo_secure_api.app:app --port 8001
```

## Seed data

Same as `demo_vulnerable_api`: `alice`/`alice-pw` (id 1), `bob`/`bob-pw` (id 2).
Order `1` belongs to Alice, order `2` belongs to Bob.

## What's fixed, compared to `demo_vulnerable_api`

| Endpoint | Fix | Closes |
|---|---|---|
| auth (`get_current_user`) | signature actually verified, only `HS256` accepted | Broken Authentication (API2) |
| `GET /me` | returns only public fields, no `password`/`password_hash` | Excessive Data Exposure (API3) |
| `PATCH /me` | applies only the validated `name` field from the parsed model, ignores raw body | Mass Assignment (API3) |
| `GET /orders/{id}` | explicit ownership check (`403` if not the caller's own order) | BOLA (API1) |

## Scan it

```bash
TOKEN_A=$(curl -s -X POST http://localhost:8001/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-pw"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
TOKEN_B=$(curl -s -X POST http://localhost:8001/login -H 'Content-Type: application/json' -d '{"username":"bob","password":"bob-pw"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

apisec --spec http://localhost:8001/openapi.json --target http://localhost:8001 \
  --auth-header "Bearer $TOKEN_A" --auth-header-b "Bearer $TOKEN_B"
```

Expected: `No findings.` and exit code `0`.
