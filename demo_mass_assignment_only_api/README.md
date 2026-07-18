# Demo Mass-Assignment-Only API

Everything is correctly defended (real signature verification, clean
responses, no id-addressable GET endpoint at all) except one thing:
`PATCH /me` blindly applies every field in the raw request body instead of
only the declared `name` field. Scanning this should produce **exactly one
finding**: `API3:2023` (Mass Assignment).

## Run it

```bash
uvicorn demo_mass_assignment_only_api.app:app --port 8003
```

## Seed data

`alice`/`alice-pw` (id 1), `bob`/`bob-pw` (id 2). No orders in this one — the
whole point is there's no id-addressable GET endpoint, so BOLA has nothing to
probe.

## The one planted bug

`PATCH /me`'s OpenAPI schema only declares `name` as writable, but the
handler reads the raw request body and copies every field onto the record —
so `{"name": "x", "role": "admin"}` silently sets `role` too. Marked
`# THE ONLY PLANTED BUG:` in `app.py`.

## Scan it

```bash
TOKEN_A=$(curl -s -X POST http://localhost:8003/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-pw"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
TOKEN_B=$(curl -s -X POST http://localhost:8003/login -H 'Content-Type: application/json' -d '{"username":"bob","password":"bob-pw"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

apisec --spec http://localhost:8003/openapi.json --target http://localhost:8003 \
  --auth-header "Bearer $TOKEN_A" --auth-header-b "Bearer $TOKEN_B"
```

Expected: one `HIGH` row, `API3:2023 Mass Assignment` on `PATCH /me`. Exit
code `1`.
