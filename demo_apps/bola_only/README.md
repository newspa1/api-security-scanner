# Demo BOLA-Only API

Everything is correctly defended (real signature verification, clean
responses, no write endpoints) except one thing: `GET /orders/{id}` has no
ownership check. Scanning this should produce **exactly one finding**:
`API1:2023` (BOLA).

## Run it

```bash
uvicorn demo_apps.bola_only.app:app --port 8002
```

## Seed data

Same as `demo_apps/vulnerable`: `alice`/`alice-pw` (id 1), `bob`/`bob-pw` (id 2).
Order `1` belongs to Alice, order `2` belongs to Bob.

## The one planted bug

`GET /orders/{id}` returns any order to any authenticated user — there's no
check that the caller owns it. Marked `# THE ONLY PLANTED BUG:` in `app.py`.

## Scan it

```bash
TOKEN_A=$(curl -s -X POST http://localhost:8002/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-pw"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
TOKEN_B=$(curl -s -X POST http://localhost:8002/login -H 'Content-Type: application/json' -d '{"username":"bob","password":"bob-pw"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

apisec --spec http://localhost:8002/openapi.json --target http://localhost:8002 \
  --auth-header "Bearer $TOKEN_A" --auth-header-b "Bearer $TOKEN_B"
```

Expected: one `HIGH` row, `API1:2023 Broken Object Level Authorization (BOLA)`
on `GET /orders/{order_id}`. Exit code `1`.
