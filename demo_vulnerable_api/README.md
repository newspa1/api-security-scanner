# Demo Vulnerable API

Placeholder for the intentionally-vulnerable FastAPI app used to demo the
scanner (Phase 2 — see the roadmap in the top-level README).

Planned vulnerabilities to bake in, one per MVP check:
- `alg=none` accepted on `/me` (Broken Authentication)
- `/orders/{id}` returns any user's order given its id (BOLA)
- `PATCH /users/{id}` accepts and applies an unlisted `role` field (Mass Assignment)
- `GET /users/{id}` returns `password_hash` in the response body (Excessive Data Exposure)

Not implemented yet.
