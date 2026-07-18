# apisec-scanner

[![Security Scan](https://github.com/newspa1/api-security-scanner/actions/workflows/scan.yml/badge.svg)](https://github.com/newspa1/api-security-scanner/actions/workflows/scan.yml)

A lightweight scanner that tests **your** REST API against the [OWASP API
Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).
Point it at your OpenAPI/Swagger spec and a running instance of your API; it
replays each endpoint with adversarial variations and reports what it finds.

## Why this exists

Most open-source API scanners either wrap a generic fuzzer or focus on
schema validation. This project instead targets the specific, well-known
attack patterns in the OWASP API Top 10 — each check encodes *how* a real
exploit for that category works, not just "send garbage and see what
breaks."

## What it checks

| Check | OWASP ID |
|---|---|
| Broken Authentication (JWT `alg=none` forgery) | API2:2023 |
| Broken Object Level Authorization (BOLA) | API1:2023 |
| Excessive Data Exposure | API3:2023 |
| Mass Assignment | API3:2023 |

> Excessive Data Exposure and Mass Assignment intentionally share OWASP id
> API3:2023 ("Broken Object Property Level Authorization") — OWASP merged
> what were two separate 2019 categories into one in the 2023 revision (read
> vs write facets of the same missing property-level authorization). This
> scanner reports them as two distinct checks under that shared id,
> distinguished by `title`.

Every check is a heuristic, not a formal proof — each module's docstring in
`src/apisec/checks/` documents its algorithm, what it deliberately doesn't
attempt, and its known false-positive classes.

## Quickstart

```bash
pip install -e ".[dev]"
```

### Try it against a real API first

Rather than take it on faith, try the scanner against a real, well-known
target before pointing it at your own API. [VAmPI](https://github.com/erev0s/VAmPI)
is a small, MIT-licensed Flask API built specifically to evaluate tools like
this one — a good five-minute sanity check. Four steps, in order:

**1. In one terminal, get VAmPI and start it running in the foreground —
leave this terminal open, it's your server log:**

```bash
git clone https://github.com/erev0s/VAmPI.git && cd VAmPI
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
vulnerable=1 python3 app.py            # runs on :5000, stays in the foreground
```

**2. In a second terminal, seed the database:**

```bash
curl -s http://localhost:5000/createdb
```

**3. Still in the second terminal, register two accounts and log in as
both — `apisec` needs two identities to test BOLA (comparing what different
users can each reach):**

```bash
curl -s -X POST http://localhost:5000/users/v1/register -H 'Content-Type: application/json' \
  -d '{"username":"scanuser1","password":"ScanPass1!","email":"a@tempmail.com"}'
curl -s -X POST http://localhost:5000/users/v1/register -H 'Content-Type: application/json' \
  -d '{"username":"scanuser2","password":"ScanPass2!","email":"b@tempmail.com"}'

TOKEN_A=$(curl -s -X POST http://localhost:5000/users/v1/login -H 'Content-Type: application/json' -d '{"username":"scanuser1","password":"ScanPass1!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['auth_token'])")
TOKEN_B=$(curl -s -X POST http://localhost:5000/users/v1/login -H 'Content-Type: application/json' -d '{"username":"scanuser2","password":"ScanPass2!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['auth_token'])")
```

**4. Still in the second terminal, run the scan** (from wherever
apisec-scanner is installed — activate its own venv here, not VAmPI's):

```bash
apisec --spec http://localhost:5000/openapi.json --target http://localhost:5000 \
  --auth-header "Bearer $TOKEN_A" --auth-header-b "Bearer $TOKEN_B"
```

Real, current output:

```
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Check             ┃ Method ┃ Endpoint         ┃ Description       ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ MEDIUM   │ API3:2023         │ GET    │ /users/v1/_debug │ The response      │
│          │ Excessive Data    │        │                  │ exposes fields    │
│          │ Exposure          │        │                  │ that look         │
│          │                   │        │                  │ sensitive.        │
└──────────┴───────────────────┴────────┴──────────────────┴───────────────────┘
```

That's a real, unauthenticated password leak in VAmPI's `/users/v1/_debug`
endpoint — exit code `0` because this one scores `MEDIUM`, not `HIGH`/`CRITICAL`.
**This isn't the whole story on purpose:** `apisec` also misses two more
severe, confirmed-exploitable bugs in this same target (an account-takeover
BOLA and a registration-time privilege escalation). A second, larger
validation pass against [OWASP crAPI](https://github.com/OWASP/crAPI) found
the opposite kind of result: a real, system-wide `alg=none` authentication
bypass, confirmed on 8 endpoints, plus a BOLA leaking payment card data —
and one more false-positive class in the scanner, found and fixed. See
[`EXTERNAL_VALIDATION.md`](EXTERNAL_VALIDATION.md) for the full write-up —
hits, misses, and three real scanner bugs that were found and fixed as a
direct result of this exercise. A tool that only ever reports clean sweeps
against itself isn't proving much; this one's report card is public.

### Now scan your own API

Same shape, pointed at your own target. You need: your API's OpenAPI spec (a
URL or local file), your API's base URL, and a valid auth token — two, if
you want BOLA tested (a second account, since BOLA is inherently about
comparing what two different users can each reach).

```bash
apisec --spec https://your-api.example.com/openapi.json \
  --target https://your-api.example.com \
  --auth-header "Bearer <token for user A>" \
  --auth-header-b "Bearer <token for user B>"
```

**Flags:**

| Flag | Required | Purpose |
|---|---|---|
| `--spec` | yes | Path or URL to your OpenAPI 3.x spec (JSON or YAML) |
| `--target` | yes | Base URL of your running API |
| `--auth-header` | no | Full `Authorization` header for one identity, e.g. `"Bearer eyJ..."` |
| `--auth-header-b` | no | A second identity's header — enables BOLA (cross-user) checks |
| `--public-paths` | no | Comma-separated glob patterns for endpoints you've confirmed are intentionally shared across users, e.g. `"/products/*,/announcements/*"` — suppresses BOLA false positives on them |
| `--json-out` | no | Also write the full findings list to this JSON file |

**Reading the report:** each finding has a severity (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`),
the OWASP check that raised it, the method + endpoint, and an evidence
string explaining specifically what was observed. The process exits `1` if
any `HIGH` or `CRITICAL` finding was reported (`0` otherwise) — wire that
into CI to fail a build on a real finding, the same way this repo's own
[`.github/workflows/scan.yml`](.github/workflows/scan.yml) does.

**A note on scope:** only scan APIs you own or are explicitly authorized to
test. `--auth-header-b` requires you to already hold valid credentials for a
second account you control — the scanner never tries to create or guess
one. Also worth knowing: `apisec` assumes `GET` requests are safe/read-only,
per HTTP convention — if your API has a `GET` endpoint with real side
effects (VAmPI's `/createdb` does), a full scan will trigger it.

## Architecture

```
src/apisec/
  spec_loader.py   # OpenAPI 3.x -> list[Endpoint] (incl. $ref-resolved schemas)
  scanner.py        # orchestrates: for each endpoint, run every check
  report.py         # rich table + JSON export
  checks/
    base.py         # Check protocol, ScanContext, Finding, concrete_url() helper
    broken_auth.py   # API2 — JWT alg=none
    bola.py           # API1 — two-identity cross-access diff
    mass_assignment.py         # API3 (write facet) — undeclared-field injection
    excessive_data_exposure.py # API3 (read facet) — hybrid 3-layer detection
```

Adding a new check means implementing the `Check` protocol (`id`, `title`,
`run(endpoint, ctx: ScanContext) -> list[Finding]`) and registering it in
`checks/__init__.py`.

## Design notes

A few decisions worth knowing about if you're reading the code:

- **BOLA is a black-box heuristic, not a proof.** The scanner never sees your
  source code, so it can't know what "ownership" means for your resources —
  it can only observe whether two independently-authenticated identities can
  both reach the same object id. That's a real signal, but a legitimately
  shared resource looks identical from outside, hence `--public-paths` and
  the `security: []`-declared-public skip. See `bola.py`'s docstring for the
  full reasoning.
- **Excessive Data Exposure layers three independent detectors** (sensitive
  field name, value shape + Shannon entropy, OpenAPI schema conformance) with
  confidence scoring, rather than relying on any single heuristic — a secret
  hidden under an innocuous field name still gets caught by its *value*
  looking like a bcrypt hash or JWT.
- **A rejected write/read is never treated as "safe."** Both BOLA and Mass
  Assignment treat a 4xx as "no evidence either way" and keep looking, rather
  than concluding an endpoint is secure from one failed probe.
- **BOLA and Mass Assignment currently only guess sequential-integer ids**
  (`"1".."5"`), not UUIDs or usernames — a known, documented scope boundary
  that has a confirmed real cost, not just a theoretical one. See
  [`EXTERNAL_VALIDATION.md`](EXTERNAL_VALIDATION.md).

## Roadmap

**MVP** ✅ done — all four checks implemented and validated, including
against an independent third-party API (see `EXTERNAL_VALIDATION.md`).
`--public-paths` allowlist keeps BOLA's false-positive rate honest on
legitimately shared resources. CI runs the full suite plus a live
two-directional scan gate on every push.

**Stretch**
- [ ] Id *discovery* (not guessing) for BOLA/Mass Assignment, so they can
      test UUID- or username-keyed resources, not just sequential integers
      — confirmed necessary, not just theoretical (`EXTERNAL_VALIDATION.md`)
- [ ] Mass Assignment on `POST` (resource creation), not just `PATCH`/`PUT`
- [ ] Re-weight finding severity by reachability (e.g. no-auth-required),
      not just detection-signal count
- [ ] Simple web dashboard for scan results

## License

MIT
