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
| Broken Authentication (no auth required at all) | API2:2023 |
| Broken Object Level Authorization (BOLA) | API1:2023 |
| Broken Object Level Authorization (BOLA) - Write Access | API1:2023 |
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
| `--mass-assignment-fields` | no | Extra undeclared fields to try injecting, extending the built-in candidate list with fields specific to your own API. Inline: `"tier=premium,limit=9999"`. Or `"@fields.txt"` to read a longer, reusable list from a file (JSON object, or one `name=value` per line with `#` comments) |
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
    missing_auth.py   # API2 — no Authorization header required at all
    bola.py           # API1 — two-identity cross-access diff (read)
    write_bola.py      # API1 — two-identity cross-access diff (PATCH/PUT)
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
- **BOLA, Mass Assignment, and the missing-auth check try a real,
  discovered id first** (create a resource, read its id back), falling back
  to guessing `"1".."5"` only when discovery doesn't work — needed for
  UUID-/nanoid-keyed resources, which a fixed guess range can never reach.
  See [`EXTERNAL_VALIDATION.md`](EXTERNAL_VALIDATION.md) for a real id that
  guessing missed and discovery found.

## Roadmap

**MVP** ✅ done — the original four checks implemented and validated,
including against an independent third-party API (see
`EXTERNAL_VALIDATION.md`). `--public-paths` allowlist keeps BOLA's
false-positive rate honest on legitimately shared resources. CI runs the
full suite plus a live two-directional scan gate on every push.

**Since MVP, all confirmed working against real, independent targets (not
just this repo's own demo apps) — see `EXTERNAL_VALIDATION.md`:**
- ✅ Id *discovery* (not guessing) for BOLA/Mass Assignment — creates a real
      resource and reads its id back, instead of guessing `"1".."5"`, so
      UUID-/nanoid-keyed resources are reachable too
- ✅ Mass Assignment on `POST` (resource creation), not just `PATCH`/`PUT`
- ✅ Mass Assignment confidence tiers (CONFIRMED/SUSPECTED/CLEAR) — an
      accepted-but-unprovable field write is reported as a low-confidence
      lead instead of staying silent
- ✅ A fifth check, **missing authentication entirely** (`missing_auth.py`)
      — distinct from JWT `alg=none` forgery, this catches endpoints that
      never check for a bearer token in the first place. Motivated by a
      real finding while scanning crAPI, not a hypothetical.
- ✅ **"Search a list" read-back** for Mass Assignment — some APIs never
      expose an injected field on any single-resource read-back, only on a
      separate "list everything" endpoint; this fallback finds and checks
      those too. Confirmed live on VAmPI: the registration bug (undeclared
      `admin: true`) now reaches full CONFIRMED/HIGH, not just a
      low-confidence lead.
- ✅ A sixth check, **write-based BOLA** (`write_bola.py`) — `PATCH`/`PUT`
      to another user's object, not just `GET`. `DELETE` is deliberately
      excluded (see the check's own docstring for why). Found a real,
      previously-uncounted bug on this repo's own demo target as a direct
      result.
- ✅ **Recovering the scanning identity's own client-chosen id** from its
      JWT (`_identity_from_session()`) — most tokens carry the username as
      a plaintext claim (`sub`, `username`, ...), which BOLA/write-BOLA can
      use as a candidate id when numeric guessing and id discovery both
      come up empty. Closed VAmPI's most severe documented bug: full
      account takeover via unauthenticated password change, on both the
      read and write side.
- ✅ **A config surface for target-specific Mass Assignment candidate
      fields** — `--mass-assignment-fields "name=value,..."` extends the
      built-in candidate list with fields specific to your own API's
      domain (e.g. `subscription_tier`, `credit_limit`), the same
      human-supplied-escape-hatch pattern as `--public-paths`. Also
      accepts `"@fields.txt"` to read a longer, reusable list from a file
      instead of one long comma-joined string.
- ✅ **Re-weight finding severity by reachability** — any finding sharing
      an endpoint with a "no authentication required" finding gets bumped
      up one severity level (e.g. a HIGH BOLA becomes CRITICAL), since
      "anyone on the internet can reach this" is strictly worse than the
      identical bug behind a login wall. Confirmed on this repo's own demo
      target.

**Stretch**
- [ ] Recovering an ARBITRARY other user's client-chosen id for BOLA — the
      identity-recovery fix above only recovers the scanning identity's
      OWN id (works for "my own resource, someone else has a copy of it
      too" endpoints like `/password`; doesn't help for an unrelated other
      user's resource)
- [ ] Simple web dashboard for scan results

## License

MIT
