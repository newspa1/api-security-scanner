# apisec-scanner

[![Security Scan](https://github.com/newspa1/api-security-scanner/actions/workflows/scan.yml/badge.svg)](https://github.com/newspa1/api-security-scanner/actions/workflows/scan.yml)

A lightweight scanner that tests REST APIs against the [OWASP API Security
Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/). Point it
at an OpenAPI/Swagger spec and a running instance of the API; it replays
each endpoint with adversarial variations and reports what it finds.

## Why this exists

Most open-source API scanners either wrap a generic fuzzer or focus on
schema validation. This project instead targets the specific, well-known
attack patterns in the OWASP API Top 10 — each check encodes *how* a real
exploit for that category works, not just "send garbage and see what
breaks."

## Status

| Check | OWASP ID | Status |
|---|---|---|
| Broken Authentication (JWT `alg=none`) | API2:2023 | ✅ implemented |
| Broken Object Level Authorization (BOLA) | API1:2023 | ✅ implemented |
| Mass Assignment | API3:2023 | ✅ implemented |
| Excessive Data Exposure | API3:2023 | ✅ implemented |

> Mass Assignment and Excessive Data Exposure intentionally share OWASP id
> API3:2023 ("Broken Object Property Level Authorization") — OWASP merged
> what were two separate 2019 categories into one in the 2023 revision (read
> vs write facets of the same missing property-level authorization). This
> scanner reports them as two distinct checks under that shared id,
> distinguished by `title`.

All four checks are validated against `demo_vulnerable_api/` — an
intentionally vulnerable FastAPI app with one planted bug per check (see its
own README). See each module in `src/apisec/checks/` for the detection
approach — every check's docstring documents its algorithm, scope decisions,
and known limitations (each is a heuristic, not a formal proof).

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# BOLA needs a second identity; --public-paths suppresses false positives
# on endpoints you've confirmed are intentionally shared across users.
apisec --spec http://localhost:8000/openapi.json --target http://localhost:8000 \
  --auth-header "Bearer eyJ...<user A>" \
  --auth-header-b "Bearer eyJ...<user B>" \
  --public-paths "/announcements/*"
```

Run the tests:

```bash
pytest
```

## Example scan output

A real run against `demo_vulnerable_api` (see below) — this is the current
scanner's actual output, not a mockup:

| Severity | Check | Method | Endpoint | Evidence |
|---|---|---|---|---|
| CRITICAL | API2:2023 Broken Authentication | GET | `/me` | Forged `alg=none` token accepted (HTTP 200) |
| HIGH | API1:2023 BOLA | GET | `/users/{user_id}` | User B read User A's record (both got HTTP 200 on the same id) |
| HIGH | API3:2023 Excessive Data Exposure | GET | `/users/{user_id}` | `password_hash` leaked — flagged by 2 independent layers: sensitive field name AND bcrypt value shape |
| HIGH | API3:2023 Mass Assignment | PATCH | `/users/{user_id}` | Undeclared fields (`role`, `is_admin`, `isAdmin`, `admin`, `permissions`) accepted and persisted |
| HIGH | API1:2023 BOLA | GET | `/orders/{order_id}` | User B read User A's order (both got HTTP 200 on the same id) |

Exit code `1` (blocks CI). `/announcements/{id}` — intentionally shared
across users — is correctly *not* flagged, because it was passed via
`--public-paths`.

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
demo_vulnerable_api/  # intentionally-broken FastAPI app, one bug per check
.github/workflows/scan.yml  # CI: pytest, then the scanner against the demo API
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

## CI

`.github/workflows/scan.yml` runs on every push: unit/integration tests
first, then it boots `demo_vulnerable_api` and scans it twice — once
expecting the gate to **block** (the vulnerable target, asserting all
expected finding categories are still caught — this is a regression guard
for the checks themselves), and once expecting the gate to **pass** cleanly
against a known-safe endpoint, proving the exit-code gate isn't just always
red.

## Roadmap

**MVP** ✅ done
- [x] Repo scaffold, spec loader, CLI, reference check (JWT `alg=none`)
- [x] Implement BOLA check (two-user auth support via `ScanContext`)
- [x] Implement Mass Assignment check
- [x] Implement Excessive Data Exposure check (hybrid: name + value-shape/entropy + schema conformance)
- [x] Build `demo_vulnerable_api/` (FastAPI app with one bug per check) to
      validate each check catches its target vulnerability
- [x] `--public-paths` allowlist + spec-declared-public detection, to keep
      BOLA's false-positive rate honest on legitimately shared resources

**Stretch**
- [x] GitHub Action so the scanner can run in CI against the demo API
- [x] Example scan output in the README (see above)
- [ ] Simple web dashboard for scan results
- [ ] Record a demo video walking through each finding

## License

MIT
