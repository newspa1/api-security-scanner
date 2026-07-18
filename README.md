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

## Scan your own API

```bash
pip install -e ".[dev]"
```

You need: your API's OpenAPI spec (a URL or local file), your API's base
URL, and a valid auth token — two, if you want BOLA tested (a second
account, since BOLA is inherently about comparing what two different users
can each reach).

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
one.

## Validated against a real API, not just our own

A self-built demo proves the scanner catches what it was told to catch; it
says nothing about whether it generalizes. `apisec` has also been run
against [VAmPI](https://github.com/erev0s/VAmPI), an independent,
third-party vulnerable API project, and graded against *its own* documented
bug list — including two real false positives that were found and
permanently fixed as a direct result. See
[`EXTERNAL_VALIDATION.md`](EXTERNAL_VALIDATION.md) for the full, honest
write-up (hits, misses, and fixes, not just a hit count).

## Developing / testing this scanner itself

```bash
pytest
```

The checks themselves are validated against a set of purpose-built demo
targets (one bug per check, a zero-bug control group, etc.) — see
[`demo_apps/README.md`](demo_apps/README.md) if you want to see that proof,
reproduce it, or add a new check.

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
demo_apps/            # targets used to develop/validate the checks -- see demo_apps/README.md
.github/workflows/scan.yml  # CI: pytest, then the scanner against demo_apps/vulnerable
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

## Roadmap

**MVP** ✅ done — all four checks implemented and validated (self-built
demos + an external, independent API). `--public-paths` allowlist keeps
BOLA's false-positive rate honest on legitimately shared resources. CI runs
the full suite plus a live two-directional scan gate on every push.

**Stretch**
- [ ] Id *discovery* (not guessing) for BOLA/Mass Assignment, so they can
      test UUID- or username-keyed resources, not just sequential integers
- [ ] Simple web dashboard for scan results
- [ ] Record a demo video walking through each finding

## License

MIT
