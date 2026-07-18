# Demo Apps — How This Scanner Is Tested On Itself

This directory holds the target APIs used to develop and validate
`apisec`'s checks. If you just want to scan **your own** API, you don't need
anything here — see the main [README](../README.md). This doc is for anyone
who wants to see proof the checks work, reproduce that proof, or extend the
scanner with a new check.

## The four targets

Each is a small, self-contained FastAPI app demonstrating a different, exact,
predictable scan outcome — every claim below is enforced by a test that runs
the real scanner and asserts the result (`tests/test_scan_all_targets.py`,
`tests/test_demo_*.py`), not just described here.

| Target | Port | Planted bug(s) | Expected scan outcome |
|---|---|---|---|
| `demo_apps/vulnerable` | 8000 | one bug per check (see its own README) | 5 findings across all 3 OWASP ids |
| `demo_apps/secure` | 8001 | none — the control group | **zero findings**, exit `0` |
| `demo_apps/bola_only` | 8002 | missing ownership check on `GET /orders/{id}` | **exactly 1 finding**: `API1:2023` |
| `demo_apps/mass_assignment_only` | 8003 | `PATCH /me` applies undeclared fields | **exactly 1 finding**: `API3:2023` |

Seed users on every target: `alice`/`alice-pw`, `bob`/`bob-pw`.

## The fastest way to see all four compared: one test command

`tests/test_scan_all_targets.py` runs the exact same scan against all four
targets and prints what it found, before asserting it's exactly what's
claimed above:

```bash
pytest tests/test_scan_all_targets.py -v -s
```

```
tests/test_scan_all_targets.py::test_scan_reveals_expected_bugs[vulnerable]
Demo Vulnerable API: 5 finding(s)
  [CRITICAL] API2:2023 Broken Authentication - JWT alg=none bypass -- GET /me
  [HIGH    ] API1:2023 Broken Object Level Authorization (BOLA) -- GET /users/{user_id}
  [HIGH    ] API3:2023 Excessive Data Exposure -- GET /users/{user_id}
  [HIGH    ] API3:2023 Mass Assignment -- PATCH /users/{user_id}
  [HIGH    ] API1:2023 Broken Object Level Authorization (BOLA) -- GET /orders/{order_id}
PASSED
tests/test_scan_all_targets.py::test_scan_reveals_expected_bugs[secure]
Demo Secure API: 0 finding(s)
  (none)
PASSED
tests/test_scan_all_targets.py::test_scan_reveals_expected_bugs[bola_only]
Demo BOLA-Only API: 1 finding(s)
  [HIGH    ] API1:2023 Broken Object Level Authorization (BOLA) -- GET /orders/{order_id}
PASSED
tests/test_scan_all_targets.py::test_scan_reveals_expected_bugs[mass_assignment_only]
Demo Mass-Assignment-Only API: 1 finding(s)
  [HIGH    ] API3:2023 Mass Assignment -- PATCH /me
PASSED
```

`-v` shows one line per target; `-s` un-hides the `print()` output pytest
normally captures, so what you see above is the actual findings, not just
green checkmarks.

## Or drive it by hand against a real running server

```bash
# pick one:
uvicorn demo_apps.vulnerable.app:app --port 8000
uvicorn demo_apps.secure.app:app --port 8001
uvicorn demo_apps.bola_only.app:app --port 8002
uvicorn demo_apps.mass_assignment_only.app:app --port 8003

# in another terminal (adjust the port to match):
PORT=8001
TOKEN_A=$(curl -s -X POST http://localhost:$PORT/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice-pw"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
TOKEN_B=$(curl -s -X POST http://localhost:$PORT/login -H 'Content-Type: application/json' -d '{"username":"bob","password":"bob-pw"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
apisec --spec http://localhost:$PORT/openapi.json --target http://localhost:$PORT \
  --auth-header "Bearer $TOKEN_A" --auth-header-b "Bearer $TOKEN_B"
```

Each target has its own README with the specifics of what's planted (or
deliberately not planted) and why.

## What CI does with these

`.github/workflows/scan.yml` boots `demo_apps/vulnerable` and scans it
twice on every push: once expecting the gate to **block** (the vulnerable
target — also asserting all expected finding categories are still caught,
a regression guard for the checks themselves), and once expecting the gate
to **pass** cleanly against a known-safe endpoint — proving the exit-code
gate isn't just always red on a portfolio repo.

## Adding a new demo target

Follow the pattern in `tests/test_scan_all_targets.py`'s `TARGETS` list:
build a small FastAPI app isolating exactly the bug(s) you want to prove
(or disprove), add it to `TARGETS` with its expected finding count and
`(check_id, title)` fingerprint, and reuse `tests/conftest.py`'s generic
`sessions_for` fixture rather than writing bespoke session-setup code.
