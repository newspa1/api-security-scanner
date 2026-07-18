# External Validation: Testing apisec-scanner Against a Real API

Every other target in this repo (`demo_apps/vulnerable`, `secure`,
`bola_only`, `mass_assignment_only`) is a FastAPI app **we wrote ourselves**,
with bugs **we planted on purpose**. That proves the scanner catches what
it was told to catch — it says nothing about whether it generalizes to real
code it has never seen. Anyone can pass a test they wrote the answer key
for.

This document is that harder test: `apisec` run against an independent,
third-party REST API, graded against **that project's own** documented
vulnerability list, not ours.

## The target: VAmPI

[VAmPI](https://github.com/erev0s/VAmPI) (erev0s/VAmPI) — a Flask REST API
built specifically to evaluate third-party API security tools, with OWASP
API Top 10 bugs planted on purpose.

- MIT licensed, actively maintained, 1,275+ stars.
- Ships a real OpenAPI 3.0.1 spec, served at `/openapi.json`.
- Its own README documents these vulnerabilities: SQL injection, unauthorized
  password change, BOLA, Mass Assignment, Excessive Data Exposure (a debug
  endpoint), user/password enumeration, RegexDOS, lack of rate limiting, and
  a JWT auth bypass via a weak signing key.
- Commit tested: `f16052dce83f05847133ec98f01c5193a41de7d8` (2026-04-07).

**Ethical note:** VAmPI is a self-hosted practice target published
specifically to be scanned — running `apisec` against a local instance is no
different from testing against OWASP Juice Shop or DVWA. This is not
scanning any live third-party production service without authorization.

## Reproduce it

```bash
git clone https://github.com/erev0s/VAmPI.git && cd VAmPI
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
vulnerable=1 python3 app.py &          # runs on :5000

curl -s http://localhost:5000/createdb  # seed the database

curl -s -X POST http://localhost:5000/users/v1/register -H 'Content-Type: application/json' \
  -d '{"username":"scanuser1","password":"ScanPass1!","email":"a@tempmail.com"}'
curl -s -X POST http://localhost:5000/users/v1/register -H 'Content-Type: application/json' \
  -d '{"username":"scanuser2","password":"ScanPass2!","email":"b@tempmail.com"}'

TOKEN_A=$(curl -s -X POST http://localhost:5000/users/v1/login -H 'Content-Type: application/json' -d '{"username":"scanuser1","password":"ScanPass1!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['auth_token'])")
TOKEN_B=$(curl -s -X POST http://localhost:5000/users/v1/login -H 'Content-Type: application/json' -d '{"username":"scanuser2","password":"ScanPass2!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['auth_token'])")

# from the apisec-scanner repo, in its own venv:
apisec --spec http://localhost:5000/openapi.json --target http://localhost:5000 \
  --auth-header "Bearer $TOKEN_A" --auth-header-b "Bearer $TOKEN_B"
```

## What happened: the honest version, including what we got wrong first

The first real scan produced **6 findings, 5 of them false positives** — and
that outcome was more useful than a clean pass would have been. Two of the
false positives were real bugs in *our* scanner, found because this was the
first time it had ever run against a target it wasn't hand-built to pass.
Both were fixed on the spot; the fixes are permanent (see `broken_auth.py`
and `excessive_data_exposure.py`), not special-cased for VAmPI.

### 1. True positive: Excessive Data Exposure on `/users/v1/_debug`

```
MEDIUM  API3:2023 Excessive Data Exposure  GET /users/v1/_debug
  users.0.password (sensitive-name); users.1.password (sensitive-name); users.2.password (sensitive-name)
```

This is an exact match for VAmPI's own documented "Excessive Data Exposure
(debug endpoint)" vulnerability — `GET /users/v1/_debug` really does dump
every user's plaintext password. Caught correctly, on the first try, with
no VAmPI-specific code.

### 2. Bug found and fixed: Broken Auth false-positived on endpoints with no auth at all

The first scan flagged 5 endpoints (`/`, `/books/v1`, `/createdb`,
`/users/v1`, `/users/v1/_debug`) as CRITICAL `alg=none` bypasses. Manually
verified every one of them: **all 5 return `200` with zero Authorization
header at all** — they were never protected in the first place. VAmPI's
spec doesn't declare `security` metadata on these operations (`security` is
`None`, not `[]` — the same "no info" vs "declared public" gap our own demo
API had, from a different framework: connexion, not FastAPI's `Header()`).

Our check's logic assumed "a forged token was accepted" implies "a
signature check was bypassed" — true only if the endpoint checks auth at
all. Fixed in `broken_auth.py`: before evaluating the forged token, send a
baseline request with an obviously-invalid credential. If even garbage
credentials get through, there's nothing to bypass, and the check now
correctly stays silent. Re-scanning after the fix: **0 of the 5 false
positives remained**, and the real finding (#1 above) was untouched.

### 3. Bug found and fixed: entropy heuristic flagged an English sentence

The root endpoint (`GET /`) returns a `help` field — an ordinary English
sentence describing the project. It's long and character-varied enough that
raw Shannon entropy crossed the "looks like a secret" threshold: a real
false positive from the Excessive Data Exposure check's value-shape layer.

Fixed in `excessive_data_exposure.py`: real secrets (JWTs, hashes, API
keys) are structurally single unbroken tokens — their encodings never
contain whitespace. Prose does. Added a whitespace pre-filter before the
entropy check. Re-scanned: this false positive is gone; the entropy layer's
true-positive tests (e.g. a bcrypt hash, a random token) are unaffected.

### 4. Confirmed limitation: BOLA and Mass Assignment can't test username-keyed resources

VAmPI documents a real BOLA vulnerability, and `GET /users/v1/{username}` /
`PUT /users/v1/{username}/email` are exactly the id-addressable shape both
checks look for — but neither found anything. Root cause, confirmed
manually: `GET /users/v1/1` (our candidate id `"1"`) returns `404 User not
found`, because VAmPI keys users by **username**, not sequential integers.
Both `bola.py`'s and `mass_assignment.py`'s id-guessing (`["1".."5"]`) never
finds an accessible resource on this path, so neither ever actually probes
its authorization or write behavior.

This isn't a new discovery — `bola.py`'s docstring already flagged "ids
beyond simple sequential integers (UUIDs can't be guessed this way)" as a
known follow-up. VAmPI turns that from a theoretical gap into a confirmed,
concrete one: **usernames are the same category of problem as UUIDs.** The
correct behavior (stay silent rather than guess wildly) is safe, but it
means a real vulnerability category is currently invisible to both checks
against this class of API. Fixing it for real means id *discovery*
(register a resource as user A, read the real id back from the response)
rather than id *guessing* — a bigger change, not attempted in this pass.

### 5. Out of scope, correctly not claimed

VAmPI's remaining documented bugs — SQL injection, user/password
enumeration, RegexDOS, lack of rate limiting, and the JWT weak-signing-key
bypass — are categories `apisec` doesn't implement. The weak-key case is
worth being precise about: reading VAmPI's source directly
(`jwt.decode(token, SECRET_KEY, algorithms=["HS256"])`), it correctly
rejects our `alg=none` forgery — its real vulnerability is a **guessable
secret value**, which requires brute-forcing/guessing the key and forging a
*validly signed* token, a different attack from the one `broken_auth.py`
implements. Not finding it is correct, not a miss.

## Summary

| VAmPI's documented bug | Result | Why |
|---|---|---|
| Excessive Data Exposure (`/users/v1/_debug`) | ✅ **Caught** | True positive, first try |
| Broken Auth false positives (5 endpoints) | 🔧 **Found & fixed in apisec** | Missing baseline "does this even check auth" probe |
| EDE false positive (`help` field) | 🔧 **Found & fixed in apisec** | Entropy heuristic didn't exclude prose |
| BOLA (`/users/v1/{username}`) | ❌ **Missed** | Candidate-id guessing (1-5) doesn't fit username keys |
| Mass Assignment (`/users/v1/{username}/email`) | ❌ **Missed** | Same root cause as above |
| SQLi / enumeration / RegexDOS / rate limiting | — Out of scope | Not implemented; different OWASP categories |
| JWT weak-signing-key bypass | — Out of scope | Different attack from `alg=none` forgery |

**Net result:** one correct true positive, two real scanner bugs found and
permanently fixed, one confirmed and clearly-scoped limitation, zero false
claims about categories the tool doesn't attempt. That's a more credible
outcome than a clean sweep would have been — it's evidence the tool was
actually tested against something it wasn't built to pass, not just
polished against its own reflection.

## Future work

- **Id discovery instead of id guessing** for BOLA/Mass Assignment (register
  or create a resource as user A, read its real id back from the response)
  — would close the gap found in §4, and generalizes beyond VAmPI to any
  UUID- or slug-keyed API.
- **[OWASP crAPI](https://github.com/OWASP/crAPI)** — a larger,
  microservices-based vulnerable API (Docker Compose, mail server, multiple
  services) covering the same OWASP API Top 10 categories at more realistic
  scale. Not attempted here; a natural next external-validation target.
