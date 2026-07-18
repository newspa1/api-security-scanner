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

### 4b. Two independent follow-up passes confirmed §4 is worse than it first looked

Two separate agents later re-tested this project independently (each was
asked to validate against a *different* well-known API — OWASP crAPI and
OWASP DevSlop's Pixi — and both had to fall back to VAmPI: Pixi turned out
to be an abandoned project with no OpenAPI spec, and crAPI requires Docker
Compose, unavailable in this sandbox). Rather than just re-confirming §4,
both manually exploited it end-to-end:

- **Full account takeover, confirmed working.** `PUT /users/v1/{username}/password`
  has no ownership check. As user B, changing user A's password
  (`204 No Content`) and then logging in as A with the new password
  succeeded — a real, complete account takeover, not a theoretical gap.
  This is VAmPI's documented "Unauthorized Password Change" bug, and it's
  the same root cause as §4 (`mass_assignment.py`'s write attempt used
  `concrete_url`'s default placeholder id `"1"`, not a real username, so
  every write attempt 400'd and the check correctly-but-uselessly stayed
  silent).
- **A worse, previously-undocumented gap: privilege escalation at
  registration.** `POST /users/v1/register` silently accepts an undeclared
  `"admin": true` field — a brand-new account registered this way gets
  instant admin rights, confirmed by using it to perform an admin-only
  `DELETE` on another user's account. `mass_assignment.py` explicitly
  excludes `POST` from its scope (see its module docstring — a documented
  MVP decision, not an oversight), so this was structurally invisible to
  it. This is a more severe finding than anything in §4: it doesn't need
  a second identity, a candidate id, or any of BOLA's machinery — just a
  single crafted registration request.

Net effect: `apisec` currently misses VAmPI's two most severe, most
directly exploitable bugs (self-registered admin; cross-user account
takeover) while correctly catching the one it's structurally built to
catch (the unauthenticated debug leak, §1) and correctly staying silent on
what it's not built to catch (§5). Both gaps trace to the same two design
decisions — integer-only id guessing, and POST excluded from Mass
Assignment — both already documented as MVP scope boundaries, now with
concrete proof of what they cost in a real API.

### 4c. A legitimate critique of the severity model

One of the follow-up passes raised a good point about §1: an *unauthenticated*
endpoint dumping every user's plaintext password (including admin's) only
scores `MEDIUM`, because `excessive_data_exposure.py`'s severity model
counts corroborating *detection signals* (name match, value shape, schema
absence), not real-world *impact* — it has no notion of "reachable with
zero auth," which is arguably the single biggest severity multiplier in
practice. Worth reconsidering the scoring model; not changed in this pass.

### 4d. Side effect worth knowing about: `GET /createdb` is not read-only

VAmPI's spec lists `GET /createdb` as an ordinary operation, but calling it
actually wipes and reseeds the entire user database — a real violation of
HTTP's "GET should be safe" convention. Since `apisec`'s Excessive Data
Exposure check GETs every spec-declared path, running a full scan against
VAmPI has the side effect of resetting it mid-scan (confirmed: accounts
registered before a scan were gone afterward). This isn't a scanner bug —
`apisec` is doing exactly what a GET is supposed to be safe to do — but
it's a sharp edge worth knowing before pointing this tool at any API that
doesn't honor GET-safety, and a reason to prefer disposable/seeded test
accounts over ones you care about persisting.

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
| Excessive Data Exposure (`/users/v1/_debug`) | ✅ **Caught** (MEDIUM — arguably under-scored, §4c) | True positive, first try |
| Broken Auth false positives (5 endpoints) | 🔧 **Found & fixed in apisec** | Missing baseline "does this even check auth" probe |
| EDE false positive (`help` field) | 🔧 **Found & fixed in apisec** | Entropy heuristic didn't exclude prose |
| Unauthorized password change (account takeover) | ❌ **Missed** — confirmed exploitable | Candidate-id guessing (1-5) doesn't fit username keys |
| Registration-time privilege escalation (`admin: true`) | ❌ **Missed** — confirmed exploitable | Mass Assignment excludes POST by design (MVP scope) |
| BOLA (`/users/v1/{username}` reads) | ❌ **Missed** | Same id-guessing root cause |
| SQLi / enumeration / RegexDOS / rate limiting | — Out of scope | Not implemented; different OWASP categories |
| JWT weak-signing-key bypass | — Out of scope | Different attack from `alg=none` forgery |

**Net result:** one correct true positive (with a fair question about its
severity score), two real scanner bugs found and permanently fixed, and two
confirmed, exploitable misses tracing to two already-documented MVP scope
boundaries (integer-only id guessing; POST excluded from Mass Assignment).
That's a more credible outcome than a clean sweep would have been — it's
evidence the tool was actually tested against something it wasn't built to
pass, including by independent follow-up passes that went as far as
demonstrating working exploits the scanner misses, not just polished
against its own reflection.

## Future work

- **Id discovery instead of id guessing** for BOLA/Mass Assignment (register
  or create a resource as user A, read its real id back from the response)
  — would close the account-takeover and BOLA gaps above, and generalizes
  beyond VAmPI to any UUID- or slug-keyed API.
- **Mass Assignment on POST** (resource creation) — would close the
  registration privilege-escalation gap above. Needs a way to find the
  created resource back (response body or `Location` header), a different
  problem from "read the same URL," which is why it was deferred originally.
- **Re-weight severity by reachability**, not just detection-signal count
  (§4c) — an unauthenticated leak should plausibly outscore an
  authenticated one with otherwise-identical evidence.
- **[OWASP crAPI](https://github.com/OWASP/crAPI)** — attempted twice
  (independently) as a second external-validation target; both attempts
  correctly detected that Docker Compose is required and unavailable in
  this environment, and safely declined rather than forcing it. Remains a
  natural next target in an environment with Docker access. OWASP DevSlop's
  Pixi was also attempted and ruled out for good reason: the project is
  explicitly marked unsupported/abandoned and ships no OpenAPI spec.
