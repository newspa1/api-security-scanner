# External Validation: Testing apisec-scanner Against Real APIs

Every other target in this repo (`demo_apps/vulnerable`, `secure`,
`bola_only`, `mass_assignment_only`) is a FastAPI app **we wrote ourselves**,
with bugs **we planted on purpose**. That proves the scanner catches what
it was told to catch — it says nothing about whether it generalizes to real
code it has never seen. Anyone can pass a test they wrote the answer key
for.

This document is that harder test: `apisec` run against independent,
third-party REST APIs, graded against **each project's own** documented
vulnerability list, not ours.

## Targets tested

| Target | What it is | Result summary |
|---|---|---|
| [VAmPI](#target-1-vampi) | Small Flask API, purpose-built to test scanners | 1 true positive, 2 scanner false positives found & fixed, 2 confirmed severe misses |
| [crAPI](#target-2-crapi) | OWASP's larger, microservices-based vulnerable API | 9 true positives (incl. a system-wide auth bypass), 1 scanner false positive found & fixed |

Two other candidates were attempted and correctly ruled out rather than
forced: **OWASP DevSlop's Pixi** (abandoned project, no OpenAPI spec) and
an earlier crAPI attempt in a sandboxed session with no Docker access
(resolved once Docker access was available — see below).

**Ethical note:** both targets are self-hosted practice applications
published specifically to be scanned — running `apisec` against a local
instance is no different from testing against OWASP Juice Shop or DVWA.
Neither involved scanning any live third-party production service without
authorization.

---

## Target 1: VAmPI

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

### Reproduce it

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

### What happened: the honest version, including what we got wrong first

The first real scan produced **6 findings, 5 of them false positives** — and
that outcome was more useful than a clean pass would have been. Two of the
false positives were real bugs in *our* scanner, found because this was the
first time it had ever run against a target it wasn't hand-built to pass.
Both were fixed on the spot; the fixes are permanent (see `broken_auth.py`
and `excessive_data_exposure.py`), not special-cased for VAmPI.

#### 1. True positive: Excessive Data Exposure on `/users/v1/_debug`

```
MEDIUM  API3:2023 Excessive Data Exposure  GET /users/v1/_debug
  users.0.password (sensitive-name); users.1.password (sensitive-name); users.2.password (sensitive-name)
```

This is an exact match for VAmPI's own documented "Excessive Data Exposure
(debug endpoint)" vulnerability — `GET /users/v1/_debug` really does dump
every user's plaintext password. Caught correctly, on the first try, with
no VAmPI-specific code.

#### 2. Bug found and fixed: Broken Auth false-positived on endpoints with no auth at all

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

#### 3. Bug found and fixed: entropy heuristic flagged an English sentence

The root endpoint (`GET /`) returns a `help` field — an ordinary English
sentence describing the project. It's long and character-varied enough that
raw Shannon entropy crossed the "looks like a secret" threshold: a real
false positive from the Excessive Data Exposure check's value-shape layer.

Fixed in `excessive_data_exposure.py`: real secrets (JWTs, hashes, API
keys) are structurally single unbroken tokens — their encodings never
contain whitespace. Prose does. Added a whitespace pre-filter before the
entropy check. Re-scanned: this false positive is gone; the entropy layer's
true-positive tests (e.g. a bcrypt hash, a random token) are unaffected.

#### 4. Confirmed limitation: BOLA and Mass Assignment can't test username-keyed resources

VAmPI documents a real BOLA vulnerability, and `GET /users/v1/{username}` /
`PUT /users/v1/{username}/email` are exactly the id-addressable shape both
checks look for — but neither found anything. Root cause, confirmed
manually: `GET /users/v1/1` (our candidate id `"1"`) returns `404 User not
found`, because VAmPI keys users by **username**, not sequential integers.
Both `bola.py`'s and `mass_assignment.py`'s id-guessing never finds an
accessible resource on this path, so neither ever actually probes its
authorization or write behavior.

This isn't a new discovery — `bola.py`'s docstring already flagged "ids
beyond simple sequential integers (UUIDs can't be guessed this way)" as a
known follow-up. VAmPI turns that from a theoretical gap into a confirmed,
concrete one: **usernames are the same category of problem as UUIDs.** The
correct behavior (stay silent rather than guess wildly) is safe, but it
means a real vulnerability category is currently invisible to both checks
against this class of API. Fixing it for real means id *discovery*
(register a resource as user A, read the real id back from the response)
rather than id *guessing* — a bigger change, not attempted in this pass.

#### 4b. Two independent follow-up passes confirmed §4 is worse than it first looked

Two separate agents later re-tested this project independently (each was
asked to validate against a *different* well-known API — OWASP crAPI and
OWASP DevSlop's Pixi — and both had to fall back to VAmPI: Pixi turned out
to be an abandoned project with no OpenAPI spec, and crAPI needed Docker
access this sandbox didn't have at the time). Rather than just re-confirming
§4, both manually exploited it end-to-end:

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

Net effect (at the time): `apisec` missed VAmPI's two most severe, most
directly exploitable bugs (self-registered admin; cross-user account
takeover) while correctly catching the one it's structurally built to
catch (the unauthenticated debug leak, §1) and correctly staying silent on
what it's not built to catch (§5). Both gaps traced to the same two design
decisions — integer-only id guessing, and POST excluded from Mass
Assignment — both already documented as MVP scope boundaries, now with
concrete proof of what they cost in a real API.

**Re-checked after adding id discovery (see crAPI target's §4): still
unresolved here, for an instructive reason.** `discover_resource_id()`
creates a resource via a sibling POST and reads its id back from the
response — but VAmPI's `POST /users/v1/register` responds with
`{"message": "...", "status": "..."}`, no id field at all, because the
identifier (username) is something the *caller* chose when registering,
not something the *server* generates and hands back. Re-scanned VAmPI
after adding discovery: the result is byte-for-byte identical to before.
This is a genuinely different failure mode from crAPI's (where discovery
worked perfectly) — id discovery only helps when the create response
actually contains a server-generated id to extract; a client-chosen
identifier needs a different mechanism entirely (the check would need to
remember what it submitted, not read a response). This account-takeover
bug still needs write-based BOLA specifically, and it's now the clearest
concrete argument for building it.

**Re-checked again after adding Mass Assignment POST support — reaches the
right resource now, but still can't see the bug, for a third, even more
precise reason.** `mass_assignment.py` now tests POST/create endpoints
(`_confirm_field_on_post()`, `checks/base.py`'s `find_item_endpoint_for_payload()`):
when a create response has no server-generated id to extract, it falls back
to matching a GET endpoint's path parameter name against a key in the
payload we just sent. For VAmPI this works exactly as designed —
`POST /users/v1/register`'s payload has a `username` field, which correctly
matches `GET /users/v1/{username}`'s path parameter, so the check DOES
locate and read back the resource it just created. Manually confirmed the
full picture with `admin: true` injected at registration:

```
$ curl -s -X POST http://localhost:5000/users/v1/register -d '{"username":"masstest2",...,"admin":true}'
{"message": "Successfully registered...", "status": "success"}

$ curl -s http://localhost:5000/users/v1/masstest2        # what the check reads back
{"username": "masstest2", "email": "masstest2@example.com"}

$ curl -s http://localhost:5000/users/v1/_debug | ...       # ground truth
{"admin": true, "email": "masstest2@example.com", "password": "MassPass2!", "username": "masstest2"}
```

`admin: true` genuinely persisted server-side — but `GET /users/v1/{username}`
never returns an `admin` field for ANY user, vulnerable or not, so there's
nothing for a correctly-executed read-back to see. Re-scanning confirmed
zero Mass Assignment findings, exactly as this reasoning predicts. The only
VAmPI endpoint that does expose `admin` is `GET /users/v1/_debug`, which
returns a list of every user rather than one resource addressable by id —
a "search a list for a matching entry" lookup shape, not "GET one resource
by id," which is a distinct mechanism this pass didn't build. So the
three-part diagnosis for this specific bug is now complete and precise: (1)
POST wasn't tested at all — fixed; (2) the id was client-chosen, not
server-generated — fixed (the payload-key fallback exists for exactly this);
(3) the item endpoint's own response schema doesn't surface the field being
tested — not fixed, and structurally different from (1) and (2): it's a
response-shape gap, not a resource-discovery gap, and would need a
list-search readback strategy as its own follow-up.

**Re-checked a fourth time after adding confidence tiers — no longer a
silent miss, even without the list-search mechanism.** Rather than building
that list-search readback next, `mass_assignment.py` was changed to stop
requiring proof of persistence before reporting anything at all (this is
closer to how real DAST/API scanners like Burp and ZAP handle the same
problem: flag "the server accepted an undeclared field without rejecting the
request" as a weaker signal on its own, since a well-built API should reject
unknown fields at validation). Every candidate field is now classified into
one of three tiers — CONFIRMED (read-back proves it), SUSPECTED (accepted,
not rejected, but nothing could prove or disprove it), CLEAR (rejected, or
a read-back explicitly shows a *different* value — real evidence against,
not silence). Re-scanning VAmPI with this change:

```
LOW  API3:2023 Mass Assignment -- POST /users/v1/register
     undeclared field(s) accepted but not confirmed: role, is_admin, isAdmin, admin, permissions
```

The registration bug is no longer invisible — it now surfaces as a LOW,
explicitly-worded "accepted, not confirmed" finding, which is an honest
description of what the scanner actually knows: the field was accepted
without complaint, and separately (per the manual `/_debug` check above) we
happen to know it really did persist, but the scanner itself still can't
prove that from any response it can reach. Trade-off, confirmed live: this
tier also fired on `POST /users/v1/login` (a body field is accepted without
rejection there too) and on the fully-secure demo app's `PATCH /me`
(`tests/test_scan_all_targets.py`) — neither is a real Mass Assignment bug,
they're just endpoints whose responses don't happen to echo the fields being
probed. LOW severity and the "not confirmed" wording are the guardrail
against over-claiming; a HIGH/CONFIRMED finding still requires an actual
read-back match. The list-search readback strategy described above would
upgrade this specific case from SUSPECTED to CONFIRMED, but is no longer
required just to avoid staying silent about it.

#### 4c. A legitimate critique of the severity model

One of the follow-up passes raised a good point about §1: an *unauthenticated*
endpoint dumping every user's plaintext password (including admin's) only
scores `MEDIUM`, because `excessive_data_exposure.py`'s severity model
counts corroborating *detection signals* (name match, value shape, schema
absence), not real-world *impact* — it has no notion of "reachable with
zero auth," which is arguably the single biggest severity multiplier in
practice. Worth reconsidering the scoring model; not changed in this pass.

#### 4d. Side effect worth knowing about: `GET /createdb` is not read-only

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

#### 5. Out of scope, correctly not claimed

VAmPI's remaining documented bugs — SQL injection, user/password
enumeration, RegexDOS, lack of rate limiting, and the JWT weak-signing-key
bypass — are categories `apisec` doesn't implement. The weak-key case is
worth being precise about: reading VAmPI's source directly
(`jwt.decode(token, SECRET_KEY, algorithms=["HS256"])`), it correctly
rejects our `alg=none` forgery — its real vulnerability is a **guessable
secret value**, which requires brute-forcing/guessing the key and forging a
*validly signed* token, a different attack from the one `broken_auth.py`
implements. Not finding it is correct, not a miss.

### VAmPI summary

| VAmPI's documented bug | Result | Why |
|---|---|---|
| Excessive Data Exposure (`/users/v1/_debug`) | ✅ **Caught** (MEDIUM — arguably under-scored, §4c) | True positive, first try |
| Broken Auth false positives (5 endpoints) | 🔧 **Found & fixed in apisec** | Missing baseline "does this even check auth" probe |
| EDE false positive (`help` field) | 🔧 **Found & fixed in apisec** | Entropy heuristic didn't exclude prose |
| Unauthorized password change (account takeover) | ❌ **Still missed** — id discovery doesn't help here | Username is client-chosen; register response has no id to extract (§4b) |
| Registration-time privilege escalation (`admin: true`) | ⚠️ **Partially caught** — reported as a LOW "accepted, not confirmed" finding, not a silent miss anymore | POST support + client-chosen-id readback locate the resource (§4b); `GET /users/v1/{username}` never returns `admin` for any user, so it can't be CONFIRMED/HIGH without a list-search readback strategy — but confidence tiers mean it's no longer invisible either (§4b) |
| BOLA (`/users/v1/{username}` reads) | ❌ **Still missed** — same reason | Same client-chosen-identifier limitation |
| SQLi / enumeration / RegexDOS / rate limiting | — Out of scope | Not implemented; different OWASP categories |
| JWT weak-signing-key bypass | — Out of scope | Different attack from `alg=none` forgery |

---

## Target 2: crAPI

[OWASP crAPI](https://github.com/OWASP/crAPI) ("completely ridiculous
API") — a much larger, microservices-based vulnerable API simulating a
vehicle-owner platform (identity, community, workshop, chatbot services
behind a gateway). OWASP-maintained; its 18 documented challenges are
explicitly based on real vulnerabilities found in production APIs at
companies like Facebook, Uber, and Shopify.

- Requires Docker Compose (`docker compose --compatibility up -d`) —
  initially blocked in a sandboxed session with no Docker daemon access;
  resolved once the sandbox user was added to the `docker` group.
- No live OpenAPI endpoint was found by probing common URLs
  (`/api/openapi.json`, `/v3/api-docs`, etc. all 404) — but the repo ships
  a genuine static OpenAPI 3.0.1 spec at `openapi-spec/crapi-openapi-spec.json`
  (40 paths), whose declared `servers` entry (`http://localhost:8888`)
  matches the default deployment exactly. `apisec --spec` accepts local
  files, so this works directly.
- Its own `docs/challenges.md` documents 18 numbered challenges mapping to
  BOLA (x2), Broken Authentication, Excessive Data Exposure (x2), Mass
  Assignment (x3), Broken Function Level Authorization, SSRF, NoSQL/SQL
  injection, rate limiting, unauthenticated access, JWT forgery, and LLM
  prompt injection.

### Reproduce it

```bash
curl -o /tmp/crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip -q /tmp/crapi.zip -d ~/projects
cd ~/projects/crAPI-main/deploy/docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d
docker compose -f docker-compose.yml ps   # wait for crapi-web to show (healthy)

curl -s -X POST http://localhost:8888/identity/api/auth/signup -H 'Content-Type: application/json' \
  -d '{"name":"Scan User1","email":"scanuser1@example.com","number":"1234567890","password":"ScanPass1!"}'
curl -s -X POST http://localhost:8888/identity/api/auth/signup -H 'Content-Type: application/json' \
  -d '{"name":"Scan User2","email":"scanuser2@example.com","number":"0987654321","password":"ScanPass2!"}'

TOKEN_A=$(curl -s -X POST http://localhost:8888/identity/api/auth/login -H 'Content-Type: application/json' -d '{"email":"scanuser1@example.com","password":"ScanPass1!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
TOKEN_B=$(curl -s -X POST http://localhost:8888/identity/api/auth/login -H 'Content-Type: application/json' -d '{"email":"scanuser2@example.com","password":"ScanPass2!"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

# from the apisec-scanner repo, in its own venv:
apisec --spec ~/projects/crAPI-main/openapi-spec/crapi-openapi-spec.json \
  --target http://localhost:8888 \
  --auth-header "Bearer $TOKEN_A" --auth-header-b "Bearer $TOKEN_B"
```

### What happened

17 findings on the first scan. Unlike VAmPI, where "the forged token
worked" mostly meant "there was never any auth check to begin with," here
every single Broken Auth finding checked out as a **real, confirmed,
system-wide vulnerability** — a genuinely different and more severe result.
One new false positive was found (a different flavor than either VAmPI
bug) and fixed on the spot.

#### 1. True positive, and a severe one: `alg=none` bypass works EVERYWHERE, confirmed on 8 endpoints

```
CRITICAL  API2:2023 Broken Authentication  GET /identity/api/v2/user/dashboard
CRITICAL  API2:2023 Broken Authentication  GET /identity/api/v2/vehicle/vehicles
CRITICAL  API2:2023 Broken Authentication  GET /community/api/v2/community/posts/recent
CRITICAL  API2:2023 Broken Authentication  GET /workshop/api/shop/products
CRITICAL  API2:2023 Broken Authentication  GET /workshop/api/shop/orders/all
CRITICAL  API2:2023 Broken Authentication  GET /workshop/api/management/users/all
CRITICAL  API2:2023 Broken Authentication  GET /workshop/api/mechanic/
CRITICAL  API2:2023 Broken Authentication  GET /workshop/api/mechanic/service_requests
```

This is exactly the false-positive pattern from VAmPI §2, so the same
question had to be asked first: does the endpoint even check auth? This
time the answer is unambiguous — manually replicated the check's exact
logic (garbage credential, then the forged `alg=none` token, then the real
token) against all 8:

```
garbage token  : 401  (7 of 8; one is 404, same effect -- rejected)
forged alg=none: 200  (all 8 -- accepted, with real data in the body)
real token     : 200  (all 8 -- for comparison)
```

Every endpoint correctly rejects a garbage credential — proving auth *is*
enforced — and every one of them still accepts a completely unsigned,
hand-forged token. This is a real, system-wide JWT signature-verification
bypass, not a scanner artifact. It's an exact match for crAPI's own
documented challenge #15, "Forge valid JWT Tokens." The forged token
returned other users' emails, credit balances, mechanic reports, and order
data — this is as real as it gets.

#### 2. True positive: BOLA on order details, including payment card data

```
HIGH  API1:2023 BOLA  GET /workshop/api/shop/orders/{order_id}
```

Manually verified beyond the check's own heuristic: created a real order
as user A (id 6), then read it with user B's own (real, non-forged) token:

```json
{"order": {"id": 6, "user": {"email": "scanuser1@example.com", ...}, ...},
 "payment": {"card_number": "XXXXXXXXXXXX3784", "card_owner_name": "Scan User1",
             "card_type": "MasterCard", "card_expiry": "02/2028", ...}}
```

User B, with nothing but their own ordinary account, can read any other
user's complete order and (masked but still sensitive) payment details.
Confirmed exploitable, not just "the check fired."

#### 3. Bug found and fixed: opaque resource ids triggered the entropy heuristic

```
HIGH  API3:2023 Excessive Data Exposure  GET /community/api/v2/community/posts/recent
  posts.0.id (value-shape:high-entropy)
```

A community post's `id` field (nanoid-style, e.g. `"XVnnBhVbD4E2Ktc2H54xDa"`)
is random enough to cross the entropy threshold — but it's an opaque
resource identifier, not a secret; it's *designed* to look random and is
meant to be shared (it's how you address the post at all). A third,
distinct false-positive class from the two found in VAmPI (that one was
prose; this one is a legitimate-but-random-looking id).

Fixed in `excessive_data_exposure.py`: the entropy fallback now skips
id-like field names (`id`, `*_id`, `*Id`, `uuid`, `slug`) — but only the
entropy fallback. An unambiguous secret *shape* (bcrypt hash, JWT, PEM key)
stored under a field literally called `id` would still be flagged; that's
tested explicitly. Re-scanned: this false positive is gone; every other
finding is unchanged.

#### 4. Confirmed limitation, then two follow-up fixes, then one remaining gap

Mass Assignment produced zero findings, despite crAPI documenting three
mass-assignment bugs (free items via order-return manipulation, balance
inflation via refund abuse, internal video-property tampering) on
endpoints that are exactly its target shape
(`PUT /workshop/api/shop/orders/{order_id}`,
`PUT /identity/api/v2/user/videos/{video_id}`). Root cause, confirmed
manually: order id `"1"` (the default placeholder `concrete_url` produces)
returns `403 You are not allowed to access this resource!` for our test
user, while the real order we created (id `6`) returns `200` — but
`mass_assignment.py` had **no retry loop at all** (unlike `bola.py`'s
5-candidate attempt), so it never got past the first placeholder id.

**Fix 1 — a retry loop, matching `bola.py`'s approach.** Added a
legit-only baseline write per candidate id (`["1".."5"]`), locking onto
the first one that isn't rejected outright. Re-scanning crAPI after this
fix: still zero findings — the real order this check needed had id `7`,
past the 5-candidate range, because the target's database had already
drifted from earlier test runs. A wider guess range just moves the
goalposts; a live database can always drift past it.

**Fix 2 — real id discovery, not guessing.** Added
`discover_resource_id()` (`checks/base.py`, shared with `bola.py`): find a
sibling `POST` on the same collection path, create a resource with a
legit payload, and read the real id back from the response — tried before
falling back to numeric guessing. Re-scanning crAPI again: discovery
correctly found and used order id `9` (still past the old guess range) —
confirmed via the request log, not just inferred. This is a materially
different mechanism from "try more candidates": it doesn't need to guess
how far a live database has drifted, because it just asks the API what a
real id looks like.

**One gap remained, confirmed even with the correct id in hand.** With a
real, writable order id now found on every scan, Mass Assignment *still*
reported nothing here — because crAPI's real mass-assignment bug
manipulates *business/financial* fields (order quantity, refund amount),
not the *privilege* fields (`role`, `is_admin`, `admin`, `permissions`)
our candidate list targets. Confirmed directly: crAPI's order response has
no place for a `role` field to even appear, so no candidate field we try
could ever "stick" — with the old binary confirm-or-nothing model, that
meant zero findings, full stop.

**Re-checked after adding Mass Assignment's confidence tiers (same fix
described in the VAmPI writeup, §4b) — no longer silent, still not
confirmed, for exactly the predicted reason.** Re-scanned crAPI with a
fresh identity after that change:

```
LOW  API3:2023 Mass Assignment -- PUT /workshop/api/shop/orders/{order_id}
     id=21: undeclared field(s) accepted but not confirmed: role, is_admin, isAdmin, admin, permissions
```

Same order-discovery mechanism as before (this time landing on id `21` —
the database had drifted further still, unsurprising for a shared,
long-lived Docker volume), same candidate fields, but now reported as a
LOW "accepted, not confirmed" finding rather than nothing at all — the
write wasn't rejected, but `role`/`admin`/etc. never appear in crAPI's
order response either way, so it lands in SUSPECTED, not CONFIRMED. This
is exactly the outcome the field-list mismatch predicts: the *fields*
being tried are still the wrong flavor for this bug (privilege, not
financial), so it can never become a HIGH/CONFIRMED finding without a
business-logic-flavored candidate list — but it's no longer invisible
either. The sole remaining known gap for this check is the same as
before: a config surface for target-specific candidate fields, or
business-logic-flavored defaults (`quantity`, `amount`, `price`,
`balance`), which would let this specific bug become CONFIRMED/HIGH
instead of merely SUSPECTED/LOW. Not attempted here.

**Id discovery also found a SECOND BOLA, invisible to any amount of
numeric guessing.** Re-scanning crAPI with discovery in place surfaced a
new finding: `GET /community/api/v2/community/posts/{postId}`. Discovery
created a real post via `POST /community/api/v2/community/posts` and
extracted its real id from the response — a nanoid-style string (e.g.
`"6gfDwUFSkXWx255aTjireV"`), not a number. `["1".."5"]` guessing could
never have found this regardless of how many candidates it tried, because
the id space isn't sequential integers at all. Confirmed as a real BOLA
the same way as §2: user B's own token reads user A's post.

#### 5. Out of scope, correctly not claimed

SSRF, NoSQL/SQL injection, layer-7 DoS/rate limiting, BFLA (deleting
another user's video), and the three LLM/chatbot-prompt-injection
challenges are categories `apisec` doesn't implement. No false claims made
about any of them.

### crAPI summary

| crAPI's documented challenge | Result | Why |
|---|---|---|
| JWT forgery (#15) | ✅ **Caught** (CRITICAL, x8 endpoints) | True positive — real, system-wide `alg=none` bypass |
| BOLA — order/payment access | ✅ **Caught** (HIGH) | True positive — confirmed exploitable, incl. payment data |
| BOLA — community posts (non-numeric ids) | ✅ **Caught** (HIGH, after id discovery) | Id discovery found a real nanoid-style post id; numeric guessing never could have |
| Opaque-id entropy false positive | 🔧 **Found & fixed in apisec** | Entropy fallback now excludes id-like field names |
| Mass assignment id-not-found (#8, #9, #10) | 🔧 **Found & fixed in apisec** | Retry loop, then real id discovery — both added and confirmed working |
| Mass assignment field mismatch (#8, #9, #10) | ⚠️ **Partially caught** — LOW "accepted, not confirmed" finding, not CONFIRMED/HIGH | Candidate fields are privilege-flavored; crAPI's bug is quantity/refund-flavored, so it can't be verbatim-confirmed — but confidence tiers (§4b of the VAmPI section) mean it's no longer silent either |
| BOLA — vehicle/mechanic reports (#2) | ❌ **Likely missed** | Not separately exploited to confirm |
| Broken auth via password reset (#3) | — Not tested | Different flow than `alg=none` forgery |
| SSRF / SQLi / NoSQLi / rate limiting / BFLA / LLM (#6, #7, #11-18) | — Out of scope | Not implemented; different OWASP/AI-security categories |

---

## Overall takeaways

- **The scanner generalizes.** Across two independent, unrelated projects
  it correctly caught real, confirmed vulnerabilities with zero
  target-specific code — including one severe, system-wide auth bypass
  (crAPI) that would matter in a real security review.
- **Four distinct false-positive classes were found and fixed**, each a
  different flavor: prose mistaken for a secret (VAmPI), an endpoint with
  no real auth check mistaken for a bypassed one (VAmPI), an opaque
  resource id mistaken for a secret (crAPI), and a fixed id-guess range
  that couldn't keep up with a live database (crAPI, fixed by discovery
  rather than a wider range). None were special-cased for the target that
  found them — all fixes are general.
- **The two originally-confirmed misses had genuinely different root
  causes, and that mattered.** BOLA/Mass Assignment's sequential-integer
  guessing looked like one problem from the outside, but turned out to be
  two: (1) resources whose real id is simply outside a small guessed
  range — fixed by `discover_resource_id()`, confirmed working on crAPI's
  orders (id 9) and, as a bonus, a second BOLA on non-numeric community
  post ids that guessing could never have found at all; (2) resources
  identified by something the *client* chose (VAmPI's usernames) rather
  than something the *server* generates — id discovery structurally
  cannot help here, confirmed by an unchanged VAmPI re-scan. Only the
  first kind was closed this pass.
- **Fixing the "can't find a resource" problem exposed a second, more
  precise gap sitting right behind it**: crAPI's Mass Assignment check now
  reliably finds a real, writable order — and still reports nothing,
  because the *fields* it tries (privilege-escalation-flavored) don't
  match crAPI's actual vulnerable fields (quantity/refund-flavored). This
  is the kind of gap that's easy to miss until the more obvious problem in
  front of it is actually solved.
- **The same pattern repeated on VAmPI's registration bug, one layer
  deeper.** Adding POST support to Mass Assignment, then a client-chosen-id
  fallback, correctly closed two of the three reasons this specific bug was
  invisible — and each fix precisely exposed the next one underneath, until
  what's left is a genuinely different kind of gap (the vulnerable field is
  never in ANY read-by-id response, only in a list-all response) rather
  than a vaguer, un-diagnosed miss. Manually confirmed with `/_debug` that
  the field really does persist server-side the whole time — every fix
  along the way was solving a real detection problem, not chasing a
  phantom.
- **The fourth layer of that same bug didn't need a smarter reader — it
  needed a different bar for "worth reporting."** Every earlier fix tried
  to make Mass Assignment *prove* persistence via read-back; VAmPI's
  registration bug kept surviving because some APIs simply never expose the
  probed field on any response reachable that way. Real DAST/API scanners
  mostly don't try to fully prove this either — they treat "the server
  accepted an undeclared field without rejecting the request" as weak
  evidence on its own. Adding that as an explicit LOW/SUSPECTED tier (next
  to the existing HIGH/CONFIRMED one) turned a silent miss into an
  honestly-worded low-confidence finding, at a known and accepted cost: it also
  fires on genuinely secure endpoints whose responses are just minimal
  (confirmed on the demo app's own secure target, `PATCH /me` — see
  `tests/test_scan_all_targets.py`). That's a real trade-off, not a bug —
  documented, not hidden.

## Future work

- ~~Id discovery instead of id guessing~~ — **done.** `discover_resource_id()`
  (`checks/base.py`) creates a real resource via a sibling POST and reads
  its id back, tried before falling back to numeric guessing. Confirmed
  working on crAPI (found order id 9, and a second, non-numeric BOLA on
  community posts).
- ~~A retry loop for Mass Assignment~~ — **done**, then found insufficient
  alone, which is what motivated id discovery above.
- ~~Mass Assignment on POST~~ — **done.** `_confirm_field_on_post()`
  (`mass_assignment.py`) creates a resource with an injected field and
  checks whether it's reflected in the create response or a subsequent
  read-back.
- ~~Recovering client-chosen identifiers~~ — **done**, as a fallback within
  the POST support above: `find_item_endpoint_for_payload()`
  (`checks/base.py`) matches a GET endpoint's path parameter name against a
  key in the payload just submitted (e.g. `username`), for cases where the
  create response has no server-generated id to extract at all. Confirmed
  correctly locating and reading back VAmPI's freshly-registered user via
  `GET /users/v1/{username}` — the resource-discovery half of VAmPI's
  registration bug is fully solved; what remains is a different problem
  (below).
- ~~Confidence tiers for Mass Assignment (CONFIRMED / SUSPECTED / CLEAR)~~ —
  **done.** `_FieldResult` (`mass_assignment.py`) stops requiring proof of
  persistence before reporting anything: a write that isn't rejected but
  can't be verified either way now surfaces as a LOW "accepted, not
  confirmed" finding instead of staying silent, matching how real DAST/API
  scanners treat "accepted an undeclared field without rejecting it" as a
  weaker signal on its own. Turned VAmPI's registration bug from a silent
  miss into a reported (if low-confidence) finding. Known, accepted cost:
  also fires on genuinely secure endpoints with minimal responses (the demo
  app's own secure target, confirmed via `tests/test_scan_all_targets.py`).
- **A "search a list" readback strategy**, distinct from "read one resource
  by id" — would upgrade VAmPI's registration bug from SUSPECTED/LOW to
  CONFIRMED/HIGH: `admin: true` genuinely persists (confirmed via
  `/_debug`), but no id-addressable endpoint ever returns an `admin` field
  for any user, so a correctly-executed read-back has nothing to see. Would
  need to recognize array-returning endpoints (`GET /users/v1/_debug`
  returns `{"users": [...]}`) and search them for an entry matching what
  was just created, a different lookup shape than everything built so far.
  No longer required just to avoid a silent miss (confidence tiers above
  already fixed that), so this is now a precision improvement, not a
  detection gap.
- **Write-based BOLA** (PATCH/DELETE/PUT another user's object, not just
  GET) — still needed for VAmPI's *other* severe bug, the password-change
  account takeover (distinct from the registration bug above; unrelated to
  Mass Assignment).
- **A broader Mass Assignment candidate-field list**, or a config surface
  for target-specific fields — today's list is privilege-escalation-flavored
  and confirmed to only reach LOW/SUSPECTED, never CONFIRMED/HIGH, on
  financial/business-logic mass assignment (crAPI §4) even with the correct
  resource id in hand, since the fields it tries are never the right ones.
- **Re-weight severity by reachability**, not just detection-signal count
  (VAmPI §4c) — an unauthenticated leak should plausibly outscore an
  authenticated one with otherwise-identical evidence.
- **OWASP DevSlop's Pixi** was ruled out for good reason (abandoned, no
  OpenAPI spec) and isn't a viable future target without the project being
  revived.
