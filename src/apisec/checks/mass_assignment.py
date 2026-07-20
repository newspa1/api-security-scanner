"""API3:2023 - Broken Object Property Level Authorization
(the "write" facet -- formerly its own category, "Mass Assignment" /
API6:2019. OWASP's 2023 revision merged Mass Assignment and Excessive Data
Exposure into one category, since both are missing property-level
authorization, just in opposite directions: Excessive Data Exposure is "too
much returned on read"; Mass Assignment is "too much accepted on write". See
excessive_data_exposure.py for the read-side sibling -- both correctly share
check id API3:2023, distinguished by `title`.)

ALGORITHM, PATCH/PUT (an existing, id-addressable resource):
1. Build a "legitimate" payload from `endpoint.request_body_schema`'s
   declared properties (a plausible placeholder value per JSON Schema type),
   so the request has a real chance of passing basic validation.
2. Find a real, writable resource: try a discovered id first
   (`discover_resource_id()`, base.py), then for each candidate guessed id
   (`_CANDIDATE_IDS`, same list bola.py uses), send the LEGIT-only payload
   (no injected field) to that id. The first one that doesn't get rejected
   outright (< 400) is treated as "a real resource user A can write to" and
   locked in -- stop trying further ids. If none work, there's nothing to
   test; return no findings rather than guessing against a resource that
   was never confirmed to exist.
3. Against that one locked-in id: for each candidate privileged field NOT
   in the declared schema (role, is_admin, permissions, ...), add it to the
   legit payload, send the write, then GET the same URL back and classify
   the result -- see CONFIDENCE TIERS below.

ALGORITHM, POST (resource creation) -- see `_check_field_on_post()`:
Each candidate field gets its own fresh create + verify round trip (unlike
PATCH/PUT, a POST makes a NEW resource every time, so there's no single id
to lock onto and reuse). After creating with the injected field, try to
confirm it stuck: first via the create response itself reflecting the field
back (many APIs return the created object directly, no read-back needed),
then via a separate GET -- first via a server-generated id extracted from
the response (`_extract_id_from_response()`) matched to a sibling item GET
endpoint (`_item_endpoint_for_collection_path()`, the reverse of
`discover_resource_id()`'s own direction), then, if that finds nothing, via
`find_item_endpoint_for_payload()` for a CLIENT-CHOSEN id (e.g. a username
WE supplied at registration, never echoed back by the server): match a GET
endpoint's path parameter name against a key in the payload we just sent,
and use the value we supplied as the id. If that read-back still can't see
the field either way, one more fallback before giving up: "search a list"
(`_search_lists_for_field()`, see below). Classified the same way as
PATCH/PUT -- see CONFIDENCE TIERS below.

"SEARCH A LIST" READBACK STRATEGY (closes the gap flagged as future work
after VAmPI's registration bug stayed SUSPECTED even with a fully-working
single-resource read-back -- see EXTERNAL_VALIDATION.md #4b): some APIs
never expose a field on ANY id-addressable response, but DO expose it on a
separate "list everything" endpoint. Confirmed exactly this way on VAmPI:
`GET /users/v1/{username}` never returns `admin` for anyone, but
`GET /users/v1/_debug` returns `{"users": [...]}`, and each entry in that
list DOES include `admin`. `_search_lists_for_field()` tries every
no-path-param GET endpoint in the spec (a real, if imperfect, signal for
"this might return a list of everything" -- an id-addressable endpoint by
definition has a path parameter, so it's excluded), searches each one's
response for an array (top-level, or one level nested under a key, same
convention as `_extract_id_from_response()`), and looks for the entry
matching what was just created/written -- by server-generated id if we
have one, otherwise by a client-chosen key/value pulled straight from the
payload we just sent (e.g. `username`). Only reached when the direct
read-back left the field ambiguous (SUSPECTED); it never overrides a
CONFIRMED or CLEAR verdict the direct read-back already reached, since
those are real evidence and a list search finding nothing shouldn't erase
that. Used by both the POST and PATCH/PUT paths -- for PATCH/PUT, the
locked-in candidate id (`run()`'s `used_id`) is passed through as the
identifier to match on, the same as the POST path's discovered/client-
chosen id.

Getting this actually working end to end on VAmPI took three more fixes,
each found by trying it live and getting a wrong (or unexplainedly absent)
answer rather than trusting it worked on the first pass:
  1. `_uniquify_legit_payload()`: every candidate field's create attempt was
     reusing the exact same placeholder username (`build_legit_payload()`'s
     fixed "apisec-test" string), so only the FIRST candidate ever actually
     registered a new user on APIs with a uniqueness constraint -- every
     later candidate silently read back the FIRST one's leftover data
     instead of its own. Fixed by suffixing every string placeholder with
     the field name being tested, so each candidate gets its own resource.
  2. `_path_affinity()`: trying every no-path-param GET in plain spec
     order meant "/createdb" (a GET with a real, destructive side effect --
     it resets VAmPI's entire database) sorted before "/users/v1/_debug",
     and go/no-go tried it first purely because it happened to come first
     in the spec, wiping out the very test user this fallback needed
     before ever reaching the endpoint that would have found it. Fixed by
     preferring candidates that share a path prefix with the endpoint under
     test.
  3. Even with that ordering fix, "/users/v1" (a clean listing with no
     `admin` field at all) TIES on path affinity with "/users/v1/_debug"
     (which has it) -- both share the "/users/v1" prefix. Matching a real
     entry in "/users/v1" first, then stopping because SOME entry was
     found, meant the search never reached "/users/v1/_debug" at all. Fixed
     by only stopping early on a CONFIRMED or CLEAR verdict, not a
     SUSPECTED one -- an ambiguous match doesn't mean the search is done,
     it means try the next candidate.
Confirmed working after all three: `admin` on VAmPI's registration bug now
reaches `HIGH -- undeclared field(s) accepted and persisted: admin`,
verified via a full live re-scan. See EXTERNAL_VALIDATION.md #4b for the
complete account, including how each of these was actually diagnosed (not
guessed) by reproducing the wrong answer first and tracing why.

CONFIDENCE TIERS (added after a live finding on VAmPI proved read-back alone
isn't enough -- see EXTERNAL_VALIDATION.md #4b): trying to always PROVE
persistence via read-back runs into a real ceiling -- some APIs simply never
expose the field being tested on any response we can reach (VAmPI's
`GET /users/v1/{username}` never returns `admin` for anyone, vulnerable or
not; only a separate list-everything endpoint does). Building a bespoke
read-back mechanism for every possible response shape doesn't generalize;
real DAST/API scanners (Burp, ZAP, commercial tools) mostly don't try to
fully prove persistence either -- they flag "the server accepted an
undeclared field without rejecting the request" as a weaker signal on its
own, since a well-built API should reject unknown fields at the validation
layer. This check now does the same thing, in three tiers per candidate
field, decided by `_FieldResult`:
  - CONFIRMED: a read-back (or the write's own response) shows the injected
    value verbatim. Strong evidence -- reported as a HIGH severity finding.
  - SUSPECTED: the write wasn't rejected (< 400), but nothing could prove
    OR disprove it -- either there was no way to read the resource back at
    all, or the read-back succeeded but that response shape just doesn't
    include this field for anyone. Weak evidence -- reported as a separate
    LOW severity finding, worded as "accepted, not confirmed" rather than
    "vulnerable".
  - CLEAR: the write was rejected outright, OR a read-back explicitly shows
    a DIFFERENT value for the field (the server is actively ignoring or
    overriding it) -- real evidence AGAINST the field being writable, not
    silence. Not reported.
Known trade-off, stated plainly: on a target with minimal POST responses and
no reachable GET endpoint at all, EVERY accepted create will now produce a
SUSPECTED/LOW finding, including on secure handlers that correctly discard
the extra field -- there's no way to distinguish "discarded" from "silently
stored somewhere we can't see" without a read-back path. That's the same
trade-off real scanners make with this heuristic; LOW severity and
"not confirmed" wording keep it from being reported as if it were proven,
and LOW findings don't affect `cli.py`'s exit code (only high/critical do).

FORMERLY SCOPED OUT, POST support added in an earlier pass (previously:
"excludes POST. A PATCH/PUT target is id-addressable, so 'read back the same
URL' is well-defined. A POST typically CREATES a resource at a different
URL... finding it back requires parsing the response for an id... a real
follow-up, not done here.") -- prompted by a confirmed, exploitable finding
on VAmPI (github.com/erev0s/VAmPI, see EXTERNAL_VALIDATION.md #4b):
`POST /users/v1/register` silently accepts an undeclared `admin: true`
field, granting instant admin rights on account creation. Re-verified after
adding CONFIRMED/SUSPECTED/CLEAR: on VAmPI this specific field now shows up
as SUSPECTED rather than staying invisible -- `GET /users/v1/{username}`
correctly locates the just-created user (id discovery + the client-chosen-id
fallback both work), but that endpoint's response just doesn't include an
`admin` key for anyone, so the injected field can't be read back and
verbatim-confirmed. Before confidence tiers, that meant zero findings at
all -- a silent miss. Now it surfaces as a LOW "accepted, not confirmed"
finding, which is honest: the scanner genuinely doesn't know whether it
persisted, but it also isn't staying quiet about a field that was accepted
without complaint.

FIXED after being found scanning OWASP crAPI (github.com/OWASP/crAPI, see
EXTERNAL_VALIDATION.md target 2 #4): `concrete_url`'s default placeholder
id ("1") wasn't a real, accessible resource for the scanning identity on
crAPI's order/video endpoints, and unlike `bola.py` this check had NO RETRY
across multiple candidate ids -- one placeholder, one attempt, done. Missed
three of crAPI's documented mass-assignment bugs as a direct result. Now
retries across `_CANDIDATE_IDS` with a legit-only baseline write per id
(step 2 above), same shape as bola.py's approach.

STILL NOT ENOUGH with retries alone, confirmed by re-scanning crAPI after
the retry fix above: the order this check needed to write to had id 7 --
past the `["1".."5"]` guess range, because the target's id sequence had
already advanced from earlier testing. A wider guess range just moves the
goalposts; a live database can always drift past it. Now tries
`discover_resource_id()` first (base.py) -- create a real resource via a
sibling POST, read its real id back -- with the numeric guesses kept as a
fallback when discovery doesn't work (no sibling POST, or the response has
no recognizable id). Re-scanning crAPI again confirmed discovery reaching
a real order (id 9, still past the guess range) reliably.

A GAP REMAINED for a while, confirmed on that same crAPI re-scan (zero Mass
Assignment findings even with the right resource id in hand): the candidate
field list was privilege-escalation-flavored only (role/admin/permissions),
which doesn't generalize to financial/business-logic mass assignment.
crAPI's real bugs manipulate order quantity and refund amounts, not
privilege fields -- confirmed crAPI's order response has no place for a
`role` field to even appear, so a perfectly-discovered id still couldn't
catch that specific bug with the old candidate list.

PARTIALLY ADDRESSED: `_CANDIDATE_BUSINESS_LOGIC_FIELDS` adds
financial/workflow-flavored candidates (`status`, `is_paid`, `price`,
`discount_percent`, `balance`) alongside the original privilege list.
`status` isn't a guess: crAPI's own OpenAPI spec declares
`PUT /workshop/api/shop/orders/{id}`'s writable body as ONLY
`{product_id, quantity}`, but that same operation's own 400-response
EXAMPLE reads "The value of 'status' has to be 'delivered', 'return
pending' or 'returned'" -- proof, straight from the target's own
documentation, that the handler reads an undeclared `status` field. Unlike
`role` on that same endpoint, crAPI's `Order` response schema DOES expose
`status`, so a successful injection there has a real shot at
CONFIRMED/HIGH, not just SUSPECTED/LOW.

Confirmed live, first partially -- re-scanning crAPI showed the new
candidates correctly wired end to end (`status` and the others appearing
among the SUSPECTED fields on POST endpoints), but the predicted
CONFIRMED/HIGH outcome on `PUT /workshop/api/shop/orders/{id}` specifically
didn't materialize on that pass, and a follow-up `docker restart` meant to
rule out target flakiness broke the environment further instead of
answering the question -- left as open follow-up at the time.

RE-VERIFIED, and the real cause turned out to be a fixable bug, not target
flakiness: re-attempting against a clean crAPI instance, and manually
confirming via curl that `status` genuinely persists arbitrary values
server-side (not just the one candidate value that happens to match its
default), showed the check still reporting SUSPECTED, never CONFIRMED, for
a specific, findable reason -- `_classify_readback()` only ever inspected a
response body's TOP-LEVEL keys, while `GET /workshop/api/shop/orders/{id}`
wraps everything in `{"order": {...}, "payment": {...}}`. The field was
right there the whole time, just one level deeper than the classifier ever
looked -- the exact same shape `_extract_id_from_response()` already
handles for id discovery, never applied to classification. FIXED:
`_classify_readback()` now checks one level of nesting the same way (see
its own docstring). Re-verified immediately after: `status` now reaches
`HIGH -- undeclared field(s) accepted and persisted`, confirmed both by
calling the check directly against a real order and via a full `apisec`
scan run (which reaches it through `POST /workshop/api/shop/orders`'s own
create-and-verify path). See EXTERNAL_VALIDATION.md's crAPI section #4 for
the full account, including two unrelated things this re-check also turned
up: an `--auth-header` invocation mistake that incidentally revealed
`GET /workshop/api/shop/orders/1` needs no authentication at all, and a
real environmental interaction where Mass Assignment's own POST-candidate
testing can exhaust a shared test account's balance before a
later-iterated sibling check gets to run.

Like BOLA, this is deliberately conservative about what counts as CONFIRMED:
a request that just gets rejected outright isn't treated as "not
vulnerable", it's treated as "no evidence either way" and skipped entirely,
so the HIGH tier stays quiet rather than guessing. The new SUSPECTED tier
is the deliberate exception to that conservatism -- see CONFIDENCE TIERS
above for why.
"""

from __future__ import annotations

from enum import Enum

import requests

from apisec.checks.base import (
    Finding,
    ScanContext,
    Severity,
    _extract_id_from_response,
    _item_endpoint_for_collection_path,
    _candidate_ids_for,
    build_legit_payload,
    concrete_url,
    discover_candidate_fields,
    find_item_endpoint_for_payload,
)
from apisec.spec_loader import Endpoint

# Privilege-escalation-flavored: does an undeclared field grant the writer
# more ACCESS than they should have.
_CANDIDATE_PRIVILEGE_FIELDS: list[tuple[str, object]] = [
    ("role", "admin"),
    ("is_admin", True),
    ("isAdmin", True),
    ("admin", True),
    ("permissions", ["admin"]),
]

# Business-logic-flavored: does an undeclared field let the writer change
# something with direct FINANCIAL/WORKFLOW consequences (free items, skipped
# payment, inflated balances) rather than gaining admin access. Added after
# this list's privilege-only focus was confirmed to miss all of crAPI's
# documented mass-assignment bugs (order/refund manipulation, not role
# fields) even with a correctly-discovered, real, writable resource in hand
# -- see EXTERNAL_VALIDATION.md's crAPI section #4. `status` isn't a guess:
# crAPI's own OpenAPI spec declares `PUT /workshop/api/shop/orders/{id}`'s
# writable body as ONLY {product_id, quantity} (`ProductQuantity` schema),
# but that same operation's own 400-response example reads "The value of
# 'status' has to be 'delivered', 'return pending' or 'returned'" -- proof
# the handler reads an undeclared `status` field, straight from the target's
# own documentation, not speculation. Unlike VAmPI's `admin` field, crAPI's
# `Order` response schema DOES expose `status`, so a successful injection
# here has a real shot at CONFIRMED, not just SUSPECTED.
_CANDIDATE_BUSINESS_LOGIC_FIELDS: list[tuple[str, object]] = [
    ("status", "delivered"),
    ("is_paid", True),
    ("price", 0.01),
    ("discount_percent", 100),
    ("balance", 999999),
]

# Built-in candidates. An operator can extend this per-scan two ways: by
# HAND, with `--mass-assignment-fields` (parsed in cli.py, threaded through
# as `ctx.custom_mass_assignment_fields`) for domain-specific sensitive
# field names this list was never going to guess -- same escape-hatch
# pattern as `--public-paths` elsewhere in this package -- or
# AUTOMATICALLY, with `--auto-discover-fields` (`ctx.auto_discover_fields`,
# `discover_candidate_fields()` in checks/base.py), which mines candidate
# field names straight from the target's OWN spec instead of requiring
# manual research at all. See `MassAssignmentCheck.run()`.
_CANDIDATE_FIELDS: list[tuple[str, object]] = [
    *_CANDIDATE_PRIVILEGE_FIELDS,
    *_CANDIDATE_BUSINESS_LOGIC_FIELDS,
]


class _FieldResult(str, Enum):
    """See the CONFIDENCE TIERS section of the module docstring."""

    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    CLEAR = "clear"


def _classify_readback(body: object, field_name: str, injected_value: object) -> _FieldResult:
    """Shared verdict logic once we have a response body to check: verbatim
    match is CONFIRMED, an explicit different value is CLEAR (the server is
    actively overriding/ignoring it -- real evidence, not silence), and the
    field simply not appearing at all is SUSPECTED (we can't tell whether it
    was silently stored somewhere this response doesn't show).

    Checks one level of nesting, not just the top level -- mirrors
    `_extract_id_from_response()`'s `{"order": {"status": ...}}` handling.
    Added after a live crAPI re-scan showed `status` capped at SUSPECTED
    forever even though it demonstrably persists: `GET .../orders/{id}`
    wraps everything in `{"order": {...}, "payment": {...}}`, so a
    top-level-only check could never see it (see EXTERNAL_VALIDATION.md)."""
    if not isinstance(body, dict):
        return _FieldResult.SUSPECTED
    if field_name in body:
        return _FieldResult.CONFIRMED if body[field_name] == injected_value else _FieldResult.CLEAR
    for value in body.values():
        if isinstance(value, dict) and field_name in value:
            return (
                _FieldResult.CONFIRMED
                if value[field_name] == injected_value
                else _FieldResult.CLEAR
            )
    return _FieldResult.SUSPECTED


def _find_list_in_body(body: object) -> list | None:
    """A response might BE the list (`[...]`), or wrap it one level deep
    under some key (`{"users": [...]}`) -- same one-level-deep convention
    used throughout this package (`_extract_id_from_response`,
    `_classify_readback`)."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for value in body.values():
            if isinstance(value, list):
                return value
    return None


def _find_entry_in_list(entries: list, id_value: str | None, payload: dict) -> dict | None:
    """Find the list entry for the resource just created/written: match a
    server-generated id first (if we have one), then fall back to a
    client-chosen key from the payload we just submitted (e.g. `username`)
    -- the same two identifier flavors `find_item_endpoint_for_payload()`
    and `_extract_id_from_response()` already handle elsewhere, just
    applied to entries inside a list instead of a single response."""
    if id_value is not None:
        for entry in entries:
            if isinstance(entry, dict) and _extract_id_from_response(entry) == id_value:
                return entry
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key, value in payload.items():
            if isinstance(value, (str, int)) and not isinstance(value, bool) and entry.get(key) == value:
                return entry
    return None


def _path_affinity(path_a: str, path_b: str) -> int:
    """How many leading path segments two paths share -- used to prefer
    list-endpoint candidates that plausibly belong to the SAME resource
    family as the endpoint under test (e.g. "/users/v1/_debug" for
    "/users/v1/register") over unrelated ones.

    Confirmed necessary, not just a theoretical nicety: on VAmPI,
    `_search_lists_for_field()` without this tried "/createdb" before
    "/users/v1/_debug" (plain spec declaration order put it first) --
    "/createdb" is a GET with a real, destructive side effect (it resets
    VAmPI's entire database; a known quirk, also documented against
    excessive_data_exposure.py's incidental GETs -- see
    EXTERNAL_VALIDATION.md). Trying it wiped out the very test user this
    fallback was trying to read back, before ever reaching the endpoint
    that would have found it. Preferring same-resource-family candidates
    first doesn't eliminate the risk in general (there's no OpenAPI
    convention for "this GET is destructive"), but it makes hitting an
    unrelated one far less likely."""
    segs_a = path_a.strip("/").split("/")
    segs_b = path_b.strip("/").split("/")
    count = 0
    for a, b in zip(segs_a, segs_b):
        if a != b:
            break
        count += 1
    return count


def _search_lists_for_field(
    endpoint: Endpoint,
    ctx: ScanContext,
    payload: dict,
    id_value: str | None,
    field_name: str,
    injected_value: object,
) -> _FieldResult | None:
    """Last-resort fallback for the SUSPECTED case, distinct from "read one
    resource by id": some APIs never expose a field on any id-addressable
    read-back, but DO expose it on a "list everything" endpoint -- e.g.
    VAmPI's `GET /users/v1/_debug` returns `{"users": [...]}` including
    `admin`, even though `GET /users/v1/{username}` never does for anyone
    (see EXTERNAL_VALIDATION.md #4b). Tries every no-path-param GET
    endpoint in the spec, closest-path-prefix-match first (`_path_affinity()`
    -- see its docstring for why order matters here), searches each one's
    response for the entry matching what was just created/written, and
    classifies against THAT entry specifically -- not the whole list, which
    would misattribute another user's field values.

    Keeps trying further candidates even after finding a matching entry, as
    long as the verdict from that entry is still SUSPECTED (matched, but
    that particular list doesn't show the field either) -- confirmed
    necessary on VAmPI, where "/users/v1" (a plain listing with no `admin`
    field) ties on path affinity with "/users/v1/_debug" (which DOES have
    it) and, without this, matching an entry there first would stop the
    search before ever reaching the list that actually answers the
    question. Only stops early on a CONFIRMED or CLEAR verdict -- real
    evidence, not more silence.

    Returns None (not SUSPECTED) when no list endpoint, or no matching
    entry within one, was found at all, OR every match found was itself
    only ever SUSPECTED -- lets the caller tell "list search genuinely
    found nothing more definitive" apart from "checked a real entry, got a
    real answer", so it never downgrades evidence it already has."""
    candidates = [e for e in ctx.all_endpoints if e.method == "GET" and "{" not in e.path]
    candidates.sort(key=lambda e: _path_affinity(e.path, endpoint.path), reverse=True)
    for list_endpoint in candidates:
        try:
            resp = ctx.session_a.get(list_endpoint.url(ctx.base_url), timeout=5)
        except requests.RequestException:
            continue
        if resp.status_code >= 400:
            continue
        try:
            body = resp.json()
        except ValueError:
            continue
        entries = _find_list_in_body(body)
        if entries is None:
            continue
        entry = _find_entry_in_list(entries, id_value, payload)
        if entry is None:
            continue
        result = _classify_readback(entry, field_name, injected_value)
        if result != _FieldResult.SUSPECTED:
            return result
    return None


def _uniquify_legit_payload(legit_payload: dict, suffix: str) -> dict:
    """Give a copy of `legit_payload` unique STRING values by appending
    `-{suffix}`, so calling `_check_field_on_post()` once per candidate
    field -- which each create a real, separate resource -- doesn't collide
    on APIs that enforce a uniqueness constraint (username, email, ...).

    Confirmed necessary on VAmPI: every candidate reused the exact same
    literal placeholder username ("apisec-test", from `build_legit_payload`'s
    fixed string placeholder), so only the FIRST candidate ever actually
    registered a NEW user -- every later one got rejected as a duplicate (or,
    on VAmPI specifically, got HTTP 200 with a `{"status": "fail", ...}`
    body, not even a 4xx to signal the collision), and then read back the
    FIRST candidate's leftover data instead of its own. `admin` stayed stuck
    at SUSPECTED/CLEAR instead of reaching CONFIRMED for exactly this
    reason, not because the field genuinely couldn't be confirmed -- see
    EXTERNAL_VALIDATION.md."""
    return {
        key: f"{value}-{suffix}" if isinstance(value, str) else value
        for key, value in legit_payload.items()
    }


def _check_field_on_post(
    endpoint: Endpoint,
    ctx: ScanContext,
    field_name: str,
    injected_value: object,
    legit_payload: dict,
) -> _FieldResult:
    """POST creates a NEW resource per attempt (unlike PATCH/PUT, which
    reuses one locked-in id), so each candidate field gets its own create +
    verify round trip -- with its own uniquified legit payload
    (`_uniquify_legit_payload()`), so different candidates' resources don't
    collide with each other on APIs that enforce unique fields. Confirmation,
    in order: the create response itself reflecting the field back (many
    APIs return the created object directly); then a separate GET, located
    either via a server-generated id in the create response matched to a
    sibling item endpoint, or via find_item_endpoint_for_payload() for
    client-chosen ids; then, if that still leaves things ambiguous, a
    "search a list" fallback (`_search_lists_for_field()`) for APIs that
    only expose the field on a list-everything endpoint. If nothing narrows
    it down at all, that's SUSPECTED, not CLEAR -- see CONFIDENCE TIERS in
    the module docstring."""
    payload = {**_uniquify_legit_payload(legit_payload, field_name), field_name: injected_value}
    try:
        resp = ctx.session_a.request("POST", endpoint.url(ctx.base_url), json=payload, timeout=5)
    except requests.RequestException:
        return _FieldResult.CLEAR
    if resp.status_code >= 400:
        return _FieldResult.CLEAR  # rejected outright -- evidence against, not silence
    try:
        body = resp.json()
    except ValueError:
        body = None

    if isinstance(body, dict) and field_name in body:
        return _classify_readback(body, field_name, injected_value)

    discovered_id = None
    read_url = None
    if isinstance(body, dict):
        discovered_id = _extract_id_from_response(body)
        if discovered_id is not None:
            item_endpoint = _item_endpoint_for_collection_path(endpoint.path, ctx.all_endpoints)
            if item_endpoint is not None:
                read_url = concrete_url(item_endpoint.path, ctx.base_url, discovered_id)
    if read_url is None:
        item_endpoint, id_value = find_item_endpoint_for_payload(payload, ctx.all_endpoints)
        if item_endpoint is not None:
            read_url = concrete_url(item_endpoint.path, ctx.base_url, id_value)
            discovered_id = discovered_id or id_value

    result = _FieldResult.SUSPECTED
    if read_url is not None:
        try:
            read_resp = ctx.session_a.get(read_url, timeout=5)
        except requests.RequestException:
            read_resp = None
        if read_resp is not None and read_resp.status_code < 400:
            try:
                read_body = read_resp.json()
            except ValueError:
                read_body = None
            if read_body is not None:
                result = _classify_readback(read_body, field_name, injected_value)

    if result == _FieldResult.SUSPECTED:
        list_result = _search_lists_for_field(
            endpoint, ctx, payload, discovered_id, field_name, injected_value
        )
        if list_result is not None:
            result = list_result

    return result


def _check_field_on_write(
    endpoint: Endpoint,
    ctx: ScanContext,
    url: str,
    field_name: str,
    injected_value: object,
    legit_payload: dict,
    id_value: str | None = None,
) -> _FieldResult:
    """PATCH/PUT variant: `url` is the already-locked-in, confirmed-real
    resource (see `run()`) -- write the injected field, then GET the SAME
    url back and classify what comes back. Falls back to
    `_search_lists_for_field()` (same as the POST path) when the direct
    read-back is ambiguous, using `id_value` (the locked-in candidate id)
    to match the right entry in a list."""
    payload = {**legit_payload, field_name: injected_value}
    try:
        write_resp = ctx.session_a.request(endpoint.method, url, json=payload, timeout=5)
    except requests.RequestException:
        return _FieldResult.CLEAR
    if write_resp.status_code >= 400:
        return _FieldResult.CLEAR  # rejected outright -- evidence against, not silence

    result = _FieldResult.SUSPECTED
    try:
        read_resp = ctx.session_a.get(url, timeout=5)
    except requests.RequestException:
        read_resp = None
    if read_resp is not None and read_resp.status_code < 400:
        try:
            body = read_resp.json()
        except ValueError:
            body = None
        if body is not None:
            result = _classify_readback(body, field_name, injected_value)

    if result == _FieldResult.SUSPECTED:
        list_result = _search_lists_for_field(endpoint, ctx, payload, id_value, field_name, injected_value)
        if list_result is not None:
            result = list_result

    return result


class MassAssignmentCheck:
    id = "API3:2023"
    title = "Mass Assignment"

    def _findings_from_results(
        self,
        endpoint: Endpoint,
        results: dict[str, _FieldResult],
        on_creation: bool,
        used_id: str | None = None,
    ) -> list[Finding]:
        confirmed = [f for f, r in results.items() if r == _FieldResult.CONFIRMED]
        suspected = [f for f, r in results.items() if r == _FieldResult.SUSPECTED]
        id_prefix = f"id={used_id}: " if used_id else ""
        creation_suffix = " on creation" if on_creation else ""

        findings: list[Finding] = []
        if confirmed:
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.HIGH,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        "The endpoint accepted and applied request body field(s) "
                        "that aren't declared in its OpenAPI schema, suggesting it "
                        "binds the raw request body onto its model instead of an "
                        "explicit allowlist of writable fields."
                    ),
                    evidence=(
                        f"{id_prefix}undeclared field(s) accepted and persisted"
                        f"{creation_suffix}: {', '.join(confirmed)}"
                    ),
                )
            )
        if suspected:
            findings.append(
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.LOW,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        "The endpoint accepted request body field(s) that aren't "
                        "declared in its OpenAPI schema without rejecting the "
                        "request, but this scan couldn't confirm whether the "
                        "field(s) actually took effect -- there was no reachable "
                        "way to read the resource back, or the response never "
                        "exposes this field for anyone. Worth a manual look: a "
                        "well-built API should reject unknown fields outright."
                    ),
                    evidence=(
                        f"{id_prefix}undeclared field(s) accepted but not confirmed"
                        f"{creation_suffix}: {', '.join(suspected)}"
                    ),
                )
            )
        return findings

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        if endpoint.method not in {"PATCH", "PUT", "POST"}:
            return []

        declared_fields = set((endpoint.request_body_schema or {}).get("properties", {}))
        all_candidate_fields = [*_CANDIDATE_FIELDS, *ctx.custom_mass_assignment_fields]
        if ctx.auto_discover_fields:
            all_candidate_fields += discover_candidate_fields(ctx.all_endpoints, declared_fields)
        seen_names: set[str] = set()
        candidates = []
        for name, value in all_candidate_fields:
            if name in declared_fields or name in seen_names:
                continue
            seen_names.add(name)
            candidates.append((name, value))
        if not candidates:
            return []

        legit_payload = build_legit_payload(endpoint.request_body_schema)

        if endpoint.method == "POST":
            results = {
                field_name: _check_field_on_post(endpoint, ctx, field_name, injected_value, legit_payload)
                for field_name, injected_value in candidates
            }
            return self._findings_from_results(endpoint, results, on_creation=True)

        url = None
        used_id = None
        for candidate_id in _candidate_ids_for(endpoint, ctx):
            candidate_url = concrete_url(endpoint.path, ctx.base_url, candidate_id)
            try:
                baseline_resp = ctx.session_a.request(
                    endpoint.method, candidate_url, json=legit_payload, timeout=5
                )
            except requests.RequestException:
                continue
            if baseline_resp.status_code < 400:
                url = candidate_url
                used_id = candidate_id
                break  # found a real, writable resource for A; stop guessing ids
        if url is None:
            return []  # no candidate id was ever a real, writable resource

        results = {
            field_name: _check_field_on_write(
                endpoint, ctx, url, field_name, injected_value, legit_payload, used_id
            )
            for field_name, injected_value in candidates
        }
        return self._findings_from_results(endpoint, results, on_creation=False, used_id=used_id)
