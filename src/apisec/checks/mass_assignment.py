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
   legit payload and send the write.
4. GET the same URL back and check whether the injected field's value
   actually stuck. If it did, the handler is binding the raw request body
   onto its model instead of an explicit allowlist of writable fields --
   that's the finding. A field that's rejected, ignored, or the request
   itself failing (4xx) is NOT evidence of anything.

ALGORITHM, POST (resource creation) -- see `_confirm_field_on_post()`:
Each candidate field gets its own fresh create + verify round trip (unlike
PATCH/PUT, a POST makes a NEW resource every time, so there's no single id
to lock onto and reuse). After creating with the injected field:
1. Check if the create response itself reflects the field back -- many
   APIs return the created object directly, no read-back needed.
2. If not, try to read the resource back and check there instead: first via
   a server-generated id extracted from the response
   (`_extract_id_from_response()`) matched to a sibling item GET endpoint
   (`_item_endpoint_for_collection_path()`, the reverse of
   `discover_resource_id()`'s own direction); if that finds nothing, via
   `find_item_endpoint_for_payload()` -- for a CLIENT-CHOSEN id (e.g. a
   username WE supplied at registration, never echoed back by the server),
   match a GET endpoint's path parameter name against a key in the payload
   we just sent, and use the value we supplied as the id.
3. If no way to read it back was found at all, that's "no evidence either
   way", not a finding.

FORMERLY SCOPED OUT, POST support added this pass (previously: "excludes
POST. A PATCH/PUT target is id-addressable, so 'read back the same URL' is
well-defined. A POST typically CREATES a resource at a different URL...
finding it back requires parsing the response for an id... a real
follow-up, not done here.") -- prompted by a confirmed, exploitable finding
on VAmPI (github.com/erev0s/VAmPI, see EXTERNAL_VALIDATION.md #4b):
`POST /users/v1/register` silently accepts an undeclared `admin: true`
field, granting instant admin rights on account creation.

STILL DOESN'T CATCH THAT SPECIFIC VAmPI BUG, for a precise and different
reason than before: VAmPI's register payload has a `username` field, which
DOES correctly match `find_item_endpoint_for_payload()` against
`GET /users/v1/{username}`'s path parameter -- the create-to-read-back
correlation works exactly as designed. But that item endpoint's own
response schema only returns `{"username", "email"}` -- it never exposes
`admin` at all, on ANY user, vulnerable or not. There's no place for the
finding to surface even with the resource correctly located; the only
VAmPI endpoint that DOES show `admin` (`GET /users/v1/_debug`) returns a
list of all users, not one resource addressable by id, which is a
different lookup shape (search-a-list, not read-by-id) not handled here.
Re-verifying this specific case requires that additional list-search
mechanism -- a further, separate piece of future work, distinct from
"POST isn't handled" (which is now fixed) and distinct from "can't find a
client-chosen id" (also now fixed).

FIXED after being found scanning OWASP crAPI (github.com/OWASP/crAPI, see
EXTERNAL_VALIDATION.md target 2 #4): `concrete_url`'s default placeholder
id ("1") wasn't a real, accessible resource for the scanning identity on
crAPI's order/video endpoints, and unlike `bola.py` this check had NO RETRY
across multiple candidate ids -- one placeholder, one attempt, done. Missed
three of crAPI's documented mass-assignment bugs as a direct result. Now
retries across `_CANDIDATE_IDS` with a legit-only baseline write per id
(step 3 above), same shape as bola.py's approach.

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

ONE LIMITATION REMAINS, confirmed on that same crAPI re-scan (still zero
Mass Assignment findings even with the right resource id in hand): the
candidate FIELD list below is privilege-escalation-flavored
(role/admin/permissions), which doesn't generalize to financial/business-
logic mass assignment. crAPI's real bugs manipulate order quantity and
refund amounts, not privilege fields -- confirmed crAPI's order response
has no place for a `role` field to even appear, so a perfectly-discovered
id still won't catch that specific bug with today's candidate list. This
is now the sole remaining known gap for this check (id discovery closed
the other one) -- a config surface for target-specific candidate fields,
or business-logic-flavored defaults (quantity, amount, price, balance),
would be the natural next step.

Like BOLA, this is deliberately conservative: a request that just gets
rejected outright isn't treated as "not vulnerable", it's treated as "no
evidence either way" and skipped, so the check stays quiet rather than
guessing.
"""

from __future__ import annotations

import requests

from apisec.checks.base import (
    Finding,
    ScanContext,
    Severity,
    _extract_id_from_response,
    _item_endpoint_for_collection_path,
    build_legit_payload,
    concrete_url,
    discover_resource_id,
    find_item_endpoint_for_payload,
)
from apisec.spec_loader import Endpoint

_CANDIDATE_IDS = ["1", "2", "3", "4", "5"]

_CANDIDATE_PRIVILEGE_FIELDS: list[tuple[str, object]] = [
    ("role", "admin"),
    ("is_admin", True),
    ("isAdmin", True),
    ("admin", True),
    ("permissions", ["admin"]),
]


def _candidate_ids_for(endpoint: Endpoint, ctx: ScanContext) -> list[str]:
    """A real, discovered id (if one can be found) tried first, then the
    numeric guesses as a fallback -- mirrors bola.py's approach."""
    discovered = discover_resource_id(endpoint, ctx)
    if discovered is None:
        return _CANDIDATE_IDS
    if discovered in _CANDIDATE_IDS:
        return _CANDIDATE_IDS
    return [discovered, *_CANDIDATE_IDS]


def _confirm_field_on_post(
    endpoint: Endpoint,
    ctx: ScanContext,
    field_name: str,
    injected_value: object,
    legit_payload: dict,
) -> bool:
    """POST creates a NEW resource per attempt (unlike PATCH/PUT, which
    reuses one locked-in id), so each candidate field gets its own create +
    verify round trip. Two ways to confirm the field stuck:
    1. The create response itself reflects it back (many APIs return the
       created object directly) -- no read-back needed.
    2. A separate GET finds the resource: first via a server-generated id
       in the create response matched to a sibling item endpoint (mirrors
       discover_resource_id()'s direction, reversed), then, if that finds
       nothing, via find_item_endpoint_for_payload() for client-chosen
       ids (e.g. a username we supplied ourselves)."""
    payload = {**legit_payload, field_name: injected_value}
    try:
        resp = ctx.session_a.request("POST", endpoint.url(ctx.base_url), json=payload, timeout=5)
    except requests.RequestException:
        return False
    if resp.status_code >= 400:
        return False  # rejected outright -- not evidence either way
    try:
        body = resp.json()
    except ValueError:
        body = None

    if isinstance(body, dict) and body.get(field_name) == injected_value:
        return True

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
    if read_url is None:
        return False  # created it, but no way to read it back and check

    try:
        read_resp = ctx.session_a.get(read_url, timeout=5)
    except requests.RequestException:
        return False
    if read_resp.status_code >= 400:
        return False
    try:
        read_body = read_resp.json()
    except ValueError:
        return False
    return isinstance(read_body, dict) and read_body.get(field_name) == injected_value


class MassAssignmentCheck:
    id = "API3:2023"
    title = "Mass Assignment"

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        if endpoint.method not in {"PATCH", "PUT", "POST"}:
            return []

        declared_fields = set((endpoint.request_body_schema or {}).get("properties", {}))
        candidates = [
            (name, value)
            for name, value in _CANDIDATE_PRIVILEGE_FIELDS
            if name not in declared_fields
        ]
        if not candidates:
            return []

        legit_payload = build_legit_payload(endpoint.request_body_schema)

        if endpoint.method == "POST":
            confirmed = [
                field_name
                for field_name, injected_value in candidates
                if _confirm_field_on_post(endpoint, ctx, field_name, injected_value, legit_payload)
            ]
            if not confirmed:
                return []
            return [
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.HIGH,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        "The creation endpoint accepted and applied request body "
                        "field(s) that aren't declared in its OpenAPI schema, "
                        "suggesting it binds the raw request body onto its model "
                        "instead of an explicit allowlist of writable fields."
                    ),
                    evidence=(
                        "undeclared field(s) accepted and persisted on creation: "
                        f"{', '.join(confirmed)}"
                    ),
                )
            ]

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

        confirmed: list[str] = []
        for field_name, injected_value in candidates:
            payload = {**legit_payload, field_name: injected_value}
            try:
                write_resp = ctx.session_a.request(endpoint.method, url, json=payload, timeout=5)
            except requests.RequestException:
                continue
            if write_resp.status_code >= 400:
                continue  # rejected outright -- not evidence either way

            try:
                read_resp = ctx.session_a.get(url, timeout=5)
            except requests.RequestException:
                continue
            if read_resp.status_code >= 400:
                continue
            try:
                body = read_resp.json()
            except ValueError:
                continue

            if isinstance(body, dict) and body.get(field_name) == injected_value:
                confirmed.append(field_name)

        if not confirmed:
            return []

        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.HIGH,
                endpoint=endpoint.path,
                method=endpoint.method,
                description=(
                    "The endpoint accepted and applied request body field(s) that "
                    "aren't declared in its OpenAPI schema, suggesting it binds the "
                    "raw request body onto its model instead of an explicit "
                    "allowlist of writable fields."
                ),
                evidence=f"id={used_id}: undeclared field(s) accepted and persisted: "
                f"{', '.join(confirmed)}",
            )
        ]
