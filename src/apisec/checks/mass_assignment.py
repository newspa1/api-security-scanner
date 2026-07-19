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
and use the value we supplied as the id. Classified the same way as
PATCH/PUT -- see CONFIDENCE TIERS below.

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

ONE LIMITATION REMAINS, confirmed on that same crAPI re-scan (still zero
Mass Assignment findings even with the right resource id in hand): the
candidate FIELD list below is privilege-escalation-flavored
(role/admin/permissions), which doesn't generalize to financial/business-
logic mass assignment. crAPI's real bugs manipulate order quantity and
refund amounts, not privilege fields -- confirmed crAPI's order response
has no place for a `role` field to even appear, so a perfectly-discovered
id still won't catch that specific bug with today's candidate list. This
is now the sole remaining known gap for this check -- a config surface for
target-specific candidate fields, or business-logic-flavored defaults
(quantity, amount, price, balance), would be the natural next step.

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


class _FieldResult(str, Enum):
    """See the CONFIDENCE TIERS section of the module docstring."""

    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    CLEAR = "clear"


def _candidate_ids_for(endpoint: Endpoint, ctx: ScanContext) -> list[str]:
    """A real, discovered id (if one can be found) tried first, then the
    numeric guesses as a fallback -- mirrors bola.py's approach."""
    discovered = discover_resource_id(endpoint, ctx)
    if discovered is None:
        return _CANDIDATE_IDS
    if discovered in _CANDIDATE_IDS:
        return _CANDIDATE_IDS
    return [discovered, *_CANDIDATE_IDS]


def _classify_readback(body: object, field_name: str, injected_value: object) -> _FieldResult:
    """Shared verdict logic once we have a response body to check: verbatim
    match is CONFIRMED, an explicit different value is CLEAR (the server is
    actively overriding/ignoring it -- real evidence, not silence), and the
    field simply not appearing at all is SUSPECTED (we can't tell whether it
    was silently stored somewhere this response doesn't show)."""
    if not isinstance(body, dict) or field_name not in body:
        return _FieldResult.SUSPECTED
    return _FieldResult.CONFIRMED if body[field_name] == injected_value else _FieldResult.CLEAR


def _check_field_on_post(
    endpoint: Endpoint,
    ctx: ScanContext,
    field_name: str,
    injected_value: object,
    legit_payload: dict,
) -> _FieldResult:
    """POST creates a NEW resource per attempt (unlike PATCH/PUT, which
    reuses one locked-in id), so each candidate field gets its own create +
    verify round trip. Confirmation, in order: the create response itself
    reflecting the field back (many APIs return the created object
    directly); then a separate GET, located either via a server-generated
    id in the create response matched to a sibling item endpoint, or via
    find_item_endpoint_for_payload() for client-chosen ids. If no read-back
    path exists at all, that's SUSPECTED, not CLEAR -- see CONFIDENCE TIERS
    in the module docstring."""
    payload = {**legit_payload, field_name: injected_value}
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
        # created successfully, but nothing about this API's shape gives us
        # a way to read it back and check -- weak evidence, not none.
        return _FieldResult.SUSPECTED

    try:
        read_resp = ctx.session_a.get(read_url, timeout=5)
    except requests.RequestException:
        return _FieldResult.SUSPECTED
    if read_resp.status_code >= 400:
        return _FieldResult.SUSPECTED
    try:
        read_body = read_resp.json()
    except ValueError:
        return _FieldResult.SUSPECTED
    return _classify_readback(read_body, field_name, injected_value)


def _check_field_on_write(
    endpoint: Endpoint,
    ctx: ScanContext,
    url: str,
    field_name: str,
    injected_value: object,
    legit_payload: dict,
) -> _FieldResult:
    """PATCH/PUT variant: `url` is the already-locked-in, confirmed-real
    resource (see `run()`) -- write the injected field, then GET the SAME
    url back and classify what comes back."""
    payload = {**legit_payload, field_name: injected_value}
    try:
        write_resp = ctx.session_a.request(endpoint.method, url, json=payload, timeout=5)
    except requests.RequestException:
        return _FieldResult.CLEAR
    if write_resp.status_code >= 400:
        return _FieldResult.CLEAR  # rejected outright -- evidence against, not silence

    try:
        read_resp = ctx.session_a.get(url, timeout=5)
    except requests.RequestException:
        return _FieldResult.SUSPECTED
    if read_resp.status_code >= 400:
        return _FieldResult.SUSPECTED
    try:
        body = read_resp.json()
    except ValueError:
        return _FieldResult.SUSPECTED
    return _classify_readback(body, field_name, injected_value)


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
        candidates = [
            (name, value)
            for name, value in _CANDIDATE_PRIVILEGE_FIELDS
            if name not in declared_fields
        ]
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
            field_name: _check_field_on_write(endpoint, ctx, url, field_name, injected_value, legit_payload)
            for field_name, injected_value in candidates
        }
        return self._findings_from_results(endpoint, results, on_creation=False, used_id=used_id)
