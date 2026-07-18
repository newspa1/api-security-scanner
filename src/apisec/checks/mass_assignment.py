"""API3:2023 - Broken Object Property Level Authorization
(the "write" facet -- formerly its own category, "Mass Assignment" /
API6:2019. OWASP's 2023 revision merged Mass Assignment and Excessive Data
Exposure into one category, since both are missing property-level
authorization, just in opposite directions: Excessive Data Exposure is "too
much returned on read"; Mass Assignment is "too much accepted on write". See
excessive_data_exposure.py for the read-side sibling -- both correctly share
check id API3:2023, distinguished by `title`.)

ALGORITHM:
1. Only PATCH/PUT on an existing, id-addressable resource (see SCOPE below
   for why POST is excluded).
2. Build a "legitimate" payload from `endpoint.request_body_schema`'s
   declared properties (a plausible placeholder value per JSON Schema type),
   so the request has a real chance of passing basic validation.
3. Find a real, writable resource: for each candidate id (same
   `_CANDIDATE_IDS` list bola.py uses), send the LEGIT-only payload (no
   injected field) to that id. The first one that doesn't get rejected
   outright (< 400) is treated as "a real resource user A can write to" and
   locked in -- stop trying further ids. If none work, there's nothing to
   test; return no findings rather than guessing against a resource that
   was never confirmed to exist.
4. Against that one locked-in id: for each candidate privileged field NOT
   in the declared schema (role, is_admin, permissions, ...), add it to the
   legit payload and send the write.
5. GET the same URL back and check whether the injected field's value
   actually stuck. If it did, the handler is binding the raw request body
   onto its model instead of an explicit allowlist of writable fields --
   that's the finding. A field that's rejected, ignored, or the request
   itself failing (4xx) is NOT evidence of anything.

SCOPE: excludes POST. A PATCH/PUT target is id-addressable, so "read back
the same URL" is well-defined. A POST typically CREATES a resource at a
different URL than the collection endpoint, and finding it back requires
parsing the response for an id (or a Location header) -- a real follow-up,
not done here.

CONFIRMED COST of the POST exclusion (external validation against VAmPI,
github.com/erev0s/VAmPI, see EXTERNAL_VALIDATION.md #4b): VAmPI's
`POST /users/v1/register` silently accepts an undeclared `admin: true`
field, granting instant admin rights on account creation -- a real,
directly exploitable privilege escalation this check cannot see, precisely
because it's a POST. This didn't change the SCOPE decision (still a bigger
change than this pass), but it upgrades "a real follow-up" from
hypothetical to confirmed-and-prioritized.

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
    build_legit_payload,
    concrete_url,
    discover_resource_id,
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


class MassAssignmentCheck:
    id = "API3:2023"
    title = "Mass Assignment"

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        if endpoint.method not in {"PATCH", "PUT"}:
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
