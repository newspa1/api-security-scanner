"""API1:2023 - Broken Object Level Authorization (BOLA), the WRITE facet.

`bola.py` only tests reads (GET): "can identity B READ an object identity A
can read?" This check asks the more severe version of the same question:
"can identity B WRITE to an object identity A can write to?" A write-based
BOLA is strictly worse than a read-based one -- user B isn't just viewing
user A's data, they can change it. Flagged as follow-up work in bola.py's
own docstring since MVP ("would be CRITICAL severity, since a write is
worse than a read") -- this is that follow-up.

Requires TWO identities, same as bola.py, for the same reason: BOLA is
inherently a cross-user comparison, and silently skips (returns []) when
`ctx.session_b` is not configured.

ALGORITHM, mirrors bola.py's shape with PATCH/PUT instead of GET:
1. Only applies to PATCH/PUT endpoints with an id-like path parameter.
   DELETE is deliberately excluded -- see SCOPE below.
2. Build a "legitimate" payload from the endpoint's declared schema (same
   `build_legit_payload()` helper mass_assignment.py uses), so the write has
   a real chance of passing basic validation without injecting anything
   malicious -- this check tests OWNERSHIP, not schema violations.
3. For each candidate id (`_candidate_ids_for()`, same discover-then-guess
   mechanism shared with bola.py and mass_assignment.py), write the legit
   payload AS USER A. The first id where A's write isn't rejected outright
   (< 400) is treated as "a real, A-writable resource" and locked in.
4. Write the SAME legit payload to the SAME id AS USER B. If B's write also
   isn't rejected, that's the finding: two independently-authenticated
   identities can both write to the same object.

SCOPE -- DELETE is deliberately NOT tested, on purpose, not an oversight:
unlike PATCH/PUT (which changes field values, generally recoverable in
principle), DELETE removes a resource outright. There's no generic,
API-agnostic way to verify a DELETE-based BOLA without actually destroying
the target resource, and no reliable way to restore it afterward (we don't
know what the resource looked like before this scan ever touched it, only
what OUR OWN legit_payload wrote). Testing GET/PATCH/PUT-based BOLA already
carries this exact same "no restoration" trade-off -- see below -- but a
destroyed resource is categorically worse than a resource with a few
overwritten fields. Left as a real, acknowledged gap, not solved here.

TRADE-OFF, stated plainly, same one mass_assignment.py's PATCH/PUT testing
already accepts without comment: THIS CHECK WRITES REAL DATA to a resource
using TWO different identities, and makes no attempt to restore the
resource's original values afterward -- there's no generic way to know what
they were. This is more invasive than every read-only check in this
scanner (bola.py, excessive_data_exposure.py) but no more invasive than
mass_assignment.py's existing PATCH/PUT candidate-field testing, which has
always mutated real target resources with injected placeholder/garbage
values and never restored them either. Consistent with that existing
posture, not a new, worse one -- but worth being explicit about before
running this against anything you don't own or have permission to test.

Same heuristic limitation as bola.py: no ground truth for who's SUPPOSED to
own the resource, so a legitimately shared/multi-writer resource looks
identical to a real BOLA from the outside. Same two mitigations apply
(`security: []` spec-declared-public skip, `--public-paths` allowlist).

LIVE-VERIFIED, with an honest result on each of two real targets:

Confirmed working on this repo's own demo_apps/vulnerable: its
`PATCH /users/{user_id}` was planted for Mass Assignment (undeclared fields
get applied) and, as a real, previously-uncounted side effect, was NEVER
given an ownership check either -- bob can write to alice's record just by
knowing her id. This check now correctly reports that as its own,
CRITICAL, distinct finding, alongside Mass Assignment's existing one on the
same endpoint (see tests/test_scan_all_targets.py's "vulnerable" target,
now 8 findings, up from 7). Not a planted bug added for this check
specifically -- a real gap that existed the whole time, now actually named.

Attempted against VAmPI's own documented, manually-confirmed account
takeover (`PUT /users/v1/{username}/password` -- exploitable: registered
two identities, confirmed user B's write to user A's password succeeds,
204 No Content, matching EXTERNAL_VALIDATION.md target 1 #4b) -- this
check does NOT catch it, for the SAME reason bola.py's read-only version
already doesn't: `/users/v1/{username}/password` is keyed by a
CLIENT-CHOSEN username, not a server-generated id, and `_collection_path()`
doesn't even match this path shape (it ends in "/password", not a bare
`/{param}`), so `discover_resource_id()` never gets a chance to run at
all -- straight to guessing `["1".."5"]`, none of which are real
usernames, so no writable candidate is ever found for user A to lock onto
in the first place. Confirmed directly: `_candidate_ids_for()` returns
exactly `['1', '2', '3', '4', '5']` for this endpoint, no discovered id
among them. This is an honest, expected limitation, not a defect in this
check's own logic -- recovering client-chosen identifiers for BOLA (read OR
write) the way mass_assignment.py's POST support already does via
`find_item_endpoint_for_payload()` is real, acknowledged follow-up work,
not solved here.
"""

from __future__ import annotations

import requests

from apisec.checks.base import (
    Finding,
    ScanContext,
    Severity,
    _candidate_ids_for,
    _matches_public_path,
    build_legit_payload,
    concrete_url,
)
from apisec.spec_loader import Endpoint


def _has_id_path_param(path: str) -> bool:
    return "{" in path and "}" in path


class WriteBolaCheck:
    id = "API1:2023"
    title = "Broken Object Level Authorization (BOLA) - Write Access"

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        if endpoint.method not in {"PATCH", "PUT"}:
            return []
        if not _has_id_path_param(endpoint.path):
            return []
        if ctx.session_b is None:
            return []  # can't test cross-user access with only one identity
        if endpoint.security == []:
            return []  # spec explicitly declares this endpoint needs no auth
        if _matches_public_path(endpoint.path, ctx.public_paths):
            return []  # operator has declared this path intentionally shared

        legit_payload = build_legit_payload(endpoint.request_body_schema)

        for candidate_id in _candidate_ids_for(endpoint, ctx):
            url = concrete_url(endpoint.path, ctx.base_url, candidate_id)

            try:
                resp_a = ctx.session_a.request(endpoint.method, url, json=legit_payload, timeout=5)
            except requests.RequestException:
                continue
            if resp_a.status_code >= 400:
                continue  # not a real/writable resource for A; try the next id

            try:
                resp_b = ctx.session_b.request(endpoint.method, url, json=legit_payload, timeout=5)
            except requests.RequestException:
                continue
            if resp_b.status_code < 400:
                return [
                    Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=Severity.CRITICAL,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        description=(
                            "Two independently-authenticated identities could both "
                            "WRITE to the same object id, with no apparent ownership "
                            "check. This is worse than a read-only BOLA -- user B "
                            "isn't just viewing user A's data, they can change it. "
                            "(Heuristic: legitimately shared/multi-writer resources "
                            "will also trigger this -- treat as a lead to verify, "
                            "not a proof.)"
                        ),
                        evidence=(
                            f"id={candidate_id}: user A's write got HTTP "
                            f"{resp_a.status_code}, user B's write to the SAME id "
                            f"(different identity) also got HTTP {resp_b.status_code}."
                        ),
                    )
                ]
            # resp_b was 3xx/4xx (e.g. 403/404) for this id -> looks properly
            # enforced for this candidate; keep trying other ids rather than
            # concluding the endpoint is safe from one sample.
        return []
