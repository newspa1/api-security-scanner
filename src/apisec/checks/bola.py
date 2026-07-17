"""API1:2023 - Broken Object Level Authorization (BOLA).

Requires TWO identities (`--auth-header` + `--auth-header-b`), since BOLA is
inherently a cross-user question: "can identity B reach an object identity A
can reach?" With only one identity there's nothing to compare against, so this
check silently skips (returns []) when `ctx.session_b` is not configured.

ALGORITHM (heuristic — read the limitation below before trusting a finding):
1. Only applies to GET endpoints with an id-like path parameter, e.g.
   `/orders/{id}`. Write-based BOLA (PATCH/DELETE another user's object) is a
   natural extension but out of MVP scope — it requires mutating and then
   restoring state during a scan, which adds real complexity; flagged here as
   a follow-up (would be CRITICAL severity, since a write is worse than a
   read).
2. For a small set of candidate ids, request the endpoint AS USER A. The first
   candidate that returns 2xx is treated as "a real, A-accessible resource" —
   this sidesteps the classic false-negative of guessing an id that doesn't
   exist at all (a 404 there tells you nothing about authorization).
3. Request that SAME id AS USER B. If B also gets 2xx, that's the finding:
   two independently-authenticated identities can both reach the same object.

LIMITATION (be upfront about this — it's a heuristic, not a proof): the check
has no ground truth for who is *supposed* to own the resource. A legitimately
shared/public resource (e.g. a public product listing) will trigger a false
positive here, because "two users can both read it" looks identical to a real
BOLA from the outside. Real BOLA scanners have the same limitation without
domain knowledge of the target API — treat a finding as "worth a human
review", not an automatic proof of a bug. This is also why a 403 for user B
is NOT flagged: that's authorization working correctly, distinct from a 404
(wrong id guess), which the check also doesn't flag.

FOLLOW-UPS (not done): ids beyond simple sequential integers (UUIDs can't be
guessed this way — would need `POST`ing a resource as user A first, noting
the id from the response, then testing B against it); write-based BOLA.
"""

from __future__ import annotations

import requests

from apisec.checks.base import Finding, ScanContext, Severity, concrete_url
from apisec.spec_loader import Endpoint

_CANDIDATE_IDS = ["1", "2", "3", "4", "5"]


class BolaCheck:
    id = "API1:2023"
    title = "Broken Object Level Authorization (BOLA)"

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        if endpoint.method != "GET":
            return []
        if not _has_id_path_param(endpoint.path):
            return []
        if ctx.session_b is None:
            return []  # can't test cross-user access with only one identity

        for candidate_id in _CANDIDATE_IDS:
            url = concrete_url(endpoint.path, ctx.base_url, candidate_id)

            try:
                resp_a = ctx.session_a.get(url, timeout=5)
            except requests.RequestException:
                continue
            if resp_a.status_code >= 300:
                continue  # not a real/accessible resource for A; try the next id

            try:
                resp_b = ctx.session_b.get(url, timeout=5)
            except requests.RequestException:
                continue
            if resp_b.status_code < 300:
                return [
                    Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=Severity.HIGH,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        description=(
                            "Two independently-authenticated identities could both "
                            "access the same object id, with no apparent ownership "
                            "check. If this resource isn't meant to be shared, this "
                            "is a BOLA — user B is reading data that belongs to "
                            "user A. (Heuristic: legitimately shared/public "
                            "resources will also trigger this — treat as a lead to "
                            "verify, not a proof.)"
                        ),
                        evidence=(
                            f"id={candidate_id}: user A got HTTP {resp_a.status_code}, "
                            f"user B (different identity, same request) also got "
                            f"HTTP {resp_b.status_code}."
                        ),
                    )
                ]
            # resp_b was 3xx/4xx (e.g. 403/404) for this id -> looks properly
            # enforced for this candidate; keep trying other ids rather than
            # concluding the endpoint is safe from one sample.
        return []


def _has_id_path_param(path: str) -> bool:
    return "{" in path and "}" in path
