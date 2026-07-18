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
has no ground truth for who is *supposed* to own the resource. "Two users can
both read this" looks identical from the outside whether the resource is
illegitimately leaked OR legitimately shared/public — real BOLA scanners have
the same limitation without domain knowledge of the target API. Treat a
finding as "worth a human review", not an automatic proof of a bug. (A 403 for
user B is NOT flagged: that's authorization working correctly, distinct from
a 404 — wrong id guess — which the check also doesn't flag.)

Two mitigations for the "legitimately public" false-positive class, each
closing a DIFFERENT flavor of it:

  1. SPEC-DECLARED public endpoints: if the OpenAPI spec explicitly marks an
     operation `security: []` (no auth required at all — a real, standard
     OpenAPI signal, distinct from the spec simply saying nothing about auth;
     see spec_loader.Endpoint.security), skip it. "Two people can read a page
     that needs no login" isn't a finding.
  2. Endpoints that DO require auth but are intentionally shared with every
     authenticated user (e.g. a public announcement) have no such signal in
     OpenAPI — there's no schema construct for "no per-object ownership
     applies here". That can't be inferred from behavior (the response is
     identical either way), so it's closed the same way secret scanners close
     unavoidable false positives: a human-maintained allowlist
     (`ctx.public_paths`, wired from `--public-paths`), not detection.

FOLLOW-UPS (not done): ids beyond simple sequential integers (UUIDs can't be
guessed this way — would need `POST`ing a resource as user A first, noting
the id from the response, then testing B against it); write-based BOLA.

CONFIRMED COST of these follow-ups (external validation against VAmPI,
github.com/erev0s/VAmPI, see EXTERNAL_VALIDATION.md #4b): VAmPI keys users
by username, not integers, so this check's `["1".."5"]` candidate list never
finds an accessible resource there -- and `PUT /users/v1/{username}/password`
has no ownership check at all, letting one user change another's password
and take over their account. Manually confirmed exploitable (full account
takeover). Both follow-ups above (id discovery, write-based BOLA) would be
needed to catch this specific bug; upgrades it from a hypothetical gap to a
confirmed, prioritized one.
"""

from __future__ import annotations

import fnmatch

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
        if endpoint.security == []:
            return []  # spec explicitly declares this endpoint needs no auth
        if _matches_public_path(endpoint.path, ctx.public_paths):
            return []  # operator has declared this path intentionally shared

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


def _matches_public_path(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)
