"""API2:2023 - Broken Authentication (the "no check at all" facet -- distinct
from broken_auth.py's `alg=none` forgery, which assumes SOME signature
verification exists to bypass. This check answers a more basic question:
does the endpoint require an `Authorization` header to be present at all?

Motivated by a real, live finding, not a hypothetical: scanning OWASP crAPI
(github.com/OWASP/crAPI, see EXTERNAL_VALIDATION.md) turned up
`GET /workshop/api/shop/orders/{order_id}` returning real order and payment
data with NO `Authorization` header sent whatsoever -- confirmed manually
with a bare `curl`, no token, no forgery, nothing. That's a strictly
simpler, more severe bug than a JWT signature bypass (it doesn't even
require an attacker to have ever seen a valid token shape), and none of the
other checks caught it: BOLA reported it as "user A and user B can both
read this", which is technically true but undersells what's actually wrong
-- ANYONE, authenticated or not, can read it.

ALGORITHM: resend the exact same request with the `Authorization` header
stripped entirely (not swapped for garbage -- this check is about presence,
not validity, unlike broken_auth.py's baseline check). If the response still
succeeds (< 400), the endpoint enforces no authentication at all.

ID-ADDRESSABLE ENDPOINTS (e.g. `/orders/{id}`) need a REAL, accessible id
first -- same reasoning as bola.py/mass_assignment.py: a 404 from a wrong
guessed id proves nothing about authentication, it just means the id didn't
resolve to anything. Reuses `_candidate_ids_for()` (base.py, also shared by
bola.py and mass_assignment.py) to try a discovered id first, then confirms
each candidate is genuinely reachable WITH auth before testing it WITHOUT --
mirrors bola.py's "lock onto a real resource, then compare" shape.

FALSE-POSITIVE GUARDS, same two used by bola.py/broken_auth.py for the
identical "this is supposed to be public" class:
  1. `endpoint.security == []` -- the spec explicitly declares this endpoint
     needs no auth. Not a bug.
  2. `ctx.public_paths` (`--public-paths`) -- an operator-declared allowlist
     for endpoints the spec can't express as public (see bola.py's docstring
     for why this can't be inferred from behavior alone).

SCOPE: like broken_auth.py, this only makes sense when the scanner is
configured with a real `Authorization` header to strip in the first place
(`--auth-header`) -- an unauthenticated scan has nothing to compare against,
and every endpoint would trivially "pass" the test for the wrong reason.
"""

from __future__ import annotations

import requests

from apisec.checks.base import (
    Finding,
    ScanContext,
    Severity,
    _candidate_ids_for,
    _matches_public_path,
    concrete_url,
)
from apisec.spec_loader import Endpoint


def _has_id_path_param(path: str) -> bool:
    return "{" in path and "}" in path


class MissingAuthCheck:
    id = "API2:2023"
    title = "Broken Authentication - No Authentication Required"

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        if endpoint.security == []:
            return []  # spec explicitly declares this endpoint needs no auth
        if _matches_public_path(endpoint.path, ctx.public_paths):
            return []  # operator has declared this path intentionally shared

        session = ctx.session_a
        if "Authorization" not in session.headers:
            return []  # nothing configured to strip -- test would be meaningless

        if not _has_id_path_param(endpoint.path):
            return self._check_url(endpoint, session, endpoint.url(ctx.base_url), None)

        for candidate_id in _candidate_ids_for(endpoint, ctx):
            url = concrete_url(endpoint.path, ctx.base_url, candidate_id)
            try:
                authed_resp = session.request(endpoint.method, url, timeout=5)
            except requests.RequestException:
                continue
            if authed_resp.status_code >= 400:
                continue  # not a real/accessible resource at this id -- try next
            return self._check_url(endpoint, session, url, candidate_id)
        return []

    def _check_url(
        self, endpoint: Endpoint, session: requests.Session, url: str, id_used: str | None
    ) -> list[Finding]:
        try:
            resp = session.request(endpoint.method, url, headers={"Authorization": None}, timeout=5)
        except requests.RequestException:
            return []

        if resp.status_code < 400:
            id_prefix = f"id={id_used}: " if id_used else ""
            return [
                Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    description=(
                        "The endpoint returned a successful response with the "
                        "Authorization header removed entirely -- not a forged or "
                        "invalid credential, no credential at all. Anyone who can "
                        "reach this URL can use it, authenticated or not."
                    ),
                    evidence=(
                        f"{id_prefix}request with no Authorization header at all "
                        f"still got HTTP {resp.status_code}."
                    ),
                )
            ]
        return []
