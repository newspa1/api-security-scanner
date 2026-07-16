"""API1:2023 - Broken Object Level Authorization (BOLA).

STATUS: stub — this is your Week 2 task. Historically the #1 API
vulnerability, so it's worth doing properly rather than rushing it.

Approach:
1. The scanner needs to be configured with TWO sets of credentials
   (user A and user B). That isn't wired up in `scanner.py` yet — you'll
   need to extend `scan()` to accept a second auth header and build a
   second `requests.Session`.
2. For an endpoint with an id-like path parameter (e.g. `/orders/{id}`),
   use user A's session to create or discover a resource A owns, note its id.
3. Request the SAME id using user B's session.
4. If user B can read (or worse, modify/delete) user A's resource, that's a
   BOLA finding — severity HIGH/CRITICAL depending on read vs write.

Edge cases worth handling once the happy path works: endpoints where the id
is not numeric (UUIDs — you can't just increment), and distinguishing
"403 because BOLA is actually enforced" from "404 because the id guess was
wrong" (try a few real ids from user A's own account, not a random guess).
"""

from __future__ import annotations

import requests

from apisec.checks.base import Finding, Severity
from apisec.spec_loader import Endpoint


class BolaCheck:
    id = "API1:2023"
    title = "Broken Object Level Authorization (BOLA)"

    def run(self, endpoint: Endpoint, base_url: str, session: requests.Session) -> list[Finding]:
        if not _has_id_path_param(endpoint.path):
            return []
        # TODO: implement — see module docstring.
        return []


def _has_id_path_param(path: str) -> bool:
    return "{" in path and "}" in path
