"""API6:2023 - Mass Assignment.

STATUS: stub — Week 3 task.

Approach:
1. For POST/PUT/PATCH endpoints, compare the request body schema
   (`endpoint.request_body_schema`) against the response schema for the
   same resource (or a GET on it). Fields present in the response but not
   in the request schema — e.g. `role`, `is_admin`, `balance` — are
   candidates.
2. Send a request with a legitimate payload PLUS one candidate field set to
   a privileged value (e.g. `"role": "admin"`).
3. Read back the created/updated resource. If the extra field was actually
   applied (not silently ignored), the handler is binding request fields
   directly onto the model — a mass assignment finding.
"""

from __future__ import annotations

from apisec.checks.base import Finding, ScanContext, Severity
from apisec.spec_loader import Endpoint


class MassAssignmentCheck:
    id = "API6:2023"
    title = "Mass Assignment"

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        if endpoint.method not in {"POST", "PUT", "PATCH"}:
            return []
        # TODO: implement — see module docstring. `ctx.session_a` and
        # `apisec.checks.base.concrete_url` (id substitution) are ready to use.
        return []
