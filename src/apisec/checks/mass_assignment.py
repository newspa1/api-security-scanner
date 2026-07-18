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
3. For each candidate privileged field NOT in the declared schema (role,
   is_admin, permissions, ...), add it to the payload with a privileged
   value and send the write.
4. GET the same URL back and check whether the injected field's value
   actually stuck. If it did, the handler is binding the raw request body
   onto its model instead of an explicit allowlist of writable fields --
   that's the finding. A field that's rejected, ignored, or the request
   itself failing (4xx) is NOT evidence of anything.

SCOPE: excludes POST. A PATCH/PUT target is id-addressable, so "read back
the same URL" is well-defined. A POST typically CREATES a resource at a
different URL than the collection endpoint, and finding it back requires
parsing the response for an id (or a Location header) -- a real follow-up,
not done here.

Like BOLA, this is deliberately conservative: a request that just gets
rejected outright isn't treated as "not vulnerable", it's treated as "no
evidence either way" and skipped, so the check stays quiet rather than
guessing.
"""

from __future__ import annotations

import requests

from apisec.checks.base import Finding, ScanContext, Severity, concrete_url
from apisec.spec_loader import Endpoint

_CANDIDATE_PRIVILEGE_FIELDS: list[tuple[str, object]] = [
    ("role", "admin"),
    ("is_admin", True),
    ("isAdmin", True),
    ("admin", True),
    ("permissions", ["admin"]),
]

_TYPE_PLACEHOLDERS: dict[str, object] = {
    "string": "apisec-test",
    "integer": 1,
    "number": 1.0,
    "boolean": True,
    "array": [],
    "object": {},
}


def _build_legit_payload(schema: dict | None) -> dict:
    """A minimal, plausible request body from the schema's declared
    properties -- one placeholder value per property, picked by JSON Schema
    `type`. Doesn't attempt to satisfy stricter rules (enum, min_length,
    formats, ...); good enough to usually clear basic type validation."""
    if not schema or not isinstance(schema, dict):
        return {}
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return {}
    payload = {}
    for name, prop_schema in props.items():
        prop_type = prop_schema.get("type") if isinstance(prop_schema, dict) else None
        payload[name] = _TYPE_PLACEHOLDERS.get(prop_type, "apisec-test")
    return payload


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

        legit_payload = _build_legit_payload(endpoint.request_body_schema)
        url = concrete_url(endpoint.path, ctx.base_url)

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
                evidence=f"Undeclared field(s) accepted and persisted: {', '.join(confirmed)}",
            )
        ]
