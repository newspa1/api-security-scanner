from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol
from urllib.parse import urljoin

import requests

from apisec.spec_loader import Endpoint


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    endpoint: str
    method: str
    description: str
    evidence: str = ""


@dataclass
class ScanContext:
    """Everything a check needs to probe an endpoint. `session_a` is always
    present (the scanner's primary identity); `session_b` is only set when the
    caller supplied a second set of credentials (`--auth-header-b`), which is
    what BOLA needs to compare cross-user access. Checks that don't need a
    second identity simply ignore `session_b`.

    `public_paths` is an operator-supplied allowlist (`--public-paths`) of
    glob patterns for endpoints known to be intentionally shared across users
    -- e.g. a public product listing that requires login but isn't owned by
    any one user. BOLA can't infer this from spec/traffic alone (see its
    module docstring), so it's a human-declared escape hatch, same pattern as
    a secret-scanner's baseline/allowlist file."""

    base_url: str
    session_a: requests.Session
    session_b: requests.Session | None = None
    public_paths: list[str] = field(default_factory=list)
    # Every endpoint in the spec, not just the one currently under test.
    # Needed for discover_resource_id() below, which looks for a sibling
    # "collection" POST to create a real resource, rather than guessing ids.
    all_endpoints: list[Endpoint] = field(default_factory=list)


class Check(Protocol):
    """Every check module exposes one of these. `run` gets the Endpoint under
    test and a ScanContext (base URL + one or two authenticated sessions), and
    returns zero or more Findings."""

    id: str
    title: str

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        ...


def concrete_url(path: str, base_url: str, value: str = "1") -> str:
    """Substitute a placeholder for every `{...}` path parameter so e.g.
    `/users/{id}` becomes a requestable URL, then join with base_url. Assumes
    numeric-style auto-increment ids; won't produce a valid id for UUID- or
    username-keyed resources — see discover_resource_id() below for the
    alternative, and bola.py / mass_assignment.py's docstrings for what this
    guessing approach has been confirmed to miss."""
    concrete_path = re.sub(r"\{[^}]+\}", value, path)
    return urljoin(base_url.rstrip("/") + "/", concrete_path.lstrip("/"))


_TYPE_PLACEHOLDERS: dict[str, object] = {
    "string": "apisec-test",
    "integer": 1,
    "number": 1.0,
    "boolean": True,
    "array": [],
    "object": {},
}


def build_legit_payload(schema: dict | None) -> dict:
    """A minimal, plausible request body from a schema's declared
    properties -- one placeholder value per property, picked by JSON Schema
    `type`. Doesn't attempt to satisfy stricter rules (enum, min_length,
    formats, ...); good enough to usually clear basic type validation.
    Shared by mass_assignment.py (building a legit PATCH/PUT body) and
    discover_resource_id() below (building a legit POST body)."""
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


def _collection_path(item_path: str) -> str | None:
    """"/orders/{order_id}" -> "/orders"; "/orders/{id}/email" -> None (the
    id isn't the last segment, so there's no obvious "create one of these"
    collection endpoint to look for)."""
    match = re.match(r"^(.*)/\{[^}]+\}$", item_path)
    return match.group(1) if match and match.group(1) else None


def _extract_id_from_response(body: object) -> str | None:
    """Best-effort: look for an id-shaped field at the top level, or one
    level deep under any key (covers both `{"id": 7}` and the common
    `{"order": {"id": 7}}` wrapper shape seen in real APIs)."""
    if not isinstance(body, dict):
        return None
    id_keys = ("id", "Id", "ID")
    for key in id_keys:
        if key in body and isinstance(body[key], (str, int)) and not isinstance(body[key], bool):
            return str(body[key])
    for value in body.values():
        if isinstance(value, dict):
            for key in id_keys:
                if (
                    key in value
                    and isinstance(value[key], (str, int))
                    and not isinstance(value[key], bool)
                ):
                    return str(value[key])
    return None


def discover_resource_id(endpoint: Endpoint, ctx: ScanContext) -> str | None:
    """Find a REAL id by creating a resource, instead of guessing one:
    locate a sibling POST on this endpoint's collection path (e.g.
    `POST /orders` for `GET /orders/{id}`), call it with a legit payload
    built from its own schema, and read the id back from the response.

    Best-effort and silent on failure at every step (no sibling POST, POST
    rejected, no id-shaped field in the response) -- callers should treat
    None as "discovery didn't work here" and fall back to guessing, not as
    an error. This is deliberately conservative: it never tries to *guess*
    a plausible collection path beyond the direct parent, and never digs
    more than one level into the response for an id.

    Confirmed necessary by external validation (EXTERNAL_VALIDATION.md):
    sequential-integer guessing (`concrete_url`'s default) misses any
    resource whose id doesn't happen to fall in the small guessed range --
    which live/shared test databases hit quickly (crAPI: a scan created
    order id 7, past the ["1".."5"] range, so guessing found nothing even
    with a retry loop) -- and misses username/UUID-keyed resources
    entirely (VAmPI)."""
    collection_path = _collection_path(endpoint.path)
    if collection_path is None:
        return None
    sibling = next(
        (
            e
            for e in ctx.all_endpoints
            if e.path == collection_path and e.method == "POST"
        ),
        None,
    )
    if sibling is None:
        return None

    payload = build_legit_payload(sibling.request_body_schema)
    url = sibling.url(ctx.base_url)
    try:
        resp = ctx.session_a.request("POST", url, json=payload, timeout=5)
    except requests.RequestException:
        return None
    if resp.status_code >= 300:
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    return _extract_id_from_response(body)
