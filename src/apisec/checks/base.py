from __future__ import annotations

import fnmatch
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


def _item_endpoint_for_collection_path(
    collection_path: str, all_endpoints: list[Endpoint]
) -> Endpoint | None:
    """Reverse of _collection_path: given a collection path (e.g. "/orders"),
    find the sibling GET item endpoint (e.g. "/orders/{id}") whose own
    computed collection path matches. Used by Mass Assignment's POST support
    to read a freshly-created resource back by its server-generated id."""
    return next(
        (e for e in all_endpoints if e.method == "GET" and _collection_path(e.path) == collection_path),
        None,
    )


def _single_path_param_name(path: str) -> str | None:
    """The one `{param}` name in a path, or None if there isn't exactly
    one -- multi-param paths are out of scope for the simple
    substitute-one-value approach both this module and concrete_url use."""
    segments = [s for s in path.strip("/").split("/") if s.startswith("{") and s.endswith("}")]
    if len(segments) != 1:
        return None
    return segments[0][1:-1]


def find_item_endpoint_for_payload(
    payload: dict, all_endpoints: list[Endpoint]
) -> tuple[Endpoint | None, str | None]:
    """Fallback for CLIENT-CHOSEN identifiers, where discover_resource_id()
    and _item_endpoint_for_collection_path() both come up empty: if the id
    is something the caller supplied (e.g. VAmPI's username, chosen at
    registration) rather than something the server generates, there's
    nothing to extract from the create response, and the create endpoint's
    own path (e.g. "/users/v1/register") often isn't a collection-path
    match for the item endpoint's path (e.g. "/users/v1/{username}") at
    all -- register is a verb-shaped endpoint, not a REST collection.

    Instead: find a GET endpoint with exactly one path parameter whose NAME
    matches a key we just submitted in the create payload (e.g. path param
    "username" <-> payload key "username"), and use the value we sent as
    the id. Returns (None, None) if nothing matches."""
    for candidate_endpoint in all_endpoints:
        if candidate_endpoint.method != "GET":
            continue
        param_name = _single_path_param_name(candidate_endpoint.path)
        if param_name is None or param_name not in payload:
            continue
        value = payload[param_name]
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            return candidate_endpoint, str(value)
    return None, None


def _matches_public_path(path: str, patterns: list[str]) -> bool:
    """Shared by bola.py and missing_auth.py: does `path` match one of the
    operator-supplied `--public-paths` glob patterns (`ctx.public_paths`)?"""
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


_CANDIDATE_IDS = ["1", "2", "3", "4", "5"]


def _candidate_ids_for(endpoint: Endpoint, ctx: ScanContext) -> list[str]:
    """A real, discovered id (if one can be found) tried first, then the
    numeric guesses as a fallback -- discovery can fail silently (no sibling
    POST, POST rejected, no id in the response), so guessing stays as a
    safety net rather than being replaced outright. Shared by bola.py,
    mass_assignment.py, and missing_auth.py -- all three need "a real,
    writable/readable id to test against", not just any placeholder."""
    discovered = discover_resource_id(endpoint, ctx)
    if discovered is None:
        return _CANDIDATE_IDS
    if discovered in _CANDIDATE_IDS:
        return _CANDIDATE_IDS
    return [discovered, *_CANDIDATE_IDS]


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
