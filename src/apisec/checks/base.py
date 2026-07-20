from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol
from urllib.parse import urljoin

import jwt
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
    a secret-scanner's baseline/allowlist file.

    `custom_mass_assignment_fields` is an operator-supplied extension
    (`--mass-assignment-fields`) to mass_assignment.py's built-in candidate
    field list. The built-in list (privilege-flavored: role, is_admin, ...;
    business-logic-flavored: status, price, ...) was chosen from patterns
    seen on real targets during this project's own external validation, but
    it can never cover every domain-specific sensitive field name a given
    API might have (e.g. `subscription_tier`, `credit_limit`,
    `tenant_id`) -- same reasoning as `public_paths` above: the scanner
    can't infer an operator's own domain vocabulary, so it's a
    human-supplied extension point, not automatic detection.

    `auto_discover_fields` (`--auto-discover-fields`) is the automatic
    counterpart to `custom_mass_assignment_fields`: instead of a human
    typing field names in, mine them straight from the target's own spec
    (`discover_candidate_fields()`, above) -- every property name declared
    ANYWHERE in the spec becomes a candidate on endpoints that don't
    declare it themselves. Opt-in, not the default: more candidates means
    more test writes per endpoint, and a large spec could mean a real
    increase in request volume/side effects on the target, which shouldn't
    change silently for every scan."""

    base_url: str
    session_a: requests.Session
    session_b: requests.Session | None = None
    public_paths: list[str] = field(default_factory=list)
    custom_mass_assignment_fields: list[tuple[str, object]] = field(default_factory=list)
    auto_discover_fields: bool = False
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


def _collect_field_placeholders(
    schema: object, declared_fields: set[str], discovered: dict[str, object], _nested: bool = False
) -> None:
    """Collects `{name: placeholder}` from a schema's top-level properties
    into `discovered`, then looks ONE level deeper into any property that's
    itself an object, or an array of objects -- same one-level-deep
    convention used throughout this package (`_extract_id_from_response`,
    `_classify_readback`, mass_assignment.py's `_find_list_in_body`).
    Confirmed necessary, not just theoretical: VAmPI's own `_debug`
    response schema wraps every user field one level down inside an array
    (`{"users": {"type": "array", "items": {"type": "object",
    "properties": {"admin": ..., "username": ..., ...}}}}`) -- a top-level-
    only scan would see `users` and stop, never finding `admin` at all,
    even though it's right there in the target's own spec. `_nested`
    guards against recursing past one level, matching the rest of this
    package's deliberate depth limit."""
    if not isinstance(schema, dict):
        return
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return
    for name, prop_schema in props.items():
        if not isinstance(prop_schema, dict):
            continue
        prop_type = prop_schema.get("type")
        if name not in declared_fields and name not in discovered:
            discovered[name] = _TYPE_PLACEHOLDERS.get(prop_type, "apisec-test")
        if _nested:
            continue
        if prop_type == "object":
            _collect_field_placeholders(prop_schema, declared_fields, discovered, _nested=True)
        elif prop_type == "array":
            items = prop_schema.get("items")
            _collect_field_placeholders(items, declared_fields, discovered, _nested=True)


def discover_candidate_fields(
    all_endpoints: list[Endpoint], declared_fields: set[str]
) -> list[tuple[str, object]]:
    """Auto-discover extra Mass Assignment candidate fields straight from
    the target's OWN spec, instead of a human typing them in
    (`--mass-assignment-fields`) or relying only on the hardcoded built-in
    list (`_CANDIDATE_FIELDS`, mass_assignment.py). Walks EVERY schema in
    the spec -- every endpoint's request body AND response schema, not
    just the one endpoint under test -- and collects property names that
    appear somewhere in the API but aren't declared on THIS endpoint
    (`declared_fields`), one level deep too (see `_collect_field_placeholders()`).
    If the spec documents a `subscription_tier` field anywhere at all (even
    a totally different endpoint's response), that's a real, spec-derived
    signal this API's domain has that field -- a much better source of
    "what might be missing here" than a fixed, target-agnostic list can
    ever be, and it needs no manual research.

    One placeholder value per discovered field, picked by JSON Schema
    `type` the same way `build_legit_payload()` does. First schema to
    declare a given name wins if types conflict across schemas -- a rare
    edge case, not worth extra complexity to resolve "correctly"."""
    discovered: dict[str, object] = {}
    for endpoint in all_endpoints:
        for schema in (endpoint.request_body_schema, endpoint.response_schema):
            _collect_field_placeholders(schema, declared_fields, discovered)
    return list(discovered.items())


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

# Common claim names a JWT uses to carry the authenticated identity's own
# id/username -- checked in this order, first match wins.
_IDENTITY_CLAIM_KEYS = ("username", "user_id", "userId", "sub", "uid", "id", "email")


def _identity_from_session(session: requests.Session) -> str | None:
    """Extract the authenticated identity's OWN id/username straight from
    its bearer JWT, if it has one -- e.g. a `"sub": "alice"` or
    `"username": "alice"` claim. Same unverified decode broken_auth.py
    already uses to forge `alg=none` tokens: no signature check needed,
    we're just reading claims out of OUR OWN token, already trusted by
    definition (we didn't forge it, the target issued it to us).

    This is a REAL, definitely-existing identifier -- unlike `_CANDIDATE_IDS`
    guessing, which invents a value with no guarantee it corresponds to
    anything. It closes a gap neither `discover_resource_id()` nor guessing
    can: CLIENT-CHOSEN identifiers (e.g. a username picked at registration)
    that the create response never echoes back, so there's nothing to
    extract an id FROM -- but the token issued for THIS identity almost
    always carries exactly that value as a claim.

    Returns None for anything that doesn't apply: no Authorization header,
    not a Bearer token, not a JWT (opaque session ids, API keys, ...), or a
    JWT with none of the common identity claim names present.

    LIVE-VERIFIED against the exact bug this was built to close: VAmPI's
    documented, manually-confirmed account takeover
    (`PUT /users/v1/{username}/password`, no ownership check -- see
    EXTERNAL_VALIDATION.md target 1 #4b). VAmPI's JWTs carry the username
    as `"sub"` -- confirmed by decoding a real token
    (`{'exp': ..., 'iat': ..., 'sub': 'jwtidA'}`). Before this, neither
    `bola.py` nor `write_bola.py` could reach this endpoint at all:
    `_collection_path()` doesn't match its shape (ends in `/password`, not
    a bare `/{param}`), so `discover_resource_id()` never even runs, and
    numeric guessing never finds a real username. With this,
    `_candidate_ids_for()` tries the scanning identity's own username
    (extracted from its own token) and reaches the resource directly --
    `write_bola.py` now correctly reports the real, exploitable finding,
    confirmed via a live re-scan (`user A's write got HTTP 204, user B's
    write to the SAME id also got HTTP 204`). Also confirmed as a genuine
    side benefit for `bola.py`'s READ-only check, which had the identical
    limitation on `GET /users/v1/{username}` and now finds that too.

    Known limit, honestly stated: this only recovers ONE identifier per
    scan (the scanning identity's own), not an arbitrary target resource's
    id -- it helps precisely when the vulnerable endpoint happens to be
    keyed by an id the scanner's OWN identity also has (a username, in
    VAmPI's case), which is common for self-service endpoints
    (`/password`, `/profile`, ...) but won't help for an arbitrary OTHER
    user's resource with no relationship to the scanning identity's own
    claims."""
    auth_header = getattr(session, "headers", {}).get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    for key in _IDENTITY_CLAIM_KEYS:
        value = claims.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            return str(value)
    return None


def _candidate_ids_for(endpoint: Endpoint, ctx: ScanContext) -> list[str]:
    """Three sources of candidate ids, in order of how much we trust them:
    1. A real, DISCOVERED id (`discover_resource_id()`) -- created a
       resource ourselves and read its real id back. Most trustworthy: not
       just real, but the RIGHT resource type for this exact endpoint.
    2. The scanning identity's OWN id/username, pulled from its JWT
       (`_identity_from_session()`) -- definitely a real, existing
       identifier, but not necessarily the right resource type for THIS
       endpoint (e.g. it's a username, and this endpoint wants an order
       id). Closes the client-chosen-id gap discovery structurally can't:
       when the resource's id is something the CALLER chose (a username at
       registration) rather than something the server generates and
       returns, there's no id in any create response to extract at all --
       but the token issued for that identity still carries it as a claim.
    3. Numeric guesses (`_CANDIDATE_IDS`) as the last-resort fallback.
    Discovery can fail silently (no sibling POST, POST rejected, no id in
    the response); the identity claim can be absent (non-JWT token, no
    matching claim name) -- guessing stays as the final safety net rather
    than either replacing it outright. Shared by bola.py, write_bola.py,
    mass_assignment.py, and missing_auth.py."""
    candidates: list[str] = []
    discovered = discover_resource_id(endpoint, ctx)
    if discovered is not None:
        candidates.append(discovered)
    identity = _identity_from_session(ctx.session_a)
    if identity is not None and identity not in candidates:
        candidates.append(identity)
    for candidate_id in _CANDIDATE_IDS:
        if candidate_id not in candidates:
            candidates.append(candidate_id)
    return candidates


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
