"""API3:2023 - Broken Object Property Level Authorization
(formerly "Excessive Data Exposure" in the 2019 OWASP API list).

HYBRID detection — no single method is reliable, so we layer three, the way
mature tools do (name/context + value-shape + entropy, à la gitleaks/trufflehog;
schema conformance, à la Schemathesis):

  Layer 1  NAME     — the field NAME looks sensitive (password/token/ssn/...).
  Layer 2  VALUE    — the field VALUE looks like a secret regardless of its
                      name (bcrypt hash, JWT, PEM key, AWS key, or high Shannon
                      entropy). Closes the "secret hidden under an innocent
                      name" blind spot that Layer 1 alone misses.
  Layer 3  SCHEMA   — the field appears in the response but is NOT declared in
                      the OpenAPI response schema. Name-independent; the
                      principled definition of "the API returned more than it
                      documented."

Each layer that fires on a field adds a reason. More reasons ⇒ higher
confidence ⇒ higher severity. Each layer is a pure function so it can be unit
tested in isolation.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

import requests

from apisec.checks.base import Finding, ScanContext, Severity, concrete_url
from apisec.spec_loader import Endpoint

# Layer 1: sensitive-looking field names.
SENSITIVE_FIELD_PATTERN = re.compile(
    r"(password|secret|token|api[_-]?key|ssn|credit[_-]?card|hash|private[_-]?key)",
    re.IGNORECASE,
)

# Layer 2: value shapes that are unmistakable secrets regardless of field name.
_VALUE_SHAPES: list[tuple[str, re.Pattern]] = [
    ("bcrypt-hash", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]+")),
    ("jwt", re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")),
    ("pem-private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
]
_ENTROPY_MIN_LEN = 20
_ENTROPY_THRESHOLD = 4.0  # bits/char; random-looking secrets sit above this.


@dataclass
class _FieldSignal:
    path: str
    reasons: list[str] = field(default_factory=list)


def _name_looks_sensitive(name: str) -> bool:
    """Layer 1."""
    return bool(SENSITIVE_FIELD_PATTERN.search(name))


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _value_looks_secret(value: object) -> str | None:
    """Layer 2. Returns a shape label (e.g. "bcrypt-hash", "high-entropy") or
    None. Only strings can match."""
    if not isinstance(value, str):
        return None
    for label, pattern in _VALUE_SHAPES:
        if pattern.search(value):
            return label
    # The entropy fallback requires no whitespace: real secrets (JWTs,
    # hashes, API keys) are structurally single unbroken tokens -- their
    # encodings (base64, hex, ...) never contain spaces. Prose almost always
    # does. Found scanning VAmPI (github.com/erev0s/VAmPI): a long, varied
    # English help-text sentence tripped the entropy threshold and was a
    # real false positive until this filter was added.
    if (
        len(value) >= _ENTROPY_MIN_LEN
        and not re.search(r"\s", value)
        and _shannon_entropy(value) >= _ENTROPY_THRESHOLD
    ):
        return "high-entropy"
    return None


def _declared_property_names(response_schema: dict | None) -> set[str] | None:
    """Property names the response schema declares. Returns None when the schema
    is absent or too loose to judge (so Layer 3 stays silent rather than guess)."""
    if not response_schema or not isinstance(response_schema, dict):
        return None
    props = response_schema.get("properties")
    if not isinstance(props, dict):
        return None
    return set(props.keys())


def _collect_signals(
    body: object,
    declared_top_level: set[str] | None,
    prefix: str = "",
) -> list[_FieldSignal]:
    """Walk the response JSON recursively, applying all three layers. Layer 3
    (schema) only applies to top-level keys, since the declared property set we
    have is for the top-level object."""
    signals: list[_FieldSignal] = []
    if isinstance(body, dict):
        for key, value in body.items():
            path = f"{prefix}{key}"
            reasons: list[str] = []
            if _name_looks_sensitive(key):
                reasons.append("sensitive-name")
            shape = _value_looks_secret(value)
            if shape:
                reasons.append(f"value-shape:{shape}")
            if prefix == "" and declared_top_level is not None and key not in declared_top_level:
                reasons.append("undeclared-in-schema")
            if reasons:
                signals.append(_FieldSignal(path=path, reasons=reasons))
            signals.extend(_collect_signals(value, None, prefix=f"{path}."))
    elif isinstance(body, list):
        for i, item in enumerate(body):
            signals.extend(_collect_signals(item, None, prefix=f"{prefix}{i}."))
    return signals


def _severity_for(signals: list[_FieldSignal]) -> Severity:
    """Confidence scoring: any field corroborated by >1 layer, or by the strong
    value-shape layer, is high-confidence."""
    max_reasons = max(len(s.reasons) for s in signals)
    any_value_shape = any(r.startswith("value-shape:") for s in signals for r in s.reasons)
    if max_reasons >= 2 or any_value_shape:
        return Severity.HIGH
    return Severity.MEDIUM


class ExcessiveDataExposureCheck:
    id = "API3:2023"
    title = "Excessive Data Exposure"

    def run(self, endpoint: Endpoint, ctx: ScanContext) -> list[Finding]:
        if endpoint.method != "GET":
            return []

        url = concrete_url(endpoint.path, ctx.base_url)
        try:
            resp = ctx.session_a.get(url, timeout=5)
        except requests.RequestException:
            return []
        if resp.status_code >= 400:
            return []
        try:
            body = resp.json()
        except ValueError:
            return []

        declared = _declared_property_names(endpoint.response_schema)
        signals = _collect_signals(body, declared)
        if not signals:
            return []

        evidence = "; ".join(f"{s.path} ({', '.join(s.reasons)})" for s in signals)
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=_severity_for(signals),
                endpoint=endpoint.path,
                method=endpoint.method,
                description=(
                    "The response exposes fields that look sensitive. Detected by "
                    "field name, value shape, and/or absence from the declared "
                    "response schema."
                ),
                evidence=evidence,
            )
        ]
