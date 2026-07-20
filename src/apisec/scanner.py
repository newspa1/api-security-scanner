from __future__ import annotations

from dataclasses import replace

import requests

from apisec.checks import ALL_CHECKS
from apisec.checks.base import Finding, ScanContext, Severity
from apisec.spec_loader import extract_endpoints, load_spec

_MISSING_AUTH_TITLE = "Broken Authentication - No Authentication Required"

# One step up each -- CRITICAL has nowhere higher to go, so it's a no-op.
_SEVERITY_BUMP = {
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
}


def _reweight_by_reachability(findings: list[Finding]) -> list[Finding]:
    """Severity re-weighting by reachability: a finding on an endpoint that
    requires NO authentication at all is strictly more dangerous than the
    identical finding behind a login wall -- anyone can reach it, not just
    someone who can get an account. missing_auth.py already tells us which
    endpoints those are; this bumps every OTHER finding sharing that same
    (endpoint, method) up one severity level (LOW->MEDIUM->HIGH->CRITICAL).

    Deliberately a post-processing pass over the FULL finding set, not
    something any single check does on its own -- reachability is a
    cross-check property (missing_auth.py's own finding is the signal;
    bola.py/excessive_data_exposure.py/etc. have no way to know it without
    duplicating missing_auth.py's own request). Confirmed on this repo's
    own demo target: `GET /orders/{order_id}/receipt` in demo_apps/vulnerable
    already produces both a CRITICAL Missing-Auth finding and a HIGH BOLA
    finding (see EXTERNAL_VALIDATION.md crAPI §5 / demo README) -- this
    pass turns that BOLA finding into CRITICAL too, since "anyone on the
    internet can read this" is worse than "any authenticated user can."

    Motivated by EXTERNAL_VALIDATION.md #4c: VAmPI's Excessive Data
    Exposure finding on an unauthenticated debug endpoint was flagged as
    arguably under-scored at MEDIUM given it needs zero credentials to
    reach -- this is that fix, applied generally rather than special-cased
    to one target."""
    unauthenticated = {
        (f.endpoint, f.method) for f in findings if f.title == _MISSING_AUTH_TITLE
    }
    reweighted = []
    for f in findings:
        if f.title != _MISSING_AUTH_TITLE and (f.endpoint, f.method) in unauthenticated:
            new_severity = _SEVERITY_BUMP[f.severity]
            if new_severity != f.severity:
                f = replace(
                    f,
                    severity=new_severity,
                    evidence=f.evidence
                    + " [Severity increased: this endpoint requires no authentication at all.]",
                )
        reweighted.append(f)
    return reweighted


def scan(
    spec_path: str,
    base_url: str,
    auth_header: str | None = None,
    auth_header_b: str | None = None,
    public_paths: list[str] | None = None,
    custom_mass_assignment_fields: list[tuple[str, object]] | None = None,
) -> list[Finding]:
    spec = load_spec(spec_path)
    endpoints = extract_endpoints(spec)

    session_a = requests.Session()
    if auth_header:
        session_a.headers["Authorization"] = auth_header

    session_b = None
    if auth_header_b:
        session_b = requests.Session()
        session_b.headers["Authorization"] = auth_header_b

    ctx = ScanContext(
        base_url=base_url,
        session_a=session_a,
        session_b=session_b,
        public_paths=public_paths or [],
        custom_mass_assignment_fields=custom_mass_assignment_fields or [],
        all_endpoints=endpoints,
    )

    findings: list[Finding] = []
    for endpoint in endpoints:
        for check in ALL_CHECKS:
            findings.extend(check.run(endpoint, ctx))
    return _reweight_by_reachability(findings)
