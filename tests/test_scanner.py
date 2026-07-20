"""Tests for scanner.py's orchestration logic beyond the endpoint x check
loop: severity re-weighting by reachability.
"""

from __future__ import annotations

from apisec.checks.base import Finding, Severity
from apisec.scanner import _reweight_by_reachability


def _finding(title, severity, endpoint="/things/{id}", method="GET", evidence="") -> Finding:
    return Finding(
        check_id="API1:2023",
        title=title,
        severity=severity,
        endpoint=endpoint,
        method=method,
        description="x",
        evidence=evidence,
    )


def test_bumps_severity_one_level_when_endpoint_is_unauthenticated():
    findings = [
        _finding("Broken Authentication - No Authentication Required", Severity.CRITICAL),
        _finding("Broken Object Level Authorization (BOLA)", Severity.HIGH),
    ]
    reweighted = _reweight_by_reachability(findings)
    bola = next(f for f in reweighted if "BOLA" in f.title)
    assert bola.severity == Severity.CRITICAL


def test_bumps_medium_to_high_and_low_to_medium():
    findings = [
        _finding("Broken Authentication - No Authentication Required", Severity.CRITICAL),
        _finding("Excessive Data Exposure", Severity.MEDIUM),
        _finding("Mass Assignment", Severity.LOW),
    ]
    reweighted = _reweight_by_reachability(findings)
    assert next(f for f in reweighted if f.title == "Excessive Data Exposure").severity == Severity.HIGH
    assert next(f for f in reweighted if f.title == "Mass Assignment").severity == Severity.MEDIUM


def test_critical_stays_critical_no_op():
    findings = [
        _finding("Broken Authentication - No Authentication Required", Severity.CRITICAL),
        _finding("Broken Authentication - JWT alg=none bypass", Severity.CRITICAL),
    ]
    reweighted = _reweight_by_reachability(findings)
    jwt_finding = next(f for f in reweighted if "alg=none" in f.title)
    assert jwt_finding.severity == Severity.CRITICAL
    assert "[Severity increased" not in jwt_finding.evidence


def test_does_not_bump_findings_on_a_different_endpoint():
    findings = [
        _finding(
            "Broken Authentication - No Authentication Required",
            Severity.CRITICAL,
            endpoint="/orders/{id}/receipt",
        ),
        _finding("Broken Object Level Authorization (BOLA)", Severity.HIGH, endpoint="/orders/{id}"),
    ]
    reweighted = _reweight_by_reachability(findings)
    bola = next(f for f in reweighted if "BOLA" in f.title)
    assert bola.severity == Severity.HIGH  # different endpoint -- must not be touched


def test_does_not_bump_findings_on_a_different_method_same_path():
    findings = [
        _finding(
            "Broken Authentication - No Authentication Required",
            Severity.CRITICAL,
            endpoint="/orders/{id}",
            method="GET",
        ),
        _finding(
            "Broken Object Level Authorization (BOLA) - Write Access",
            Severity.CRITICAL,
            endpoint="/orders/{id}",
            method="PATCH",
        ),
    ]
    reweighted = _reweight_by_reachability(findings)
    write_bola = next(f for f in reweighted if "Write Access" in f.title)
    assert "[Severity increased" not in write_bola.evidence


def test_no_op_when_no_missing_auth_finding_present():
    findings = [_finding("Broken Object Level Authorization (BOLA)", Severity.HIGH)]
    reweighted = _reweight_by_reachability(findings)
    assert reweighted[0].severity == Severity.HIGH
    assert reweighted[0].evidence == ""


def test_appends_an_explanatory_note_to_evidence():
    findings = [
        _finding("Broken Authentication - No Authentication Required", Severity.CRITICAL),
        _finding("Broken Object Level Authorization (BOLA)", Severity.HIGH, evidence="id=1: ..."),
    ]
    reweighted = _reweight_by_reachability(findings)
    bola = next(f for f in reweighted if "BOLA" in f.title)
    assert bola.evidence.startswith("id=1: ...")
    assert "no authentication at all" in bola.evidence


def test_does_not_mutate_the_missing_auth_finding_itself():
    findings = [_finding("Broken Authentication - No Authentication Required", Severity.CRITICAL, evidence="x")]
    reweighted = _reweight_by_reachability(findings)
    assert reweighted[0].evidence == "x"
