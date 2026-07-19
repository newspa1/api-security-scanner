"""Runs the SAME scan against every demo target, side by side. This is the
single source of truth for "different bugs -> different outcomes": run

    pytest tests/test_scan_all_targets.py -v -s

and the output itself IS the comparison -- one test per target, each
printing exactly what the scanner found before asserting it's exactly what
was expected. `-v` shows each target's pass/fail on its own line; `-s`
un-hides the print() output pytest normally captures, so you see the actual
findings, not just green checkmarks.
"""

from __future__ import annotations

import pytest

from apisec.checks import ALL_CHECKS
from apisec.checks.base import ScanContext
from apisec.spec_loader import extract_endpoints
from demo_apps.bola_only.app import _reset_state as reset_bola_only
from demo_apps.bola_only.app import app as bola_only_app
from demo_apps.mass_assignment_only.app import _reset_state as reset_mass_assignment_only
from demo_apps.mass_assignment_only.app import app as mass_assignment_only_app
from demo_apps.secure.app import _reset_state as reset_secure
from demo_apps.secure.app import app as secure_app
from demo_apps.vulnerable.app import _reset_state as reset_vulnerable
from demo_apps.vulnerable.app import app as vulnerable_app

# Each target: (app, its _reset_state, expected finding count, expected set of
# (check_id, title) pairs -- distinct bug TYPES, not instances. BOLA fires
# once each on /users and /orders in the vulnerable app, same (id, title), so
# it collapses to one entry here; `expected_count` is what catches that.
TARGETS = [
    pytest.param(
        vulnerable_app,
        reset_vulnerable,
        5,
        {
            ("API2:2023", "Broken Authentication - JWT alg=none bypass"),
            ("API1:2023", "Broken Object Level Authorization (BOLA)"),
            ("API3:2023", "Excessive Data Exposure"),
            ("API3:2023", "Mass Assignment"),
        },
        id="vulnerable",
    ),
    # NOT a real bug: `/me` genuinely never has role/admin/permissions
    # fields (see demo_apps/secure/app.py's MeUpdate model and USERS dict --
    # there's nothing to leak). But Mass Assignment's new SUSPECTED tier
    # (mass_assignment.py's CONFIDENCE TIERS) reports "accepted, couldn't
    # confirm either way" as LOW whenever a write isn't rejected AND the
    # read-back response just doesn't include the field at all -- which is
    # exactly this case. This is the documented trade-off of that tier: it
    # can't tell "field doesn't exist in this API's data model" apart from
    # "field exists but this response doesn't show it", so even a genuinely
    # secure target gets one LOW/informational finding here.
    pytest.param(
        secure_app,
        reset_secure,
        1,
        {("API3:2023", "Mass Assignment")},
        id="secure",
    ),
    pytest.param(
        bola_only_app,
        reset_bola_only,
        1,
        {("API1:2023", "Broken Object Level Authorization (BOLA)")},
        id="bola_only",
    ),
    pytest.param(
        mass_assignment_only_app,
        reset_mass_assignment_only,
        1,
        {("API3:2023", "Mass Assignment")},
        id="mass_assignment_only",
    ),
]


@pytest.mark.parametrize("app,reset_state,expected_count,expected_bug_types", TARGETS)
def test_scan_reveals_expected_bugs(
    app, reset_state, expected_count, expected_bug_types, sessions_for
):
    reset_state()
    client, (session_a, session_b) = sessions_for(app, ("alice", "alice-pw"), ("bob", "bob-pw"))
    spec = client.get("/openapi.json").json()
    endpoints = extract_endpoints(spec)
    # /announcements/{id} (vulnerable demo only) is intentionally shared across
    # users -- without this allowlist it's an expected, documented false
    # positive (see bola.py); this matches the README's recommended scan
    # invocation, not a raw/unconfigured one.
    ctx = ScanContext(
        base_url="http://testserver",
        session_a=session_a,
        session_b=session_b,
        public_paths=["/announcements/*"],
    )

    findings = [f for ep in endpoints for check in ALL_CHECKS for f in check.run(ep, ctx)]

    print(f"\n{app.title}: {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity.value.upper():8}] {f.check_id} {f.title} -- {f.method} {f.endpoint}")
    if not findings:
        print("  (none)")

    assert len(findings) == expected_count
    assert {(f.check_id, f.title) for f in findings} == expected_bug_types
