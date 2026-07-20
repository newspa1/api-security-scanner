from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apisec.report import print_report, write_json_report
from apisec.scanner import scan


def _infer_value_type(raw: str) -> object:
    """Best-effort type inference for a `--mass-assignment-fields` value: a
    plain string on the command line could mean a bool, int, float, or
    really was meant as a string -- guess in that order, since that's the
    order this matters for `_classify_readback()`'s exact-value comparison
    (injecting "true" as a literal string will never match a server
    storing the JSON boolean `true`)."""
    if raw.lower() in ("true", "false"):
        return raw.lower() == "true"
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _parse_inline_fields(raw: str) -> list[tuple[str, object]]:
    """Parses `"field1=value1,field2=value2"` into the same
    `[(name, value), ...]` shape mass_assignment.py's own built-in
    candidate list uses. Malformed entries (no `=`) are skipped rather than
    raising -- a typo in one field name shouldn't abort using the rest."""
    fields = []
    for item in raw.split(","):
        item = item.strip()
        if "=" not in item:
            continue
        name, _, value = item.partition("=")
        fields.append((name.strip(), _infer_value_type(value.strip())))
    return fields


def _parse_fields_file(path: str) -> list[tuple[str, object]]:
    """Parses a `--mass-assignment-fields @path` file, in one of two
    formats, auto-detected: a JSON object (`{"field": value, ...}` --
    types come straight from JSON, no inference needed), or a plain-text
    file with one `name=value` per line (same inline syntax as the
    comma-separated flag, blank lines and `#`-comments ignored) -- for
    quick hand-editing without JSON's punctuation, and for leaving notes
    about WHY a field is a candidate next to the field itself."""
    text = Path(path).read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        return list(data.items())

    fields = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        fields.append((name.strip(), _infer_value_type(value.strip())))
    return fields


def _parse_mass_assignment_fields(raw: str) -> list[tuple[str, object]]:
    """Entry point for `--mass-assignment-fields`: either the inline
    "name=value,name2=value2" form, or "@path/to/file" (the same
    convention curl's `-d @file` and similar tools use) for a longer,
    reusable, shareable, version-controllable list that doesn't need
    retyping -- or re-escaping through shell quoting -- on every scan."""
    if not raw:
        return []
    if raw.startswith("@"):
        return _parse_fields_file(raw[1:])
    return _parse_inline_fields(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="apisec",
        description="Scan a REST API against the OWASP API Security Top 10.",
    )
    parser.add_argument("--spec", required=True, help="Path or URL to an OpenAPI 3.x spec (json/yaml)")
    parser.add_argument(
        "--target", required=True, help="Base URL of the running API, e.g. http://localhost:8000"
    )
    parser.add_argument("--auth-header", help='Full Authorization header to use, e.g. "Bearer eyJ..."')
    parser.add_argument(
        "--auth-header-b",
        help="A second identity's Authorization header, e.g. \"Bearer eyJ...\". "
        "Enables cross-user checks (BOLA) that need two distinct accounts.",
    )
    parser.add_argument(
        "--public-paths",
        help="Comma-separated glob patterns for endpoints known to be "
        'intentionally shared across users, e.g. "/products/*,/announcements/*". '
        "Suppresses BOLA findings on matching paths -- for resources that "
        "require auth but have no per-object ownership model, which the "
        "scanner can't infer on its own.",
    )
    parser.add_argument(
        "--mass-assignment-fields",
        help="Extra undeclared fields to try injecting, extending the "
        "built-in candidate list (role, is_admin, price, ...) with fields "
        "specific to your own API's domain. Two forms: inline "
        'comma-separated name=value pairs (e.g. "tier=premium,limit=9999"), '
        'or "@path/to/file" to read a longer, reusable list from a file '
        "-- either a JSON object ({\"tier\": \"premium\"}) or one name=value "
        "per line (# comments allowed). Values are parsed as bool/int/float "
        "where possible, otherwise kept as strings.",
    )
    parser.add_argument(
        "--auto-discover-fields",
        action="store_true",
        help="Automatically mine extra Mass Assignment candidate fields from "
        "the target's OWN OpenAPI spec: any property name declared ANYWHERE "
        "in the spec becomes a candidate on endpoints that don't declare it "
        "themselves -- no manual research or typing needed. Off by default, "
        "since more candidates means more test writes per endpoint.",
    )
    parser.add_argument("--json-out", help="Also write findings to this JSON file")
    args = parser.parse_args(argv)

    public_paths = args.public_paths.split(",") if args.public_paths else None
    custom_mass_assignment_fields = _parse_mass_assignment_fields(args.mass_assignment_fields or "")
    findings = scan(
        spec_path=args.spec,
        base_url=args.target,
        auth_header=args.auth_header,
        auth_header_b=args.auth_header_b,
        public_paths=public_paths,
        custom_mass_assignment_fields=custom_mass_assignment_fields,
        auto_discover_fields=args.auto_discover_fields,
    )
    print_report(findings)
    if args.json_out:
        write_json_report(findings, args.json_out)

    return 1 if any(f.severity.value in {"high", "critical"} for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
