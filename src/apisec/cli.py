from __future__ import annotations

import argparse
import sys

from apisec.report import print_report, write_json_report
from apisec.scanner import scan


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
    parser.add_argument("--json-out", help="Also write findings to this JSON file")
    args = parser.parse_args(argv)

    findings = scan(
        spec_path=args.spec,
        base_url=args.target,
        auth_header=args.auth_header,
        auth_header_b=args.auth_header_b,
    )
    print_report(findings)
    if args.json_out:
        write_json_report(findings, args.json_out)

    return 1 if any(f.severity.value in {"high", "critical"} for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
