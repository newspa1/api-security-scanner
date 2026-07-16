from __future__ import annotations

import json
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from apisec.checks.base import Finding, Severity

_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_SEVERITY_COLOR = {
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


def print_report(findings: list[Finding]) -> None:
    console = Console()
    if not findings:
        console.print("[bold green]No findings.[/bold green]")
        return

    table = Table(title="API Security Scan Results")
    table.add_column("Severity")
    table.add_column("Check")
    table.add_column("Method")
    table.add_column("Endpoint")
    table.add_column("Description")

    for f in sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity), reverse=True):
        color = _SEVERITY_COLOR[f.severity]
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f"{f.check_id} {f.title}",
            f.method,
            f.endpoint,
            f.description,
        )
    console.print(table)


def write_json_report(findings: list[Finding], path: str) -> None:
    with open(path, "w") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2, default=str)
