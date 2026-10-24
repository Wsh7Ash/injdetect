#!/usr/bin/env python3
"""injdetect — local structural scanner for prompt-injection patterns.

Workflows:
  injdetect scan FILE...      scan files (or stdin with '-') for known shapes
  injdetect rules             list the detection rules and their taxonomy

Defensive only: matches the *structure* of injection attempts (OWASP LLM01,
LLM07; MITRE ATLAS AML.T0051/AML.T0054) so you can filter inputs/outputs or
audit documents you own. Nothing is sent anywhere; see SECURITY.md.
"""
from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.table import Table

from injdetect.patterns import PATTERNS, scan, score, worst_severity

console = Console()

EXIT_THRESHOLD = {"clean": 0, "low": 0, "medium": 1, "high": 1}


@click.group()
def main() -> None:
    """Structural prompt-injection detection (local, defensive, offline)."""


@main.command("rules")
@click.option("--json-out", is_flag=True)
def rules_cmd(json_out: bool) -> None:
    """List every detection rule with its severity and taxonomy mapping."""
    if json_out:
        click.echo(json.dumps([
            {"code": p.code, "title": p.title, "severity": p.severity,
             "taxonomy": p.taxonomy, "pattern": p.regex.pattern}
            for p in PATTERNS
        ], indent=2))
        return
    table = Table(title="injdetect rules")
    for column in ("code", "severity", "taxonomy", "title"):
        table.add_column(column)
    for p in PATTERNS:
        table.add_row(p.code, p.severity, p.taxonomy, p.title)
    console.print(table)


@main.command("scan")
@click.argument("files", nargs=-1, required=True)
@click.option("--json-out", is_flag=True, help="Emit full findings as JSON.")
@click.option("--min-severity", type=click.Choice(["low", "medium", "high"]),
              default="low", show_default=True,
              help="Hide findings below this severity.")
def scan_cmd(files: tuple[str, ...], json_out: bool, min_severity: str) -> None:
    """Scan each FILE ('-' = stdin) for structural injection patterns.

    Exit codes: 0 clean (or only below --min-severity), 1 findings at/above
    threshold, 2 usage/read error.
    """
    cutoff = {"low": 1, "medium": 2, "high": 3}[min_severity]
    reports = []
    try:
        for name in files:
            if name == "-":
                text = sys.stdin.read()
            else:
                with open(name, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            findings = [f for f in scan(text)
                        if {"high": 3, "medium": 2, "low": 1}[f["severity"]] >= cutoff]
            reports.append({
                "file": name,
                "chars": len(text),
                "findings": findings,
                "score": score(findings),
                "worst_severity": worst_severity(findings),
            })
    except OSError as exc:
        console.print(f"[red]error:[/red] {exc}")
        sys.exit(2)

    if json_out:
        click.echo(json.dumps(reports, indent=2))
    else:
        colors = {"high": "red", "medium": "yellow", "low": "cyan", "clean": "green"}
        for report in reports:
            console.print(f"[bold]{report['file']}[/bold] — "
                          f"[{colors[report['worst_severity']]}]"
                          f"{report['worst_severity']}[/] "
                          f"(score {report['score']})")
            for f in report["findings"]:
                console.print(f"  [{colors[f['severity']]}]{f['severity']:6}[/] "
                              f"{f['code']}  {f['taxonomy']}")
                console.print(f"         [dim]{f['context']}[/dim]")

    if any(EXIT_THRESHOLD[r["worst_severity"]] for r in reports):
        sys.exit(1)


if __name__ == "__main__":
    main()