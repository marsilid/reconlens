"""Command-line interface."""

from __future__ import annotations

import asyncio
import json
import re
import webbrowser
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reconlens import __version__
from reconlens.email_lookup import analyze_email
from reconlens.errors import InvalidTargetError, ReconLensError
from reconlens.models import ModuleResult, ScanReport, Severity
from reconlens.modules import ALL_MODULES, get_modules
from reconlens.phone import analyze_phone
from reconlens.report import (
    write_html,
    write_json,
    write_lookup_html,
    write_lookup_json,
)
from reconlens.scanner import scan_domain
from reconlens.usernames import SITES, check_username, username_report, validate_username
from reconlens.utils import normalize_domain

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="[bold]ReconLens[/] — passive OSINT reconnaissance of a domain's attack surface.",
)
console = Console(record=True)

BANNER = r"""[bold cyan]
  ___                    _
 | _ \___ __ ___ _ _    | |   ___ _ _  ___
 |   / -_) _/ _ \ ' \   | |__/ -_) ' \(_-<
 |_|_\___\__\___/_||_|  |____\___|_||_/__/[/]  [dim]v{version} · passive OSINT recon[/]
"""

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}


class DnsChoice(str, Enum):
    auto = "auto"
    system = "system"
    doh = "doh"


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"ReconLens {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Use `reconlens COMMAND --help` for details on each command."""


def _fail(message: str, code: int = 2) -> typer.Exit:
    console.print(f"[bold red]✗[/] {message}")
    return typer.Exit(code)


def _print_module_line(result: ModuleResult) -> None:
    if result.error:
        status = f"[red]✗ {result.error}[/]"
    else:
        count = len(result.findings)
        status = f"[green]✓[/] {count} finding{'s' if count != 1 else ''}"
    console.print(f"  {result.title:<24} [dim]{result.duration:5.1f}s[/]  {status}")


def _print_summary(report: ScanReport) -> None:
    grade_style = GRADE_STYLE[report.grade]
    counts = "  ".join(
        f"[{SEVERITY_STYLE[s]}]{report.severity_counts[s.label]} {s.label}[/]"
        for s in sorted(Severity, reverse=True)
    )
    console.print()
    console.print(
        Panel(
            f"Grade [{grade_style}]{report.grade}[/]   Score [bold]{report.score}[/]/100\n{counts}",
            title=f"[bold]{report.target}[/]",
            expand=False,
            padding=(0, 2),
        )
    )

    if not report.findings:
        console.print("[green]No findings.[/]")
        return
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("Severity", no_wrap=True)
    table.add_column("Module", style="dim", no_wrap=True)
    table.add_column("Finding")
    for f in report.findings:
        table.add_row(
            Text(f.severity.label.upper(), style=SEVERITY_STYLE[f.severity]), f.module, f.title
        )
    console.print(table)


def _export_svg(path: Path | None, title: str) -> None:
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        console.save_svg(str(path), title=title)
        console.print(f"[dim]Terminal output saved to {path}[/]")


@app.command()
def domain(
    target: Annotated[str, typer.Argument(help="Domain or URL, e.g. example.com")],
    modules: Annotated[
        str | None,
        typer.Option("--modules", "-m", help="Comma-separated modules to run (default: all)."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="HTML report path (default: reports/<domain>-<time>.html)."
        ),
    ] = None,
    json_path: Annotated[
        Path | None, typer.Option("--json", help="Also save the raw results as JSON.")
    ] = None,
    no_report: Annotated[
        bool, typer.Option("--no-report", help="Do not write an HTML report.")
    ] = False,
    open_report: Annotated[
        bool,
        typer.Option("--open/--no-open", help="Open the HTML report in the browser when done."),
    ] = True,
    timeout: Annotated[
        float, typer.Option("--timeout", "-t", min=1.0, help="Network timeout in seconds.")
    ] = 10.0,
    dns_mode: Annotated[
        DnsChoice,
        typer.Option(
            "--dns",
            help="DNS backend: auto (system, falls back to DoH if filtered), system, or doh.",
        ),
    ] = DnsChoice.auto,
    fail_under: Annotated[
        str | None,
        typer.Option(
            "--fail-under",
            help="Exit with code 3 if the grade is worse than this (A–F). For CI/CD.",
        ),
    ] = None,
    export_svg: Annotated[
        Path | None,
        typer.Option("--export-svg", help="Save the terminal output as an SVG screenshot."),
    ] = None,
) -> None:
    """Scan a domain: DNS, WHOIS, subdomains, e-mail, TLS, HTTP, tech, network, ports."""
    try:
        target_domain = normalize_domain(target)
        selected = get_modules(modules.split(",") if modules else None)
        threshold = _validate_grade(fail_under)
    except ReconLensError as exc:
        raise _fail(str(exc)) from exc

    console.print(BANNER.format(version=__version__))
    console.print(
        f"Target [bold]{target_domain}[/] · modules: {', '.join(m.name for m in selected)}\n"
    )

    try:
        with console.status("Scanning…", spinner="dots"):
            report = asyncio.run(
                scan_domain(
                    target_domain,
                    selected,
                    timeout=timeout,
                    resolver_mode=dns_mode.value,
                    on_result=_print_module_line,
                )
            )
    except ReconLensError as exc:
        raise _fail(str(exc), code=1) from exc

    for note in report.notes:
        console.print(f"\n[yellow]![/] {note}")
    _print_summary(report)

    if not no_report:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        html_path = output or Path("reports") / f"{target_domain}-{stamp}.html"
        write_html(report, html_path)
        console.print(f"\n[bold]HTML report:[/] {html_path}")
        if open_report:
            webbrowser.open(html_path.resolve().as_uri())
    if json_path is not None:
        write_json(report, json_path)
        console.print(f"[bold]JSON:[/] {json_path}")
    _export_svg(export_svg, f"reconlens domain {target_domain}")

    if threshold is not None and _grade_rank(report.grade) > _grade_rank(threshold):
        console.print(
            f"\n[bold red]✗ Grade {report.grade} is worse than the required {threshold}.[/]"
        )
        raise typer.Exit(3)


GRADE_ORDER = ("A", "B", "C", "D", "F")


def _grade_rank(grade: str) -> int:
    return GRADE_ORDER.index(grade)


def _validate_grade(value: str | None) -> str | None:
    if value is None:
        return None
    grade = value.strip().upper()
    if grade not in GRADE_ORDER:
        raise InvalidTargetError(f"--fail-under must be one of A, B, C, D, F (got '{value}')")
    return grade


def _emit_lookup(
    report, out: Path | None, json_out: Path | None, open_report: bool, slug: str
) -> None:
    """Write the HTML/JSON for a lookup report and print where they went."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    html_path = out or Path("reports") / f"{report.kind}-{slug}-{stamp}.html"
    write_lookup_html(report, html_path)
    console.print(f"\n[bold]HTML report:[/] {html_path}")
    if open_report:
        webbrowser.open(html_path.resolve().as_uri())
    if json_out is not None:
        write_lookup_json(report, json_out)
        console.print(f"[bold]JSON:[/] {json_out}")


@app.command()
def username(
    name: Annotated[str, typer.Argument(help="Username to look up, e.g. torvalds")],
    timeout: Annotated[float, typer.Option("--timeout", "-t", min=1.0)] = 10.0,
    show_all: Annotated[
        bool, typer.Option("--all", "-a", help="Also list sites where it was not found.")
    ] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="HTML report path.")] = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Save results as JSON.")] = None,
    open_report: Annotated[bool, typer.Option("--open/--no-open")] = True,
    export_svg: Annotated[Path | None, typer.Option("--export-svg")] = None,
) -> None:
    """Check on which public platforms a username is registered."""
    try:
        name = validate_username(name)
    except ReconLensError as exc:
        raise _fail(str(exc)) from exc

    with console.status(f"Checking [bold]{name}[/] on {len(SITES)} platforms…", spinner="dots"):
        results = asyncio.run(check_username(name, timeout=timeout))

    styles = {"found": "bold green", "not found": "dim", "unknown": "yellow"}
    table = Table(title=f"Username: {name}", box=None, header_style="bold", padding=(0, 1))
    table.add_column("Site")
    table.add_column("Category", style="dim")
    table.add_column("Status")
    table.add_column("Profile")
    for r in sorted(results, key=lambda r: (r.status != "found", r.category, r.site.lower())):
        if r.status == "not found" and not show_all:
            continue
        status = r.status + (f" ({r.detail})" if r.detail else "")
        table.add_row(
            r.site,
            r.category,
            Text(status, style=styles[r.status]),
            r.url if r.status != "not found" else "",
        )
    console.print(table)
    found = sum(r.status == "found" for r in results)
    console.print(f"\nFound on [bold]{found}[/] of {len(results)} sites.")
    _emit_lookup(username_report(name, results), output, json_path, open_report, name)
    _export_svg(export_svg, f"reconlens username {name}")


@app.command()
def phone(
    number: Annotated[str, typer.Argument(help='Phone number, e.g. "+7 900 000 00 00"')],
    region: Annotated[
        str, typer.Option("--region", "-r", help="Default country for numbers without '+'.")
    ] = "RU",
    output: Annotated[Path | None, typer.Option("--output", "-o", help="HTML report path.")] = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Save results as JSON.")] = None,
    open_report: Annotated[bool, typer.Option("--open/--no-open")] = True,
) -> None:
    """Describe a phone number offline: country, region, carrier, line type, time zones."""
    try:
        report = analyze_phone(number, default_region=region.upper())
    except ReconLensError as exc:
        raise _fail(str(exc)) from exc

    console.print(f"\n[bold]{report.target}[/]")
    for label, value in report.summary.items():
        console.print(f"  {label + ':':<22} {value}")
    for note in report.notes:
        console.print(f"\n[yellow]![/] {note}")
    _emit_lookup(report, output, json_path, open_report, re.sub(r"\D", "", report.target))


@app.command()
def email(
    address: Annotated[str, typer.Argument(help="E-mail address, e.g. user@example.com")],
    timeout: Annotated[float, typer.Option("--timeout", "-t", min=1.0)] = 10.0,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="HTML report path.")] = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Save results as JSON.")] = None,
    open_report: Annotated[bool, typer.Option("--open/--no-open")] = True,
) -> None:
    """Describe an e-mail address's domain: deliverability, provider type, Gravatar."""
    try:
        with console.status(f"Checking [bold]{address}[/]…", spinner="dots"):
            report = asyncio.run(analyze_email(address, timeout=timeout))
    except ReconLensError as exc:
        raise _fail(str(exc)) from exc

    console.print(f"\n[bold]{report.target}[/]")
    for label, value in report.summary.items():
        console.print(f"  {label + ':':<26} {value}")
    for note in report.notes:
        console.print(f"\n[yellow]![/] {note}")
    _emit_lookup(report, output, json_path, open_report, report.target.replace("@", "_at_"))


@app.command()
def batch(
    file: Annotated[Path, typer.Argument(help="Text file with one domain per line (# = comment).")],
    modules: Annotated[str | None, typer.Option("--modules", "-m")] = None,
    out_dir: Annotated[
        Path, typer.Option("--out-dir", help="Where to write per-domain HTML reports.")
    ] = Path("reports"),
    timeout: Annotated[float, typer.Option("--timeout", "-t", min=1.0)] = 10.0,
) -> None:
    """Scan many domains from a file and print a summary table (one report each)."""
    if not file.exists():
        raise _fail(f"file not found: {file}")
    raw = [ln.strip() for ln in file.read_text(encoding="utf-8").splitlines()]
    targets = [ln for ln in raw if ln and not ln.startswith("#")]
    if not targets:
        raise _fail("no domains found in the file")

    console.print(BANNER.format(version=__version__))
    console.print(f"Batch scan of [bold]{len(targets)}[/] domains → {out_dir}\n")

    table = Table(box=None, header_style="bold", padding=(0, 2))
    table.add_column("Domain")
    table.add_column("Grade", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("C/H/M/L", justify="center", style="dim")
    table.add_column("Report", style="dim")

    async def run_one(name: str):
        selected = get_modules(modules.split(",") if modules else None)
        return await scan_domain(name, selected, timeout=timeout, resolver_mode="auto")

    for target in targets:
        try:
            normalized = normalize_domain(target)
            report = asyncio.run(run_one(normalized))
        except ReconLensError as exc:
            table.add_row(target, "[red]ERR[/]", "-", "-", str(exc)[:40])
            continue
        path = out_dir / f"{normalized}.html"
        write_html(report, path)
        counts = report.severity_counts
        table.add_row(
            normalized,
            Text(report.grade, style=GRADE_STYLE[report.grade]),
            str(report.score),
            f"{counts['critical']}/{counts['high']}/{counts['medium']}/{counts['low']}",
            str(path),
        )
    console.print(table)


@app.command()
def diff(
    old: Annotated[Path, typer.Argument(help="Earlier JSON report (from --json).")],
    new: Annotated[Path, typer.Argument(help="Later JSON report to compare against.")],
) -> None:
    """Show what changed between two JSON reports of the same target."""
    try:
        a = json.loads(old.read_text(encoding="utf-8"))
        b = json.loads(new.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _fail(f"could not read reports: {exc}") from exc

    a_titles = {f["title"] for f in a.get("findings", [])}
    b_titles = {f["title"] for f in b.get("findings", [])}
    added = sorted(b_titles - a_titles)
    resolved = sorted(a_titles - b_titles)

    console.print(
        f"\n[bold]{a.get('target', '?')}[/]: grade {a.get('grade')} → {b.get('grade')}, "
        f"score {a.get('score')} → {b.get('score')}\n"
    )
    for title in resolved:
        console.print(f"  [green]✓ resolved[/] {title}")
    for title in added:
        console.print(f"  [red]✗ new[/]      {title}")
    if not added and not resolved:
        console.print("  [dim]No change in findings.[/]")


@app.command("modules")
def list_modules() -> None:
    """List available commands and the modules used by `domain`."""
    commands = Table(
        title="Commands", box=None, header_style="bold", padding=(0, 2), title_justify="left"
    )
    commands.add_column("Command", style="cyan")
    commands.add_column("What it does")
    commands.add_row("domain <name>", "Full passive scan of a domain's attack surface")
    commands.add_row("batch <file>", "Scan many domains from a file into a summary table")
    commands.add_row("diff <old> <new>", "Compare two JSON reports of the same target")
    commands.add_row("username <name>", f"Look up a nickname on {len(SITES)} public platforms")
    commands.add_row("phone <number>", "Describe a phone number offline (country, carrier, type)")
    commands.add_row("email <address>", "Describe an e-mail's domain (deliverability, provider)")
    console.print(commands)

    table = Table(
        title="\ndomain modules",
        box=None,
        header_style="bold",
        padding=(0, 2),
        title_justify="left",
    )
    table.add_column("Name", style="cyan")
    table.add_column("Title")
    table.add_column("Checks", style="dim")
    for cls in ALL_MODULES:
        table.add_row(cls.name, cls.title, cls.description)
    console.print(table)
