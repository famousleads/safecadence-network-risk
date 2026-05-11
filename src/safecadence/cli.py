"""
SafeCadence Network Risk — command-line interface.

Examples:
    safecadence scan device.txt
    safecadence scan device.txt --vendor cisco-ios --output report.md
    safecadence scan device.txt --json report.json --save-history
    safecadence list-vendors
    safecadence list-rules --vendor cisco-ios
    safecadence rule-info cisco-ios-telnet-enabled
    safecadence ai-explain device.txt
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import click

from safecadence import __version__
from safecadence.ai import AIError, detect_provider, explain_findings
from safecadence.bulk import bulk_scan
from safecadence.core.registry import AdapterRegistry
from safecadence.core.schema import Asset, ScanResult, Severity
from safecadence.core.store import HistoryStore
from safecadence.dashboard import build_dashboard_data, load_scan_dir, render_dashboard
from safecadence.discovery import discover_subnet
from safecadence.enrichment import eol_status, find_cves
from safecadence.topology import (
    parse_lldp_text, render_dot, render_html, render_mermaid, render_text,
)
from safecadence.engines.config_audit import ConfigAuditEngine, load_rules
from safecadence.engines.health import compute_health, health_band
from safecadence.engines.risk import compute_risk, risk_band, summarize
from safecadence.reports.docx import to_docx
from safecadence.reports.html import to_html
from safecadence.reports.json import to_json
from safecadence.reports.markdown import to_markdown
from safecadence.reports.pdf import to_pdf


# --------------------------------------------------------------------------- #
# Pretty printing (rich) — degrades gracefully if rich isn't available.        #
# --------------------------------------------------------------------------- #
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    _CONSOLE = Console()

    def _print(*args, **kwargs):
        _CONSOLE.print(*args, **kwargs)

    def _has_rich() -> bool:
        return True
except ImportError:   # pragma: no cover
    _CONSOLE = None

    def _print(msg=""):
        click.echo(msg if isinstance(msg, str) else str(msg))

    def _has_rich() -> bool:
        return False


_SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "white",
}


# --------------------------------------------------------------------------- #
# Commands                                                                    #
# --------------------------------------------------------------------------- #
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="safecadence")
def cli():
    """SafeCadence Network Risk — open-source network audit tool."""


@cli.command("scan")
@click.argument("source", type=click.Path(exists=True, readable=True))
@click.option("--vendor", default=None, help="Force a vendor adapter (e.g. cisco-ios).")
@click.option("--dir", "as_dir", is_flag=True,
              help="Treat SOURCE as a directory of configs and bulk-scan in parallel.")
@click.option("--workers", "-w", default=8, show_default=True,
              help="Parallel workers for --dir bulk mode.")
@click.option("--out-dir", type=click.Path(file_okay=False), default=None,
              help="Output directory for per-device JSON/Markdown reports in --dir mode.")
@click.option("--output", "-o", type=click.Path(dir_okay=False), default=None,
              help="Write the Markdown report to this file.")
@click.option("--json", "json_path", type=click.Path(dir_okay=False), default=None,
              help="Write the machine-readable JSON report to this file.")
@click.option("--html", "html_path", type=click.Path(dir_okay=False), default=None,
              help="Write a polished single-file HTML report.")
@click.option("--docx", "docx_path", type=click.Path(dir_okay=False), default=None,
              help="Write a Word .docx report (consultant-style).")
@click.option("--pdf", "pdf_path", type=click.Path(dir_okay=False), default=None,
              help="Write a paginated PDF report (pure stdlib, no deps).")
@click.option("--quiet", "-q", is_flag=True, help="Don't print the live summary.")
@click.option("--criticality", type=click.Choice(["low", "medium", "high", "critical"]),
              default="medium", show_default=True,
              help="Business criticality of the device (affects risk weighting).")
@click.option("--save-history", is_flag=True,
              help="Append the scan to local SQLite history.")
def scan(source, vendor, as_dir, workers, out_dir, output, json_path, html_path, docx_path,
         pdf_path, quiet, criticality, save_history):
    """Scan a config file (or a whole directory in --dir mode) and produce scored reports."""
    if as_dir:
        _bulk_scan(source, workers=workers, out_dir=out_dir, vendor=vendor,
                   criticality=criticality, save_history=save_history, quiet=quiet)
        return

    started = time.perf_counter()
    text = Path(source).read_text(encoding="utf-8", errors="replace")

    if vendor:
        adapter = AdapterRegistry.get(vendor)
        if adapter is None:
            click.echo(f"Unknown vendor: {vendor!r}. Try `safecadence list-vendors`.",
                       err=True)
            sys.exit(2)
    else:
        adapter = AdapterRegistry.detect(text, filename=str(source))
        if adapter is None:
            click.echo("Could not auto-detect vendor. Pass --vendor.", err=True)
            sys.exit(2)

    parsed = adapter.parse_config(text)
    findings = ConfigAuditEngine(vendor=adapter.slug).run(parsed)
    health = compute_health(parsed, findings)
    risk = compute_risk(findings, business_criticality=criticality)
    summary = summarize(findings)

    asset = Asset(
        asset_id=parsed.hostname or Path(source).stem,
        hostname=parsed.hostname,
        vendor=adapter.slug,
        model=parsed.model,
        os=parsed.os,
        version=parsed.version,
        device_type=parsed.device_type,
        business_criticality=criticality,
        interfaces=parsed.interfaces,
        neighbors=parsed.neighbors,
        health_score=health,
        risk_score=risk,
        health_band=health_band(health),
        risk_band=risk_band(risk),
        findings=findings,
    )

    duration_ms = int((time.perf_counter() - started) * 1000)

    # Enrichment: CVEs + EOL (always-on, 100% local from bundled data)
    cves_matched = find_cves(vendor=adapter.slug, os=parsed.os, version=parsed.version)
    eol_rec = eol_status(vendor=adapter.slug, os=parsed.os, version=parsed.version)
    eol_dict = None
    if eol_rec is not None:
        eol_dict = eol_rec.to_dict()
        eol_dict["status_today"] = eol_rec.status_today()

    result = ScanResult(
        source=str(source),
        vendor=adapter.slug,
        duration_ms=duration_ms,
        parsed=parsed,
        asset=asset,
        findings=findings,
        health_score=health,
        risk_score=risk,
        health_band=health_band(health),
        risk_band=risk_band(risk),
        summary=summary,
        cves=[c.to_dict() for c in cves_matched],
        eol=eol_dict,
    )

    if not quiet:
        _print_summary(result)

    if output:
        Path(output).write_text(to_markdown(result), encoding="utf-8")
        _print(f"[green]Markdown report:[/green] {output}" if _has_rich() else f"Markdown report: {output}")

    if json_path:
        Path(json_path).write_text(to_json(result), encoding="utf-8")
        _print(f"[green]JSON report:[/green] {json_path}" if _has_rich() else f"JSON report: {json_path}")

    if html_path:
        Path(html_path).write_text(to_html(result), encoding="utf-8")
        _print(f"[green]HTML report:[/green] {html_path}" if _has_rich() else f"HTML report: {html_path}")

    if docx_path:
        to_docx(result, docx_path)
        _print(f"[green]DOCX report:[/green] {docx_path}" if _has_rich() else f"DOCX report: {docx_path}")

    if pdf_path:
        to_pdf(result, pdf_path)
        _print(f"[green]PDF report:[/green] {pdf_path}" if _has_rich() else f"PDF report: {pdf_path}")

    if save_history:
        store = HistoryStore()
        sid = store.save(result)
        store.close()
        _print(f"Saved to local history (id #{sid}).")


def _bulk_scan(source, *, workers, out_dir, vendor, criticality, save_history, quiet):
    """Run a bulk scan over a directory of configs in parallel."""
    src = Path(source)
    if not src.is_dir():
        click.echo(f"--dir given but {source} is not a directory.", err=True)
        sys.exit(2)
    out_dir = out_dir or str(src.parent / (src.name + ".scans"))

    if _has_rich():
        from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                                   TimeElapsedColumn, MofNCompleteColumn)
        with Progress(
            SpinnerColumn(), TextColumn("[bold]{task.description}"),
            BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
            console=_CONSOLE, transient=False,
        ) as prog:
            task = prog.add_task(f"Scanning {source}", total=None)
            def cb(done, total, summary):
                prog.update(task, total=total, completed=done,
                            description=f"{summary.hostname or '?'}  ({summary.vendor})")
            results = bulk_scan(
                src, workers=workers, out_dir=out_dir, vendor=vendor,
                criticality=criticality, save_history=save_history, progress_cb=cb,
            )
    else:
        results = bulk_scan(
            src, workers=workers, out_dir=out_dir, vendor=vendor,
            criticality=criticality, save_history=save_history,
        )

    if not results:
        click.echo("No config files found.", err=True)
        sys.exit(2)

    crit = sum(1 for r in results if r.risk >= 81)
    high = sum(1 for r in results if 61 <= r.risk < 81)
    err  = sum(1 for r in results if r.error)

    if not quiet and _has_rich():
        t = Table(title=f"Bulk scan summary — {len(results)} device(s)")
        t.add_column("Hostname", style="bold cyan")
        t.add_column("Vendor")
        t.add_column("Health", justify="right")
        t.add_column("Risk", justify="right")
        t.add_column("Findings", justify="right")
        t.add_column("CVEs", justify="right")
        t.add_column("EOL")
        t.add_column("ms", justify="right")
        for r in results[:20]:
            risk_color = "red" if r.risk >= 81 else "yellow" if r.risk >= 61 else "green"
            t.add_row(
                r.hostname or Path(r.source).stem, r.vendor,
                str(r.health), f"[{risk_color}]{r.risk}[/]",
                str(r.findings), str(r.cves),
                r.eol_status, str(r.duration_ms),
            )
        _CONSOLE.print(t)
        if len(results) > 20:
            _CONSOLE.print(f"[dim]…and {len(results)-20} more (full list in {out_dir}).[/dim]")
        _CONSOLE.print(
            f"\n[bold]Done.[/bold]  "
            f"[red]{crit} critical[/red] · [yellow]{high} high[/yellow] · "
            f"[dim]{err} errored[/dim]\n"
            f"Per-device JSON + Markdown written to: [green]{out_dir}[/green]\n"
            f"Build a fleet dashboard:   [cyan]safecadence dashboard --scans {out_dir}[/cyan]"
        )
    elif not quiet:
        click.echo(f"Scanned {len(results)} device(s). {crit} critical, {high} high, {err} errors.")
        click.echo(f"Output: {out_dir}")


@cli.command("list-vendors")
def list_vendors():
    """List every adapter registered in this build."""
    adapters = AdapterRegistry.all()
    if not adapters:
        click.echo("No adapters registered.")
        return
    if _has_rich():
        t = Table(title="Available adapters", show_lines=False)
        t.add_column("Slug", style="bold cyan")
        t.add_column("Label")
        t.add_column("OS family")
        t.add_column("SSH")
        for a in sorted(adapters, key=lambda x: x.slug):
            t.add_row(a.slug, a.label, ", ".join(a.os_family or []),
                      "yes" if a.supports_ssh() else "no")
        _CONSOLE.print(t)
    else:
        for a in sorted(adapters, key=lambda x: x.slug):
            click.echo(f"{a.slug:20s}  {a.label}")


@cli.command("migrate")
@click.option("--from", "src_kind", type=click.Choice(["sqlite"]), default="sqlite",
              show_default=True, help="Source backend (only sqlite supported for now).")
@click.option("--to", "dst_kind", type=click.Choice(["postgres"]), default="postgres",
              show_default=True, help="Destination backend.")
@click.option("--sqlite-path", default=None,
              help="Source SQLite path. Defaults to the platform default.")
@click.option("--postgres-url", default=None,
              help="Destination Postgres URL. Defaults to $SC_POSTGRES_URL.")
@click.option("--batch", default=500, show_default=True,
              help="Rows per INSERT batch.")
def cmd_migrate(src_kind, dst_kind, sqlite_path, postgres_url, batch):
    """Copy scan history from SQLite to Postgres in batches.

    Example::

        SC_POSTGRES_URL=postgresql://safe:pw@127.0.0.1:5432/safecadence \\
        safecadence migrate --from sqlite --to postgres
    """
    import os as _os
    from pathlib import Path as _P
    from safecadence.storage.sqlite_store import SqliteStore
    from safecadence.storage.postgres_store import PostgresStore

    src = SqliteStore(_P(sqlite_path) if sqlite_path else None)
    pg_url = postgres_url or _os.environ.get("SC_POSTGRES_URL")
    if not pg_url:
        raise click.ClickException(
            "No Postgres URL — pass --postgres-url or set SC_POSTGRES_URL."
        )
    dst = PostgresStore(pg_url)

    # Stream rows from SQLite in batches so we don't load the entire
    # table into memory.
    cur = src._conn.execute(
        "SELECT tenant_id, started_at, source, vendor, hostname, ip, site, "
        "health, risk, risk_band, eol_status, cves, findings, summary, payload "
        "FROM scans ORDER BY id ASC"
    )
    total = 0
    while True:
        rows = cur.fetchmany(batch)
        if not rows:
            break
        tuples = [tuple(r) for r in rows]
        with dst._conn.cursor() as pgcur:  # type: ignore[attr-defined]
            pgcur.executemany(
                "INSERT INTO scans (tenant_id, started_at, source, vendor, hostname, ip, site,"
                " health, risk, risk_band, eol_status, cves, findings, summary, payload) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                tuples,
            )
        total += len(rows)
        click.echo(f"  migrated {total} rows")
    click.echo(f"Done. {total} rows migrated to Postgres.")
    src.close()
    dst.close()


@cli.command("list-rules")
@click.option("--vendor", default=None, help="Filter to one vendor (e.g. cisco-ios).")
def list_rules(vendor):
    """List every audit rule, optionally filtered by vendor."""
    rules = load_rules(vendor=vendor)
    if not rules:
        click.echo("No rules loaded.")
        return
    if _has_rich():
        t = Table(title=f"Rules ({len(rules)})")
        t.add_column("ID", style="cyan")
        t.add_column("Sev")
        t.add_column("Vendor")
        t.add_column("Domain")
        t.add_column("Title")
        for r in rules:
            t.add_row(r.id,
                      f"[{_SEV_COLOR[r.severity]}]{r.severity.value}[/]",
                      r.vendor, r.domain, r.title)
        _CONSOLE.print(t)
    else:
        for r in rules:
            click.echo(f"{r.id:40s} {r.severity.value:8s} {r.vendor:12s} {r.title}")


@cli.command("rule-info")
@click.argument("rule_id")
def rule_info(rule_id):
    """Show full detail for one rule."""
    for r in load_rules():
        if r.id == rule_id:
            click.echo(f"# {r.title}")
            click.echo(f"id:        {r.id}")
            click.echo(f"severity:  {r.severity.value}")
            click.echo(f"vendor:    {r.vendor}")
            click.echo(f"domain:    {r.domain}")
            click.echo()
            if r.description:
                click.echo("Description:")
                click.echo(f"  {r.description}")
            if r.remediation:
                click.echo()
                click.echo("Remediation:")
                click.echo(f"  {r.remediation}")
            if r.fix_snippet:
                click.echo()
                click.echo("Fix snippet:")
                for line in r.fix_snippet.splitlines():
                    click.echo(f"  {line}")
            if r.references:
                click.echo()
                click.echo("References:")
                for ref in r.references:
                    click.echo(f"  - {ref}")
            return
    click.echo(f"Rule {rule_id!r} not found.", err=True)
    sys.exit(2)


@cli.command("ai-explain")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--vendor", default=None)
@click.option("--provider", type=click.Choice(["openai", "anthropic", "ollama", "auto", "none"]),
              default="auto", show_default=True,
              help="ollama = local LLM (set OLLAMA_HOST or use default 127.0.0.1:11434).")
@click.option("--model", default=None, help="Override the default model name.")
@click.option("--api-key", default=None, help="API key (else read from env).")
@click.option("--output", "-o", type=click.Path(dir_okay=False), default=None,
              help="Write the briefing to this Markdown file (in addition to printing).")
def ai_explain(source, vendor, provider, model, api_key, output):
    """Run a scan, then ask your BYO LLM for an executive remediation plan."""
    text = Path(source).read_text(encoding="utf-8", errors="replace")
    if vendor:
        adapter = AdapterRegistry.get(vendor)
    else:
        adapter = AdapterRegistry.detect(text, filename=str(source))
    if adapter is None:
        click.echo("Could not pick an adapter; pass --vendor.", err=True)
        sys.exit(2)

    parsed = adapter.parse_config(text)
    findings = ConfigAuditEngine(vendor=adapter.slug).run(parsed)
    health = compute_health(parsed, findings)
    risk = compute_risk(findings)
    asset = Asset(asset_id=parsed.hostname or Path(source).stem,
                  hostname=parsed.hostname, vendor=adapter.slug,
                  model=parsed.model, os=parsed.os, version=parsed.version,
                  device_type=parsed.device_type, findings=findings,
                  health_score=health, risk_score=risk,
                  health_band=health_band(health), risk_band=risk_band(risk))
    result = ScanResult(source=str(source), vendor=adapter.slug, duration_ms=0,
                        parsed=parsed, asset=asset, findings=findings,
                        health_score=health, risk_score=risk,
                        health_band=health_band(health), risk_band=risk_band(risk),
                        summary=summarize(findings))

    prov = None if provider == "auto" else provider
    try:
        out = explain_findings(result, provider=prov, api_key=api_key, model=model)
    except AIError as exc:
        click.echo(str(exc), err=True)
        sys.exit(2)

    if output:
        Path(output).write_text(out, encoding="utf-8")
        if _has_rich():
            _CONSOLE.print(f"[green]Saved AI briefing to:[/green] {output}")
        else:
            click.echo(f"Saved AI briefing to: {output}")

    if _has_rich():
        _CONSOLE.print(Panel(out, title="AI remediation briefing",
                             border_style="cyan", expand=True))
    else:
        click.echo(out)


@cli.command("discover")
@click.argument("cidr")
@click.option("--workers", "-w", default=64, show_default=True,
              help="Number of concurrent TCP probe workers.")
@click.option("--timeout", "-t", default=0.6, show_default=True,
              help="TCP connect timeout in seconds.")
@click.option("--extended", "-x", is_flag=True,
              help="Probe extended port set (slower, deeper).")
@click.option("--no-banner", is_flag=True,
              help="Skip banner-grabbing (faster, less info).")
@click.option("--no-dns", is_flag=True,
              help="Skip reverse DNS lookups.")
@click.option("--json", "json_path", type=click.Path(dir_okay=False), default=None,
              help="Write the discovery result to a JSON file.")
@click.option("--nmap", is_flag=True,
              help="Use nmap (if installed) instead of TCP-only sweep — gets richer service info.")
def discover(cidr, workers, timeout, extended, no_banner, no_dns, json_path, nmap):
    """Discover every device on a subnet (e.g. safecadence discover 10.10.10.0/24)."""
    import json as _json
    if nmap:
        from safecadence.discovery.nmap_scan import nmap_available, nmap_scan
        from safecadence.discovery.asset import DiscoveryResult
        from datetime import datetime as _dt, timezone as _tz
        if not nmap_available():
            click.echo("nmap not found on PATH. Install with: brew install nmap "
                       "(or apt install nmap). Falling back to TCP-only sweep...", err=True)
            nmap = False
        else:
            t0 = time.perf_counter()
            hosts = nmap_scan(cidr)
            duration_ms = int((time.perf_counter() - t0) * 1000)
            result = DiscoveryResult(
                subnet=cidr,
                started_at=_dt.now(_tz.utc).isoformat(),
                finished_at=_dt.now(_tz.utc).isoformat(),
                duration_ms=duration_ms,
                hosts_scanned=len(hosts) or 0,
                hosts_responding=len(hosts),
                hosts=hosts,
            )
    if not nmap:
        if _has_rich():
            with _CONSOLE.status(f"[cyan]Sweeping {cidr} with {workers} workers...[/cyan]"):
                result = discover_subnet(
                    cidr, workers=workers, timeout=timeout, extended=extended,
                    grab_banner=not no_banner, reverse_dns=not no_dns,
                )
        else:
            click.echo(f"Sweeping {cidr}...")
            result = discover_subnet(
                cidr, workers=workers, timeout=timeout, extended=extended,
                grab_banner=not no_banner, reverse_dns=not no_dns,
            )

    if json_path:
        Path(json_path).write_text(_json.dumps(result.to_dict(), indent=2), encoding="utf-8")

    if not _has_rich():
        click.echo(f"Scanned {result.hosts_scanned}, responding {result.hosts_responding}, in {result.duration_ms}ms")
        for h in result.hosts:
            click.echo(f"  {h.ip:15s} {h.vendor_guess or '?':18s} {h.os_guess or '?':10s} {h.device_type_guess or '?':10s} ports={h.open_ports}")
        if json_path:
            click.echo(f"JSON: {json_path}")
        return

    _CONSOLE.print(Panel.fit(
        f"[bold]{result.subnet}[/bold]   "
        f"scanned=[cyan]{result.hosts_scanned}[/cyan]   "
        f"responding=[bold green]{result.hosts_responding}[/bold green]   "
        f"duration=[cyan]{result.duration_ms}ms[/cyan]",
        title="Discovery", border_style="cyan"
    ))
    if not result.hosts:
        _CONSOLE.print("[yellow]No hosts responded.[/yellow]")
        return

    t = Table(show_header=True, header_style="bold")
    t.add_column("IP", style="bold cyan", no_wrap=True)
    t.add_column("Hostname")
    t.add_column("MAC", no_wrap=True)
    t.add_column("Vendor")
    t.add_column("OS")
    t.add_column("Type")
    t.add_column("Open ports", style="dim")
    for h in result.hosts:
        t.add_row(
            h.ip, h.hostname or "—", h.mac or "—",
            h.vendor_guess or "[dim]unknown[/dim]",
            h.os_guess or "[dim]?[/dim]",
            h.device_type_guess or "[dim]?[/dim]",
            ",".join(str(p) for p in h.open_ports),
        )
    _CONSOLE.print(t)
    if json_path:
        _CONSOLE.print(f"[green]JSON:[/green] {json_path}")
    _CONSOLE.print(
        "[dim]Tip: pull configs from network gear and pipe to "
        "[cyan]safecadence scan[/cyan] for a full audit.[/dim]"
    )


@cli.command("topology")
@click.argument("input_file", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--device", default="LOCAL", show_default=True,
              help="Name to use for the device whose LLDP output you're parsing.")
@click.option("--format", "fmt",
              type=click.Choice(["text", "mermaid", "dot", "html", "json"]),
              default="text", show_default=True)
@click.option("--output", "-o", type=click.Path(dir_okay=False), default=None,
              help="Write rendered output to this file (default: stdout).")
@click.option("--scans", "scans_dir", type=click.Path(exists=True, file_okay=False, readable=True),
              default=None,
              help="Directory of scan-result JSON files; matched to nodes by hostname/IP "
                   "and exposed in the HTML double-click panel (with running config).")
def topology(input_file, device, fmt, output, scans_dir):
    """Build a topology graph from LLDP / CDP neighbor output.

    Paste the output of `show lldp neighbors detail` (Cisco IOS / NX-OS,
    Aruba CX uses `show lldp neighbor-info detail`, Arista uses the same
    Cisco syntax) into a file and run:

        safecadence topology lldp.txt --format html -o map.html

    Pair with --scans to attach full per-device scan results (running config,
    findings, CVEs, EOL) to each node — surfaced on double-click in HTML mode.
    """
    import json as _json
    text = Path(input_file).read_text(encoding="utf-8", errors="replace")
    topo = parse_lldp_text(text, local_device=device)

    # Optional: attach per-device scan results
    if scans_dir:
        attached = 0
        for f in Path(scans_dir).iterdir():
            if f.suffix.lower() != ".json" or not f.is_file():
                continue
            try:
                d = _json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if topo.attach_scan_result(d):
                attached += 1
        if _has_rich():
            _CONSOLE.print(f"[dim]Attached {attached} scan result(s) from {scans_dir}[/dim]")
        else:
            click.echo(f"Attached {attached} scan result(s) from {scans_dir}")

    if fmt == "text":
        out = render_text(topo)
    elif fmt == "mermaid":
        out = render_mermaid(topo)
    elif fmt == "dot":
        out = render_dot(topo)
    elif fmt == "html":
        out = render_html(topo, title=f"Topology — {device}")
    else:  # json
        out = _json.dumps(topo.to_dict(), indent=2)

    if output:
        Path(output).write_text(out, encoding="utf-8")
        if _has_rich():
            _CONSOLE.print(f"[green]Wrote {fmt} to:[/green] {output}")
        else:
            click.echo(f"Wrote {fmt} to: {output}")
    else:
        click.echo(out)

    if _has_rich() and not output:
        _CONSOLE.print(
            f"\n[dim]{len(topo.nodes)} nodes · {len(topo.edges)} links discovered. "
            f"Try --format html -o map.html for an interactive view.[/dim]"
        )


@cli.command("dashboard")
@click.option("--scans", "scans_dir", type=click.Path(exists=True, file_okay=False),
              required=True,
              help="Directory of scan-result JSON files (each from `safecadence scan --json`).")
@click.option("--topology", "topology_file", type=click.Path(exists=True, dir_okay=False),
              default=None,
              help="Optional LLDP-output text file to embed as an interactive topology graph.")
@click.option("--device", default="LOCAL", show_default=True,
              help="Local device name when parsing the LLDP file.")
@click.option("--output", "-o", type=click.Path(dir_okay=False),
              default="dashboard.html", show_default=True,
              help="Output HTML file path.")
@click.option("--title", default="SafeCadence Fleet Dashboard", show_default=True)
def dashboard(scans_dir, topology_file, device, output, title):
    """Build a single-file HTML fleet dashboard from a directory of scan results.

    Example:
        safecadence dashboard --scans ./scans/ --topology lldp.txt -o dashboard.html
    """
    scans = load_scan_dir(scans_dir)
    if not scans:
        click.echo(f"No scan-result JSON files found under {scans_dir}.", err=True)
        sys.exit(2)

    topo_dict = None
    if topology_file:
        topo_text = Path(topology_file).read_text(encoding="utf-8", errors="replace")
        topo = parse_lldp_text(topo_text, local_device=device)
        # Attach scans to topo nodes too (for the embedded topology drill-down)
        for s in scans:
            topo.attach_scan_result(s)
        topo_dict = topo.to_dict()

    data = build_dashboard_data(scans, topology=topo_dict)
    html = render_dashboard(data, title=title)
    Path(output).write_text(html, encoding="utf-8")

    if _has_rich():
        _CONSOLE.print(Panel.fit(
            f"[bold]Fleet dashboard generated[/bold]\n"
            f"Devices:        [cyan]{data.overview['device_count']}[/cyan]\n"
            f"Avg risk:       [bold red]{data.overview['avg_risk']}[/bold red] / 100\n"
            f"Critical risk:  [bold red]{data.overview['critical_devices']}[/bold red] device(s)\n"
            f"KEV exposed:    [bold red]{data.overview['kev_devices']}[/bold red] device(s)\n"
            f"End-of-support: [bold yellow]{data.overview['eol_devices']}[/bold yellow] device(s)\n"
            f"Unique CVEs:    [cyan]{len(data.cves_by_id)}[/cyan]\n\n"
            f"Wrote: [green]{output}[/green]   ({Path(output).stat().st_size:,} bytes)\n"
            f"[dim]Open in browser: open {output}[/dim]",
            title="dashboard", border_style="cyan"
        ))
    else:
        click.echo(f"Wrote dashboard: {output}")
        click.echo(f"Devices: {data.overview['device_count']}")
        click.echo(f"Avg risk: {data.overview['avg_risk']}/100")


@cli.command("history")
@click.option("--limit", default=20, show_default=True)
def history(limit):
    """Show recent saved scans (only populated when --save-history was used)."""
    store = HistoryStore()
    rows = store.list(limit=limit)
    store.close()
    if not rows:
        click.echo("No saved history. Run a scan with --save-history first.")
        return
    if _has_rich():
        t = Table(title=f"Last {len(rows)} scans")
        for col in ("id", "started_at", "vendor", "hostname", "health", "risk", "findings", "source"):
            t.add_column(col)
        for r in rows:
            t.add_row(str(r["id"]), r["started_at"], r["vendor"], r["hostname"] or "—",
                      str(r["health"]), str(r["risk"]), str(r["findings"]), r["source"])
        _CONSOLE.print(t)
    else:
        for r in rows:
            click.echo(json.dumps(r))


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _print_summary(result: ScanResult) -> None:
    if not _has_rich():
        click.echo(f"Hostname: {result.parsed.hostname or '—'}")
        click.echo(f"Vendor:   {result.vendor}")
        click.echo(f"OS:       {result.parsed.os} {result.parsed.version}")
        click.echo(f"Health:   {result.health_score}/100 ({result.health_band})")
        click.echo(f"Risk:     {result.risk_score}/100 ({result.risk_band})")
        click.echo(f"Summary:  {result.summary}")
        click.echo(f"Findings: {len(result.findings)}")
        for f in result.findings[:10]:
            click.echo(f"  [{f.severity.value.upper():8s}] {f.title}")
        if len(result.findings) > 10:
            click.echo(f"  ...and {len(result.findings) - 10} more.")
        return

    p = result.parsed
    header = Text()
    header.append("SafeCadence Scan ", style="bold")
    header.append(f"v{__version__}", style="dim")

    enrich_lines = []
    if result.cves:
        kev_n = sum(1 for c in result.cves if c.get("kev"))
        crit_n = sum(1 for c in result.cves if c.get("severity") == "critical")
        kev_str = f" · [bold red]{kev_n} KEV[/bold red]" if kev_n else ""
        enrich_lines.append(
            f"CVEs: [bold red]{len(result.cves)}[/bold red] matched "
            f"({crit_n} critical{kev_str})"
        )
    if result.eol:
        st = result.eol.get("status_today", "")
        color = "red" if "end-of-support" in st else ("yellow" if "end-of-software" in st else "green")
        enrich_lines.append(
            f"EOL: [bold {color}]{st}[/bold {color}]   "
            f"end-of-software={result.eol.get('end_of_software', '—')}   "
            f"end-of-support={result.eol.get('end_of_support', '—')}"
        )
    enrich_block = "\n" + "\n".join(enrich_lines) if enrich_lines else ""

    _CONSOLE.print(Panel.fit(
        f"[bold]{p.hostname or result.source}[/bold]   "
        f"vendor=[cyan]{result.vendor}[/cyan]   os=[cyan]{p.os}[/cyan]   "
        f"version=[cyan]{p.version or '—'}[/cyan]   model=[cyan]{p.model or '—'}[/cyan]\n"
        f"health=[bold green]{result.health_score}[/bold green]/100 "
        f"([italic]{result.health_band}[/italic])    "
        f"risk=[bold red]{result.risk_score}[/bold red]/100 "
        f"([italic]{result.risk_band}[/italic])\n"
        f"summary: {result.summary}"
        f"{enrich_block}",
        title=header, border_style="cyan"
    ))
    if not result.findings:
        _CONSOLE.print("[green]No findings — clean device or no rules matched.[/green]")
        return

    t = Table(show_header=True, header_style="bold", show_lines=False)
    t.add_column("Severity", no_wrap=True)
    t.add_column("Rule")
    t.add_column("Title")
    for f in result.findings:
        t.add_row(
            f"[{_SEV_COLOR[f.severity]}]{f.severity.value.upper()}[/]",
            f.rule_id, f.title,
        )
    _CONSOLE.print(t)
    detected = detect_provider().value
    _CONSOLE.print(
        f"[dim]AI provider auto-detected: [bold]{detected}[/bold] — "
        f"run [cyan]safecadence ai-explain {result.source}[/cyan] for a plan.[/dim]"
    )


@cli.command("collect")
@click.argument("inventory", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--out-dir", type=click.Path(file_okay=False), default="collected",
              show_default=True)
@click.option("--workers", "-w", default=8, show_default=True)
@click.option("--timeout", "-t", default=30, show_default=True)
def collect_cmd(inventory, out_dir, workers, timeout):
    """SSH-collect running configs from every device in INVENTORY (YAML)."""
    from safecadence.collect import collect_all, load_inventory
    devices = load_inventory(inventory)

    def cb(done, total, r):
        status = "OK" if not r.error else "FAIL"
        if _has_rich():
            _CONSOLE.print(f"  [{done}/{total}] {r.name or r.host:30s} {status} {r.error or f'{r.bytes_received}b'}")
        else:
            click.echo(f"[{done}/{total}] {r.name or r.host} {status} {r.error or f'{r.bytes_received}b'}")
    results = collect_all(devices, out_dir=out_dir, workers=workers, timeout=timeout,
                          progress_cb=cb)
    ok = sum(1 for r in results if not r.error and r.bytes_received > 0)
    click.echo(f"\nCollected {ok}/{len(results)} configs into {out_dir}/")
    click.echo(f"Run:  safecadence scan {out_dir} --dir --out-dir {out_dir}.scans")


@cli.command("watch-file")
@click.argument("source", type=click.Path(exists=True))
@click.option("--interval", default=3600, show_default=True,
              help="Re-scan interval in seconds (default: hourly).")
@click.option("--out-dir", type=click.Path(file_okay=False), default=None)
@click.option("--workers", "-w", default=8, show_default=True)
@click.option("--once", is_flag=True, help="Run a single iteration and exit (for cron use).")
def watch_file_cmd(source, interval, out_dir, workers, once):
    """Re-scan SOURCE config file on an interval, diffing against the last run.
    For network discovery monitoring use `safecadence watch <cidr>` instead."""
    import json as _json
    src = Path(source)
    state_dir = Path(out_dir) if out_dir else src.parent / (src.name + ".watch")
    state_dir.mkdir(parents=True, exist_ok=True)
    last_path = state_dir / "last.json"

    def one_pass():
        from safecadence.bulk import bulk_scan
        results = bulk_scan(src if src.is_dir() else src.parent,
                            workers=workers, out_dir=str(state_dir / "scans"))
        snapshot = {r.hostname or Path(r.source).stem: {
            "risk": r.risk, "health": r.health, "findings": r.findings,
            "cves": r.cves, "eol": r.eol_status,
        } for r in results}
        prev = {}
        if last_path.exists():
            try:
                prev = _json.loads(last_path.read_text())
            except Exception:
                prev = {}
        diffs = []
        for name, cur in snapshot.items():
            old = prev.get(name)
            if old is None:
                diffs.append(f"  + NEW   {name}  risk={cur['risk']}")
                continue
            if cur["risk"] != old.get("risk") or cur["findings"] != old.get("findings"):
                diffs.append(
                    f"  ~ CHG   {name}  "
                    f"risk {old.get('risk')} → {cur['risk']}   "
                    f"findings {old.get('findings')} → {cur['findings']}"
                )
        for name in prev:
            if name not in snapshot:
                diffs.append(f"  - GONE  {name}")
        last_path.write_text(_json.dumps(snapshot, indent=2))
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        click.echo(f"[{ts}] {len(results)} device(s) scanned · {len(diffs)} change(s):")
        for d in diffs[:30]:
            click.echo(d)

    one_pass()
    if once:
        return
    while True:
        time.sleep(interval)
        one_pass()


@cli.command("serve")
@click.option("--scans", "scans_dir", type=click.Path(exists=True, file_okay=False),
              required=True)
@click.option("--port", default=8765, show_default=True)
@click.option("--bind", default="127.0.0.1", show_default=True,
              help="Bind address. Defaults to localhost only for safety.")
@click.option("--topology", "topology_file", type=click.Path(exists=True, dir_okay=False),
              default=None)
def serve_cmd(scans_dir, port, bind, topology_file):
    """Serve the fleet dashboard over a local HTTP server (live regenerates on each request)."""
    import http.server
    import socketserver

    from safecadence.dashboard import build_dashboard_data, load_scan_dir, render_dashboard
    from safecadence.topology import parse_lldp_text

    def render_live() -> bytes:
        scans = load_scan_dir(scans_dir)
        topo = None
        if topology_file:
            t = parse_lldp_text(Path(topology_file).read_text(encoding="utf-8"),
                                local_device="LOCAL")
            for s in scans:
                t.attach_scan_result(s)
            topo = t.to_dict()
        data = build_dashboard_data(scans, topology=topo)
        return render_dashboard(data).encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw):    # quiet by default
            pass
        def do_GET(self):
            try:
                body = render_live()
            except Exception as exc:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Render error: {exc}".encode())
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    with socketserver.ThreadingTCPServer((bind, port), Handler) as httpd:
        httpd.allow_reuse_address = True
        url = f"http://{bind}:{port}/"
        click.echo(f"SafeCadence dashboard live at {url}")
        click.echo(f"  scans:    {scans_dir}")
        if topology_file:
            click.echo(f"  topology: {topology_file}")
        click.echo("Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            click.echo("\nStopped.")


@cli.command("enrich")
@click.option("--refresh", is_flag=True,
              help="Refresh KEV + EOL feeds. Combine with --online (or --kev-file).")
@click.option("--online", is_flag=True,
              help="Fetch from public sources (CISA KEV + endoflife.date).")
@click.option("--kev-file", default=None,
              help="Path to a downloaded CISA KEV JSON (for air-gapped sites).")
@click.option("--show-stats", is_flag=True, help="Print bundled CVE / EOL DB stats.")
def enrich_cmd(refresh, online, kev_file, show_stats):
    """Inspect or refresh the bundled CVE + EOL datasets."""
    from safecadence.enrichment import load_cve_db, load_eol_db, refresh_eol, refresh_kev
    if refresh:
        try:
            kev_result = refresh_kev(online=online, kev_file=kev_file)
            click.echo(f"  KEV refresh: matched {kev_result['kev_total']} entries, "
                       f"updated {kev_result['rules_updated']} CVE records "
                       f"in {kev_result['files_touched']} file(s).")
        except Exception as exc:
            click.echo(f"  KEV refresh failed: {exc}", err=True)
        try:
            eol_result = refresh_eol(online=online)
            click.echo(f"  EOL refresh: {eol_result.get('updated', 0)} product file(s) refreshed.")
        except Exception as exc:
            click.echo(f"  EOL refresh failed: {exc}", err=True)
    db = load_cve_db()
    eol = load_eol_db()
    if _has_rich():
        t = Table(title="Bundled enrichment datasets")
        t.add_column("Vendor"); t.add_column("CVEs", justify="right"); t.add_column("EOL records", justify="right")
        vendors = sorted(set(list(db.keys()) + [r.vendor for r in eol]))
        for v in vendors:
            cves = len(db.get(v, []))
            eols = sum(1 for r in eol if r.vendor == v)
            t.add_row(v, str(cves), str(eols))
        _CONSOLE.print(t)
    else:
        click.echo(f"CVEs: {sum(len(v) for v in db.values())} across {len(db)} vendors")
        click.echo(f"EOL records: {len(eol)}")


@cli.command("api")
@click.option("--bind", default="127.0.0.1", show_default=True,
              help="Bind address. Defaults to localhost (private mode).")
@click.option("--port", default=8765, show_default=True)
@click.option("--db-url", default=None,
              help="DB URL (postgresql://… or sqlite:///path.db). Defaults to local SQLite.")
@click.option("--users-file", default=None,
              help="Path to safecadence-users.yaml (auto-bootstrapped on first run).")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (dev).")
def api_cmd(bind, port, db_url, users_file, reload):
    """Run the SafeCadence FastAPI server (REST API + auth)."""
    try:
        import uvicorn
    except ImportError:
        click.echo("API server requires the [server] extras. "
                   "Install with: pip install 'safecadence-network-risk[server]'", err=True)
        sys.exit(2)
    if users_file:
        os.environ["SC_USERS_FILE"] = users_file
    if db_url:
        os.environ["DATABASE_URL"] = db_url
    from safecadence.server import create_app
    app = create_app(db_url=db_url, users_file=users_file)
    uvicorn.run(app, host=bind, port=port)


@cli.command("watch")
@click.argument("cidrs", nargs=-1, required=True)
@click.option("--interval", default=3600, show_default=True, type=int,
              help="Seconds between scans (default 1 hour).")
@click.option("--mode", default="lan_deep",
              type=click.Choice(["lan_deep", "extended", "quick"]),
              help="Discover mode for each scan.")
@click.option("--slack-webhook", default=None,
              help="Slack incoming-webhook URL for change alerts.")
@click.option("--teams-webhook", default=None,
              help="Microsoft Teams incoming-webhook URL.")
@click.option("--webhook-url", default=None,
              help="Generic JSON webhook (POST raw payload).")
@click.option("--alert-on", default="changes",
              type=click.Choice(["changes", "critical", "all"]),
              help="When to send alerts. 'changes' = diff vs last scan; 'critical' = any critical finding; 'all' = every scan.")
@click.option("--once", is_flag=True, help="Run once then exit (for cron).")
def watch_cmd(cidrs, interval, mode, slack_webhook, teams_webhook, webhook_url, alert_on, once):
    """Continuous monitoring — scan CIDR(s) on a schedule, alert on changes.

    Designed to run in the background:
      safecadence watch 192.168.4.0/24 --interval 3600 --slack-webhook https://...

    Or as a cron job:
      0 * * * * safecadence watch 192.168.4.0/24 --once --slack-webhook https://...
    """
    import time as _time
    from safecadence.discovery.lan_scan import deep_scan
    from safecadence.discovery.cve_match import cves_for_device, cve_summary_for_fleet
    from safecadence.discovery.toxic_combinations import enrich_device_with_toxic_combos
    from safecadence.discovery.webhooks import (
        post_slack, post_teams, post_generic,
        format_diff_alert, format_critical_alert,
    )
    from safecadence.ui.discover_store import get_discover_store

    store = get_discover_store()

    def _scan_and_alert():
        for cidr in cidrs:
            click.echo(f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] scanning {cidr}...")
            result = deep_scan(cidr, mode=mode, workers=64, timeout=1.0)
            hosts = getattr(result, "hosts", []) or []
            results = []
            for h in hosts:
                d = {
                    "ip": getattr(h, "ip", ""),
                    "hostname": getattr(h, "hostname", "") or "",
                    "mac": getattr(h, "mac", "") or "",
                    "vendor": getattr(h, "vendor_guess", "") or "",
                    "os": getattr(h, "os_guess", "") or "",
                    "category": getattr(h, "device_type_guess", "") or "",
                    "snmp_sysdescr": getattr(h, "snmp_sysdescr", "") or "",
                    "open_ports": list(getattr(h, "open_ports", []) or []),
                    "banners": dict(getattr(h, "banners", {}) or {}),
                }
                # Pop synthetic risk keys
                d["category"] = d["banners"].pop("__category__", d["category"])
                d["risk_score"] = int(d["banners"].pop("__risk_score__", "0") or 0)
                d["risk_band"] = d["banners"].pop("__risk_band__", "safe")
                fs = d["banners"].pop("__risk_findings__", "")
                ras = d["banners"].pop("__risk_actions__", "")
                d["findings"] = [f for f in fs.split("␟") if f] if fs else []
                d["recommended_actions"] = [a for a in ras.split("␟") if a] if ras else []
                d["cves"] = cves_for_device(d)
                d = enrich_device_with_toxic_combos(d)
                results.append(d)

            results.sort(key=lambda r: -r.get("risk_score", 0))
            bands = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
            cats: dict = {}
            for r in results:
                bands[r.get("risk_band", "safe")] = bands.get(r.get("risk_band", "safe"), 0) + 1
                c = r.get("category", "unknown")
                cats[c] = cats.get(c, 0) + 1

            payload = {
                "cidr": cidr,
                "mode": mode,
                "count": len(results),
                "scanned": getattr(result, "hosts_scanned", 0),
                "duration_ms": getattr(result, "duration_ms", 0),
                "summary": {
                    "by_risk_band": bands,
                    "by_category": cats,
                    "highest_risk_count": bands["critical"] + bands["high"],
                    "cves": cve_summary_for_fleet(results),
                },
                "results": results,
            }

            # Persist
            run_id = store.save_run(payload, label="watch")
            click.echo(f"  saved as run #{run_id} ({len(results)} devices, {bands['critical']} critical, {bands['high']} high)")

            # Decide whether to alert
            should_alert = False
            alert_summary = ""
            alert_blocks = []

            if alert_on == "all":
                should_alert = True
                alert_summary, alert_blocks = format_critical_alert(payload)
            elif alert_on == "critical":
                if bands["critical"] > 0 or payload["summary"]["cves"].get("kev_cves", 0) > 0:
                    should_alert = True
                    alert_summary, alert_blocks = format_critical_alert(payload)
            elif alert_on == "changes":
                # Find previous run for this CIDR
                prev = store.list_runs(limit=2, cidr=cidr)
                if len(prev) >= 2:
                    old_id = prev[1]["id"]  # second-to-most-recent
                    diff = store.diff_runs(old_id, run_id)
                    if diff.get("summary", {}).get("added_count", 0) + diff.get("summary", {}).get("removed_count", 0) + diff.get("summary", {}).get("changed_count", 0) > 0:
                        should_alert = True
                        alert_summary, alert_blocks = format_diff_alert(diff, cidr=cidr)

            if should_alert:
                color = "danger" if bands["critical"] > 0 else "warning"
                if slack_webhook:
                    res = post_slack(slack_webhook, summary=alert_summary, detail_blocks=alert_blocks, color=color)
                    click.echo(f"  Slack alert: {'OK' if res.get('ok') else 'FAILED ' + str(res.get('error',''))}")
                if teams_webhook:
                    res = post_teams(teams_webhook, title="SafeCadence Network Risk", summary=alert_summary,
                                      facts=[{"title": b.get("title"), "value": b.get("value")} for b in alert_blocks])
                    click.echo(f"  Teams alert: {'OK' if res.get('ok') else 'FAILED'}")
                if webhook_url:
                    res = post_generic(webhook_url, {"summary": alert_summary, "blocks": alert_blocks, "fleet": payload})
                    click.echo(f"  Webhook: {'OK' if res.get('ok') else 'FAILED'}")

    # Main loop
    try:
        _scan_and_alert()
        if once:
            return
        click.echo(f"watching: every {interval}s. Press Ctrl-C to stop.")
        while True:
            _time.sleep(interval)
            _scan_and_alert()
    except KeyboardInterrupt:
        click.echo("\nstopped.")


@cli.command("ui")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address. Defaults to localhost (private mode).")
@click.option("--port", default=8765, show_default=True,
              help="HTTP port (auto-finds the next free one if taken).")
@click.option("--no-browser", is_flag=True, default=False,
              help="Don't auto-open the browser.")
@click.option("--password", default=None, envvar="SC_UI_PASSWORD",
              help="Optional password to gate the UI (cookie-based, "
                   "8-hour session). Reads from $SC_UI_PASSWORD if unset. "
                   "Recommended when binding beyond 127.0.0.1.")
def ui_cmd(host, port, no_browser, password):
    """Launch the local web UI in your default browser.

    Multi-tab dashboard with v2 audit + v4 platform + v5 policy under one
    sidebar. By default no authentication (single-user localhost).
    Use --password to gate access on shared workstations.

    Requires the [server] extras:
      pip install 'safecadence-netrisk[server]'

    Examples:
      safecadence ui                            # localhost, no auth
      safecadence ui --port 9000                # custom port
      safecadence ui --no-browser               # don't auto-open
      safecadence ui --password mySecret        # require login
      SC_UI_PASSWORD=... safecadence ui         # via environment
    """
    try:
        from safecadence.ui import run_ui
    except ImportError as e:
        click.echo(f"UI launcher import failed: {e}", err=True)
        sys.exit(2)
    run_ui(host=host, port=port, open_browser=not no_browser, password=password)


@cli.command("vault")
@click.argument("action", type=click.Choice(["init", "set", "get", "list", "delete"]))
@click.argument("name", required=False)
@click.option("--value", default=None, help="Value for set (else prompted).")
@click.option("--path", "vault_path", default="safecadence.vault", show_default=True)
@click.option("--passphrase", default=None,
              help="Passphrase. Defaults to env SC_VAULT_PASS or prompts.")
def vault_cmd(action, name, value, vault_path, passphrase):
    """Manage the encrypted credential vault."""
    from safecadence.security import EncryptedVault, VaultError, derive_key, generate_key
    salt_path = vault_path + ".salt"
    if action == "init":
        click.echo("Random key generated. Set this in your env:")
        click.echo(f"  export SC_VAULT_KEY='{generate_key()}'")
        click.echo("Or use a passphrase: re-run any vault command with --passphrase.")
        return

    raw_key = os.environ.get("SC_VAULT_KEY")
    if not raw_key:
        if not passphrase:
            passphrase = os.environ.get("SC_VAULT_PASS") or click.prompt("Passphrase", hide_input=True)
        try:
            raw_key = derive_key(passphrase, salt_path=salt_path)
        except VaultError as exc:
            click.echo(str(exc), err=True); sys.exit(2)
    try:
        v = EncryptedVault(vault_path, key=raw_key)
    except VaultError as exc:
        click.echo(str(exc), err=True); sys.exit(2)

    if action == "list":
        for k in v.list(): click.echo(k)
    elif action == "get":
        if not name: click.echo("get requires NAME", err=True); sys.exit(2)
        click.echo(v.get(name) or "")
    elif action == "set":
        if not name: click.echo("set requires NAME", err=True); sys.exit(2)
        if value is None:
            value = click.prompt("Value", hide_input=True, confirmation_prompt=True)
        v.set(name, value); v.save()
        click.echo(f"Stored: {name}")
    elif action == "delete":
        if not name: click.echo("delete requires NAME", err=True); sys.exit(2)
        ok = v.delete(name); v.save()
        click.echo("Deleted." if ok else "Not found.")


@cli.group("admin")
def admin_cmd():
    """Manage SafeCadence API users (no server restart required)."""
    pass


@admin_cmd.command("reset-password")
@click.option("--username", "-u", default="admin", show_default=True)
@click.option("--password", "-p", default=None,
              help="New password. If omitted, a strong random one is generated and printed.")
@click.option("--tenant", default="default", show_default=True)
@click.option("--users-file", default="safecadence-users.yaml", show_default=True)
def admin_reset_password(username, password, tenant, users_file):
    """Reset (or create) a user's password in safecadence-users.yaml."""
    import secrets as _sec
    import yaml as _yaml
    try:
        from safecadence.server.auth import hash_password
    except RuntimeError as exc:
        click.echo(str(exc), err=True); sys.exit(2)

    p = Path(users_file)
    data = _yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {"tenants": {}}
    data.setdefault("tenants", {}).setdefault(tenant, {}).setdefault("users", [])

    if password is None:
        password = _sec.token_urlsafe(20)

    found = False
    for u in data["tenants"][tenant]["users"]:
        if u.get("username") == username:
            u["password_hash"] = hash_password(password)
            u.setdefault("roles", ["admin"])
            found = True
            break
    if not found:
        data["tenants"][tenant]["users"].append({
            "username": username,
            "password_hash": hash_password(password),
            "roles": ["admin"],
        })

    p.write_text(_yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass

    click.echo(f"User: {username}    Tenant: {tenant}")
    click.echo(f"New password: {password}")
    click.echo(f"Wrote: {p.resolve()}")


@admin_cmd.command("list-users")
@click.option("--users-file", default="safecadence-users.yaml", show_default=True)
def admin_list_users(users_file):
    """List every user across every tenant in the users file."""
    import yaml as _yaml
    p = Path(users_file)
    if not p.exists():
        click.echo(f"No users file at {p}", err=True); sys.exit(2)
    data = _yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    for tenant, t in (data.get("tenants") or {}).items():
        for u in t.get("users", []):
            click.echo(f"  {tenant:20s} {u.get('username','?'):20s} roles={u.get('roles',[])}")


@cli.command("export")
@click.argument("scans_dir", type=click.Path(exists=True, file_okay=False))
@click.option("--csv", "csv_path", required=True, type=click.Path(dir_okay=False),
              help="Output CSV path.")
def export_cmd(scans_dir, csv_path):
    """Export a directory of scan-result JSON files to a flat CSV."""
    import json as _json
    from safecadence.io_csv import write_assets_csv
    rows = []
    for f in sorted(Path(scans_dir).iterdir()):
        if f.suffix.lower() != ".json": continue
        try:
            rows.append(_json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    n = write_assets_csv(rows, csv_path)
    click.echo(f"Wrote {n} row(s) to {csv_path}")


# ---- v5.0: policy intelligence subcommand group ---- #
try:
    from safecadence.cli_policy import policy_cli as _policy_cli
    cli.add_command(_policy_cli)
except Exception:                              # pragma: no cover
    pass


# ---- v7.0: secure command execution engine ----------------------- #

@cli.group("adapter")
def adapter_cli():
    """v7.4 — adapter contract test harness (fixtures or live hardware)."""
    pass


@adapter_cli.command("sweep")
def cmd_adapter_sweep():
    """Run the contract harness against every production adapter that
    has a fixtures/ directory. Reports pass/fail per adapter."""
    from safecadence.adapter_harness import sweep_fixtures
    results = sweep_fixtures()
    total_pass = total_fail = 0
    for name, r in sorted(results.items()):
        mark = "✓" if r.ok and r.total > 0 else "✗" if r.fail_count else "—"
        click.echo(f"  {mark}  {name:<22} {r.pass_count} pass / {r.fail_count} fail")
        total_pass += r.pass_count
        total_fail += r.fail_count
    click.echo(f"\nTotal: {total_pass} pass, {total_fail} fail across "
               f"{len(results)} adapters.")


@adapter_cli.command("test")
@click.argument("adapter_name")
@click.option("--live", is_flag=True, help="Run against real hardware.")
@click.option("--host", default="", help="Live mode host/IP.")
@click.option("--username", default="")
@click.option("--password", default="")
@click.option("--key-file", "key_filename", default="")
@click.option("--port", type=int, default=22)
def cmd_adapter_test(adapter_name: str, live: bool, host: str,
                       username: str, password: str, key_filename: str,
                       port: int):
    """Run the contract harness against one adapter."""
    from safecadence.adapter_harness import (
        _load_adapter, run_fixture, run_live,
    )
    from pathlib import Path
    adapter = _load_adapter(adapter_name)
    if not adapter:
        click.echo(f"Adapter '{adapter_name}' not loadable. "
                   "Check the manifest with `safecadence list-adapters`.",
                   err=True)
        return
    if live:
        if not host:
            click.echo("--host is required in live mode", err=True)
            return
        result = run_live(adapter, host=host, username=username,
                            password=password, key_filename=key_filename,
                            port=port, name=adapter_name)
    else:
        fixture_dir = (Path(__file__).resolve().parents[2]
                        / "tests" / "fixtures" / "adapters" / adapter_name)
        result = run_fixture(adapter, fixture_dir, name=adapter_name)
    for f in result.findings:
        mark = "✓" if f["passed"] else "✗"
        suffix = f"  -- {f['detail']}" if f["detail"] else ""
        click.echo(f"  {mark}  {f['check']}{suffix}")
    click.echo(f"\n{result.pass_count} pass, {result.fail_count} fail")


@cli.group("msp")
def msp_cli():
    """v7.4 — MSP control-plane agent (register, heartbeat, run loop)."""
    pass


@msp_cli.command("register")
@click.argument("control_plane_url")
@click.option("--agent-id", default="", help="Stable identifier — usually customer name.")
@click.option("--claim-token", default="", help="One-time token from MSP.")
def cmd_msp_register(control_plane_url: str, agent_id: str, claim_token: str):
    """Register this SafeCadence instance with an MSP control plane."""
    from safecadence.msp_agent import register
    if not agent_id:
        click.echo("--agent-id required", err=True); return
    if not claim_token:
        click.echo("--claim-token required", err=True); return
    state = register(control_plane_url=control_plane_url,
                       agent_id=agent_id, claim_token=claim_token)
    click.echo(f"Registered as {state.agent_id} (heartbeat every "
               f"{state.heartbeat_interval_s}s)")


@msp_cli.command("heartbeat")
@click.argument("control_plane_url")
def cmd_msp_heartbeat(control_plane_url: str):
    """Send one heartbeat now (test of the registration)."""
    from safecadence.msp_agent import AgentState, heartbeat_once
    state = AgentState.load()
    if not state.agent_id:
        click.echo("Not registered. Run `safecadence msp register` first.",
                   err=True)
        return
    r = heartbeat_once(control_plane_url=control_plane_url, state=state)
    click.echo(f"Heartbeat sent at {r['sent_at']}; "
               f"ran {r['commands_run']} command(s).")


@msp_cli.command("run")
@click.argument("control_plane_url")
def cmd_msp_run(control_plane_url: str):
    """Foreground heartbeat loop until SIGINT."""
    from safecadence.msp_agent import AgentState, run_loop
    state = AgentState.load()
    if not state.agent_id:
        click.echo("Not registered. Run `safecadence msp register` first.",
                   err=True)
        return
    click.echo(f"MSP agent running ({state.agent_id} → {control_plane_url}). "
               "Ctrl+C to stop.")
    run_loop(control_plane_url=control_plane_url, state=state)


@cli.group("onboard")
def onboard_cli():
    """v7.3 — Get assets into the platform store.

    Three paths, one validated commit:
      onboard csv-template > template.csv  (download canonical schema)
      onboard csv-import < my-fleet.csv    (validate + commit)
      onboard scan 10.0.0.0/24             (scan + adopt)
      onboard credentials < creds.csv      (bulk vault load)
    """
    pass


@onboard_cli.command("csv-template")
def cmd_onboard_template():
    """Print the canonical CSV template to stdout."""
    from safecadence.onboarding import template_csv
    click.echo(template_csv())


@onboard_cli.command("csv-import")
@click.option("--file", "-f", type=click.Path(exists=True, dir_okay=False),
              required=True, help="Path to assets CSV.")
@click.option("--commit", is_flag=True,
              help="Actually write to the store. Without this flag, "
                   "you get a preview / validation report only.")
@click.option("--overwrite", is_flag=True,
              help="Overwrite existing asset_ids; default is skip.")
def cmd_onboard_csv_import(file: str, commit: bool, overwrite: bool):
    """Import assets from a CSV file. Default is dry-run."""
    from safecadence.onboarding import parse_csv, commit_preview
    text = open(file, encoding="utf-8").read()
    preview = parse_csv(text)
    click.echo(preview.summary)
    if preview.error_count:
        for r in preview.rows:
            if r.errors:
                click.echo(f"  row {r.row_number}: {'; '.join(r.errors)}")
    if not commit:
        click.echo("\n(dry-run — pass --commit to write to the store)")
        return
    if preview.error_count and not overwrite:
        click.echo("\nRefusing to commit while errors exist. "
                   "Fix CSV or pass --overwrite to skip bad rows.")
        return
    result = commit_preview(preview, overwrite=overwrite)
    click.echo(result["summary"])


@onboard_cli.command("scan")
@click.argument("cidr")
@click.option("--owner", default="", help="Bulk-set owner field on adopted assets.")
@click.option("--team", default="", help="Bulk-set team field on adopted assets.")
@click.option("--site", default="", help="Bulk-set site field on adopted assets.")
@click.option("--commit", is_flag=True,
              help="Actually adopt; without this you get a preview list.")
def cmd_onboard_scan(cidr: str, owner: str, team: str, site: str, commit: bool):
    """Scan a CIDR + adopt the discovered assets in one shot.

    Without --commit, prints the list of assets that would be created.
    With --commit, calls the existing platform.adopt-discovered flow.
    """
    try:
        from safecadence.discovery import discover as _discover
    except Exception as e:
        click.echo(f"Discovery module unavailable: {e}", err=True)
        return
    click.echo(f"Scanning {cidr}…")
    discovered = _discover(cidr) if hasattr(_discover, "__call__") else []
    if not discovered:
        click.echo("No assets discovered.")
        return
    click.echo(f"Found {len(discovered)} candidates.")
    for a in discovered[:20]:
        ident = (a.get("identity") or {})
        click.echo(f"  {ident.get('asset_id', '?'):<28} "
                   f"{ident.get('vendor', '?'):<14} {ident.get('hostname','')}")
    if not commit:
        click.echo("\n(dry-run — pass --commit to adopt)")
        return
    # Bulk-apply metadata overrides + save
    from safecadence.server.platform_api import save_asset
    written = 0
    for a in discovered:
        ident = a.setdefault("identity", {})
        if owner: ident["owner"] = owner
        if team:  ident["team"]  = team
        if site:  ident["site"]  = site
        try:
            save_asset(a)
            written += 1
        except Exception as e:
            click.echo(f"  failed: {ident.get('asset_id','?')}: {e}")
    click.echo(f"Adopted {written} assets.")


@onboard_cli.command("credentials")
@click.option("--file", "-f", type=click.Path(exists=True, dir_okay=False),
              required=True, help="Bulk credentials CSV.")
@click.option("--commit", is_flag=True)
@click.option("--overwrite", is_flag=True)
def cmd_onboard_credentials(file: str, commit: bool, overwrite: bool):
    """Bulk-vault credentials from a CSV.

    Required columns: asset_id, username. One of password / key_filename
    must be present per row.
    """
    from safecadence.onboarding import (
        parse_credentials_csv, commit_credentials_preview,
    )
    text = open(file, encoding="utf-8").read()
    preview = parse_credentials_csv(text)
    click.echo(preview["summary"])
    if not commit:
        click.echo("(dry-run — pass --commit)")
        return
    result = commit_credentials_preview(preview, overwrite=overwrite)
    click.echo(result["summary"])


@cli.group("execute")
def execute_cli():
    """v7.0 — Plan, approve, dry-run command jobs across the fleet.

    SafeCadence does NOT push commands to live devices. We generate
    per-vendor command sets, run them through guardrails + approval,
    and emit Ansible / Salt / NSO / raw artefacts that your existing
    automation tooling executes. This stays out of the 'we accidentally
    bricked your datacenter' business by design.
    """
    pass


@execute_cli.command("plan")
@click.argument("intent")
@click.option("--asset-id", "asset_ids", multiple=True)
@click.option("--asset-group", "asset_group_ids", multiple=True)
def cmd_execute_plan(intent: str, asset_ids: tuple[str, ...],
                      asset_group_ids: tuple[str, ...]):
    """AI Command Builder — natural language → per-vendor commands.

    Example:
        safecadence execute plan "check BGP on all Cisco routers"
        safecadence execute plan "show interface errors" --asset-group cisco-edge
    """
    from safecadence.execution.builder import build_plan
    plan = build_plan(intent,
                       asset_ids=list(asset_ids),
                       asset_group_ids=list(asset_group_ids))
    click.echo(plan.summary)
    if plan.blocked:
        click.echo("\nBLOCKED:")
        for r in plan.block_reasons:
            click.echo(f"  - {r}")
        return
    click.echo(f"\nMatched packs: {', '.join(plan.matched_packs) or '(none)'}")
    click.echo(f"Mode:    {plan.mode.value}")
    click.echo(f"Risk:    {plan.risk.value}")
    if plan.target_filter:
        click.echo(f"Filter:  {plan.target_filter}")
    click.echo("\nCommands by vendor:")
    for vendor, cmds in plan.commands_by_vendor.items():
        click.echo(f"  --- {vendor} ---")
        for c in cmds:
            click.echo(f"    {c}")


@execute_cli.command("submit")
@click.argument("intent")
@click.option("--name", default="")
@click.option("--asset-id", "asset_ids", multiple=True)
@click.option("--asset-group", "asset_group_ids", multiple=True)
def cmd_execute_submit(intent: str, name: str,
                         asset_ids: tuple[str, ...],
                         asset_group_ids: tuple[str, ...]):
    """Build a plan, save it as a DRAFT job, submit for review."""
    from safecadence.execution.builder import build_plan, plan_to_job
    from safecadence.execution import workflow
    from safecadence.execution.rbac import Role
    plan = build_plan(intent, asset_ids=list(asset_ids),
                       asset_group_ids=list(asset_group_ids))
    if plan.blocked:
        click.echo("BLOCKED — refusing to save.")
        for r in plan.block_reasons:
            click.echo(f"  - {r}")
        return
    if not plan.matched_packs:
        click.echo(plan.summary)
        return
    job = plan_to_job(plan, name=name, created_by="cli")
    try:
        workflow.create_job(job, actor="cli", role=Role.SECURITY_ADMIN)
        workflow.submit_for_review(job.job_id, actor="cli")
    except workflow.WorkflowError as e:
        click.echo(f"WorkflowError: {e}", err=True)
        return
    click.echo(f"Saved + submitted job {job.job_id}  (risk={job.risk.value})")


@execute_cli.command("list")
@click.option("--status", default=None,
              type=click.Choice(["draft", "review", "approved", "scheduled",
                                  "running", "done", "failed", "rejected",
                                  "blocked", "rolled_back", "canceled"]))
def cmd_execute_list(status):
    """List command jobs, optionally filtered by status."""
    from safecadence.execution import store
    jobs = store.list_jobs(status=status)
    if not jobs:
        click.echo("No jobs.")
        return
    for j in jobs:
        click.echo(f"  {j.job_id:<22} [{j.status.value:<10}] "
                   f"{j.risk.value:<8} {j.mode.value:<11} {j.name}")


@execute_cli.command("show")
@click.argument("job_id")
def cmd_execute_show(job_id: str):
    """Show full detail for a job."""
    from safecadence.execution import store
    j = store.get_job(job_id)
    if not j:
        click.echo(f"Job '{job_id}' not found.")
        return
    import json as _j
    from dataclasses import asdict
    click.echo(_j.dumps(asdict(j), indent=2, default=str))


@execute_cli.command("approve")
@click.argument("job_id")
@click.option("--note", default="")
def cmd_execute_approve(job_id: str, note: str):
    """Approve a job (REVIEW → APPROVED)."""
    from safecadence.execution import workflow
    from safecadence.execution.rbac import Role
    try:
        j = workflow.approve(job_id, approver="cli-admin",
                              role=Role.SECURITY_ADMIN, note=note)
        click.echo(f"Status: {j.status.value}  (approvers: {j.approvers})")
    except workflow.WorkflowError as e:
        click.echo(f"WorkflowError: {e}", err=True)


@execute_cli.command("dry-run")
@click.argument("job_id")
def cmd_execute_dryrun(job_id: str):
    """Simulate execution against the platform asset store."""
    from safecadence.execution.executor import dry_run
    import json as _j
    result = dry_run(job_id, actor="cli")
    click.echo(_j.dumps(result, indent=2, default=str))


@execute_cli.command("export")
@click.argument("job_id")
@click.option("--format", "fmt", default="ansible",
              type=click.Choice(["ansible", "salt", "nso", "raw", "markdown"]))
@click.option("--out", type=click.Path(dir_okay=False), default=None)
def cmd_execute_export(job_id: str, fmt: str, out: str):
    """Export an approved job as Ansible/Salt/NSO/raw/markdown."""
    from safecadence.execution import store
    from safecadence.execution.executor import export
    j = store.get_job(job_id)
    if not j:
        click.echo(f"Job '{job_id}' not found.", err=True)
        return
    text = export(j, fmt)
    if out:
        from pathlib import Path
        Path(out).write_text(text, encoding="utf-8")
        click.echo(f"wrote {len(text)} chars to {out}")
    else:
        click.echo(text)


@execute_cli.command("audit")
@click.option("--job", default=None, help="Filter to a single job_id.")
@click.option("--limit", default=50, type=int)
def cmd_execute_audit(job: str, limit: int):
    """Read the immutable execution audit log."""
    from safecadence.execution import store
    rows = store.read_audit(job_id=job, limit=limit)
    if not rows:
        click.echo("No audit entries.")
        return
    for r in rows:
        ts = r.get("timestamp", "")[:19]
        click.echo(f"  {ts}  {r.get('actor','?'):<12}  "
                   f"{r.get('action',''):<22}  {r.get('job_id','')}  "
                   f"{r.get('detail','')[:60]}")


@execute_cli.command("rbac")
def cmd_execute_rbac():
    """Show the 6-tier RBAC capability matrix."""
    from safecadence.execution.rbac import (
        Role, capabilities_for, approvals_needed,
    )
    for role in Role:
        caps = capabilities_for(role)
        click.echo(f"\n{role.value.upper()}  ({len(caps)} capabilities):")
        for c in sorted(c.value for c in caps):
            click.echo(f"  - {c}")
    click.echo("\nApprovals needed by risk level:")
    for r in ("safe", "low", "medium", "high", "critical"):
        click.echo(f"  {r:<10} {approvals_needed(r)} approver(s)")


# ---- v6.3: demo + daemon — turn first-run from empty into magical ---- #

@cli.command("demo")
@click.option("--clear", is_flag=True,
              help="Remove demo assets from the platform store.")
@click.option("--overwrite", is_flag=True,
              help="Re-write demo assets even if they already exist.")
def cmd_demo(clear: bool, overwrite: bool):
    """Load 30 realistic fake assets so the UI is alive on first run.

    Designed to surface policy violations + cross-system drift +
    attack paths immediately, so a brand-new user can see what the
    platform does without having to wire up a single adapter first.
    """
    from safecadence.demo import load_demo_fleet, clear_demo_fleet
    if clear:
        result = clear_demo_fleet()
        click.echo(f"Removed {result['removed']} demo assets from "
                   f"{result['target_dir']}")
        return
    result = load_demo_fleet(overwrite=overwrite)
    click.echo(f"Loaded {result['written']} demo assets "
               f"({result['skipped']} already present, use --overwrite "
               f"to replace) into {result['target_dir']}")
    click.echo("")
    click.echo(result["summary"])
    click.echo("")
    click.echo("Next steps:")
    click.echo("  1. safecadence ui                           # open the UI")
    click.echo("  2. safecadence policy briefing              # exec summary")
    click.echo("  3. safecadence policy drift-cross-system    # 17-detector run")
    click.echo("  4. safecadence demo --clear                 # remove when done")


@cli.group("groups")
def groups_cli():
    """v6.4 — asset groups (the device-selection primitive)."""
    pass


@groups_cli.command("list")
def cmd_groups_list():
    """List every saved asset group with current member count."""
    from safecadence.policy.asset_groups import list_groups, resolve_members
    from safecadence.server.platform_api import list_assets
    assets = list_assets()
    groups = list_groups()
    if not groups:
        click.echo("No asset groups defined yet. Create one with "
                   "`safecadence groups create`.")
        return
    for g in groups:
        members = resolve_members(g, assets)
        kind = "static" if g.is_static() else ("dynamic" if g.is_dynamic() else "empty")
        click.echo(f"  {g.group_id:<28} [{kind:<7}] "
                   f"{len(members):>4} members  {g.name}")


@groups_cli.command("show")
@click.argument("group_id")
def cmd_groups_show(group_id: str):
    """Show a group's spec and current members."""
    from safecadence.policy.asset_groups import get, resolve_members
    from safecadence.server.platform_api import list_assets
    g = get(group_id)
    if not g:
        click.echo(f"Asset group '{group_id}' not found.")
        return
    click.echo(f"Group:         {g.group_id}")
    click.echo(f"Name:          {g.name}")
    click.echo(f"Description:   {g.description or '(none)'}")
    if g.is_static():
        click.echo(f"Type:          static — {len(g.asset_ids)} explicit asset_ids")
    elif g.is_dynamic():
        import json as _j
        click.echo("Type:          dynamic")
        click.echo("Filter:        " + _j.dumps(g.filter, indent=2))
    if g.exclude_asset_ids:
        click.echo(f"Excludes:      {', '.join(g.exclude_asset_ids)}")
    members = resolve_members(g, list_assets())
    click.echo(f"\nCurrent members ({len(members)}):")
    for m in members[:50]:
        ident = m.get("identity") or {}
        click.echo(f"  - {ident.get('asset_id'):<32} "
                   f"{ident.get('vendor', ''):<12} "
                   f"{ident.get('environment', '')}")
    if len(members) > 50:
        click.echo(f"  ... +{len(members) - 50} more")


@groups_cli.command("create")
@click.argument("group_id")
@click.option("--name", required=True, help="Human-readable name.")
@click.option("--description", default="", help="What this group is for.")
@click.option("--filter-json", default=None,
              help="JSON filter spec (dynamic group).")
@click.option("--asset-id", "asset_ids", multiple=True,
              help="Asset id (repeat for multiple) — static group.")
def cmd_groups_create(group_id: str, name: str, description: str,
                       filter_json: str, asset_ids: tuple[str, ...]):
    """Create an asset group, either static (--asset-id ...) OR dynamic
    (--filter-json '{"all":[...]}').

    Examples:
      safecadence groups create cisco-edge --name "Cisco edge routers" \\
        --filter-json '{"all":[{"field":"vendor","op":"eq","value":"cisco"},
                                {"field":"network.zone","op":"eq","value":"edge"}]}'

      safecadence groups create pci-scope --name "PCI scope" \\
        --asset-id crm-prod-01 --asset-id rds-prod-customer
    """
    import json as _j
    from safecadence.policy.asset_groups import AssetGroup, save
    g = AssetGroup(
        group_id=group_id, name=name, description=description,
        asset_ids=list(asset_ids),
        filter=_j.loads(filter_json) if filter_json else {},
    )
    try:
        save(g)
    except ValueError as e:
        click.echo(f"validation failed: {e}")
        return
    click.echo(f"Saved asset group '{group_id}'.")


@groups_cli.command("delete")
@click.argument("group_id")
@click.confirmation_option(prompt="Delete this asset group?")
def cmd_groups_delete(group_id: str):
    from safecadence.policy.asset_groups import delete
    if delete(group_id):
        click.echo(f"Deleted '{group_id}'.")
    else:
        click.echo(f"Group '{group_id}' not found.")


@cli.command("list-adapters")
@click.option("--status", type=click.Choice(["all", "production",
                                              "experimental", "stub"]),
              default="all")
def cmd_list_adapters(status: str):
    """Truthful adapter classification — what works, what's experimental,
    what's a stub. Replaces the inflated 45-adapter marketing count."""
    from safecadence.adapter_manifest import manifest
    m = manifest()
    click.echo(m["tagline"])
    click.echo("")
    for row in m["adapters"]:
        if status != "all" and row["status"] != status:
            continue
        click.echo(f"  [{row['status']:<13}] {row['name']:<22} "
                   f"{row['description']}")


@cli.command("daemon")
@click.option("--interval", type=int, default=1800,
              help="Seconds between scan cycles (default 1800 = 30 min).")
@click.option("--once", is_flag=True,
              help="Run a single scan cycle then exit (useful for cron).")
@click.option("--slack-webhook", default=None,
              help="Slack incoming-webhook URL for critical alerts.")
def cmd_daemon(interval: int, once: bool, slack_webhook: str):
    """Continuously re-evaluate every active policy + drift detector.

    This is what turns SafeCadence from a CLI into a platform: the
    daemon re-runs policy evaluations, cross-system drift, and attack-
    path computation on a schedule, persists deltas to ~/.safecadence/
    daemon.log, and fires Slack alerts on new critical findings.
    """
    from safecadence.daemon import run_daemon
    run_daemon(interval=interval, once=once, slack_webhook=slack_webhook)


@cli.command("selfcheck")
@click.option("--server", default="http://127.0.0.1:8767",
              help="Base URL of a running safecadence server (default 8767).")
@click.option("--timeout", type=float, default=5.0,
              help="Per-request timeout in seconds (default 5.0).")
@click.option("--json", "as_json", is_flag=True,
              help="Emit machine-readable JSON instead of pretty output.")
def cmd_selfcheck(server: str, timeout: float, as_json: bool):
    """v9.23 — crawl a running server and report broken nav links.

    Hits every page reachable from the v9 sidebar, extracts every
    internal href, then GETs each one. Flags 404s and any navigation
    link that returns JSON instead of HTML (the v9.16.1 foot-gun).

    Use this on your own deployment to verify the box is healthy
    before you hand the URL to the team.
    """
    import json as _json
    import re as _re
    import sys as _sys
    import urllib.request as _ur
    import urllib.error as _ue

    server = server.rstrip("/")
    pages = [
        "/home", "/inventory", "/groups", "/topology", "/shadow-it",
        "/coverage", "/changes", "/discovery-jobs", "/tags", "/scope",
        "/policies", "/findings", "/drift", "/evidence",
        "/identity", "/jit", "/paths", "/simulate", "/access",
        "/execute", "/builder", "/approvals", "/queue", "/rollback",
        "/per-device-diff", "/blast-radius",
        "/scores", "/compliance", "/risks", "/vendors", "/policies/new",
        "/automation", "/watchlists", "/briefing",
        "/timeline", "/share",
        "/onboarding", "/hub", "/help", "/tour", "/ask",
    ]
    href_re = _re.compile(r'''href\s*=\s*["'](?P<u>/[^"'\s>#]+)["']''',
                          _re.IGNORECASE)

    def _fetch(url: str):
        try:
            with _ur.urlopen(url, timeout=timeout) as resp:
                return (resp.status,
                        resp.headers.get("content-type", ""),
                        resp.read().decode("utf-8", errors="replace"))
        except _ue.HTTPError as e:
            return (e.code,
                    e.headers.get("content-type", "") if e.headers else "",
                    "")
        except Exception as e:
            return -1, str(e), ""

    seen: set[str] = set()
    failures: list[str] = []
    visited = 0

    for p in pages:
        url = server + p
        status, ctype, body = _fetch(url)
        visited += 1
        if status != 200:
            failures.append(f"{p} -> status {status}")
            continue
        if "text/html" not in ctype.lower():
            failures.append(f"{p} -> content-type {ctype} (expected HTML)")
        for m in href_re.finditer(body):
            u = m.group("u").split("?", 1)[0].rstrip("/") or "/"
            if u.startswith("/api/"):
                continue
            if any(s in u for s in ("/static/", "/_next/", ".csv",
                                     ".pdf", ".json")):
                continue
            if "{" in u:
                continue
            seen.add(u)

    extras = sorted(seen - set(pages))
    for u in extras:
        url = server + u
        status, ctype, _ = _fetch(url)
        visited += 1
        if status not in (200, 301, 302, 303, 307, 308, 401, 405):
            failures.append(f"{u} -> status {status}")
        elif status == 200 and "text/html" not in ctype.lower():
            failures.append(
                f"{u} -> content-type {ctype} "
                "(navigation link served non-HTML)")

    summary = {
        "server": server,
        "pages_visited": visited,
        "pages_seeded": len(pages),
        "extra_links_followed": len(extras),
        "failures": failures,
        "ok": not failures,
    }

    if as_json:
        click.echo(_json.dumps(summary, indent=2))
    else:
        click.echo(f"Server:           {server}")
        click.echo(f"Pages visited:    {visited} "
                   f"({len(pages)} seeded + {len(extras)} discovered)")
        if failures:
            click.echo(click.style(
                f"Failures:         {len(failures)}",
                fg="red", bold=True))
            for f in failures:
                click.echo(f"  - {f}")
        else:
            click.echo(click.style(
                "Failures:         0  (every link resolved)",
                fg="green", bold=True))

    _sys.exit(0 if not failures else 2)


# ============================================================================
# v7.5 — Identity command group: NL → IR → preview → apply, plus who-can.
# ============================================================================

@cli.group("identity")
def identity_cli():
    """v7.5 — unified identity policy (read effective permissions; author
    via AI; preview per-system change set; apply through Tier-3 gating)."""
    pass


@identity_cli.command("translate")
@click.argument("intent", required=False)
@click.option("--form", is_flag=True,
              help="Use the air-gapped guided form (no AI required).")
@click.option("--groups", multiple=True, help="(form) Groups this targets.")
@click.option("--actions", multiple=True, default=("ssh",), show_default=True,
              help="(form) Actions to enforce on.")
@click.option("--environments", multiple=True, default=("prod",), show_default=True,
              help="(form) Environments to scope to.")
@click.option("--effect", type=click.Choice(["allow", "deny", "require_step_up"]),
              default="deny", show_default=True)
@click.option("--require-mfa/--no-require-mfa", default=True, show_default=True)
@click.option("--targets", multiple=True,
              help="Systems to enforce in. Default: all.")
@click.option("--out", "out_path", default=None,
              help="Write the IR JSON to this path instead of stdout.")
def cmd_identity_translate(intent, form, groups, actions, environments,
                            effect, require_mfa, targets, out_path):
    """Translate a plain-English intent into a Unified Policy IR.

    Example:
      safecadence identity translate "contractors without MFA cannot SSH to prod"
      safecadence identity translate --form --groups Contractors --effect deny
    """
    from safecadence.identity.ai_translator import (
        translate as ai_translate, from_form,
    )
    from dataclasses import asdict
    import json as _json

    if form:
        if not groups:
            click.echo("--form requires at least one --groups", err=True)
            sys.exit(2)
        ir = from_form(
            intent=intent or f"deny {','.join(actions)} for {','.join(groups)}",
            groups=list(groups), actions=list(actions),
            environments=list(environments), effect=effect,
            require_mfa=require_mfa,
            targets=list(targets) if targets else None,
        )
    else:
        if not intent:
            click.echo("intent required (or use --form for the guided path)",
                        err=True)
            sys.exit(2)
        try:
            result = ai_translate(intent)
        except Exception as exc:
            click.echo(f"AI translation failed: {exc}", err=True)
            click.echo("Tip: re-run with --form for the no-AI guided path.",
                        err=True)
            sys.exit(2)
        ir = result.ir

    payload = _json.dumps(asdict(ir), indent=2, sort_keys=True)
    if out_path:
        Path(out_path).write_text(payload, encoding="utf-8")
        click.echo(f"Wrote IR to {out_path}")
    else:
        click.echo(payload)


@identity_cli.command("preview")
@click.argument("ir_path", type=click.Path(exists=True, dir_okay=False))
def cmd_identity_preview(ir_path):
    """Compile an IR file into per-system change preview."""
    from safecadence.identity.ir import validate_ir
    from safecadence.identity.compiler import compile_plan
    import json as _json

    doc = _json.loads(Path(ir_path).read_text(encoding="utf-8"))
    ir = validate_ir(doc)
    plan = compile_plan(ir)
    click.echo(plan.diff())


@identity_cli.command("apply")
@click.argument("ir_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--target", default="okta", show_default=True,
              type=click.Choice(["okta", "ise", "ad", "entra", "clearpass"]),
              help="Which system to commit to. v7.6 ships all 5.")
@click.option("--dry-run/--commit", default=True, show_default=True,
              help="Default is dry-run. Use --commit to actually write.")
@click.option("--target-host", default=None,
              help="Adapter target (Okta domain, ISE host, AD server, "
                   "Entra tenant, ClearPass host). Falls back to env: "
                   "OKTA_DOMAIN / ISE_HOST / AD_SERVER / ENTRA_TENANT / "
                   "CLEARPASS_HOST.")
@click.option("--cred-env-prefix", default=None,
              help="Env-var prefix for credentials (default: target uppercased).")
def cmd_identity_apply(ir_path, target, dry_run, target_host, cred_env_prefix):
    """Apply (or preview the apply of) an IR against a target system.

    --dry-run is the default. The flag is opt-in by design.

    Credentials are pulled from environment variables by convention:

      okta:      OKTA_DOMAIN, OKTA_API_TOKEN
      ise:       ISE_HOST, ISE_USERNAME, ISE_PASSWORD
      ad:        AD_SERVER, AD_BIND_DN, AD_BIND_PASSWORD, AD_BASE_DN
      entra:     ENTRA_TENANT, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET
      clearpass: CLEARPASS_HOST, CLEARPASS_CLIENT_ID, CLEARPASS_CLIENT_SECRET
    """
    from safecadence.identity.ir import validate_ir
    from safecadence.platform.adapters.identity_adapters import (
        ActiveDirectoryAdapter, CiscoISEAdapter, EntraIDAdapter,
        HPEClearPassAdapter, OktaAdapter,
    )
    import json as _json

    doc = _json.loads(Path(ir_path).read_text(encoding="utf-8"))
    ir = validate_ir(doc)

    target_to_class = {
        "okta": OktaAdapter,
        "ise": CiscoISEAdapter,
        "ad": ActiveDirectoryAdapter,
        "entra": EntraIDAdapter,
        "clearpass": HPEClearPassAdapter,
    }
    adapter_cls = target_to_class[target]

    target_host_envs = {
        "okta": "OKTA_DOMAIN", "ise": "ISE_HOST", "ad": "AD_SERVER",
        "entra": "ENTRA_TENANT", "clearpass": "CLEARPASS_HOST",
    }
    host = target_host or os.environ.get(target_host_envs[target], "")
    creds = _build_creds_for_target(target)

    if not dry_run and not host:
        click.echo(f"--commit requires --target-host or "
                   f"{target_host_envs[target]} env var.", err=True)
        sys.exit(2)

    adapter = adapter_cls(target=host or f"stub.{target}.local",
                          credentials=creds)
    result = adapter.apply_policy(ir, dry_run=dry_run)
    click.echo(_json.dumps(result, indent=2))


def _build_creds_for_target(target: str) -> dict:
    """Pull credentials from env by target convention."""
    table = {
        "okta": [("api_token", "OKTA_API_TOKEN")],
        "ise": [("username", "ISE_USERNAME"), ("password", "ISE_PASSWORD")],
        "ad": [("bind_dn", "AD_BIND_DN"),
                ("bind_password", "AD_BIND_PASSWORD"),
                ("base_dn", "AD_BASE_DN")],
        "entra": [("tenant_id", "ENTRA_TENANT"),
                   ("client_id", "ENTRA_CLIENT_ID"),
                   ("client_secret", "ENTRA_CLIENT_SECRET")],
        "clearpass": [("client_id", "CLEARPASS_CLIENT_ID"),
                       ("client_secret", "CLEARPASS_CLIENT_SECRET")],
    }
    out: dict[str, str] = {}
    for k, env in table.get(target, []):
        out[k] = os.environ.get(env, "")
    return out


# ---- v7.6: JIT access subcommands ----

@identity_cli.group("jit")
def identity_jit_cli():
    """v7.6 — Just-in-Time access grants (time-bounded, auto-revoke)."""
    pass


@identity_jit_cli.command("grant")
@click.option("--principal", required=True, help="user@domain or NHI id")
@click.option("--action", required=True, help="ssh / rdp / admin / read / ...")
@click.option("--resource", required=True, help="asset-id of the target")
@click.option("--duration", default="4h", show_default=True,
              help="Duration (e.g. 30m, 4h, 2d). Max 14d.")
@click.option("--target", default="okta", show_default=True,
              type=click.Choice(["okta", "ise", "ad", "entra", "clearpass"]),
              help="Which IdP enforces the grant.")
@click.option("--reason", default="", help="Audit-trail reason.")
def cmd_jit_grant(principal, action, resource, duration, target, reason):
    """Grant time-bounded access. Persists the grant to ~/.safecadence/jit.json."""
    from safecadence.identity.jit import grant
    seconds = _parse_duration(duration)
    g = grant(principal=principal, action=action, resource=resource,
               duration_seconds=seconds, target=target, reason=reason,
               created_by=os.environ.get("USER", "cli"))
    click.echo(f"Granted: {g.grant_id}")
    click.echo(f"  expires_at: {int(g.expires_at)}  ({duration})")
    click.echo(f"  target:     {g.target}")
    click.echo(f"  Apply via:  safecadence identity jit apply {g.grant_id}")


@identity_jit_cli.command("list")
@click.option("--active-only", is_flag=True)
def cmd_jit_list(active_only):
    """List all JIT grants."""
    from safecadence.identity.jit import list_grants
    grants = list_grants(only_active=active_only)
    if not grants:
        click.echo("No JIT grants.")
        return
    for g in grants:
        click.echo(f"{g.grant_id}  {g.status:8s}  "
                   f"{g.principal} → {g.action} → {g.resource}  "
                   f"(expires {int(g.expires_at)}, target={g.target})")


@identity_jit_cli.command("expire-due")
def cmd_jit_expire_due():
    """Mark grants whose expires_at has passed. Returns the IRs to revoke."""
    from safecadence.identity.jit import expire_due
    expired = expire_due()
    if not expired:
        click.echo("No grants past expiry.")
        return
    click.echo(f"Expired {len(expired)} grant(s):")
    for g in expired:
        click.echo(f"  {g.grant_id}  ({g.principal} → {g.action})")
    click.echo("\nApply revoke IRs via: safecadence identity apply <revoke.json>")


@identity_cli.command("discover")
@click.option("--email-domain", default=None,
              help="Probe Okta/Entra by email domain (e.g. acme.com).")
@click.option("--entra-tenant", default=None,
              help="Microsoft Entra tenant hint (e.g. acme.onmicrosoft.com).")
@click.option("--ad-domain", default=None,
              help="AD domain to resolve via DNS (e.g. corp.local).")
@click.option("--lan-cidr", multiple=True,
              help="LAN CIDR(s) to probe for ISE/ClearPass. "
                   "Default scans common /24 ranges.")
def cmd_identity_discover(email_domain, entra_tenant, ad_domain, lan_cidr):
    """v7.8 — auto-detect identity systems reachable from this host.

    Probes the network and well-known endpoints. Reports what's found
    plus the env-var recipe to set if you want to commit. Removes the
    "where do I even start?" friction from first-run setup.

    Examples:
      safecadence identity discover --email-domain acme.com
      safecadence identity discover --ad-domain corp.local --lan-cidr 10.0.0.0/24
    """
    from safecadence.identity.discover import discover
    findings = discover(
        email_domain=email_domain,
        entra_tenant_hint=entra_tenant,
        lan_cidrs=list(lan_cidr) if lan_cidr else None,
        ad_domain=ad_domain,
    )
    if not findings:
        click.echo("No identity systems detected. Try with --email-domain, "
                   "--entra-tenant, or --ad-domain hints.", err=True)
        return
    click.echo(f"\nDetected {len(findings)} identity system(s):\n")
    for f in findings:
        click.echo(f"  [{f.system:9s}]  {f.target}")
        click.echo(f"             confidence: {f.confidence:.0%}")
        click.echo(f"             evidence:   {f.evidence}")
        click.echo(f"             next step:  {f.next_step}")
        if f.env_vars:
            click.echo("             env vars:")
            for k, v in f.env_vars.items():
                click.echo(f"                 export {k}='{v}'")
        click.echo("")


def _parse_duration(s: str) -> int:
    s = (s or "").strip().lower()
    if s.endswith("s"): return int(s[:-1])
    if s.endswith("m"): return int(s[:-1]) * 60
    if s.endswith("h"): return int(s[:-1]) * 3600
    if s.endswith("d"): return int(s[:-1]) * 86400
    return int(s)


@identity_cli.command("who-can")
@click.argument("action")
@click.argument("resource")
@click.option("--as", "principal", required=True,
              help="Principal to evaluate (email or NHI id).")
@click.option("--groups", multiple=True,
              help="Resolved group memberships for the principal.")
@click.option("--mfa/--no-mfa", default=False, help="Current MFA state.")
@click.option("--posture-compliant/--no-posture", default=False)
@click.option("--device-trusted/--no-device-trusted", default=False)
def cmd_identity_who_can(action, resource, principal, groups,
                          mfa, posture_compliant, device_trusted):
    """Effective-permission lookup. Composes ALL connected identity systems.

    Example:
      safecadence identity who-can ssh prod-db-01 \\
          --as alice@contractor.com --groups Contractors --no-mfa
    """
    from safecadence.identity.effective_permissions import (
        decide, rules_from_assets,
    )
    try:
        from safecadence.server.platform_api import list_assets
        assets = list_assets()
    except Exception:
        assets = []

    rules = rules_from_assets(assets)
    # Find the resource's attributes if it exists in the store
    resource_attrs = {}
    for a in assets:
        ident = (a.get("identity") or {})
        if ident.get("asset_id") == resource or ident.get("hostname") == resource:
            resource_attrs = {
                "asset_type": ident.get("asset_type", ""),
                "env": ident.get("environment", ""),
                "criticality": ident.get("criticality", ""),
                "site": ident.get("site", ""),
            }
            break

    decision = decide(
        principal, action, resource,
        context={"mfa": mfa, "posture_compliant": posture_compliant,
                  "device_trusted": device_trusted},
        rules=rules,
        principal_groups=list(groups),
        resource_attrs=resource_attrs,
    )
    verdict = "ALLOW" if decision.allowed else (
        "DENY (requires step-up)" if decision.requires_step_up else "DENY")
    click.echo(f"\n  {principal}  →  {action}  →  {resource}")
    click.echo(f"  Decision:  {verdict}")
    click.echo(f"  Systems:   {', '.join(decision.systems_consulted) or '(none)'}")
    if decision.chain:
        click.echo("  Rule chain:")
        for r in decision.chain:
            click.echo(f"    - [{r.system}] {r.rule_name} → {r.effect}  "
                       f"({', '.join(r.matched_on)})")
    click.echo("  Reasoning:")
    for reason in decision.reasons:
        click.echo(f"    - {reason}")


# ============================================================================
# v9.34.1 #3 — CLI parity for the v9.34 connect/sync/disconnect/NHI flows.
# Mirrors the HTTP endpoints so headless / scripted setups work identically
# to the UI. Same vault, same adapter, same trust property:
#   - identity connect runs adapter.test_connection() first; only persists on ok
#   - identity sync reads from the vault, calls collect+normalize+save_asset
#   - identity disconnect removes the vault record; idempotent
# ============================================================================


@identity_cli.command("connect")
@click.argument("system",
                type=click.Choice(["okta", "entra", "ise", "clearpass", "ad"]))
@click.option("--target", required=True,
              help="System target (Okta domain, ISE host, AD URL, …).")
@click.option("--cred", "creds", multiple=True,
              help="Credential as key=value. Repeat per field. e.g. "
                   "--cred api_token=abc --cred client_id=xyz")
@click.option("--save/--test-only", default=False,
              help="--save persists to the vault on a passing test. "
                   "Default --test-only never persists.")
def cmd_identity_connect(system, target, creds, save):
    """Test (and optionally save) credentials for an identity system.

    Trust property: persistence only happens AFTER a passing
    adapter.test_connection() call. A failed test never writes to
    the vault, regardless of --save.

    Example:
      safecadence identity connect okta \\
          --target acme.okta.com \\
          --cred api_token=ABCDEF \\
          --save
    """
    cred_dict = {}
    for kv in creds:
        if "=" not in kv:
            click.echo(f"--cred must be key=value, got {kv!r}", err=True)
            raise click.Abort()
        k, v = kv.split("=", 1)
        cred_dict[k.strip()] = v.strip()
    if not cred_dict:
        click.echo("at least one --cred is required", err=True)
        raise click.Abort()
    # Build the adapter the same way the HTTP endpoint does.
    from safecadence.platform.adapters.identity_adapters import (
        ActiveDirectoryAdapter, CiscoISEAdapter, EntraIDAdapter,
        HPEClearPassAdapter, OktaAdapter,
    )
    classes = {
        "okta": OktaAdapter, "ise": CiscoISEAdapter,
        "ad": ActiveDirectoryAdapter, "entra": EntraIDAdapter,
        "clearpass": HPEClearPassAdapter,
    }
    adapter = classes[system](target=target, credentials=cred_dict)
    click.echo(f"\n  Testing {system} → {target} …")
    try:
        result = adapter.test_connection() or {}
    except Exception as exc:
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    if not result.get("ok"):
        click.echo(f"  ✗ Test failed: {result.get('error', 'unknown error')}",
                   err=True)
        click.echo("  Nothing was saved. Fix credentials and retry.",
                   err=True)
        raise click.Abort()
    click.echo(f"  ✓ Test passed.")
    if not save:
        click.echo("  --test-only: nothing saved. Re-run with --save to persist.")
        return
    from safecadence.identity.vault import IdentityVault
    IdentityVault().save_creds(
        system=system, target=target,
        credentials=cred_dict, test_passed=True,
        actor="cli",
    )
    click.echo(f"  ✓ Saved to vault. Run "
               f"`safecadence identity sync {system}` to pull data.")


@identity_cli.command("sync")
@click.argument("system",
                type=click.Choice(["okta", "entra", "ise", "clearpass", "ad"]))
def cmd_identity_sync(system):
    """Pull users/groups/policies from a connected system. Read-only —
    write-back uses `identity apply` separately, gated by confirm_token.
    """
    from safecadence.identity.vault import IdentityVault
    from safecadence.platform.adapters.identity_adapters import (
        ActiveDirectoryAdapter, CiscoISEAdapter, EntraIDAdapter,
        HPEClearPassAdapter, OktaAdapter,
    )
    classes = {
        "okta": OktaAdapter, "ise": CiscoISEAdapter,
        "ad": ActiveDirectoryAdapter, "entra": EntraIDAdapter,
        "clearpass": HPEClearPassAdapter,
    }
    vault = IdentityVault()
    rec = vault.load_creds(system)
    if rec is None:
        click.echo(f"\n  ✗ {system} is not connected. Run "
                   f"`safecadence identity connect {system} ... --save` first.",
                   err=True)
        raise click.Abort()
    adapter = classes[system](target=rec.target,
                                credentials=dict(rec.credentials))
    asset_id = f"{system}:{rec.target}"
    click.echo(f"\n  Syncing {system} → {rec.target} …")
    try:
        raw = adapter.collect(asset_id) or {}
    except Exception as exc:
        click.echo(f"  ✗ collect failed: {exc}", err=True)
        raise click.Abort()
    if isinstance(raw, dict) and raw.get("error"):
        click.echo(f"  ✗ {system} returned error: {raw['error']}", err=True)
        raise click.Abort()
    counts = {}
    for k, v in raw.items():
        if isinstance(v, list):
            counts[k] = len(v)
        elif isinstance(v, dict) and isinstance(v.get("value"), list):
            counts[k] = len(v["value"])
    unified = adapter.normalize(asset_id, raw)
    from safecadence.server.platform_api import save_asset
    save_asset(unified)
    vault.mark_synced(system)
    click.echo(f"  ✓ Synced. Counts: " +
               ", ".join(f"{k}={n}" for k, n in counts.items()))
    click.echo(f"  Asset: {asset_id}")


@identity_cli.command("disconnect")
@click.argument("system",
                type=click.Choice(["okta", "entra", "ise", "clearpass", "ad"]))
def cmd_identity_disconnect(system):
    """Remove a saved connector from the vault. Idempotent."""
    from safecadence.identity.vault import IdentityVault
    removed = IdentityVault().disconnect(system)
    click.echo(f"\n  {'✓ Removed' if removed else '— Not connected (no-op)'}: {system}")


@identity_cli.group("nhi")
def identity_nhi_cli():
    """Non-human identity registry — service accounts, API keys, IAM roles."""
    pass


@identity_nhi_cli.command("list")
@click.option("--include-deprecated/--no-deprecated", default=False)
def cmd_nhi_list(include_deprecated):
    from safecadence.identity import nhi_store
    rows = nhi_store.list_all()
    if not include_deprecated:
        rows = [r for r in rows if not r.deprecated]
    if not rows:
        click.echo("(no NHIs registered)")
        return
    click.echo(f"\n  {len(rows)} NHI(s):")
    for r in rows:
        last_rot = (r.last_rotated_at or "never")[:10]
        click.echo(f"    {r.nhi_id}  {r.name:24s}  {r.subtype:18s}  "
                   f"owner={r.owner or '—':24s}  last_rot={last_rot}")


@identity_nhi_cli.command("add")
@click.option("--name", required=True)
@click.option("--subtype", default="service_account")
@click.option("--owner", default="")
@click.option("--provider", default="")
@click.option("--rotation-days", "rotation_policy_days", default=0, type=int)
def cmd_nhi_add(name, subtype, owner, provider, rotation_policy_days):
    from safecadence.identity import nhi_store
    rec = nhi_store.register(
        name=name, subtype=subtype, owner=owner, provider=provider,
        rotation_policy_days=rotation_policy_days,
    )
    click.echo(f"\n  ✓ Registered {rec.nhi_id} — {rec.name}")


@identity_nhi_cli.command("attest")
@click.argument("nhi_id")
@click.option("--by", default="cli")
def cmd_nhi_attest(nhi_id, by):
    from safecadence.identity import nhi_store
    try:
        rec = nhi_store.attest(nhi_id, by=by)
    except KeyError:
        click.echo(f"\n  ✗ NHI not found: {nhi_id}", err=True)
        raise click.Abort()
    click.echo(f"\n  ✓ Attested {rec.nhi_id} by {rec.attested_by} at "
               f"{rec.attested_at}")


@identity_nhi_cli.command("rotate")
@click.argument("nhi_id")
def cmd_nhi_rotate(nhi_id):
    from safecadence.identity import nhi_store
    try:
        rec = nhi_store.rotate(nhi_id)
    except KeyError:
        click.echo(f"\n  ✗ NHI not found: {nhi_id}", err=True)
        raise click.Abort()
    click.echo(f"\n  ✓ Rotated {rec.nhi_id} at {rec.last_rotated_at}")


@identity_nhi_cli.command("findings")
@click.option("--stale-days", default=90, type=int,
              help="Emit a finding when last_used_at is older than N days.")
def cmd_nhi_findings(stale_days):
    from safecadence.identity import nhi_store
    fs = nhi_store.stale_findings(stale_unused_days=stale_days)
    if not fs:
        click.echo("(no stale or rotation-overdue NHIs)")
        return
    click.echo(f"\n  {len(fs)} NHI finding(s):")
    for f in fs:
        click.echo(f"    [{f['severity'].upper():8s}] {f['title']}")


# --------------------------------------------------------------------------
# v9.45 — CLI parity for users / webhooks / notify-prefs.
# Headless ops parity: anything you can do in /users or /settings#webhooks
# you can also do from a script. No new functionality — these wrap the
# same upsert/list/delete calls the HTTP endpoints already use.
# --------------------------------------------------------------------------


@cli.group("users")
def users_cli():
    """Manage the user directory (admin / approver / viewer)."""


@users_cli.command("list")
@click.option("--tenant", default="default", show_default=True)
@click.option("--users-file", default="safecadence-users.yaml",
              show_default=True)
def cmd_users_list(tenant, users_file):
    from safecadence.users import directory as _dir
    from pathlib import Path as _Path
    rows = _dir.list_users(tenant=tenant, path=_Path(users_file))
    if not rows:
        click.echo(f"(no users in tenant {tenant!r} — add one with "
                    "'safecadence users add')")
        return
    click.echo(f"  {'username':<18} {'role':<14} {'email':<30} display_name")
    click.echo(f"  {'-' * 18} {'-' * 14} {'-' * 30} {'-' * 24}")
    for u in rows:
        click.echo(f"  {u.username:<18} {','.join(u.roles)[:14]:<14} "
                   f"{u.email[:30]:<30} {u.display_name}")


@users_cli.command("add")
@click.argument("username")
@click.option("--email", required=True)
@click.option("--role", "roles", multiple=True, default=("viewer",),
              show_default=True,
              type=click.Choice(["admin", "approver", "operator", "viewer"]))
@click.option("--display-name", default="")
@click.option("--tenant", default="default", show_default=True)
@click.option("--users-file", default="safecadence-users.yaml",
              show_default=True)
def cmd_users_add(username, email, roles, display_name, tenant, users_file):
    from safecadence.users import directory as _dir
    from pathlib import Path as _Path
    body = {"username": username, "email": email,
            "roles": list(roles), "display_name": display_name}
    try:
        rec = _dir.upsert_user(body, tenant=tenant,
                                path=_Path(users_file))
    except ValueError as exc:
        click.echo(f"  ✗ {exc}", err=True)
        raise click.Abort()
    click.echo(f"  ✓ user {rec.username} ({','.join(rec.roles)}) saved "
               f"to tenant {tenant}")


@users_cli.command("delete")
@click.argument("username")
@click.option("--tenant", default="default", show_default=True)
@click.option("--users-file", default="safecadence-users.yaml",
              show_default=True)
@click.confirmation_option(prompt="Delete this user?")
def cmd_users_delete(username, tenant, users_file):
    from safecadence.users import directory as _dir
    from pathlib import Path as _Path
    ok = _dir.delete_user(username, tenant=tenant,
                           path=_Path(users_file))
    if not ok:
        click.echo(f"  ✗ no such user: {username}", err=True)
        raise click.Abort()
    click.echo(f"  ✓ deleted {username}")


@cli.group("webhooks")
def webhooks_cli():
    """Manage outbound webhooks (Slack, Teams, PagerDuty, ...)."""


@webhooks_cli.command("list")
def cmd_webhooks_list():
    from safecadence.notifier import webhook_registry as _wh
    rows = _wh.list_webhooks()
    if not rows:
        click.echo("(no webhooks — add one with 'safecadence webhooks add')")
        return
    click.echo(f"  {'id':<22} {'provider':<14} {'on?':<5} {'sev':<8} "
               f"{'cats':<32} url")
    click.echo(f"  {'-' * 22} {'-' * 14} {'-' * 5} {'-' * 8} "
               f"{'-' * 32} {'-' * 24}")
    for w in rows:
        cats = ",".join(w.categories or []) or "(any)"
        click.echo(f"  {w.id:<22} {w.provider:<14} "
                   f"{'on' if w.enabled else 'off':<5} "
                   f"{(w.min_severity or 'any'):<8} {cats[:32]:<32} "
                   f"{w.to_public_dict().get('url_preview', '')}")


@webhooks_cli.command("add")
@click.argument("id_")
@click.option("--url", required=True)
@click.option("--provider", default="",
              help="Auto-detected from URL if blank.")
@click.option("--api-token", default="",
              help="Required for opsgenie/pagerduty/webex/servicenow.")
@click.option("--signing-secret", default="",
              help="Required for generic_hmac provider.")
@click.option("--category", "categories", multiple=True,
              help="Restrict to these NOTIFY_CATEGORIES (repeatable).")
@click.option("--min-severity", default="",
              type=click.Choice(["", "info", "low", "medium", "high",
                                  "critical"]))
@click.option("--enabled/--disabled", default=True, show_default=True)
@click.option("--notes", default="")
def cmd_webhooks_add(id_, url, provider, api_token, signing_secret,
                     categories, min_severity, enabled, notes):
    from safecadence.notifier import webhook_registry as _wh
    body = {"id": id_, "url": url, "provider": provider,
            "categories": list(categories),
            "min_severity": min_severity,
            "enabled": enabled, "notes": notes}
    if api_token:
        body["api_token"] = api_token
    if signing_secret:
        body["signing_secret"] = signing_secret
    try:
        w = _wh.upsert(body)
    except ValueError as exc:
        click.echo(f"  ✗ {exc}", err=True)
        raise click.Abort()
    click.echo(f"  ✓ webhook {w.id} ({w.provider}) saved")


@webhooks_cli.command("delete")
@click.argument("id_")
@click.confirmation_option(prompt="Delete this webhook?")
def cmd_webhooks_delete(id_):
    from safecadence.notifier import webhook_registry as _wh
    if not _wh.delete(id_):
        click.echo(f"  ✗ no such webhook: {id_}", err=True)
        raise click.Abort()
    click.echo(f"  ✓ deleted {id_}")


@webhooks_cli.command("test")
@click.argument("id_")
def cmd_webhooks_test(id_):
    """Send a synthetic event through this webhook to prove the wire."""
    from safecadence.notifier import webhook_registry as _wh
    w = _wh.get(id_)
    if not w:
        click.echo(f"  ✗ no such webhook: {id_}", err=True)
        raise click.Abort()
    event = {"kind": "finding_critical",
             "title": f"SafeCadence webhook test ({id_})",
             "summary": "If you see this, the wire works end-to-end.",
             "severity": "info",
             "link": "/settings#webhooks"}
    ok, detail = _wh.fire_one(w, event)
    if ok:
        click.echo(f"  ✓ test delivered: {detail}")
    else:
        click.echo(f"  ✗ test failed: {detail}", err=True)
        raise click.Abort()


@cli.group("notify-prefs")
def notify_prefs_cli():
    """Inspect or set per-user notification routing preferences."""


@notify_prefs_cli.command("get")
@click.argument("username")
@click.option("--tenant", default="default", show_default=True)
@click.option("--users-file", default="safecadence-users.yaml",
              show_default=True)
def cmd_notify_prefs_get(username, tenant, users_file):
    from safecadence.users import directory as _dir
    from safecadence.notifier import prefs as _prefs
    from pathlib import Path as _Path
    rec = next((u for u in _dir.list_users(tenant=tenant,
                                            path=_Path(users_file))
                 if u.username == username), None)
    if not rec:
        click.echo(f"  ✗ no such user: {username}", err=True)
        raise click.Abort()
    p = _prefs.user_prefs(rec)
    if not p:
        click.echo(f"  (no overrides — falls back to tenant defaults)")
        return
    for cat, chans in sorted(p.items()):
        click.echo(f"  {cat:<22} {','.join(chans) or '(none)'}")


@notify_prefs_cli.command("set")
@click.argument("username")
@click.argument("category")
@click.option("--channel", "channels", multiple=True,
              help="Channels for this category (repeatable). "
                    "Pass with no value to clear.")
@click.option("--tenant", default="default", show_default=True)
@click.option("--users-file", default="safecadence-users.yaml",
              show_default=True)
def cmd_notify_prefs_set(username, category, channels, tenant, users_file):
    from safecadence.users import directory as _dir
    from pathlib import Path as _Path
    rec = next((u for u in _dir.list_users(tenant=tenant,
                                            path=_Path(users_file))
                 if u.username == username), None)
    if not rec:
        click.echo(f"  ✗ no such user: {username}", err=True)
        raise click.Abort()
    new_prefs = dict(rec.notify_prefs or {})
    new_prefs[category] = list(channels)
    body = {"username": rec.username,
            "roles": list(rec.roles),
            "email": rec.email,
            "display_name": rec.display_name,
            "notify_prefs": new_prefs}
    _dir.upsert_user(body, tenant=tenant, path=_Path(users_file))
    click.echo(f"  ✓ set {category} → {','.join(channels) or '(none)'} "
               f"for {username}")


# --------------------------------------------------------------------------
# v9.48 — CLI parity for capability-based RBAC.
# --------------------------------------------------------------------------


@cli.group("capabilities")
def caps_cli():
    """Inspect / grant / revoke per-user capabilities."""


@caps_cli.command("list-types")
def cmd_caps_list_types():
    """Print every grantable capability + its description + the
    role floor (which roles get it for free).

    The keys you see here are exactly what `grant` / `revoke`
    accept as the second argument."""
    from safecadence.capabilities.constants import (
        ALL_CAPABILITIES, DESCRIPTIONS, ROLE_FLOOR,
    )
    # Build inverted index: capability → list of roles that include it
    by_role: dict[str, list[str]] = {c: [] for c in ALL_CAPABILITIES}
    for role, caps in ROLE_FLOOR.items():
        if role == "admin":
            continue                # admin gets all by short-circuit
        for c in caps:
            by_role.setdefault(c, []).append(role)
    click.echo(f"\n  {len(ALL_CAPABILITIES)} capabilities:\n")
    click.echo(f"  {'capability':<32} {'role-floor':<32} description")
    click.echo(f"  {'-' * 32} {'-' * 32} {'-' * 36}")
    for c in ALL_CAPABILITIES:
        roles = ",".join(sorted(by_role.get(c, []))) or "—"
        desc = DESCRIPTIONS.get(c, "")[:36]
        click.echo(f"  {c:<32} {roles:<32} {desc}")
    click.echo(f"\n  admin role short-circuits all of the above. "
                "Use `safecadence capabilities grant <user> <key>` to "
                "extend a non-admin user.\n"
                "  Note: the legacy execute_real check + v9.50 dual-gate "
                "means execute.real also requires an explicit grant "
                "EVEN FOR ADMINS.\n")


@caps_cli.command("list")
@click.option("--tenant", default="default", show_default=True)
def cmd_caps_list(tenant):
    from safecadence.capabilities import list_grants
    rows = list_grants(tenant=tenant)
    if not rows:
        click.echo(f"(no per-user capability grants in tenant {tenant!r})")
        return
    click.echo(f"  {'user':<14} {'grants':<40} {'denies':<30}")
    click.echo(f"  {'-' * 14} {'-' * 40} {'-' * 30}")
    for r in rows:
        click.echo(f"  {r.username:<14} "
                   f"{(','.join(r.grant) or '—')[:40]:<40} "
                   f"{(','.join(r.deny) or '—')[:30]:<30}")


@caps_cli.command("show")
@click.argument("username")
@click.option("--tenant", default="default", show_default=True)
def cmd_caps_show(username, tenant):
    from safecadence.capabilities.store import (
        get_grant, user_capabilities,
    )
    from safecadence.capabilities.constants import DESCRIPTIONS
    from safecadence.users import directory as _dir
    rec = next((u for u in _dir.list_users(tenant=tenant)
                 if u.username == username), None)
    roles = list(rec.roles) if rec else []
    eff = sorted(user_capabilities(username=username, roles=roles,
                                      tenant=tenant))
    cap = get_grant(username, tenant=tenant)
    click.echo(f"\n  User:    {username}")
    click.echo(f"  Tenant:  {tenant}")
    click.echo(f"  Roles:   {','.join(roles) or '—'}")
    click.echo(f"  Grants:  {','.join(cap.grant) or '—'}")
    click.echo(f"  Denies:  {','.join(cap.deny) or '—'}")
    click.echo(f"  Effective ({len(eff)}):")
    for c in eff:
        desc = DESCRIPTIONS.get(c, "")
        click.echo(f"    • {c:<32} {desc}")


@caps_cli.command("grant")
@click.argument("username")
@click.argument("capability")
@click.option("--tenant", default="default", show_default=True)
@click.option("--actor", default="cli", show_default=True,
              help="Audit-trail attribution for this grant.")
@click.option("--reason", default="",
              help="Free-text justification (logged).")
def cmd_caps_grant(username, capability, tenant, actor, reason):
    from safecadence.capabilities.store import grant
    try:
        rec = grant(username, capability, tenant=tenant,
                     actor=actor, reason=reason)
    except ValueError as exc:
        click.echo(f"  ✗ {exc}", err=True)
        raise click.Abort()
    click.echo(f"  ✓ granted {capability} to {rec.username}")


@caps_cli.command("revoke")
@click.argument("username")
@click.argument("capability")
@click.option("--tenant", default="default", show_default=True)
@click.option("--actor", default="cli", show_default=True)
@click.option("--reason", default="")
def cmd_caps_revoke(username, capability, tenant, actor, reason):
    from safecadence.capabilities.store import revoke
    try:
        rec = revoke(username, capability, tenant=tenant,
                      actor=actor, reason=reason)
    except ValueError as exc:
        click.echo(f"  ✗ {exc}", err=True)
        raise click.Abort()
    click.echo(f"  ✓ revoked {capability} from {rec.username}")


@caps_cli.command("clear-deny")
@click.argument("username")
@click.argument("capability")
@click.option("--tenant", default="default", show_default=True)
@click.option("--actor", default="cli", show_default=True)
@click.option("--reason", default="")
def cmd_caps_clear_deny(username, capability, tenant, actor, reason):
    """Clear an explicit deny without granting — falls back to the
    role floor for this user."""
    from safecadence.capabilities.store import clear_deny
    try:
        rec = clear_deny(username, capability, tenant=tenant,
                          actor=actor, reason=reason)
    except ValueError as exc:
        click.echo(f"  ✗ {exc}", err=True)
        raise click.Abort()
    click.echo(f"  ✓ cleared deny on {capability} for {rec.username}")


# --------------------------------------------------------------------------
# v9.50 — CLI parity for IdP-sourced approver groups.
# --------------------------------------------------------------------------


@cli.group("groups")
def groups_cli():
    """Inspect or refresh the IdP-sourced approver-group cache."""


@groups_cli.command("list")
@click.option("--system", default="",
              help="Filter to one system (okta / entra / ad / ise / clearpass).")
def cmd_groups_list(system):
    from safecadence.identity.groups import list_groups, stale_groups
    rows = list_groups(system=(system or None))
    if not rows:
        click.echo("(no groups cached — run 'safecadence groups refresh' "
                   "or wait for the daemon cycle)")
        return
    stale_set = {(g.system, g.id) for g in stale_groups()}
    click.echo(f"  {'system':<10} {'name':<28} {'members':<8} synced")
    click.echo(f"  {'-' * 10} {'-' * 28} {'-' * 8} {'-' * 24}")
    for g in rows:
        flag = "  STALE" if (g.system, g.id) in stale_set else ""
        click.echo(f"  {g.system:<10} {g.name[:28]:<28} "
                   f"{len(g.members):<8} {g.synced_at or '—'}{flag}")


@groups_cli.command("show")
@click.argument("name_or_id")
def cmd_groups_show(name_or_id):
    from safecadence.identity.groups import get_group
    g = get_group(name_or_id)
    if not g:
        click.echo(f"  ✗ no such group: {name_or_id}", err=True)
        raise click.Abort()
    click.echo(f"\n  System:    {g.system}")
    click.echo(f"  ID:        {g.id}")
    click.echo(f"  Name:      {g.name}")
    click.echo(f"  Synced:    {g.synced_at or '—'}")
    click.echo(f"  Members ({len(g.members)}):")
    for m in g.members:
        click.echo(f"    • {m}")


@groups_cli.command("refresh")
def cmd_groups_refresh():
    """Force a synchronous refresh from every connected IdP."""
    from safecadence.identity.groups import refresh_from_adapters
    summary = refresh_from_adapters()
    if "error" in summary:
        click.echo(f"  ✗ {summary['error']}", err=True)
        raise click.Abort()
    if not summary:
        click.echo("(no connected identity systems)")
        return
    for sys_name, info in summary.items():
        if info.get("ok"):
            click.echo(f"  ✓ {sys_name}: {info['count']} group(s)")
        else:
            click.echo(f"  ✗ {sys_name}: {info.get('error', 'unknown error')}",
                        err=True)


# =====================================================================
# v9.55.1 — Activity log retention CLI
# =====================================================================
#
# Daemon hook (v9.54) handles ongoing retention. This CLI is for
# ad-hoc one-shot runs — the case where an operator wants to free
# disk *right now* without waiting for the next 30-min daemon cycle,
# or for non-daemon installs that just want a cron entry.

@cli.group("activity")
def activity_cli():
    """Inspect or prune the activity log."""


@activity_cli.command("prune")
@click.option("--retention", default=90, type=int,
              help="Delete YYYY-MM-DD.jsonl files older than N days. "
                    "Default 90.")
@click.option("--dry-run", is_flag=True,
              help="Print what would be deleted; don't actually delete.")
def cmd_activity_prune(retention, dry_run):
    """One-shot prune of the activity directory.

    Filename-based — looks at the YYYY-MM-DD stem of each .jsonl
    file, not mtime, so logrotate's copytruncate doesn't confuse
    it. Non-date-named files are left alone.
    """
    from datetime import datetime, timezone, timedelta
    import os
    from pathlib import Path
    days = max(1, int(retention))
    base = Path(os.environ.get("SC_DATA_DIR")
                  or (Path.home() / ".safecadence"))
    root = base / "activity"
    if not root.exists():
        click.echo(f"  (no activity dir at {root}; nothing to prune)")
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    if dry_run:
        # Walk + report only — don't call the real prune so we
        # honestly preview without touching disk.
        deleted = 0
        kept = 0
        freed = 0
        for p in sorted(root.glob("*.jsonl")):
            try:
                day = datetime.strptime(p.stem, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc)
            except ValueError:
                kept += 1
                continue
            if day < cutoff:
                deleted += 1
                try:
                    freed += p.stat().st_size
                except OSError:
                    pass
                click.echo(f"  would delete {p.name}")
            else:
                kept += 1
        click.echo(f"  Dry run: would delete {deleted} file(s), "
                   f"keep {kept}, free {freed} byte(s).")
        return
    # Real prune via the same module path the daemon uses, so the
    # behaviour stays identical.
    from safecadence.activity import prune as _prune
    summary = _prune(retention_days=days)
    click.echo(f"  ✓ retention={summary['retention_days']}d · "
               f"deleted={summary['deleted']} · "
               f"kept={summary['kept']} · "
               f"freed={summary['freed_bytes']} byte(s)")
    if summary.get("errors"):
        for e in summary["errors"]:
            click.echo(f"  ! {e}", err=True)


# =====================================================================
# v9.55 — Automation CLI parity
# =====================================================================
#
# Every other v9.x admin surface (users, webhooks, capabilities, groups,
# notify-prefs) has a CLI command group. Automation didn't until now —
# you had to either edit ~/.safecadence/intel/automation.json by hand
# or use the /automation web page. This group brings parity.

@cli.group("automation")
def automation_cli():
    """List, create, delete, preview, and inspect fires for
    automation rules."""


@automation_cli.command("list")
def cmd_automation_list():
    """List every saved automation rule with its enabled flag and
    last-fired timestamp."""
    from safecadence.intel.automation import list_rules
    import time as _time
    rows = list_rules()
    if not rows:
        click.echo("(no automation rules — create one with "
                   "'safecadence automation create' or in /automation)")
        return
    click.echo(f"  {'rule_id':<14} {'on':<3} {'name':<30} "
               f"{'when.kind':<14} last_fired")
    click.echo(f"  {'-' * 14} {'-' * 3} {'-' * 30} "
               f"{'-' * 14} {'-' * 24}")
    for r in rows:
        last = (_time.strftime("%Y-%m-%d %H:%M:%S",
                                  _time.gmtime(r.last_fired_at))
                 if r.last_fired_at else "never")
        kind = (r.when.get("kind") or "*") if r.when else "*"
        click.echo(f"  {r.rule_id:<14} "
                   f"{'on' if r.enabled else 'off':<3} "
                   f"{r.name[:30]:<30} {kind[:14]:<14} {last}")


@automation_cli.command("create")
@click.option("--name", required=True, help="Human-readable rule name.")
@click.option("--when-kind", default="",
              help="Finding kind to match (stale_nhi, no_mfa, etc.). "
                    "Empty = match every kind.")
@click.option("--when-severity-at-least", default="",
              help="Minimum severity (info|low|medium|high|critical).")
@click.option("--when-principal-match", default="",
              help="Regex against finding.principal.")
@click.option("--then-action", required=True,
              type=click.Choice(["auto_fix", "assign", "notify_log",
                                   "notify_slack", "add_to_watchlist",
                                   "add_comment", "notify_pagerduty",
                                   "notify_webhook"]),
              help="Single action to fire when matched.")
@click.option("--then-arg", multiple=True,
              help="key=value action arg (repeatable). E.g. "
                    "--then-arg to=alice@x or --then-arg commit=true")
@click.option("--rate-limit-seconds", default=3600, type=int,
              help="Don't refire on the same matching cycle within "
                    "this many seconds.")
@click.option("--disabled", is_flag=True,
              help="Save the rule disabled (default: enabled).")
def cmd_automation_create(name, when_kind, when_severity_at_least,
                            when_principal_match, then_action,
                            then_arg, rate_limit_seconds, disabled):
    """Save a one-action rule from the CLI. Multi-action rules need
    the JSON API or /automation."""
    from safecadence.intel.automation import save_rule
    when: dict = {}
    if when_kind:
        when["kind"] = when_kind
    if when_severity_at_least:
        when["severity_at_least"] = when_severity_at_least
    if when_principal_match:
        when["principal_match"] = when_principal_match
    action: dict = {"action": then_action}
    for kv in (then_arg or []):
        if "=" not in kv:
            click.echo(f"  ! ignoring malformed --then-arg {kv!r} "
                       "(expected key=value)", err=True)
            continue
        k, _, v = kv.partition("=")
        if v.lower() in ("true", "false"):
            action[k] = (v.lower() == "true")
        else:
            action[k] = v
    rule = save_rule({
        "name": name,
        "enabled": not disabled,
        "when": when,
        "then": [action],
        "rate_limit_seconds": int(rate_limit_seconds),
    })
    click.echo(f"  ✓ saved {rule.rule_id}: {rule.name} "
               f"({'enabled' if rule.enabled else 'DISABLED'})")


@automation_cli.command("delete")
@click.argument("rule_id")
def cmd_automation_delete(rule_id):
    """Delete a rule by id."""
    from safecadence.intel.automation import delete_rule
    if delete_rule(rule_id):
        click.echo(f"  ✓ deleted {rule_id}")
    else:
        click.echo(f"  ✗ no such rule: {rule_id}", err=True)
        raise click.Abort()


@automation_cli.command("preview")
def cmd_automation_preview():
    """Run every enabled rule against the current finding set and
    show what WOULD fire — apply_actions=False, side-effect-free."""
    from safecadence.intel.automation import evaluate_rules
    from safecadence.identity.findings import scan_findings
    try:
        from safecadence.server.platform_api import list_assets
        assets = list_assets()
    except Exception:
        assets = []
    findings = scan_findings(assets)
    fires = evaluate_rules(findings, apply_actions=False)
    if not fires:
        click.echo(f"  (0 rules would fire across "
                   f"{len(findings)} finding(s))")
        return
    click.echo(f"  {len(fires)} rule fire(s) would happen across "
               f"{len(findings)} finding(s):")
    for f in fires:
        click.echo(f"    • {f['rule_name']} → {f['action']} "
                   f"on {f['finding_id']} ({f['severity']}) "
                   f"→ {f['outcome']}")


@automation_cli.command("fires")
@click.option("--limit", default=20, type=int,
              help="How many recent fires to show (max 500).")
def cmd_automation_fires(limit):
    """Show the most recent rule-fires recorded in
    automation.json."""
    from safecadence.intel._store import read
    n = max(1, min(int(limit), 500))
    data = read("automation", {"rules": [], "fires": []})
    fires = sorted((data.get("fires") or []),
                    key=lambda f: f.get("at", 0), reverse=True)[:n]
    if not fires:
        click.echo("(no automation fires yet — run 'safecadence "
                   "daemon --once' or trigger via /automation preview)")
        return
    import time as _time
    click.echo(f"  {'when':<20} {'rule':<24} {'action':<18} "
               f"finding → outcome")
    click.echo(f"  {'-' * 20} {'-' * 24} {'-' * 18} {'-' * 30}")
    for f in fires:
        ts = (_time.strftime("%Y-%m-%d %H:%M:%S",
                                _time.gmtime(f.get("at", 0)))
                if f.get("at") else "—")
        click.echo(f"  {ts:<20} {(f.get('rule_name') or '')[:24]:<24} "
                   f"{(f.get('action') or '')[:18]:<18} "
                   f"{f.get('finding_id', '')} → {f.get('outcome', '')}")


# --------------------------------------------------------------------------- #
# `safecadence report` — compose / send / schedule reports from the CLI       #
# --------------------------------------------------------------------------- #


_REPORT_FORMATS = ["html", "pdf", "json", "docx", "pptx", "xlsx"]
_REPORT_PRESETS = ["exec_brief", "technical_deepdive",
                   "compliance_audit", "quarterly_review"]


@cli.group("report")
def report_cli():
    """Compose, email, and schedule reports from the command line."""


def _render_report_to_bytes(preset_id, fmt, sections, prepared_for,
                            org_name, primary_color):
    """Shared helper: compose + render, returns (bytes, applied_preset)."""
    from safecadence.reports.builder import compose_report
    from safecadence.reports.presets import apply_preset
    from safecadence.reports import renderers as _r

    applied = apply_preset(preset_id, {})
    section_list = list(sections) if sections else applied["sections"]
    report = compose_report(
        sections=section_list,
        scope=applied["scope"],
        title=f"SafeCadence NetRisk — {applied['name']}",
    )
    brand = {}
    if org_name:
        brand["org_name"] = org_name
    if primary_color:
        brand["primary_color"] = primary_color
    if prepared_for:
        brand["prepared_for"] = prepared_for
    if brand:
        report["brand"] = {**(report.get("brand") or {}), **brand}

    render_map = {
        "html":  ("render_html",  True),
        "pdf":   ("render_pdf",   True),
        "json":  ("render_json",  False),
        "docx":  ("render_docx",  True),
        "pptx":  ("render_pptx",  True),
        "xlsx":  ("render_xlsx",  True),
    }
    fn_name, accepts_preset = render_map[fmt]
    fn = getattr(_r, fn_name)
    rendered = fn(report, preset=applied) if accepts_preset else fn(report)
    if isinstance(rendered, str):
        rendered = rendered.encode("utf-8")
    return rendered, applied


@report_cli.command("compose")
@click.option("--preset", type=click.Choice(_REPORT_PRESETS), required=True,
              help="Preset (audience template) to use.")
@click.option("--format", "fmt", type=click.Choice(_REPORT_FORMATS),
              required=True, help="Output format.")
@click.option("--out", "out_path", type=click.Path(dir_okay=False),
              required=True, help="Path to write the rendered report to.")
@click.option("--prepared-for", default="",
              help="Organisation name printed on the cover page.")
@click.option("--org-name", default="",
              help="Organisation name shown in chrome (footer, header).")
@click.option("--primary-color", default="",
              help="Hex colour override for accents (e.g. #1f6f6a).")
@click.option("--sections", default="",
              help="Comma-separated section keys to override the preset's default set.")
def report_compose(preset, fmt, out_path, prepared_for, org_name,
                   primary_color, sections):
    """Compose + render a report to disk."""
    section_list = [s.strip() for s in sections.split(",") if s.strip()]
    try:
        data, _applied = _render_report_to_bytes(
            preset, fmt, section_list,
            prepared_for, org_name, primary_color,
        )
    except Exception as exc:
        click.echo(f"  ! compose failed: {exc}", err=True)
        sys.exit(1)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    click.echo(f"Wrote: {out} ({len(data)} bytes)")
    sys.exit(0)


@report_cli.command("list-presets")
def report_list_presets():
    """Print the available report presets (id and name)."""
    from safecadence.reports.presets import list_presets
    for p in list_presets():
        click.echo(f"  {p['id']:<22} {p['name']}")


@report_cli.command("list-sections")
def report_list_sections():
    """Print the available report sections (key + description)."""
    from safecadence.reports.builder import list_section_keys
    for s in list_section_keys():
        click.echo(f"  {s['key']:<32} {s.get('description', '')}")


@report_cli.command("send")
@click.option("--preset", type=click.Choice(_REPORT_PRESETS), required=True)
@click.option("--format", "fmt", type=click.Choice(_REPORT_FORMATS),
              required=True)
@click.option("--to", "to_csv", required=True,
              help="Comma-separated recipient list.")
@click.option("--cc", "cc_csv", default="",
              help="Comma-separated CC list.")
@click.option("--subject", default="",
              help="Email subject. Default: 'SafeCadence <preset name>'.")
@click.option("--prepared-for", default="")
@click.option("--org-name", default="")
@click.option("--primary-color", default="")
@click.option("--sections", default="")
def report_send(preset, fmt, to_csv, cc_csv, subject, prepared_for,
                org_name, primary_color, sections):
    """Compose, render, and email a report in one shot."""
    from safecadence.reports import email_delivery as _email
    from safecadence.reports.presets import get_preset

    recipients = [t.strip() for t in to_csv.split(",") if t.strip()]
    cc = [c.strip() for c in cc_csv.split(",") if c.strip()]
    if not recipients:
        click.echo("  ! --to is required (no valid recipients)", err=True)
        sys.exit(1)

    section_list = [s.strip() for s in sections.split(",") if s.strip()]
    try:
        data, applied = _render_report_to_bytes(
            preset, fmt, section_list,
            prepared_for, org_name, primary_color,
        )
    except Exception as exc:
        click.echo(f"  ! compose failed: {exc}", err=True)
        sys.exit(1)

    nice_name = (get_preset(preset) or {}).get("name") or preset
    subj = subject or f"SafeCadence {nice_name}"
    filename = f"safecadence-{preset}.{fmt}"
    err = _email.send_report(
        recipients=recipients,
        cc=cc,
        subject=subj,
        body_text=f"Attached: SafeCadence NetRisk {nice_name} ({fmt.upper()}).",
        attachment_bytes=data,
        attachment_filename=filename,
        attachment_mimetype=_email.mimetype_for_format(fmt),
    )
    if err:
        click.echo(f"  ! send failed: {err}", err=True)
        sys.exit(1)
    click.echo(f"Sent: {filename} to {', '.join(recipients)} ({len(data)} bytes)")
    sys.exit(0)


# --- safecadence report schedule ... -------------------------------------- #


@report_cli.group("schedule")
def report_schedule_cli():
    """Manage scheduled report runs (cron-style)."""


@report_schedule_cli.command("list")
def report_schedule_list():
    """Show every scheduled report."""
    from safecadence.reports.scheduler import load_schedules
    items = load_schedules()
    if not items:
        click.echo("  (no schedules yet — use 'safecadence report schedule add')")
        return
    click.echo(f"  {'id':<28} {'cron':<14} {'preset':<22} "
               f"{'fmt':<5} {'last':<20} {'status'}")
    click.echo(f"  {'-'*28} {'-'*14} {'-'*22} {'-'*5} {'-'*20} {'-'*8}")
    for s in items:
        click.echo(
            f"  {(s.get('id') or '')[:28]:<28} "
            f"{(s.get('cron') or '')[:14]:<14} "
            f"{(s.get('preset') or '')[:22]:<22} "
            f"{(s.get('format') or '')[:5]:<5} "
            f"{(s.get('last_run') or '—'):<20} "
            f"{s.get('last_status') or '—'}"
        )


@report_schedule_cli.command("add")
@click.option("--preset", type=click.Choice(_REPORT_PRESETS), required=True)
@click.option("--format", "fmt", type=click.Choice(_REPORT_FORMATS),
              required=True)
@click.option("--to", "to_csv", required=True,
              help="Comma-separated recipient list.")
@click.option("--cc", "cc_csv", default="")
@click.option("--cron", "cron_expr", required=True,
              help='Cron expression, e.g. "0 8 * * MON".')
@click.option("--name", default="",
              help="Display name (defaults to '<preset>' if blank).")
@click.option("--subject", default="",
              help='Subject template — supports "{{date}}".')
@click.option("--prepared-for", default="")
@click.option("--disabled", is_flag=True,
              help="Add the schedule but don't run it until enabled.")
def report_schedule_add(preset, fmt, to_csv, cc_csv, cron_expr, name,
                        subject, prepared_for, disabled):
    """Add a new scheduled report."""
    from safecadence.reports.scheduler import add_schedule
    recipients = [t.strip() for t in to_csv.split(",") if t.strip()]
    cc = [c.strip() for c in cc_csv.split(",") if c.strip()]
    try:
        rec = add_schedule({
            "name": name or f"{preset} report",
            "cron": cron_expr,
            "preset": preset,
            "format": fmt,
            "to": recipients,
            "cc": cc,
            "subject": subject or f"SafeCadence {preset} — {{{{date}}}}",
            "prepared_for": prepared_for,
            "enabled": not disabled,
        })
    except Exception as exc:
        click.echo(f"  ! add failed: {exc}", err=True)
        sys.exit(1)
    click.echo(f"  ✓ added schedule {rec['id']} ({rec['cron']})")


@report_schedule_cli.command("remove")
@click.argument("schedule_id")
def report_schedule_remove(schedule_id):
    """Remove a schedule by id."""
    from safecadence.reports.scheduler import remove_schedule
    if remove_schedule(schedule_id):
        click.echo(f"  ✓ removed {schedule_id}")
    else:
        click.echo(f"  ✗ no such schedule: {schedule_id}", err=True)
        sys.exit(1)


@report_schedule_cli.command("run-due")
def report_schedule_run_due():
    """Run any schedules whose cron matches the current minute, once."""
    from safecadence.reports.scheduler import run_due
    results = run_due()
    if not results:
        click.echo("  (nothing due this minute)")
        return
    for r in results:
        status = "ok" if r.get("ok") else f"error: {r.get('error')}"
        click.echo(f"  {r.get('id')}: {status} "
                   f"({r.get('format')}, {r.get('size_bytes') or 0} bytes)")


@report_schedule_cli.command("daemon")
@click.option("--interval", default=60, show_default=True, type=int,
              help="Seconds between run_due() ticks.")
def report_schedule_daemon(interval):
    """Run scheduled reports forever (foreground)."""
    from safecadence.reports.scheduler import daemon_loop
    click.echo(f"  starting scheduler daemon (interval={interval}s)…")
    try:
        daemon_loop(interval_seconds=interval)
    except KeyboardInterrupt:
        click.echo("  daemon interrupted, exiting")
        sys.exit(0)


# --------------------------------------------------------------------------- #
# v10.8 — external finding ingestion (AWS Security Hub, etc.)                  #
# --------------------------------------------------------------------------- #


@cli.group("ingest")
def ingest_cli():
    """Pull findings from external sources (e.g. AWS Security Hub)."""


@ingest_cli.command("aws-security-hub")
@click.option("--region", default=None, help="AWS region (else AWS_REGION env).")
@click.option("--max", "max_findings", default=100, show_default=True, type=int,
              help="Maximum number of findings to fetch.")
@click.option("--profile", default=None,
              help="(Reserved) AWS profile name. Env credentials are required.")
@click.option("--output", "-o", type=click.Path(dir_okay=False), default=None,
              help="Write normalized JSON to this file instead of stdout.")
def ingest_aws_security_hub(region, max_findings, profile, output):
    """Fetch findings from AWS Security Hub + normalize for SafeCadence."""
    from safecadence.integrations import aws_security_hub as sh
    if not sh.is_configured():
        click.echo(
            "  ! AWS credentials missing — set AWS_ACCESS_KEY_ID and "
            "AWS_SECRET_ACCESS_KEY before running.",
            err=True,
        )
        sys.exit(2)
    rows = sh.ingest_findings(profile=profile, region=region, max=max_findings)
    payload = json.dumps(rows, indent=2, default=str)
    if output:
        Path(output).write_text(payload, encoding="utf-8")
        click.echo(f"  ✓ wrote {len(rows)} findings to {output}")
    else:
        click.echo(payload)


# --------------------------------------------------------------------------- #
# v11.2 — OpenAPI schema export (for SDK code generation in CI).               #
# --------------------------------------------------------------------------- #


@cli.group("openapi")
def openapi_cli():
    """Inspect or export the FastAPI OpenAPI schema."""


@openapi_cli.command("export")
@click.option("--out", "out_path", type=click.Path(dir_okay=False), default="openapi.json",
              show_default=True, help="Path to write the OpenAPI JSON schema.")
@click.option("--indent", default=2, show_default=True, type=int,
              help="JSON pretty-print indent (use 0 for compact).")
def openapi_export(out_path, indent):
    """Export the FastAPI OpenAPI 3.1 schema as JSON.

    Imports the FastAPI app from ``safecadence.ui.app`` (or the lightweight
    fallback if the optional ``server`` extras are not installed) and dumps
    ``app.openapi()`` to disk. Used by SDK code generation in CI.
    """
    try:
        from safecadence.ui.app import create_app
    except Exception as exc:  # pragma: no cover - import-time misconfiguration
        click.echo(f"  ! failed to import FastAPI app: {exc}", err=True)
        sys.exit(2)

    app = create_app()
    schema = None
    try:
        schema = app.openapi()
    except Exception as exc:
        # pydantic 2.13 has a known forward-ref bug that breaks
        # FastAPI's openapi() call. Fall back to a manual walk of the
        # route table so SDK generation in CI still works.
        click.echo(
            f"  ! app.openapi() raised ({type(exc).__name__}); "
            "falling back to route-table schema generator.",
            err=True,
        )
        try:
            from fastapi.routing import APIRoute
        except Exception:                            # pragma: no cover
            APIRoute = None
        paths: dict = {}
        for route in getattr(app, "routes", []):
            if APIRoute is None or not isinstance(route, APIRoute):
                continue
            entry = paths.setdefault(route.path, {})
            for method in sorted(m.lower() for m in route.methods if m != "HEAD"):
                entry[method] = {
                    "summary": route.summary or route.name,
                    "operationId": route.name,
                    "responses": {"200": {"description": "OK"}},
                }
        schema = {
            "openapi": "3.1.0",
            "info": {
                "title": "SafeCadence NetRisk API",
                "version": __version__,
            },
            "paths": paths,
        }

    # Stamp the schema with the current package version so SDK generators
    # produce versioned clients.
    schema.setdefault("info", {})
    schema["info"]["version"] = __version__
    schema["info"].setdefault("title", "SafeCadence NetRisk API")
    schema.setdefault("openapi", "3.1.0")

    pretty = json.dumps(schema, indent=indent if indent > 0 else None,
                        sort_keys=False, default=str)
    Path(out_path).write_text(pretty, encoding="utf-8")
    click.echo(f"  ✓ wrote OpenAPI schema (version {__version__}) to {out_path}")


# --------------------------------------------------------------------------- #
# v11.3 — Operations + governance commands.                                    #
#                                                                              #
# Group ``safecadence ops`` covers backup/restore, GDPR export, immutable      #
# audit chain verification, and data retention policy management.              #
# --------------------------------------------------------------------------- #


@cli.group("ops")
def ops_cli():
    """Operations + governance — backup, restore, retention, audit chain."""


@ops_cli.command("backup")
@click.option("--out", "out_dir", type=click.Path(file_okay=False), required=True,
              help="Directory to write the .tar.gz backup into.")
@click.option("--org-id", "include_orgs", multiple=True,
              help="Restrict to one or more org ids; repeat the flag. "
                   "Omit to back up every org.")
def cmd_ops_backup(out_dir, include_orgs):
    """Create a .tar.gz backup of all (or selected) org data."""
    from safecadence.ops.backup import create_backup
    orgs = list(include_orgs) if include_orgs else None
    path = create_backup(Path(out_dir), include_orgs=orgs)
    size_mb = path.stat().st_size / (1024 * 1024)
    click.echo(f"  ✓ wrote backup: {path} ({size_mb:.2f} MB)")


@ops_cli.command("verify")
@click.option("--from", "src", type=click.Path(exists=True, dir_okay=False), required=True,
              help="Path to a .tar.gz backup.")
def cmd_ops_verify(src):
    """Re-hash every file in a backup against MANIFEST.json."""
    from safecadence.ops.backup import verify_backup
    result = verify_backup(src)
    if result["ok"]:
        click.echo(f"  ✓ backup OK — {result['file_count']} files verified")
        sys.exit(0)
    click.echo(f"  ✗ backup BROKEN — {len(result['errors'])} error(s):", err=True)
    for err in result["errors"][:25]:
        click.echo(f"    - {err}", err=True)
    sys.exit(1)


@ops_cli.command("restore")
@click.option("--from", "src", type=click.Path(exists=True, dir_okay=False), required=True,
              help="Path to a .tar.gz backup.")
@click.option("--target-dir", type=click.Path(file_okay=False), default=None,
              help="Destination dir (default: live SafeCadence home).")
@click.option("--dry-run", is_flag=True,
              help="Verify the backup but do not extract.")
def cmd_ops_restore(src, target_dir, dry_run):
    """Extract a backup into the SafeCadence home (or --target-dir)."""
    from safecadence.ops.backup import restore_backup
    result = restore_backup(src, target_dir=target_dir, dry_run=dry_run)
    if result["ok"]:
        verb = "verified" if dry_run else "restored"
        click.echo(f"  ✓ {verb} {result['restored']} files → {result['target']}")
        sys.exit(0)
    click.echo("  ✗ restore failed:", err=True)
    for err in result["errors"][:25]:
        click.echo(f"    - {err}", err=True)
    sys.exit(1)


@ops_cli.command("export-org")
@click.option("--org-id", required=True, help="Org id to export.")
@click.option("--out", "out_path", type=click.Path(dir_okay=False), required=True,
              help="Output JSON path.")
@click.option("--include-blobs", is_flag=True,
              help="Inline evidence file bytes (base64).")
def cmd_ops_export_org(org_id, out_path, include_blobs):
    """Produce a GDPR-style JSON export of one org."""
    from safecadence.ops.export_org import export_org
    p = export_org(org_id, Path(out_path), include_blobs=include_blobs)
    size_kb = p.stat().st_size / 1024
    click.echo(f"  ✓ exported org {org_id} → {p} ({size_kb:.1f} KB)")


@ops_cli.command("verify-audit")
@click.option("--org-id", required=True, help="Org id whose audit chain to verify.")
def cmd_ops_verify_audit(org_id):
    """Walk the hash-chained audit log and confirm integrity."""
    from safecadence.audit.log import verify_chain
    res = verify_chain(org_id)
    if res["ok"]:
        click.echo(f"  ✓ audit chain OK — {res['line_count']} event(s) verified")
        sys.exit(0)
    click.echo(
        f"  ✗ audit chain BROKEN at line {res['broken_at_line']} "
        f"(of {res['line_count']} read)",
        err=True,
    )
    sys.exit(1)


@ops_cli.group("retention")
def retention_cli():
    """Show / set / apply retention policies for an org."""


@retention_cli.command("show")
@click.option("--org-id", required=True)
def cmd_retention_show(org_id):
    """Print the org's current retention policies."""
    from safecadence.ops.retention import get_retention
    pol = get_retention(org_id)
    click.echo(f"Retention policies for {org_id}:")
    for kind in ("scans", "audit", "reports", "errors"):
        p = pol[kind]
        click.echo(f"  {kind:8s}  keep_days={p.keep_days:5d}  min_count={p.keep_min_count}")


@retention_cli.command("set")
@click.option("--org-id", required=True)
@click.option("--kind", type=click.Choice(["scans", "audit", "reports", "errors"]),
              required=True)
@click.option("--keep-days", type=int, required=True)
@click.option("--keep-min-count", type=int, default=50, show_default=True)
def cmd_retention_set(org_id, kind, keep_days, keep_min_count):
    """Update a single-kind retention policy for an org."""
    from safecadence.ops.retention import set_retention, RetentionPolicy
    pol = set_retention(
        org_id,
        RetentionPolicy(kind=kind, keep_days=keep_days, keep_min_count=keep_min_count),
    )
    new = pol[kind]
    click.echo(f"  ✓ {org_id} {kind}: keep_days={new.keep_days} min={new.keep_min_count}")


@retention_cli.command("apply")
@click.option("--org-id", required=True)
def cmd_retention_apply(org_id):
    """Run a retention pass for an org, return what was purged."""
    from safecadence.ops.retention import apply_retention
    report = apply_retention(org_id)
    click.echo(f"Retention pass for {org_id}:")
    for kind in ("scans", "audit", "reports", "errors"):
        v = report.get(kind, {})
        click.echo(
            f"  {kind:8s}  before={v.get('before', 0):5d}  "
            f"after={v.get('after', 0):5d}  purged={v.get('purged', 0):5d}"
        )
    click.echo(f"  total purged: {report.get('total_purged', 0)}")


if __name__ == "__main__":   # pragma: no cover
    cli()
