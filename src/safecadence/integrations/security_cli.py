"""Offline security ecosystem CLI. Live connectors are deliberately absent."""
from __future__ import annotations

import json

import click

from .security_catalog import catalog, IMPORT_SOURCES
from .security_import import ImportRejected
from .security_store import SecurityEvidenceStore


@click.group("ecosystem")
@click.option("--db", type=click.Path(dir_okay=False), default=None,
              help="Local evidence SQLite path (default: SC_DATA_DIR/security-evidence.db).")
@click.pass_context
def ecosystem(ctx, db):
    """Import security evidence locally; view readiness, findings and audit."""
    ctx.ensure_object(dict)
    ctx.obj["security_db"] = db


def _print(value):
    click.echo(json.dumps(value, indent=2))


@ecosystem.command("catalog")
def catalog_cmd():
    """List 32 tracked projects with honest implementation status."""
    _print(catalog())


@ecosystem.command("import")
@click.argument("source", type=click.Choice(sorted(IMPORT_SOURCES)))
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--tenant", required=True)
@click.option("--instance", required=True, help="Sensor/manager identity; never inferred from an IP.")
@click.option("--source-version", required=True)
@click.option("--actor", default="local-operator")
@click.pass_context
def import_cmd(ctx, source, file, tenant, instance, source_version, actor):
    """Import a supplied JSON/JSONL export atomically, without network access."""
    store = SecurityEvidenceStore(ctx.obj["security_db"])
    try:
        _print(store.import_file(file, source=source, tenant=tenant, instance=instance,
                                 source_version=source_version, actor=actor))
    except ImportRejected as error:
        raise click.ClickException("Import rejected: " + str(error)) from None
    finally:
        store.close()


@ecosystem.command("events")
@click.option("--tenant", required=True)
@click.option("--source", type=click.Choice(sorted(IMPORT_SOURCES)))
@click.option("--limit", type=click.IntRange(1, 10000), default=100)
@click.pass_context
def events_cmd(ctx, tenant, source, limit):
    """Read source evidence; alerts are not verified compromise."""
    store = SecurityEvidenceStore(ctx.obj["security_db"])
    try:
        _print(store.events(tenant=tenant, source=source, limit=limit))
    finally:
        store.close()


@ecosystem.command("status")
@click.option("--tenant", required=True)
@click.pass_context
def status_cmd(ctx, tenant):
    """Show import receipts separately from unknown sensor health/coverage."""
    store = SecurityEvidenceStore(ctx.obj["security_db"])
    try:
        _print(store.status(tenant=tenant))
    finally:
        store.close()


@ecosystem.command("audit")
@click.option("--tenant", required=True)
@click.pass_context
def audit_cmd(ctx, tenant):
    """Read accepted/rejected imports and verify the local hash chain."""
    store = SecurityEvidenceStore(ctx.obj["security_db"])
    try:
        result = store.audit(tenant=tenant)
        _print(result)
        if not result["chain_valid"]:
            raise click.ClickException("Audit chain verification failed")
    finally:
        store.close()


@ecosystem.command("graph")
@click.option("--tenant", required=True)
@click.option("--output", required=True, type=click.Path(dir_okay=False))
@click.pass_context
def graph_cmd(ctx, tenant, output):
    """Project alert evidence into a local NetRisk graph (no observations-as-vulns)."""
    store = SecurityEvidenceStore(ctx.obj["security_db"])
    try:
        _print(store.export_graph(tenant=tenant, graph_path=output))
    finally:
        store.close()
