"""Local Public Safety pilot CLI; no live subscriptions or physical controls."""
from __future__ import annotations

import json

import click

from .public_safety_import import SOURCES
from .public_safety_exposure import DECISIONS
from .public_safety_store import PublicSafetyEvidenceStore
from .security_import import ImportRejected


@click.group("safety")
@click.option("--db", type=click.Path(dir_okay=False), default=None)
@click.pass_context
def safety(ctx, db):
    """Import scoped safety/brand evidence; never search, dispatch or control."""
    ctx.ensure_object(dict)
    ctx.obj["safety_db"] = db


def _run(ctx, method, **kwargs):
    store = PublicSafetyEvidenceStore(ctx.obj["safety_db"])
    try:
        result = getattr(store, method)(**kwargs)
        click.echo(json.dumps(result, indent=2))
        if method == "audit" and not result["chain_valid"]:
            raise click.ClickException("Audit chain verification failed")
    except (ImportRejected, OSError, ValueError):
        # Exceptions never echo untrusted payloads, credentials or filesystem paths.
        raise click.ClickException("Public Safety operation rejected; inspect the local audit for details.") from None
    finally:
        store.close()


@safety.command("register")
@click.argument("source", type=click.Choice(sorted(SOURCES)))
@click.option("--tenant", required=True)
@click.option("--site", required=True)
@click.option("--instance", required=True)
@click.option("--source-version", required=True)
@click.option("--purpose", required=True)
@click.option("--scope", "scope_file", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--stale-after", type=click.IntRange(30, 86400), default=300)
@click.option("--actor", default="local-operator")
@click.pass_context
def register_cmd(ctx, source, tenant, site, instance, source_version, purpose, scope_file, stale_after, actor):
    """Register explicit camera, sensor, device or authorized brand scope."""
    _run(ctx, "register_file", path=scope_file, tenant=tenant, site=site, source=source, instance=instance,
         source_version=source_version, purpose=purpose, stale_after=stale_after, actor=actor)


@safety.command("import")
@click.argument("source", type=click.Choice(sorted(SOURCES)))
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--tenant", required=True)
@click.option("--site", required=True)
@click.option("--instance", required=True)
@click.option("--actor", default="local-operator")
@click.option("--observed-at", default=None, help="Required report time with timezone for Sherlock/Maigret CSV only.")
@click.pass_context
def import_cmd(ctx, source, file, tenant, site, instance, actor, observed_at):
    """Import JSON/JSONL safety events or brand CSV atomically under scope."""
    _run(ctx, "import_file", path=file, source=source, tenant=tenant, site=site,
         instance=instance, actor=actor, observed_at=observed_at)


@safety.command("review-brand")
@click.argument("event_id")
@click.option("--tenant", required=True)
@click.option("--site", required=True)
@click.option("--decision", type=click.Choice(DECISIONS), required=True)
@click.option("--evidence-ref", required=True, help="Reference to reviewed local ownership evidence, not an external URL.")
@click.option("--expected-revision", type=click.IntRange(0), required=True)
@click.option("--actor", required=True, help="Local reviewer identifier; not authenticated by this CLI.")
@click.pass_context
def review_brand_cmd(ctx, event_id, tenant, site, decision, evidence_ref, expected_revision, actor):
    """Record a human brand-ownership decision bound to one evidence version."""
    _run(ctx, "review_brand", event_id=event_id, tenant=tenant, site=site, decision=decision,
         evidence_ref=evidence_ref, expected_revision=expected_revision, actor=actor)


@safety.command("events")
@click.option("--tenant", required=True)
@click.option("--site", required=True)
@click.option("--source", type=click.Choice(sorted(SOURCES)))
@click.option("--limit", type=click.IntRange(1, 10000), default=100)
@click.pass_context
def events_cmd(ctx, tenant, site, source, limit):
    """Read minimized observations, not vulnerabilities or identity findings."""
    _run(ctx, "events", tenant=tenant, site=site, source=source, limit=limit)


@safety.command("status")
@click.option("--tenant", required=True)
@click.option("--site", required=True)
@click.pass_context
def status_cmd(ctx, tenant, site):
    """Show export freshness and reported availability; live health stays unknown."""
    _run(ctx, "status", tenant=tenant, site=site)


@safety.command("audit")
@click.option("--tenant", required=True)
@click.pass_context
def audit_cmd(ctx, tenant):
    """Verify shared tenant evidence audit, including Public Safety mutations."""
    _run(ctx, "audit", tenant=tenant)
