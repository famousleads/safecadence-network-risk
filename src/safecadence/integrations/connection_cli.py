"""Trusted-local operator commands for explicitly approved read-only polling."""
import json
import sqlite3
from pathlib import Path

import click

from .local_connectors import ConnectorRejected, SOURCES, poll
from .security_import import MAX_BYTES, decode
from .security_store import SecurityEvidenceStore
from .public_safety_store import PublicSafetyEvidenceStore


@click.group("connections")
def connections():
    """Poll approved local sources; never modify a source or infer complete coverage."""


@connections.command("poll")
@click.option("--config", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--db", type=click.Path(dir_okay=False), default=None)
def poll_cmd(config, db):
    """Collect one bounded snapshot; credentials stay in owner-only local files."""
    store = None
    try:
        with Path(config).open("rb") as stream:
            rows = decode(stream.read(MAX_BYTES + 1), unwrap=False)
        if len(rows) != 1:
            raise ConnectorRejected("one_connector_config_required")
        value = rows[0]
        cls = SecurityEvidenceStore if value.get("source") in {"wazuh", "crowdsec"} else PublicSafetyEvidenceStore
        store = cls(db)
        click.echo(json.dumps(poll(store, value), indent=2))
    except (ConnectorRejected, OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        raise click.ClickException("Collection failed; preserve evidence and check storage and the local audit, which may be unavailable. No source changes were requested.") from None
    finally:
        if store:
            store.close()


@connections.command("capabilities")
def capabilities_cmd():
    """List available adapters, not connected deployments or installed engines."""
    click.echo(json.dumps(dict(sources=sorted(SOURCES), mode="read-only local HTTPS polling",
                             sensor_health="unknown until independently qualified",
                             stream_subscriptions=False, brand_searches=False), indent=2))
