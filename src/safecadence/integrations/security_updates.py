"""Explicit download-only exception: public NVD/Cisco PSIRT into local staging.

This is not cloud sync. No asset identifiers, credentials or customer evidence
are accepted by the request builder. Downloads never execute or activate fixes.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlencode

import click

from .security_import import MAX_BYTES, MAX_RECORDS, ImportRejected, _json, digest
from .security_store import SecurityEvidenceStore

SOURCES = {
    "nist-nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "cisco-psirt": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ImportRejected("update_redirect_denied")


def request_for(source, *, at=None):
    if source not in SOURCES:
        raise ImportRejected("update_source_not_allowed")
    url = SOURCES[source]
    if source == "nist-nvd":
        end = at or datetime.now(timezone.utc)
        if end.tzinfo is None:
            raise ImportRejected("update_timezone_required")
        end = end.astimezone(timezone.utc)
        start = end - timedelta(days=1)
        url += "?" + urlencode({
            "lastModStartDate": start.isoformat(timespec="seconds"),
            "lastModEndDate": end.isoformat(timespec="seconds"), "resultsPerPage": 2000,
        })
    return urllib.request.Request(url, method="GET", headers={
        "User-Agent": "SafeCadence-NetRisk-SecurityUpdates/1",
        "Accept": "application/json" if source == "nist-nvd" else "application/rss+xml, application/xml",
        "Accept-Encoding": "identity",
    })


def parse_update(source, data):
    if len(data) > MAX_BYTES:
        raise ImportRejected("update_size_limit")
    try:
        text = data.decode("utf-8-sig")
        if source == "nist-nvd":
            obj = _json(text)
            if not isinstance(obj, dict) or not isinstance(obj.get("vulnerabilities"), list):
                raise ImportRejected("invalid_nvd_update")
            records = obj["vulnerabilities"]
            if any(not isinstance(item, dict) or not isinstance(item.get("cve"), dict)
                   or not isinstance(item["cve"].get("id"), str) for item in records):
                raise ImportRejected("invalid_nvd_record")
            total = obj.get("totalResults")
            if not isinstance(total, int) or isinstance(total, bool) or total < len(records):
                raise ImportRejected("invalid_nvd_count")
            complete = obj.get("startIndex") == 0 and total == len(records)
        elif source == "cisco-psirt":
            if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
                raise ImportRejected("xml_entities_denied")
            root = ET.fromstring(text)
            if root.tag != "rss" or root.find("channel") is None:
                raise ImportRejected("invalid_psirt_feed")
            records = []
            for item in root.findall("channel/item"):
                title = item.findtext("title")
                if not title:
                    raise ImportRejected("invalid_psirt_record")
                published = item.findtext("pubDate")
                if published:
                    published = parsedate_to_datetime(published).isoformat()
                records.append(dict(title=title[:1024], link=item.findtext("link"),
                                    published_at=published, id=item.findtext("guid")))
            complete = False  # RSS is a publisher-selected list, not full historical coverage.
        else:
            raise ImportRejected("update_source_not_allowed")
    except (UnicodeDecodeError, ET.ParseError, ValueError, TypeError, RecursionError) as error:
        if isinstance(error, ImportRejected):
            raise
        raise ImportRejected("invalid_update_format") from None
    if len(records) > MAX_RECORDS:
        raise ImportRejected("update_record_limit")
    return dict(schema_version=1, source=source, fetched_at=datetime.now(timezone.utc).isoformat(),
                source_hash=hashlib.sha256(data).hexdigest(), records_hash=digest(records),
                complete=complete, records=records,
                authenticity="HTTPS transport; hashes are not publisher signatures",
                status="staged; not activated", coverage="Recent update window/feed, not a full database")


def download(source, output, *, enabled=False, opener=None, store=None):
    if not enabled:
        if store:
            with store.conn:
                store.conn.execute("BEGIN IMMEDIATE")
                store._audit("security-updates", "download", "denied",
                             reason="security_download_not_enabled")
        raise ImportRejected("security_download_not_enabled")
    req = request_for(source)
    path = Path(output)
    staged = None
    try:
        # Ignore inherited proxies; reject all redirects, not just cross-host ones.
        client = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with client.open(req, timeout=20) as response:
            if response.geturl() != req.full_url or response.status != 200:
                raise ImportRejected("unexpected_update_response")
            data = response.read(MAX_BYTES + 1)
        package = parse_update(source, data)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".security-update-", delete=False) as stream:
            staged = stream.name
            json.dump(package, stream, sort_keys=True, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, path)
        staged = None
        if store:
            with store.conn:
                store.conn.execute("BEGIN IMMEDIATE")
                store._audit("security-updates", "download", "staged", source=source,
                             records=len(package["records"]), records_hash=package["records_hash"],
                             complete=package["complete"])
        return {key: value for key, value in package.items() if key != "records"}
    except Exception:
        if store:
            with store.conn:
                store.conn.execute("BEGIN IMMEDIATE")
                store._audit("security-updates", "download", "failed", source=source,
                             reason="security_update_download_failed",
                             recommendation="Keep last-known-good data; review connectivity, source and format.")
        raise
    finally:
        if staged:
            Path(staged).unlink(missing_ok=True)


@click.group()
def cli():
    """Separate public-security-data updater; never sends customer evidence."""


@cli.command("sources")
def sources_cmd():
    click.echo(json.dumps(SOURCES, indent=2))


@cli.command("download")
@click.argument("source", type=click.Choice(sorted(SOURCES)))
@click.option("--output", required=True, type=click.Path(dir_okay=False))
@click.option("--allow-security-downloads", is_flag=True,
              help="Explicitly authorize this public-data download (default: disabled).")
def download_cmd(source, output, allow_security_downloads):
    store = SecurityEvidenceStore()
    try:
        click.echo(json.dumps(download(source, output, enabled=allow_security_downloads,
                                       store=store), indent=2))
    except Exception:
        raise click.ClickException("Security update failed or was not authorized; local data remains available.") from None
    finally:
        store.close()


if __name__ == "__main__":
    cli()
