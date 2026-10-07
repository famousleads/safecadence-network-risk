"""Authorized organization-brand CSV evidence; never search or identify people."""
from __future__ import annotations

import csv
import io
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from .security_import import MAX_BYTES, MAX_RECORDS, ImportRejected, digest, timestamp

EXPOSURE_SOURCES = frozenset({"sherlock", "maigret"})
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
DECISIONS = ("confirmed-brand-account", "not-brand-account", "needs-more-evidence")


def identifier(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ImportRejected("invalid_brand_identifier")
    return value


def host(value):
    if not isinstance(value, str) or len(value) > 253 or not _HOST.fullmatch(value):
        raise ImportRejected("invalid_platform_host")
    return value


def validate_exposure_scope(scope):
    if (not isinstance(scope, dict) or
            set(scope) != {"subject_type", "authorization_ref", "brands"} or
            scope["subject_type"] != "organization-brand"):
        raise ImportRejected("organization_brand_scope_required")
    authority = identifier(scope["authorization_ref"])
    brands = scope["brands"]
    if not isinstance(brands, dict) or not 1 <= len(brands) <= 100:
        raise ImportRejected("invalid_brand_scope")
    result, seen = {}, set()
    for brand, config in brands.items():
        identifier(brand)
        if not isinstance(config, dict) or set(config) != {"usernames", "platform_hosts"}:
            raise ImportRejected("invalid_brand_scope")
        users, hosts = config["usernames"], config["platform_hosts"]
        if any(not isinstance(items, list) or not 1 <= len(items) <= 100 for items in (users, hosts)):
            raise ImportRejected("invalid_brand_scope")
        users, hosts = [identifier(item) for item in users], [host(item) for item in hosts]
        if len(set(users)) != len(users) or len(set(hosts)) != len(hosts) or seen.intersection(users):
            raise ImportRejected("ambiguous_brand_scope")
        seen.update(users)
        result[brand] = dict(usernames=sorted(users), platform_hosts=sorted(hosts))
    return dict(subject_type="organization-brand", authorization_ref=authority, brands=result)


def decode_exposure_csv(data, source, observed_at):
    if len(data) > MAX_BYTES:
        raise ImportRejected("file_size_limit")
    observed = timestamp(observed_at)
    if observed is None:
        raise ImportRejected("report_observation_time_required")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ImportRejected("invalid_encoding") from None
    expected = {"username", "name", "url_main", "url_user", "exists", "http_status",
                "response_time_s" if source == "sherlock" else "error_reason"}
    rows = []
    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(reader, [])
        if len(header) != len(expected) or set(header) != expected:
            raise ImportRejected("unsupported_exposure_csv_header")
        for values in reader:
            if not values:
                continue
            if len(values) != len(header) or any(len(value) > 4096 for value in values):
                raise ImportRejected("invalid_exposure_csv_row")
            if len(rows) >= MAX_RECORDS:
                raise ImportRejected("record_count_limit")
            rows.append(dict(zip(header, values), observed_at=observed))
    except csv.Error:
        raise ImportRejected("invalid_exposure_csv") from None
    return rows


def _url(value, allowed):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ImportRejected("invalid_account_url")
    decoded = unquote(value)
    if any(ord(char) <= 32 or ord(char) >= 127 for char in decoded) or "\\" in decoded:
        raise ImportRejected("invalid_account_url")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None or
                parsed.port is not None or parsed.query or parsed.fragment or "?" in value or "#" in value):
            raise ImportRejected("unsafe_account_url")
        if parsed.hostname not in allowed or parsed.netloc != parsed.hostname:
            raise ImportRejected("platform_out_of_scope")
        return urlunsplit(("https", parsed.hostname, parsed.path, "", ""))
    except ImportRejected:
        raise
    except ValueError:
        raise ImportRejected("invalid_account_url") from None


def normalize_exposure(row, scope):
    user = identifier(row.get("username"))
    matches = [(brand, spec) for brand, spec in scope["brands"].items() if user in spec["usernames"]]
    if len(matches) != 1:
        raise ImportRejected("brand_username_out_of_scope")
    brand, spec = matches[0]
    platform = identifier(row.get("name"))
    status = row.get("exists")
    if status not in {"Claimed", "Available", "Unknown", "Illegal"}:
        raise ImportRejected("unsupported_account_status")
    account_url = _url(row.get("url_user"), spec["platform_hosts"])
    main_url = _url(row.get("url_main"), spec["platform_hosts"])
    if urlsplit(main_url).hostname != urlsplit(account_url).hostname:
        raise ImportRejected("platform_identity_mismatch")
    observed = timestamp(row.get("observed_at"))
    if observed is None:
        raise ImportRejected("report_observation_time_required")
    return dict(source_event_id=digest([brand, user, platform, account_url, observed]),
                observed_at=observed, asset_ref=brand, kind="brand-exposure",
                title="Organization brand/account observation",
                evidence=dict(brand=brand, username=user, platform=platform,
                              account_url=account_url, source_status=status,
                              authorization_ref=scope["authorization_ref"],
                              review_status="unreviewed", identity_verified=False,
                              limitation="Account existence/username similarity does not prove ownership, impersonation or a person's identity."))
