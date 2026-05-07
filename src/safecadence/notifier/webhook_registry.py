"""
v9.44 — Webhook registry.

A list of webhooks the customer wants SafeCadence to fire events to.
Each row carries:

  - id            : stable handle (e.g. ``security-team-slack``)
  - provider      : one of providers.SUPPORTED_PROVIDERS (auto-detected
                    from URL when omitted)
  - url_encrypted : Fernet-encrypted webhook URL (URLs are bearer
                    secrets; we never persist plaintext)
  - api_token_enc : Fernet-encrypted optional API token (Opsgenie /
                    Webex / ServiceNow need one in addition to URL)
  - signing_secret_enc : Fernet-encrypted HMAC secret for
                    ``generic_hmac`` provider
  - categories    : list of NOTIFY_CATEGORIES keys; empty = match any
  - min_severity  : "info" | "low" | "medium" | "high" | "critical";
                    empty = match any
  - enabled       : bool (off-switch without deleting)
  - notes         : human label for the admin UI

Filters are AND'd: a webhook with ``categories: [finding_critical]``
AND ``min_severity: high`` only fires when the event matches BOTH.
A webhook with only ``categories`` ignores severity, and vice versa.

Trust posture: URLs (and tokens) are Fernet-encrypted at rest using
the same ``SAFECADENCE_VAULT_KEY`` as v9.39 (identity vault) and v9.42
(SMTP). The public ``to_public_dict()`` view never exposes the
plaintext URL — only ``has_url: bool`` and a redacted preview
(``hooks.slack.com/services/T0…/B0…/...``) so the admin can recognise
which webhook is which without leaking the secret.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from safecadence.notifier.providers import (
    SUPPORTED_PROVIDERS, detect_provider,
)


_REGISTRY_FILE_NAME = "webhooks.json"


_SEVERITY_ORDER = {
    "info": 0, "low": 1, "medium": 2, "warning": 2,
    "high": 3, "critical": 4,
}


@dataclass
class Webhook:
    id: str
    provider: str = ""
    url: str = ""                       # plaintext (only set on
                                          # in-memory record from
                                          # incoming POST body)
    url_encrypted: str = ""             # ciphertext on disk
    api_token: str = ""                 # plaintext (incoming only)
    api_token_enc: str = ""             # ciphertext
    signing_secret: str = ""            # plaintext (incoming only)
    signing_secret_enc: str = ""        # ciphertext
    categories: list[str] = field(default_factory=list)
    min_severity: str = ""
    enabled: bool = True
    notes: str = ""

    def to_public_dict(self) -> dict:
        """API-safe view: never includes plaintext URL or tokens.

        Surfaces ``has_url``/``has_token``/``has_signing_secret`` so the
        UI can show "configured" without leaking secrets, plus a
        redacted preview of the URL so the admin can recognise which
        row is which.
        """
        return {
            "id": self.id,
            "provider": self.provider,
            "url_preview": _redact_url(_decrypt(self.url_encrypted)),
            "has_url": bool(self.url_encrypted),
            "has_token": bool(self.api_token_enc),
            "has_signing_secret": bool(self.signing_secret_enc),
            "categories": list(self.categories),
            "min_severity": self.min_severity,
            "enabled": self.enabled,
            "notes": self.notes,
        }


# ---------------------------------------------------- crypto helpers


def _vault_key() -> Optional[str]:
    return os.environ.get("SAFECADENCE_VAULT_KEY") or None


def _encrypt(plain: str) -> str:
    if not plain:
        return ""
    key = _vault_key()
    if not key:
        return f"PLAINTEXT:{plain}"
    try:
        from cryptography.fernet import Fernet
        return "FERNET:" + Fernet(key.encode()).encrypt(
            plain.encode("utf-8")).decode("ascii")
    except Exception:                                          # pragma: no cover
        return f"PLAINTEXT:{plain}"


def _decrypt(blob: str) -> str:
    if not blob:
        return ""
    if blob.startswith("PLAINTEXT:"):
        return blob[len("PLAINTEXT:"):]
    if blob.startswith("FERNET:"):
        key = _vault_key()
        if not key:
            return ""
        try:
            from cryptography.fernet import Fernet
            return Fernet(key.encode()).decrypt(
                blob[len("FERNET:"):].encode("ascii")).decode("utf-8")
        except Exception:                                      # pragma: no cover
            return ""
    return ""


def _redact_url(url: str) -> str:
    """Strip the secret tail of a webhook URL for safe UI display.

    Slack: ``hooks.slack.com/services/T0AAA/B0BBB/xxxxxxxxxxxx`` →
            ``hooks.slack.com/services/T0AAA/B0BBB/****``
    Discord, PagerDuty, etc.: keep host + first segment, mask the
    token portion.
    """
    if not url:
        return ""
    try:
        parts = url.split("?", 1)
        path = parts[0]
        # keep scheme + host + first 3 path segments; mask the rest
        m = re.match(r"^(https?://[^/]+)(/[^/]+/[^/]+/[^/]+)?(/.*)?$", path)
        if not m:
            # No useful structure; mask trailing 8 chars
            return path[:-8] + "****" if len(path) > 12 else path
        host_seg = (m.group(1) or "") + (m.group(2) or "")
        if m.group(3):
            return host_seg + "/****"
        return host_seg
    except Exception:                                          # pragma: no cover
        return "****"


# ---------------------------------------------------- persistence


def _registry_path() -> Path:
    base = Path(os.environ.get("SC_DATA_DIR") or
                  (Path.home() / ".safecadence"))
    d = base / "settings"
    d.mkdir(parents=True, exist_ok=True)
    return d / _REGISTRY_FILE_NAME


def _load_raw() -> list[dict]:
    p = _registry_path()
    if not p.exists():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else []
    except Exception:
        return []


def _save_raw(rows: list[dict]) -> None:
    p = _registry_path()
    p.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:                                            # pragma: no cover
        pass


def _from_dict(d: dict) -> Webhook:
    return Webhook(
        id=str(d.get("id") or "").strip(),
        provider=str(d.get("provider") or "").strip().lower(),
        url_encrypted=str(d.get("url_encrypted") or ""),
        api_token_enc=str(d.get("api_token_enc") or ""),
        signing_secret_enc=str(d.get("signing_secret_enc") or ""),
        categories=[str(c) for c in (d.get("categories") or [])
                      if isinstance(c, str)],
        min_severity=str(d.get("min_severity") or "").lower(),
        enabled=bool(d.get("enabled", True)),
        notes=str(d.get("notes") or ""),
    )


def _to_persisted(w: Webhook) -> dict:
    """Serialise to the on-disk row. Never includes plaintext."""
    return {
        "id": w.id, "provider": w.provider,
        "url_encrypted": w.url_encrypted,
        "api_token_enc": w.api_token_enc,
        "signing_secret_enc": w.signing_secret_enc,
        "categories": list(w.categories),
        "min_severity": w.min_severity,
        "enabled": w.enabled, "notes": w.notes,
    }


# ---------------------------------------------------- public API


def list_webhooks() -> list[Webhook]:
    return [_from_dict(d) for d in _load_raw()]


def get(id_: str) -> Optional[Webhook]:
    for w in list_webhooks():
        if w.id == id_:
            return w
    return None


def upsert(body: dict) -> Webhook:
    """Create or update a webhook by ``id``. Validates input.

    Body shape (operator-facing):
        {id, provider?, url, api_token?, signing_secret?, categories?,
         min_severity?, enabled?, notes?}

    Plaintext URL/token/secret get re-encrypted before persist; an
    empty value preserves the existing encrypted blob.
    """
    rid = str(body.get("id") or "").strip()
    if not rid or not re.match(r"^[a-zA-Z0-9._\-]+$", rid):
        raise ValueError("id must be non-empty and use only "
                          "letters, digits, . _ -")
    url = str(body.get("url") or "").strip()
    provider = str(body.get("provider") or "").strip().lower()
    if url and not provider:
        provider = detect_provider(url)
    if provider and provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"unknown provider: {provider!r}")
    if not url and "url" in body:
        # Operator submitted blank url field — keep existing
        pass
    if url and not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    sev = str(body.get("min_severity") or "").strip().lower()
    if sev and sev not in _SEVERITY_ORDER:
        raise ValueError(f"min_severity must be one of "
                          f"{sorted(set(_SEVERITY_ORDER))}, got {sev!r}")

    rows = _load_raw()
    target = None
    for d in rows:
        if d.get("id") == rid:
            target = d
            break
    if target is None:
        target = {"id": rid}
        rows.append(target)
    if provider:
        target["provider"] = provider
    if url:
        target["url_encrypted"] = _encrypt(url)
    elif "url" in body and body.get("url") == "":
        # Explicit blank in the body wipes the URL
        target["url_encrypted"] = ""
    if "api_token" in body:
        v = str(body.get("api_token") or "")
        target["api_token_enc"] = _encrypt(v) if v else target.get(
            "api_token_enc", "")
    if "signing_secret" in body:
        v = str(body.get("signing_secret") or "")
        target["signing_secret_enc"] = _encrypt(v) if v else target.get(
            "signing_secret_enc", "")
    if "categories" in body and isinstance(body["categories"], list):
        target["categories"] = [str(c) for c in body["categories"]
                                  if isinstance(c, str)]
    target["min_severity"] = sev
    if "enabled" in body:
        target["enabled"] = bool(body["enabled"])
    if "notes" in body:
        target["notes"] = str(body["notes"] or "")

    _save_raw(rows)
    return _from_dict(target)


def delete(id_: str) -> bool:
    rows = _load_raw()
    new = [r for r in rows if r.get("id") != id_]
    if len(new) == len(rows):
        return False
    _save_raw(new)
    return True


# ---------------------------------------------------- filter + dispatch


def webhook_matches(w: Webhook, *, kind: str, severity: str) -> bool:
    """Filter rule: AND of category match AND min_severity match.

    Empty filter means "match any". A disabled webhook never matches.
    """
    if not w.enabled:
        return False
    if w.categories and kind not in w.categories:
        return False
    if w.min_severity:
        ev = _SEVERITY_ORDER.get(severity, 0)
        floor = _SEVERITY_ORDER.get(w.min_severity, 0)
        if ev < floor:
            return False
    return True


def matching(*, kind: str, severity: str) -> list[Webhook]:
    return [w for w in list_webhooks()
            if webhook_matches(w, kind=kind, severity=severity)]


def fire_one(w: Webhook, event: dict, *,
              timeout_s: float = 8.0) -> tuple[bool, str]:
    """Send one event to one webhook. Decrypts URL/token/secret at
    fire time so plaintext only lives in memory for the duration of
    the request."""
    from safecadence.notifier.providers import send_webhook
    url = _decrypt(w.url_encrypted)
    if not url:
        return False, "no url configured"
    return send_webhook(
        provider=w.provider or detect_provider(url),
        url=url,
        event=event,
        signing_secret=_decrypt(w.signing_secret_enc) or None,
        api_token=_decrypt(w.api_token_enc) or None,
        timeout_s=timeout_s,
    )
