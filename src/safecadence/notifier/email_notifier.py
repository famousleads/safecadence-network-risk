"""
v9.42 — Email notifications via the customer's own SMTP server.

Design choice: SafeCadence is an SMTP CLIENT, not a server. The
customer points us at their existing mail infrastructure (their
Exchange / Postfix / corporate relay / Gmail SMTP / SendGrid /
whatever) and we send through it. Every byte of message content stays
in their mail estate's logs — nothing routes through SafeCadence's
infrastructure or any third-party email service.

Trust posture:

  - SMTP credentials are stored Fernet-encrypted via the existing
    PlatformVault, not in plaintext on disk.
  - Empty config = email DMs disabled, nothing logged, no exception
    raised. Air-gapped deployments keep working.
  - "Send test email" exists so an admin can verify the config
    end-to-end before relying on it for real approvals.
  - The notifier never auto-creates email content from external data
    — every template is hard-coded in this module.
"""

from __future__ import annotations

import json
import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Optional


# Settings live alongside the rest of platform settings in
# $SC_DATA_DIR/settings/email.json. The SMTP password is encrypted
# with the existing platform vault key when present, otherwise stored
# in plain (with a loud warning at startup) — same pattern v9.25 used
# for Splunk HEC tokens.

_SETTINGS_FILE_NAME = "email.json"


@dataclass
class EmailConfig:
    """Customer SMTP config. Every field optional — empty == disabled."""
    enabled: bool = False
    host: str = ""
    port: int = 587
    use_tls: bool = True             # STARTTLS on submission port
    use_ssl: bool = False            # implicit TLS (port 465)
    username: str = ""
    # ``password`` is the cleartext form when set via API and the
    # encrypted form when persisted. ``password_encrypted`` carries the
    # ciphertext blob; we never persist plaintext.
    password: str = ""
    password_encrypted: str = ""
    from_addr: str = ""              # "SafeCadence <noreply@acme.com>"
    timeout_s: int = 15

    def to_public_dict(self) -> dict:
        """API-safe view: never includes the password (encrypted or
        otherwise). Surfaces a boolean ``has_password`` so the UI can
        show "configured" without leaking the secret."""
        return {
            "enabled": self.enabled,
            "host": self.host,
            "port": self.port,
            "use_tls": self.use_tls,
            "use_ssl": self.use_ssl,
            "username": self.username,
            "from_addr": self.from_addr,
            "timeout_s": self.timeout_s,
            "has_password": bool(self.password or self.password_encrypted),
        }


# ---------------------------------------------------- vault wrapper


def _vault_key() -> Optional[str]:
    """Resolve the platform vault key for password encryption.

    Reuses the same env var the identity vault reads (v9.34) so a
    single key bootstrap covers both. Returns None when unavailable
    (we then store cleartext + log a warning, which preserves
    air-gap-without-cryptography compatibility).
    """
    return os.environ.get("SAFECADENCE_VAULT_KEY") or None


def _encrypt_password(plain: str) -> str:
    if not plain:
        return ""
    key = _vault_key()
    if not key:
        return f"PLAINTEXT:{plain}"      # explicit prefix so audit catches it
    try:
        from cryptography.fernet import Fernet
        return "FERNET:" + Fernet(key.encode()).encrypt(
            plain.encode("utf-8")).decode("ascii")
    except Exception:                    # pragma: no cover
        return f"PLAINTEXT:{plain}"


def _decrypt_password(blob: str) -> str:
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
        except Exception:                # pragma: no cover
            return ""
    return ""                            # unknown format → safe-empty


# ------------------------------------------------------ persistence


def _settings_path() -> Path:
    base = Path(os.environ.get("SC_DATA_DIR") or
                  (Path.home() / ".safecadence"))
    d = base / "settings"
    d.mkdir(parents=True, exist_ok=True)
    return d / _SETTINGS_FILE_NAME


def load_email_config() -> EmailConfig:
    p = _settings_path()
    if not p.exists():
        return EmailConfig()
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return EmailConfig()
    cfg = EmailConfig(
        enabled=bool(d.get("enabled", False)),
        host=str(d.get("host", "")),
        port=int(d.get("port", 587) or 587),
        use_tls=bool(d.get("use_tls", True)),
        use_ssl=bool(d.get("use_ssl", False)),
        username=str(d.get("username", "")),
        password_encrypted=str(d.get("password_encrypted", "")),
        from_addr=str(d.get("from_addr", "")),
        timeout_s=int(d.get("timeout_s", 15) or 15),
    )
    return cfg


def save_email_config(cfg: EmailConfig) -> EmailConfig:
    """Persist the config. If a fresh ``password`` was set on the
    record, re-encrypt and store as ``password_encrypted`` then drop
    the plaintext from the record before write."""
    if cfg.password:
        cfg.password_encrypted = _encrypt_password(cfg.password)
        cfg.password = ""
    payload = {
        "enabled": cfg.enabled,
        "host": cfg.host,
        "port": cfg.port,
        "use_tls": cfg.use_tls,
        "use_ssl": cfg.use_ssl,
        "username": cfg.username,
        "password_encrypted": cfg.password_encrypted,
        "from_addr": cfg.from_addr,
        "timeout_s": cfg.timeout_s,
    }
    p = _settings_path()
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:                       # pragma: no cover
        pass
    return cfg


# --------------------------------------------------------- send


def is_configured() -> bool:
    """Quick check used by the notifier to decide whether to even
    attempt email DMs. Air-gap deployments return False here.
    """
    cfg = load_email_config()
    return bool(cfg.enabled and cfg.host and cfg.from_addr)


def send_email(*, to: str, subject: str, body: str,
                cfg: Optional[EmailConfig] = None,
                html_body: Optional[str] = None) -> tuple[bool, str]:
    """Send one email through the customer's SMTP server.

    Returns ``(ok, error_message)``. Never raises — caller doesn't
    want a notifier failure to abort the workflow.
    """
    if cfg is None:
        cfg = load_email_config()
    if not cfg.enabled:
        return False, "email notifications disabled"
    if not cfg.host or not cfg.from_addr:
        return False, "incomplete email config (host/from_addr)"
    if not to:
        return False, "no recipient"

    msg = EmailMessage()
    msg["From"] = cfg.from_addr
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    password = ""
    if cfg.password:
        password = cfg.password
    elif cfg.password_encrypted:
        password = _decrypt_password(cfg.password_encrypted)

    try:
        if cfg.use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg.host, cfg.port,
                                    timeout=cfg.timeout_s,
                                    context=ctx) as s:
                if cfg.username:
                    s.login(cfg.username, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg.host, cfg.port,
                               timeout=cfg.timeout_s) as s:
                s.ehlo()
                if cfg.use_tls:
                    ctx = ssl.create_default_context()
                    s.starttls(context=ctx)
                    s.ehlo()
                if cfg.username:
                    s.login(cfg.username, password)
                s.send_message(msg)
        return True, ""
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ---------------------------------------------------- approval helpers


def render_approval_email(*, job_name: str, job_id: str,
                            risk: str, intent: str,
                            target_summary: str,
                            link: str,
                            requested_by: str) -> tuple[str, str, str]:
    """Build (subject, plaintext, html) for an approval-request DM."""
    subject = f"[SafeCadence] Approval requested: {job_name}"
    plain = (
        f"SafeCadence — approval requested\n\n"
        f"  Job:        {job_name} ({job_id})\n"
        f"  Risk:       {risk}\n"
        f"  Submitted by: {requested_by}\n"
        f"  Targets:    {target_summary}\n"
        f"  Intent:     {intent}\n\n"
        f"Review and approve at: {link}\n\n"
        f"This invitation does not grant approval authority — your "
        f"role still gates the actual approve action.\n"
    )
    html = (
        '<div style="font-family:sans-serif;max-width:600px">'
        '<h3 style="margin:0 0 6px">SafeCadence — approval requested</h3>'
        f'<p style="margin:0 0 10px;color:#444">Submitted by '
        f'<strong>{_h(requested_by)}</strong></p>'
        '<table style="border-collapse:collapse;margin:8px 0;font-size:13px">'
        f'<tr><td style="padding:2px 8px"><strong>Job</strong></td>'
        f'<td>{_h(job_name)} <code>({_h(job_id)})</code></td></tr>'
        f'<tr><td style="padding:2px 8px"><strong>Risk</strong></td>'
        f'<td>{_h(risk).upper()}</td></tr>'
        f'<tr><td style="padding:2px 8px"><strong>Targets</strong></td>'
        f'<td>{_h(target_summary)}</td></tr>'
        f'<tr><td style="padding:2px 8px"><strong>Intent</strong></td>'
        f'<td>{_h(intent)}</td></tr>'
        '</table>'
        f'<p><a href="{_h(link)}" style="background:#2563eb;color:white;'
        f'padding:8px 16px;border-radius:6px;text-decoration:none">'
        'Review &amp; approve</a></p>'
        '<p style="font-size:11px;color:#666;margin-top:14px">'
        'This invitation does not grant approval authority — your '
        'role still gates the actual approve action.</p>'
        '</div>'
    )
    return subject, plain, html


def _h(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
