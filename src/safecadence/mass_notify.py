"""Mass Notification — trigger, approve, deliver, PROVE.

SafeCadence is the intelligence and accountability layer, not another
siren vendor. Every alert is (1) drafted from a template or an incident,
(2) approved by a NAMED human — no exceptions, no auto-send — and
(3) recorded in a hash-chained audit log an evaluator can re-verify.
Delivery rides on integrations the agency already owns:

Tier 1 — your people (built in, works today):
  * email          — the agency's own SMTP relay (SC_SMTP_*)
  * sms_gateway    — email-to-SMS carrier gateways (no cloud vendor)
  * sms_http       — any HTTP SMS provider (Twilio-compatible payloads)
  * webhook        — Slack / Teams / generic JSON with HMAC signature
Tier 1.5 — local telephony (outbound calls & overhead paging):
  * asterisk       — Asterisk/FreePBX AMI: originate calls that play an
                      announcement (works with any SIP phone fleet)
  * informacast    — Singlewire InformaCast REST: text + audio to Cisco
                      IP phones, speakers, and paging (the Cisco path)
Tier 2/3 — community & IPAWS (bridge, never impersonate):
  * alert_bridge   — trigger a pre-built notification/scenario in the
                      agency's EXISTING alerting platform (Everbridge,
                      Rave, OnSolve, ...). Community opt-in lists and
                      IPAWS/WEA stay with the system that is authorized
                      to do them; SafeCadence supplies the trigger, the
                      approval gate, and the audit trail.

Honesty rules baked in: adapters run in `test` mode until the agency
supplies credentials; community-facing groups require recorded consent
on every member (same rule as the Community registry); nothing here
claims IPAWS authority — the bridge fires the system that has it.
Config and logs live under ``<SC_DATA_DIR>/notify/``.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import re
import smtplib
import socket
import uuid
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Callable
from urllib import request as _rq

GENESIS = "0" * 64
TEMPLATES: dict[str, dict[str, str]] = {
    "lockdown": {
        "subject": "LOCKDOWN - {site}",
        "body": ("Lockdown at {site}. Secure in place now. "
                  "Follow your lockdown procedure. Updates will follow "
                  "on this channel. Initiated by {approved_by}."),
    },
    "evacuation": {
        "subject": "EVACUATE - {site}",
        "body": ("Evacuate {site} now via the nearest safe exit. "
                  "Assemble at your rally point. Do not re-enter until "
                  "the all-clear. Initiated by {approved_by}."),
    },
    "shelter": {
        "subject": "SHELTER IN PLACE - {site}",
        "body": ("Shelter in place at {site}. Move away from windows. "
                  "Await further instructions. Initiated by {approved_by}."),
    },
    "all_clear": {
        "subject": "ALL CLEAR - {site}",
        "body": ("All clear at {site}. Normal operations may resume. "
                  "Report anything unusual. Issued by {approved_by}."),
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _root() -> Path:
    base = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(base) / "notify"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _load(name: str, default: Any) -> Any:
    f = _root() / name
    if not f.exists():
        return default
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return default


def _save(name: str, data: Any) -> None:
    (_root() / name).write_text(
        json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")


# ================================================================ groups

def list_groups() -> list[dict]:
    return _load("groups.json", [])


def save_group(*, name: str, members: list[dict],
                community: bool = False,
                channels: list[str] | None = None) -> dict:
    """A notification group. `community=True` marks a public-facing
    group: every member must carry consent_confirmed=True (the same
    consent rule as the Community camera registry)."""
    if not (name or "").strip():
        raise ValueError("group name is required")
    clean_members = []
    for m in members or []:
        rec = {
            "name": str(m.get("name", "")).strip()[:120],
            "email": str(m.get("email", "")).strip()[:160],
            "phone": str(m.get("phone", "")).strip()[:40],
            "extension": str(m.get("extension", "")).strip()[:20],
            "sms_gateway": str(m.get("sms_gateway", "")).strip()[:160],
        }
        if community:
            if not m.get("consent_confirmed"):
                raise ValueError(
                    "community groups require consent_confirmed=True on "
                    "every member - no consent, no entry")
            rec["consent_confirmed"] = True
            rec["consent_recorded_at"] = _now()
        clean_members.append(rec)
    groups = [g for g in list_groups() if g.get("name") != name.strip()]
    grp = {"name": name.strip()[:80], "community": bool(community),
            "channels": list(channels or ["email"]),
            "members": clean_members, "updated_at": _now()}
    groups.append(grp)
    _save("groups.json", groups)
    return grp


def get_group(name: str) -> dict | None:
    for g in list_groups():
        if g.get("name") == name:
            return g
    return None


# ================================================================ channels

def channel_config() -> dict:
    """Per-channel integration settings (endpoints, creds). Secrets stay
    in this local file / env — they are never logged or echoed."""
    return _load("channels.json", {})


def save_channel_config(channel: str, config: dict) -> dict:
    cfg = channel_config()
    cfg[str(channel)] = dict(config or {})
    _save("channels.json", cfg)
    return {"channel": channel, "saved": True}


def _smtp_send(to_addrs: list[str], subject: str, body: str) -> dict:
    host = os.environ.get("SC_SMTP_HOST", "")
    if not host or not to_addrs:
        return {"sent": 0, "skipped": len(to_addrs),
                 "reason": "SC_SMTP_HOST not configured" if not host else "no recipients"}
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = os.environ.get("SC_SMTP_FROM", "command@localhost")
    msg["To"] = ", ".join(to_addrs)
    port = int(os.environ.get("SC_SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=20) as s:
        s.ehlo()
        try:
            s.starttls(); s.ehlo()
        except smtplib.SMTPException:
            pass
        user = os.environ.get("SC_SMTP_USER", "")
        if user:
            s.login(user, os.environ.get("SC_SMTP_PASS", ""))
        s.sendmail(msg["From"], to_addrs, msg.as_string())
    return {"sent": len(to_addrs)}


def _ch_email(group: dict, subject: str, body: str, cfg: dict,
               live: bool) -> dict:
    targets = [m["email"] for m in group["members"] if m.get("email")]
    if not live:
        return {"channel": "email", "mode": "test", "targets": len(targets)}
    out = _smtp_send(targets, subject, body)
    return {"channel": "email", "mode": "live", "targets": len(targets), **out}


def _ch_sms_gateway(group: dict, subject: str, body: str, cfg: dict,
                     live: bool) -> dict:
    """Email-to-SMS: phone@carrier-gateway addresses on each member.
    No cloud vendor, rides the agency's own SMTP relay."""
    targets = [m["sms_gateway"] for m in group["members"]
                if m.get("sms_gateway")]
    if not live:
        return {"channel": "sms_gateway", "mode": "test",
                 "targets": len(targets)}
    out = _smtp_send(targets, subject, body[:150])
    return {"channel": "sms_gateway", "mode": "live",
             "targets": len(targets), **out}


def _http_json(url: str, payload: dict, headers: dict | None = None,
                form: bool = False, auth: tuple | None = None) -> int:
    if form:
        from urllib.parse import urlencode
        data = urlencode(payload).encode("utf-8")
        ctype = "application/x-www-form-urlencoded"
    else:
        data = json.dumps(payload).encode("utf-8")
        ctype = "application/json"
    req = _rq.Request(url, data=data, method="POST")
    req.add_header("Content-Type", ctype)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if auth:
        import base64
        tok = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", "Basic " + tok)
    with _rq.urlopen(req, timeout=15) as resp:      # noqa: S310 (agency-configured endpoint)
        return resp.status


def _ch_sms_http(group: dict, subject: str, body: str, cfg: dict,
                  live: bool) -> dict:
    """Generic HTTP SMS. Twilio-compatible when `style: twilio`
    (POSTs form-encoded To/From/Body per number); otherwise one JSON
    POST {to:[...], message} to the configured url."""
    numbers = [m["phone"] for m in group["members"] if m.get("phone")]
    if not live:
        return {"channel": "sms_http", "mode": "test", "targets": len(numbers)}
    url = (cfg or {}).get("url", "")
    if not url or not numbers:
        return {"channel": "sms_http", "mode": "live", "targets": 0,
                 "reason": "url not configured" if not url else "no numbers"}
    text = (subject + " - " + body)[:300]
    sent = 0
    if (cfg or {}).get("style") == "twilio":
        auth = (cfg.get("account_sid", ""), cfg.get("auth_token", ""))
        for n in numbers:
            _http_json(url, {"To": n, "From": cfg.get("from", ""),
                              "Body": text}, form=True, auth=auth)
            sent += 1
    else:
        headers = {}
        if cfg.get("token"):
            headers["Authorization"] = "Bearer " + cfg["token"]
        _http_json(url, {"to": numbers, "message": text}, headers=headers)
        sent = len(numbers)
    return {"channel": "sms_http", "mode": "live", "targets": sent}


def _ch_webhook(group: dict, subject: str, body: str, cfg: dict,
                 live: bool) -> dict:
    """Slack/Teams/generic JSON webhook with optional HMAC signature."""
    url = (cfg or {}).get("url", "")
    if not live:
        return {"channel": "webhook", "mode": "test",
                 "targets": 1 if url else 0}
    if not url:
        return {"channel": "webhook", "mode": "live", "targets": 0,
                 "reason": "url not configured"}
    payload = {"text": f"*{subject}*\n{body}"}
    headers = {}
    secret = cfg.get("secret", "")
    if secret:
        sig = _hmac.new(secret.encode(), json.dumps(payload).encode(),
                         hashlib.sha256).hexdigest()
        headers["X-SafeCadence-Signature"] = "sha256=" + sig
    _http_json(url, payload, headers=headers)
    return {"channel": "webhook", "mode": "live", "targets": 1}


def _ch_asterisk(group: dict, subject: str, body: str, cfg: dict,
                  live: bool) -> dict:
    """Outbound calls through the agency's OWN PBX (Asterisk/FreePBX
    AMI). Originates a call to each member's extension that plays the
    announcement configured for this alert (cfg: host, port, username,
    secret, context, announcement). Works with any SIP phone fleet —
    including Cisco phones registered to Asterisk."""
    exts = [m["extension"] for m in group["members"] if m.get("extension")]
    if not live:
        return {"channel": "asterisk", "mode": "test", "targets": len(exts)}
    host = (cfg or {}).get("host", "")
    if not host or not exts:
        return {"channel": "asterisk", "mode": "live", "targets": 0,
                 "reason": "host not configured" if not host else "no extensions"}
    port = int(cfg.get("port", 5038))
    called = 0
    with socket.create_connection((host, port), timeout=10) as sk:
        def send(lines: list[str]) -> None:
            sk.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        sk.recv(1024)                                # banner
        send(["Action: Login",
               f"Username: {cfg.get('username', '')}",
               f"Secret: {cfg.get('secret', '')}"])
        sk.recv(4096)
        for ext in exts:
            send(["Action: Originate",
                   f"Channel: Local/{ext}@{cfg.get('context', 'from-internal')}",
                   "Application: Playback",
                   f"Data: {cfg.get('announcement', 'custom/sc-alert')}",
                   f"CallerID: SafeCadence Alert <{cfg.get('callerid', '3000')}>",
                   "Async: true"])
            sk.recv(4096)
            called += 1
        send(["Action: Logoff"])
    return {"channel": "asterisk", "mode": "live", "targets": called}


def _ch_informacast(group: dict, subject: str, body: str, cfg: dict,
                     live: bool) -> dict:
    """Singlewire InformaCast (the Cisco-ecosystem paging/notification
    system): trigger a pre-configured message to its recipient groups —
    IP phone text+audio, overhead speakers, desktop alerts.
    cfg: url (message trigger endpoint), token, recipient_group."""
    if not live:
        return {"channel": "informacast", "mode": "test",
                 "targets": 1 if (cfg or {}).get("url") else 0}
    url = (cfg or {}).get("url", "")
    if not url:
        return {"channel": "informacast", "mode": "live", "targets": 0,
                 "reason": "url not configured"}
    headers = {"Authorization": "Bearer " + cfg.get("token", "")}
    _http_json(url, {"messageTemplate": cfg.get("template", ""),
                      "subject": subject, "body": body,
                      "recipientGroups": [cfg.get("recipient_group", "")]},
                headers=headers)
    return {"channel": "informacast", "mode": "live", "targets": 1}


def _ch_alert_bridge(group: dict, subject: str, body: str, cfg: dict,
                      live: bool) -> dict:
    """Community / IPAWS bridge: fire a pre-built notification in the
    agency's EXISTING alerting platform (Everbridge, Rave, OnSolve...).
    The incumbent system keeps its opt-in lists and its IPAWS/WEA
    authority; SafeCadence contributes the trigger + approval + proof.
    cfg: provider, url, token or username/password, scenario_id."""
    if not live:
        return {"channel": "alert_bridge", "mode": "test",
                 "targets": 1 if (cfg or {}).get("url") else 0,
                 "provider": (cfg or {}).get("provider", "unset")}
    url = (cfg or {}).get("url", "")
    if not url:
        return {"channel": "alert_bridge", "mode": "live", "targets": 0,
                 "reason": "url not configured"}
    headers = {}
    auth = None
    if cfg.get("token"):
        headers["Authorization"] = "Bearer " + cfg["token"]
    elif cfg.get("username"):
        auth = (cfg.get("username", ""), cfg.get("password", ""))
    _http_json(url, {"scenario": cfg.get("scenario_id", ""),
                      "title": subject, "message": body,
                      "source": "SafeCadence Command"},
                headers=headers, auth=auth)
    return {"channel": "alert_bridge", "mode": "live", "targets": 1,
             "provider": cfg.get("provider", "generic")}


CHANNELS: dict[str, Callable] = {
    "email": _ch_email,
    "sms_gateway": _ch_sms_gateway,
    "sms_http": _ch_sms_http,
    "webhook": _ch_webhook,
    "asterisk": _ch_asterisk,
    "informacast": _ch_informacast,
    "alert_bridge": _ch_alert_bridge,
}


# ================================================================ audit log

def _log_path() -> Path:
    return _root() / "alert-log.jsonl"


def _entry_hash(body: dict) -> str:
    canon = json.dumps({k: v for k, v in body.items() if k != "entry_hash"},
                        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _append_log(entry: dict) -> dict:
    prev = GENESIS
    f = _log_path()
    if f.exists():
        lines = f.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            try:
                prev = json.loads(lines[-1]).get("entry_hash", GENESIS)
            except Exception:
                prev = GENESIS
    entry["prev_hash"] = prev
    entry["entry_hash"] = _entry_hash(entry)
    with f.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def verify_log() -> dict:
    f = _log_path()
    if not f.exists():
        return {"ok": True, "entries": 0}
    prev = GENESIS
    n = 0
    for line in f.read_text(encoding="utf-8").strip().splitlines():
        try:
            e = json.loads(line)
        except Exception:
            return {"ok": False, "entries": n, "reason": "unparseable line"}
        if e.get("prev_hash") != prev:
            return {"ok": False, "entries": n, "failed_at": e.get("id"),
                     "reason": "chain broken"}
        if _entry_hash(e) != e.get("entry_hash"):
            return {"ok": False, "entries": n, "failed_at": e.get("id"),
                     "reason": "entry tampered"}
        prev = e["entry_hash"]
        n += 1
    return {"ok": True, "entries": n}


def alert_log(limit: int = 50) -> list[dict]:
    f = _log_path()
    if not f.exists():
        return []
    lines = f.read_text(encoding="utf-8").strip().splitlines()
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return list(reversed(out))


# ================================================================ send

def send_notification(*, group: str, subject: str = "", body: str = "",
                       template: str = "", site: str = "",
                       channels: list[str] | None = None,
                       initiated_by: str, approved_by: str,
                       incident_id: str = "",
                       live: bool | None = None) -> dict[str, Any]:
    """The one send path. A NAMED approver is mandatory — this is the
    human-approval gate, and it is not optional. `live` defaults to the
    SC_NOTIFY_LIVE env (off = test mode: full pipeline, no delivery)."""
    if not (initiated_by or "").strip():
        raise ValueError("initiated_by is required")
    if not (approved_by or "").strip():
        raise ValueError(
            "approved_by is required - every alert needs a named human "
            "approver before anything is sent")
    grp = get_group(group)
    if not grp:
        raise KeyError(f"notification group not found: {group}")
    if template:
        t = TEMPLATES.get(template)
        if not t:
            raise ValueError(f"unknown template: {template} "
                              f"(have: {', '.join(sorted(TEMPLATES))})")
        subject = subject or t["subject"].format(
            site=site or "all sites", approved_by=approved_by)
        body = body or t["body"].format(
            site=site or "all sites", approved_by=approved_by)
    if not (subject or "").strip() or not (body or "").strip():
        raise ValueError("subject and body are required "
                          "(or pass template=...)")
    if grp.get("community"):
        bad = [m["name"] for m in grp["members"]
                if not m.get("consent_confirmed")]
        if bad:
            raise ValueError("community group has members without "
                              "recorded consent: " + ", ".join(bad[:5]))
    if live is None:
        live = os.environ.get("SC_NOTIFY_LIVE") == "1"
    use = channels if channels is not None else grp.get("channels") or ["email"]
    cfg_all = channel_config()
    results = []
    for ch in use:
        fn = CHANNELS.get(ch)
        if not fn:
            results.append({"channel": ch, "error": "unknown channel"})
            continue
        try:
            results.append(fn(grp, subject, body, cfg_all.get(ch) or {},
                               bool(live)))
        except Exception as exc:
            results.append({"channel": ch, "error": str(exc)[:200]})
    entry = _append_log({
        "id": f"al-{uuid.uuid4().hex[:10]}",
        "at": _now(),
        "group": grp["name"],
        "community": bool(grp.get("community")),
        "subject": subject,
        "body": body[:500],
        "template": template,
        "incident_id": incident_id,
        "initiated_by": str(initiated_by).strip()[:120],
        "approved_by": str(approved_by).strip()[:120],
        "mode": "live" if live else "test",
        "channels": results,
    })
    return {"ok": True, "mode": entry["mode"], "id": entry["id"],
             "channels": results, "entry_hash": entry["entry_hash"]}


def summary() -> dict:
    groups = list_groups()
    cfg = channel_config()
    v = verify_log()
    return {
        "groups": len(groups),
        "community_groups": sum(1 for g in groups if g.get("community")),
        "members": sum(len(g.get("members", [])) for g in groups),
        "channels_configured": sorted(cfg.keys()),
        "channels_available": sorted(CHANNELS.keys()),
        "live_mode": os.environ.get("SC_NOTIFY_LIVE") == "1",
        "alerts_logged": v.get("entries", 0),
        "log_ok": v.get("ok"),
        "templates": sorted(TEMPLATES.keys()),
    }
