"""
Email digest delivery — pure stdlib smtplib, no extra deps.

Pairs with `safecadence watch` for daily/weekly summary email.
Supports plain SMTP, SMTP+STARTTLS, and SMTP_SSL (Gmail-style 465).

Designed to send a single email with a beautifully-formatted HTML
fleet snapshot — same content as the management report but inline-emailable.
"""

from __future__ import annotations

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_digest(
    *,
    smtp_host: str,
    smtp_port: int = 587,
    smtp_user: str = "",
    smtp_password: str = "",
    use_tls: bool = True,
    use_ssl: bool = False,
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    html_body: str,
    text_body: str = "",
) -> dict:
    """
    Send an HTML email digest.

    Returns: {ok: bool, error?: str, sent_to: [...]}
    """
    if not text_body:
        # Quick-and-dirty plain-text fallback
        import re
        text_body = re.sub(r"<[^>]+>", "", html_body).strip()[:5000]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)

    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=ctx, timeout=30) as s:
                if smtp_user:
                    s.login(smtp_user, smtp_password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as s:
                s.ehlo()
                if use_tls:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if smtp_user:
                    s.login(smtp_user, smtp_password)
                s.send_message(msg)
    except Exception as e:
        return {"ok": False, "error": str(e), "sent_to": []}

    return {"ok": True, "sent_to": to_addrs}


def render_digest_html(fleet: dict, *, subject_prefix: str = "🛡 SafeCadence") -> tuple[str, str]:
    """
    Render an HTML email body for a discover payload.
    Returns (subject, html_body).

    Output is inline-styled (email clients hate <style> blocks) and
    designed to render on Gmail / Outlook / Apple Mail / mobile.
    """
    cidr = fleet.get("cidr", "?")
    count = fleet.get("count", 0)
    summary = fleet.get("summary", {})
    bands = summary.get("by_risk_band", {})
    cves = summary.get("cves", {})
    crit = bands.get("critical", 0)
    high = bands.get("high", 0)
    kev = cves.get("kev_cves", 0)

    # Top critical/high devices
    spotlight = [r for r in (fleet.get("results") or []) if r.get("risk_band") in ("critical", "high")][:5]

    # Subject line — terse and informative
    subject = f"{subject_prefix} {cidr}: {crit} critical, {high} high, {kev} KEV"

    # Spotlight rows
    spotlight_rows = ""
    for d in spotlight:
        band = d.get("risk_band", "safe")
        bg = {"critical": "#0f172a", "high": "#dc2626", "medium": "#d97706"}.get(band, "#475569")
        spotlight_rows += f"""
        <tr>
          <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; vertical-align:top">
            <span style="display:inline-block; padding:3px 8px; background:{bg}; color:#fff; border-radius:4px; font-size:11px; font-weight:700">{band.upper()}</span>
            <strong style="margin-left:6px"><code style="font-family:Consolas,monospace; background:#f8fafc; padding:1px 4px; border-radius:3px">{d.get('ip','?')}</code></strong>
            ({d.get('vendor','?')})
            <div style="font-size:11px; color:#64748b; margin-top:2px">Risk {d.get('risk_score', 0)}/100 · {len(d.get('cves', []))} CVE(s)</div>
          </td>
        </tr>"""

    html = f"""<!doctype html>
<html><body style="margin:0; padding:0; background:#f1f5f9; font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; color:#0f172a">

<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9; padding:24px 12px">
  <tr><td>
    <table width="600" align="center" cellpadding="0" cellspacing="0" style="max-width:600px; margin:0 auto; background:#fff; border-radius:12px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.06)">

      <!-- Header -->
      <tr>
        <td style="background:linear-gradient(135deg, #0f172a, #1e3a8a); padding:24px 28px; color:#fff">
          <div style="font-size:11px; letter-spacing:.12em; text-transform:uppercase; color:#94a3b8; font-weight:700; margin-bottom:4px">SafeCadence Network Risk · Daily Digest</div>
          <div style="font-size:22px; font-weight:800; margin-bottom:6px">Network Audit: <code style="background:transparent; color:#fff">{cidr}</code></div>
          <div style="font-size:13px; color:#cbd5e1">{count} devices scanned</div>
        </td>
      </tr>

      <!-- KPI bar -->
      <tr>
        <td style="padding:24px 28px">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="width:25%; text-align:center; padding:0 4px">
                <div style="font-size:10px; color:#64748b; text-transform:uppercase; letter-spacing:.06em; font-weight:700">Devices</div>
                <div style="font-size:28px; font-weight:800; color:#1d4ed8">{count}</div>
              </td>
              <td style="width:25%; text-align:center; padding:0 4px; background:#fef3c7; border-radius:8px">
                <div style="font-size:10px; color:#64748b; text-transform:uppercase; letter-spacing:.06em; font-weight:700">Critical</div>
                <div style="font-size:28px; font-weight:800; color:#0f172a">{crit}</div>
              </td>
              <td style="width:25%; text-align:center; padding:0 4px">
                <div style="font-size:10px; color:#64748b; text-transform:uppercase; letter-spacing:.06em; font-weight:700">High</div>
                <div style="font-size:28px; font-weight:800; color:#dc2626">{high}</div>
              </td>
              <td style="width:25%; text-align:center; padding:0 4px; background:#fee2e2; border-radius:8px">
                <div style="font-size:10px; color:#64748b; text-transform:uppercase; letter-spacing:.06em; font-weight:700">KEV CVEs</div>
                <div style="font-size:28px; font-weight:800; color:#dc2626">{kev}</div>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Spotlight -->
      {f'''<tr>
        <td style="padding:0 28px 12px">
          <h3 style="margin:0 0 8px; font-size:16px">Top {len(spotlight)} devices requiring attention</h3>
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">{spotlight_rows}</table>
        </td>
      </tr>''' if spotlight else ''}

      <!-- Footer -->
      <tr>
        <td style="padding:18px 28px; background:#f8fafc; font-size:11px; color:#64748b; border-top:1px solid #e2e8f0">
          Sent by <a href="https://pypi.org/project/safecadence-netrisk/" style="color:#1d4ed8; text-decoration:none">safecadence-netrisk</a> running on your machine.
          To stop these emails, kill the <code>safecadence watch</code> process.
        </td>
      </tr>

    </table>
  </td></tr>
</table>

</body></html>"""
    return subject, html
