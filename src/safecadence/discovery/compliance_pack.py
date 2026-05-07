"""
Compliance audit packs — generate framework-specific evidence reports.

Supported frameworks:
  - SOC 2 Type 2 (Trust Services Criteria)
  - PCI-DSS v4.0
  - HIPAA Security Rule
  - NIST 800-53 Rev. 5
  - CIS Controls v8

Each pack maps fleet findings to specific control IDs and produces an
auditor-ready HTML report with:
  - Control-by-control coverage status
  - Evidence (specific devices, finding IDs, dates)
  - Remediation status
  - Sign-off blocks
  - Methodology + scope statement

Designed to be the deliverable consultants give to their clients.
"""

from __future__ import annotations

import html as html_lib
from datetime import datetime, timezone


def _esc(s) -> str:
    return html_lib.escape(str(s) if s is not None else "")


# ---------------------------------------------------------------- control mappings
# Each control: (framework_id, control_id, control_name, finding_keywords, evidence_template)
_CONTROL_MAPPINGS = {
    "soc2": [
        ("CC6.1", "Logical Access — Authentication", ["telnet", "ftp", "default", "cleartext", "admin"]),
        ("CC6.2", "Logical Access — User Management", ["snmp default", "default credential"]),
        ("CC6.6", "Logical Access — Network Segmentation", ["smb1", "iot", "open ports"]),
        ("CC6.7", "Encryption in Transit", ["telnet", "http admin", "ftp", "tls", "self-signed"]),
        ("CC7.1", "Detection of Anomalies", ["unidentified", "unknown vendor"]),
        ("CC7.2", "Change Management", ["eol", "deprecated", "outdated"]),
        ("CC8.1", "Vulnerability Management", ["cve", "kev", "patch"]),
    ],
    "pci": [
        ("1.2", "Network Segmentation", ["smb", "iot", "vlan"]),
        ("2.1", "Default Credentials", ["default", "snmp"]),
        ("2.3", "Encrypt non-console admin access", ["telnet", "http admin", "cleartext"]),
        ("4.1", "Strong cryptography for data in transit", ["tls", "self-signed", "weak cipher"]),
        ("6.2", "Patch Management", ["cve", "kev", "patch", "eol"]),
        ("8.2", "Authentication", ["default credential", "weak password"]),
        ("11.2", "Vulnerability Scanning", ["cve", "scan"]),
        ("11.3", "Penetration Testing", ["telnet", "rdp", "smb"]),
    ],
    "hipaa": [
        ("164.308(a)(1)", "Security Management Process — Risk Analysis", ["cve", "kev"]),
        ("164.308(a)(5)", "Security Awareness Training — Default credentials", ["default", "snmp"]),
        ("164.312(a)(1)", "Access Control — Unique User Identification", ["telnet", "default credential"]),
        ("164.312(a)(2)(iv)", "Encryption and Decryption — at rest", ["unencrypted", "vault"]),
        ("164.312(b)", "Audit Controls", ["snmp", "logging"]),
        ("164.312(d)", "Person or Entity Authentication", ["default", "weak"]),
        ("164.312(e)(1)", "Transmission Security — Encryption", ["telnet", "ftp", "http", "tls", "cleartext"]),
        ("164.312(e)(2)(ii)", "Transmission Security — Integrity Controls", ["self-signed", "weak cipher"]),
    ],
    "nist": [
        ("AC-17", "Remote Access", ["telnet", "rdp", "vpn", "cleartext"]),
        ("CM-2", "Baseline Configuration", ["unidentified", "unknown vendor"]),
        ("IA-2", "Identification and Authentication", ["default credential", "weak password"]),
        ("IA-5", "Authenticator Management", ["snmp default", "default community"]),
        ("RA-5", "Vulnerability Scanning", ["cve", "kev"]),
        ("SC-7", "Boundary Protection", ["smb", "ftp", "open ports"]),
        ("SC-8", "Transmission Confidentiality", ["telnet", "ftp", "http", "tls"]),
        ("SC-12", "Cryptographic Key Establishment", ["self-signed", "weak cipher"]),
        ("SI-2", "Flaw Remediation", ["cve", "patch", "eol"]),
        ("SI-4", "System Monitoring", ["snmp", "logging"]),
    ],
    "cis": [
        ("4.1", "Establish Secure Configurations", ["default", "telnet"]),
        ("4.5", "Use Encrypted Channels for Remote Administration", ["telnet", "ftp", "http"]),
        ("5.4", "Restrict Administrator Privileges to Dedicated Accounts", ["default credential", "snmp"]),
        ("7.1", "Establish a Vulnerability Management Process", ["cve", "kev"]),
        ("7.6", "Perform Authenticated Vulnerability Scanning", ["cve", "scan"]),
        ("8.2", "Collect Audit Logs", ["snmp", "logging"]),
        ("12.6", "Use Secure Remote Access Methods", ["rdp", "telnet", "vpn"]),
        ("13.6", "Collect Network Traffic Flow Logs", ["network", "flow"]),
    ],
}

_FRAMEWORK_NAMES = {
    "soc2": "SOC 2 Type II — Trust Services Criteria",
    "pci": "PCI-DSS v4.0",
    "hipaa": "HIPAA Security Rule (45 CFR § 164.302–318)",
    "nist": "NIST SP 800-53 Rev. 5",
    "cis": "CIS Controls v8",
}


def _matches_control(finding: str, keywords: list[str]) -> bool:
    f = finding.lower()
    return any(k in f for k in keywords)


def map_findings_to_controls(results: list[dict], framework: str) -> dict:
    """Map fleet findings to specific control IDs in the chosen framework."""
    controls = _CONTROL_MAPPINGS.get(framework, [])
    coverage = {}
    for ctrl_id, ctrl_name, keywords in controls:
        matching_devices = []
        for device in results:
            findings = device.get("findings", [])
            for f in findings:
                if _matches_control(f, keywords):
                    matching_devices.append({
                        "ip": device.get("ip"),
                        "hostname": device.get("hostname", ""),
                        "vendor": device.get("vendor", ""),
                        "finding": f,
                    })
        coverage[ctrl_id] = {
            "control_id": ctrl_id,
            "control_name": ctrl_name,
            "status": "FAIL" if matching_devices else "PASS",
            "evidence_count": len(matching_devices),
            "evidence": matching_devices[:10],  # cap for report length
        }
    return coverage


def render_compliance_pack(
    discover_data: dict,
    framework: str = "soc2",
    *,
    organization: str = "Your Organization",
    auditor_name: str = "",
    audit_period: str = "",
) -> str:
    """Render a complete compliance audit pack as self-contained HTML."""
    framework = framework.lower()
    if framework not in _CONTROL_MAPPINGS:
        framework = "soc2"

    framework_name = _FRAMEWORK_NAMES[framework]
    cidr = discover_data.get("cidr", "?")
    results = discover_data.get("results", [])
    coverage = map_findings_to_controls(results, framework)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total_controls = len(coverage)
    failed_controls = sum(1 for c in coverage.values() if c["status"] == "FAIL")
    passed_controls = total_controls - failed_controls
    pass_rate = int((passed_controls / max(total_controls, 1)) * 100)

    # Render control rows
    control_rows = ""
    for ctrl_id, ctrl in coverage.items():
        status_color = "#16a34a" if ctrl["status"] == "PASS" else "#dc2626"
        status_bg = "#dcfce7" if ctrl["status"] == "PASS" else "#fee2e2"
        evidence_html = ""
        if ctrl["evidence"]:
            evidence_html = "<details style='margin-top:6px'><summary style='cursor:pointer; color:#1d4ed8; font-size:11px'>View evidence (" + str(ctrl["evidence_count"]) + ")</summary><ul style='margin:4px 0 0; padding-left:20px; font-size:11px'>" + "".join(
                f"<li><code>{_esc(e['ip'])}</code> ({_esc(e['vendor'])}): {_esc(e['finding'][:120])}</li>" for e in ctrl["evidence"]
            ) + "</ul></details>"

        control_rows += f"""
        <tr>
          <td style="font-family:ui-monospace,monospace; font-weight:700; color:#1e293b">{_esc(ctrl_id)}</td>
          <td>{_esc(ctrl['control_name'])}</td>
          <td><span style="display:inline-block; padding:3px 10px; border-radius:4px; background:{status_bg}; color:{status_color}; font-weight:700; font-size:11px">{_esc(ctrl['status'])}</span></td>
          <td>{ctrl['evidence_count']}</td>
          <td>{evidence_html}</td>
        </tr>
        """

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(framework_name)} — Compliance Audit Pack — {_esc(cidr)}</title>
<style>
  *,*::before,*::after {{ box-sizing: border-box; }}
  body {{ margin:0; font-family:-apple-system,"Segoe UI",Roboto,sans-serif; color:#0f172a; background:#fff;
          font-size:14px; line-height:1.5; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .page {{ max-width:1100px; margin:0 auto; padding:0 32px 50px; }}
  .cover {{ background:linear-gradient(135deg, #0f172a, #1e3a8a); color:#fff;
            padding:50px 32px; margin:0 -32px 30px; }}
  .cover .brand {{ font-size:11px; letter-spacing:.16em; text-transform:uppercase;
                    color:#94a3b8; font-weight:700; }}
  .cover h1 {{ font-size:30px; line-height:1.2; margin:14px 0 8px; font-weight:800; }}
  .cover .sub {{ font-size:15px; color:#cbd5e1; margin-bottom:18px; max-width:780px; }}
  .cover-meta {{ font-size:13px; color:#94a3b8; line-height:1.8; }}
  .cover-meta strong {{ color:#fff; }}
  h2 {{ font-size:18px; margin:32px 0 14px; font-weight:700; padding-bottom:6px;
        border-bottom:2px solid #0f172a; }}
  table {{ width:100%; border-collapse:collapse; font-size:12px; margin:8px 0; }}
  th {{ text-align:left; padding:10px; background:#0f172a; color:#cbd5e1; font-size:10px;
       font-weight:700; text-transform:uppercase; letter-spacing:.06em; }}
  td {{ padding:10px; border-bottom:1px solid #f1f5f9; vertical-align:top; }}
  .pass-rate {{ font-size:48px; font-weight:800; }}
  .pass-rate.high {{ color:#16a34a; }}
  .pass-rate.medium {{ color:#d97706; }}
  .pass-rate.low {{ color:#dc2626; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(4, 1fr); gap:14px; margin:18px 0; }}
  .summary-card {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px;
                    padding:16px 18px; }}
  .summary-card .lbl {{ font-size:10px; text-transform:uppercase; color:#64748b;
                         letter-spacing:.06em; font-weight:700; }}
  .summary-card .v {{ font-size:24px; font-weight:800; margin:4px 0; }}
  .signoff {{ background:#fefce8; border:2px solid #eab308; border-radius:10px;
              padding:20px 24px; margin:24px 0; }}
  .signoff h3 {{ margin:0 0 12px; }}
  .signoff-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-top:12px; }}
  .sig-line {{ border-bottom:1px solid #0f172a; height:30px; margin-bottom:4px; }}
  .sig-label {{ font-size:11px; color:#64748b; }}
  .footer {{ margin-top:50px; padding:18px 0; border-top:1px solid #e2e8f0;
             font-size:11px; color:#64748b; text-align:center; }}
  @media print {{
    .cover {{ padding:36px 24px; }}
    h2 {{ page-break-after:avoid; }}
    tr {{ page-break-inside:avoid; }}
  }}
</style>
</head>
<body>
<div class="page">

<div class="cover">
  <div class="brand">SafeCadence Network Risk · Compliance Audit Pack</div>
  <h1>{_esc(framework_name)}</h1>
  <div class="sub">Control-by-control compliance evidence collected from network audit on {_esc(cidr)}</div>
  <div class="cover-meta">
    Organization: <strong>{_esc(organization)}</strong><br>
    Subnet in scope: <strong>{_esc(cidr)}</strong><br>
    Devices assessed: <strong>{discover_data.get('count', 0)}</strong><br>
    {f"Audit period: <strong>{_esc(audit_period)}</strong><br>" if audit_period else ""}
    {f"Auditor: <strong>{_esc(auditor_name)}</strong><br>" if auditor_name else ""}
    Generated: {_esc(generated)}
  </div>
</div>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="summary-card">
    <div class="lbl">Controls assessed</div>
    <div class="v">{total_controls}</div>
    <div style="font-size:11px; color:#64748b">{_esc(framework_name.split('—')[0].strip())}</div>
  </div>
  <div class="summary-card" style="background:linear-gradient(135deg,#fff,#dcfce7); border-color:#86efac">
    <div class="lbl">Pass rate</div>
    <div class="pass-rate {'high' if pass_rate >= 80 else 'medium' if pass_rate >= 60 else 'low'}">{pass_rate}%</div>
    <div style="font-size:11px; color:#64748b">{passed_controls} of {total_controls} passing</div>
  </div>
  <div class="summary-card" style="background:linear-gradient(135deg,#fff,#fee2e2); border-color:#fecaca">
    <div class="lbl">Findings</div>
    <div class="v" style="color:#dc2626">{failed_controls}</div>
    <div style="font-size:11px; color:#64748b">controls require remediation</div>
  </div>
  <div class="summary-card">
    <div class="lbl">Methodology</div>
    <div style="font-size:13px; font-weight:600; margin-top:8px">Automated network discovery + finding-to-control mapping</div>
  </div>
</div>

<h2>Control Coverage Detail</h2>
<table>
  <thead><tr><th style="width:120px">Control ID</th><th>Control Name</th><th>Status</th><th>Findings</th><th>Evidence</th></tr></thead>
  <tbody>{control_rows}</tbody>
</table>

<h2>Methodology &amp; Scope</h2>
<p style="font-size:12px; color:#475569">
  This evidence pack was generated by <code>safecadence-netrisk</code> (open-source, MIT-licensed),
  running locally on the auditor's workstation. <strong>No data was transmitted to any third party.</strong>
  Discovery used five concurrent identification techniques (TCP probing, ARP cache reading, mDNS
  multicast, SNMPv2c sysDescr, TLS subject extraction) followed by automatic finding-to-control mapping
  against the {_esc(framework_name)} framework. Each control's status is determined heuristically by
  matching finding text against framework-specific keywords. <strong>This pack is best-effort evidence
  for an audit conversation; final compliance determination requires review by a qualified assessor.</strong>
</p>

<div class="signoff">
  <h3>Sign-off</h3>
  <p style="font-size:12px; color:#475569; margin-bottom:14px">
    By signing below, the parties acknowledge that the audit findings have been reviewed and that
    a remediation plan exists for any controls flagged FAIL. Findings flagged FAIL require remediation
    before this pack can be submitted as final compliance evidence.
  </p>
  <div class="signoff-grid">
    <div>
      <div class="sig-line"></div>
      <div class="sig-label">Auditor / Assessor signature, date</div>
    </div>
    <div>
      <div class="sig-line"></div>
      <div class="sig-label">Customer authorized signatory, date</div>
    </div>
  </div>
</div>

<div class="footer">
  Generated by <a href="https://pypi.org/project/safecadence-netrisk/" style="color:#1d4ed8">safecadence-netrisk</a> ·
  MIT licensed · 100% local · {_esc(generated)}
</div>

</div>
</body>
</html>
"""
