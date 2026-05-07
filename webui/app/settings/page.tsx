"use client";

import { useEffect, useState } from "react";

interface License { licensee: string; asset_count: number; max_assets: number;
  expires_at: string; signature_state: string; over_limit: boolean;
  features: string[]; }
interface Rbac { role: string; capabilities: string[]; }
interface Totp { enrolled: boolean; }

export default function SettingsPage() {
  const [token, setToken] = useState("");
  const [license, setLicense] = useState<License | null>(null);
  const [rbac, setRbac] = useState<Rbac | null>(null);
  const [totp, setTotp] = useState<Totp | null>(null);

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (!t) return;
    const h = { Authorization: "Bearer " + t };
    fetch("/api/platform/license", { headers: h })
      .then(r => r.ok ? r.json() : null).then(setLicense);
    fetch("/api/execute/rbac", { headers: h })
      .then(r => r.ok ? r.json() : null).then(setRbac);
    fetch("/api/execute/totp/status", { headers: h })
      .then(r => r.ok ? r.json() : null).then(setTotp);
  }, []);

  async function enrollTotp() {
    const r = await fetch("/api/execute/totp/enroll", {
      method: "POST", headers: { Authorization: "Bearer " + token },
    });
    if (!r.ok) { alert("Enroll failed: " + r.status); return; }
    const j = await r.json();
    alert(`TOTP secret:\n\n${j.secret}\n\nAdd to your authenticator app.\n\nOR scan: ${j.otpauth_uri}`);
    setTotp({ enrolled: true });
  }

  async function previewDigest() {
    const r = await fetch("/api/platform/digest/preview",
      { headers: { Authorization: "Bearer " + token } });
    const j = await r.json();
    alert(j.text);
  }

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">⚙ Settings</h2>

      <div className="bg-panel rounded-lg border border-border p-4 space-y-2">
        <h3 className="font-semibold">Bearer token</h3>
        <input
          type="password" placeholder="JWT from /api/login"
          className="w-full bg-bg border border-border rounded px-3 py-2 text-sm font-mono"
          value={token}
          onChange={e => {
            localStorage.setItem("SC_TOKEN", e.target.value);
            setToken(e.target.value);
          }}/>
        <div className="flex gap-2">
          <button
            onClick={() => alert("Saved.")}
            className="bg-accent text-white px-3 py-1 rounded text-sm">Save</button>
          <button
            onClick={() => {
              localStorage.removeItem("SC_TOKEN");
              setToken("");
            }}
            className="border border-border px-3 py-1 rounded text-sm">Clear</button>
        </div>
      </div>

      {license && (
        <div className="bg-panel rounded-lg border border-border p-4 space-y-2">
          <h3 className="font-semibold">License</h3>
          <div className="text-sm">
            <div><span className="text-muted">Licensee:</span> <strong>{license.licensee}</strong></div>
            <div><span className="text-muted">Assets:</span> {license.asset_count} of {license.max_assets || "∞"}
              {license.over_limit && <span className="ml-2 text-bad font-bold">OVER LIMIT</span>}</div>
            <div><span className="text-muted">Signature:</span> {license.signature_state}</div>
            <div><span className="text-muted">Features:</span>{" "}
              {license.features.map(f => (
                <span key={f} className="inline-block mr-1 mt-1 px-2 py-0.5
                                          rounded bg-bg text-xs">{f}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      {rbac && (
        <div className="bg-panel rounded-lg border border-border p-4 space-y-2">
          <h3 className="font-semibold">Your role + capabilities</h3>
          <div className="text-sm">Role: <strong>{rbac.role}</strong> — {rbac.capabilities.length} capabilities</div>
          <details>
            <summary className="cursor-pointer text-xs text-muted">List capabilities</summary>
            <pre className="text-xs mt-2">{rbac.capabilities.join("\n")}</pre>
          </details>
        </div>
      )}

      {totp && (
        <div className="bg-panel rounded-lg border border-border p-4 space-y-2">
          <h3 className="font-semibold">TOTP enrollment (Tier3 SSH)</h3>
          <div className="text-sm">
            Status:{" "}
            <strong className={totp.enrolled ? "text-good" : "text-warn"}>
              {totp.enrolled ? "enrolled" : "NOT enrolled"}
            </strong>
          </div>
          <button
            onClick={enrollTotp}
            className="bg-accent text-white px-4 py-2 rounded text-sm">
            {totp.enrolled ? "Re-enroll" : "Enroll TOTP"}
          </button>
        </div>
      )}

      <div className="bg-panel rounded-lg border border-border p-4 space-y-2">
        <h3 className="font-semibold">Notifications + digest</h3>
        <p className="text-muted text-xs">
          Configure SMTP + recipients via env vars on the server.
        </p>
        <pre className="text-xs bg-bg p-2 rounded">{`export SC_SLACK_WEBHOOK=...
export SC_TEAMS_WEBHOOK=...
export SC_PAGERDUTY_URL=...
export SC_SMTP_HOST=...
export SC_DIGEST_RECIPIENTS=security@acme.com`}</pre>
        <button
          onClick={previewDigest}
          className="bg-panel border border-border px-3 py-1 rounded text-sm">
          Preview digest
        </button>
      </div>

      <div className="bg-panel rounded-lg border border-border p-4 space-y-2">
        <h3 className="font-semibold">Compliance evidence pack</h3>
        <div className="flex flex-wrap gap-2">
          {["nist", "cis", "pci", "hipaa", "iso", "zerotrust"].map(f => (
            <a key={f}
               href={`/api/platform/evidence-pack?framework=${f}`}
               target="_blank"
               className="border border-border px-3 py-1 rounded text-sm">
              {f.toUpperCase()}.pdf
            </a>
          ))}
        </div>
      </div>
    </section>
  );
}
