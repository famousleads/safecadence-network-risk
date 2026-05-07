"use client";

import { useEffect, useState } from "react";

interface Policy { policy_id: string; policy_name: string; }

export default function RemediationPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [token, setToken] = useState("");
  const [pid, setPid] = useState("(top-5)");
  const [fmt, setFmt] = useState("ansible");
  const [vendor, setVendor] = useState("");

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (!t) return;
    fetch("/api/policy/", { headers: { Authorization: "Bearer " + t } })
      .then(r => r.ok ? r.json() : Promise.reject("HTTP " + r.status))
      .then(j => setPolicies(j.policies || []))
      .catch(() => {});
  }, []);

  async function download() {
    if (!token) return;
    let url = "";
    if (pid === "(top-5)") {
      url = `/api/policy/fix-top-risks?top=5&format=${fmt}`;
      if (vendor) url += `&vendor=${vendor}`;
    } else {
      url = `/api/policy/${encodeURIComponent(pid)}/export?format=${fmt}`;
      if (vendor) url += `&vendor=${vendor}`;
    }
    const r = await fetch(url, { headers: { Authorization: "Bearer " + token } });
    if (!r.ok) { alert("Export failed: " + r.status); return; }
    const text = await r.text();
    const blob = new Blob([text], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `safecadence-remediation.${
      fmt === "markdown" ? "md" : fmt === "ansible" ? "yml" : "txt"
    }`;
    a.click();
  }

  if (!token) return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">🩹 Remediation</h2>
      <p className="text-muted text-sm">
        Pick a policy and a target format. SafeCadence generates the
        per-vendor commands; your existing automation tooling executes.
      </p>

      <div className="bg-panel rounded-lg border border-border p-4 space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1">Policy</label>
          <select
            value={pid}
            onChange={e => setPid(e.target.value)}
            className="w-full bg-bg border border-border rounded px-3 py-2 text-sm">
            <option value="(top-5)">⚡ Top 5 highest-priority across ALL policies</option>
            {policies.map(p => (
              <option key={p.policy_id} value={p.policy_id}>{p.policy_name}</option>
            ))}
          </select>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-muted mb-1">Format</label>
            <select
              value={fmt}
              onChange={e => setFmt(e.target.value)}
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm">
              <option value="ansible">Ansible playbook</option>
              <option value="terraform">Terraform HCL</option>
              <option value="powershell">PowerShell</option>
              <option value="bash">Bash</option>
              <option value="markdown">Markdown runbook</option>
              <option value="raw">Raw configs</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-muted mb-1">Vendor (optional)</label>
            <input
              value={vendor}
              onChange={e => setVendor(e.target.value)}
              placeholder="e.g. cisco_ios"
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm"/>
          </div>
        </div>
        <button onClick={download}
                 className="bg-accent text-white px-4 py-2 rounded font-semibold">
          ⬇ Download remediation
        </button>
      </div>
    </section>
  );
}
