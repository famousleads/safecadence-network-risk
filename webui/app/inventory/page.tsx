"use client";

import { useEffect, useState } from "react";

interface Asset {
  identity?: {
    asset_id?: string; asset_type?: string; vendor?: string;
    hostname?: string; criticality?: string; site?: string;
    environment?: string; owner?: string; team?: string;
    country?: string; city?: string; campus?: string;
  };
  health?: { grade?: string };
  security?: { kev_cves?: number; critical_cves?: number };
}

export default function InventoryPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");
  const [token, setToken] = useState("");

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (!t) return;
    fetch("/api/platform/inventory", {
      headers: { Authorization: "Bearer " + t },
    })
      .then(r => r.ok ? r.json() : Promise.reject("HTTP " + r.status))
      .then(j => setAssets(j.assets || []))
      .catch(e => setError(String(e)));
  }, []);

  if (!token) return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;
  if (error) return (
    <div className="bg-panel border border-border rounded-lg p-6">
      <div className="text-bad mb-3">{error}</div>
      <a href="/" className="text-accent hover:underline">→ Sign in</a>
    </div>
  );

  const filtered = assets.filter(a => {
    if (!filter) return true;
    const f = filter.toLowerCase();
    const ident = a.identity || {};
    return [ident.asset_id, ident.vendor, ident.hostname,
            ident.site, ident.owner, ident.team]
      .some(v => (v || "").toLowerCase().includes(f));
  });

  return (
    <section className="space-y-4">
      <div className="flex items-baseline gap-3">
        <h2 className="text-2xl font-bold">Asset inventory</h2>
        <span className="text-muted text-sm">{filtered.length} of {assets.length}</span>
      </div>

      <input
        placeholder="Filter by id / vendor / site / owner..."
        className="w-full max-w-md bg-panel border border-border rounded px-3 py-2 text-sm"
        onChange={e => setFilter(e.target.value)}
      />

      <div className="bg-panel rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="text-muted text-xs text-left">
            <tr>
              <th className="px-3 py-2">Asset</th>
              <th className="px-3 py-2">Vendor</th>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Site</th>
              <th className="px-3 py-2">Owner</th>
              <th className="px-3 py-2">Health</th>
              <th className="px-3 py-2">KEV</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((a, i) => {
              const id = a.identity || {};
              const grade = a.health?.grade || "?";
              const kev = a.security?.kev_cves || 0;
              const gradeColor = grade === "A" ? "text-good"
                : grade === "B" ? "text-good"
                : grade === "C" ? "text-warn"
                : grade === "?" ? "text-muted"
                : "text-bad";
              return (
                <tr key={i} className="border-t border-border hover:bg-bg/50">
                  <td className="px-3 py-2">
                    <div className="font-medium">{id.hostname || id.asset_id}</div>
                    <div className="text-muted text-xs font-mono">{id.asset_id}</div>
                  </td>
                  <td className="px-3 py-2">{id.vendor}</td>
                  <td className="px-3 py-2 text-muted">{id.asset_type}</td>
                  <td className="px-3 py-2">{id.site}</td>
                  <td className="px-3 py-2 text-muted">{id.owner || "—"}</td>
                  <td className={`px-3 py-2 font-bold ${gradeColor}`}>{grade}</td>
                  <td className={`px-3 py-2 ${kev > 0 ? "text-bad font-bold" : "text-muted"}`}>{kev}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
