"use client";

import { useEffect, useState } from "react";

interface Entry {
  timestamp: string; actor: string; action: string;
  job_id?: string; policy_id?: string; detail?: string;
  source: "policy" | "execution";
}

export default function AuditPage() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [filter, setFilter] = useState("");
  const [src, setSrc] = useState("");
  const [token, setToken] = useState("");

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (!t) return;
    Promise.all([
      fetch("/api/policy/audit?limit=200",
            { headers: { Authorization: "Bearer " + t } }).then(r => r.ok ? r.json() : { events: [] }),
      fetch("/api/execute/audit?limit=200",
            { headers: { Authorization: "Bearer " + t } }).then(r => r.ok ? r.json() : { entries: [] }),
    ]).then(([p, e]) => {
      const merged: Entry[] = [
        ...(p.events || []).map((x: any) => ({
          timestamp: x.ts || x.timestamp || "",
          actor: x.actor || "", action: x.action || "",
          job_id: "", policy_id: x.policy_id || "",
          detail: typeof x.detail === "string" ? x.detail
                   : JSON.stringify(x.detail || {}),
          source: "policy" as const,
        })),
        ...(e.entries || []).map((x: any) => ({
          timestamp: x.timestamp || "",
          actor: x.actor || "", action: x.action || "",
          job_id: x.job_id || "", policy_id: "",
          detail: x.detail || "",
          source: "execution" as const,
        })),
      ];
      merged.sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
      setEntries(merged);
    });
  }, []);

  if (!token) return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;

  const filtered = entries.filter(e => {
    if (src && e.source !== src) return false;
    if (!filter) return true;
    const f = filter.toLowerCase();
    return [e.actor, e.action, e.policy_id, e.job_id, e.detail]
      .some(v => (v || "").toLowerCase().includes(f));
  });

  function exportCsv() {
    const cols = ["timestamp", "source", "actor", "action",
                   "policy_id", "job_id", "detail"];
    const csv = [cols.join(",")].concat(
      entries.map(r => cols.map(c => '"' + String((r as any)[c] || "")
                                    .replace(/"/g, '""') + '"').join(","))
    ).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `safecadence-audit-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
  }

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">📜 Audit log</h2>
      <p className="text-muted text-sm">
        Append-only record. Combines policy + execution feeds.
      </p>

      <div className="flex flex-wrap gap-2">
        <input
          placeholder="Filter (actor / action / policy / job)..."
          className="flex-1 min-w-[240px] bg-panel border border-border rounded px-3 py-2 text-sm"
          value={filter}
          onChange={e => setFilter(e.target.value)}/>
        <select
          value={src}
          onChange={e => setSrc(e.target.value)}
          className="bg-panel border border-border rounded px-3 py-2 text-sm">
          <option value="">all sources</option>
          <option value="policy">policy</option>
          <option value="execution">execution</option>
        </select>
        <button onClick={exportCsv}
                 className="bg-panel border border-border px-4 py-2 rounded text-sm">
          ⬇ CSV
        </button>
      </div>

      <div className="bg-panel rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="text-muted text-xs text-left">
            <tr>
              <th className="px-3 py-2">Time</th>
              <th>Source</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Subject</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 500).map((e, i) => (
              <tr key={i} className="border-t border-border">
                <td className="px-3 py-2 text-xs text-muted whitespace-nowrap">
                  {(e.timestamp || "").slice(0, 19)}
                </td>
                <td>
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    e.source === "execution" ? "bg-warn/20 text-warn" : "bg-good/20 text-good"
                  }`}>{e.source}</span>
                </td>
                <td>{e.actor}</td>
                <td><code className="text-xs">{e.action}</code></td>
                <td><code className="text-xs">{e.job_id || e.policy_id}</code></td>
                <td className="text-xs text-muted">
                  {(e.detail || "").slice(0, 120)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
