"use client";

import { useEffect, useState } from "react";

interface Job {
  job_id: string; name: string; status: string; risk: string;
  mode: string; rollback_plan_id?: string;
  approvers?: string[]; approvals_required?: number;
  target_asset_ids?: string[]; target_asset_group_ids?: string[];
}

export default function ExecutionQueuePage() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [token, setToken] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (t) load(t);
  }, []);

  async function load(t: string) {
    try {
      const r = await fetch("/api/execute/queue",
        { headers: { Authorization: "Bearer " + t } });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      setJobs(j.queue || []);
    } catch (e: any) {
      setError(String(e));
    }
  }

  async function dryRun(jid: string) {
    const r = await fetch(`/api/execute/jobs/${encodeURIComponent(jid)}/dry-run`, {
      method: "POST",
      headers: { Authorization: "Bearer " + token },
    });
    if (!r.ok) { alert("Dry-run failed: " + (await r.text())); return; }
    const j = await r.json();
    alert(`Dry-run completed against ${j.asset_count} assets. ` +
           `Executions: ${(j.executions || []).length}, ` +
           `Blocked: ${(j.blocked || []).length}`);
    load(token);
  }

  async function exportJob(jid: string, fmt: string) {
    const r = await fetch(
      `/api/execute/jobs/${encodeURIComponent(jid)}/export?fmt=${fmt}`,
      { headers: { Authorization: "Bearer " + token } });
    if (!r.ok) { alert("Export failed: " + r.status); return; }
    const text = await r.text();
    const blob = new Blob([text], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${jid}.${fmt === "ansible" ? "yml" : fmt === "markdown" ? "md" : "txt"}`;
    a.click();
  }

  if (!token) return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;
  if (error) return <div className="text-bad">{error}</div>;

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">📋 Execution Queue</h2>
      <p className="text-muted text-sm">
        Active jobs: REVIEW / APPROVED / SCHEDULED / RUNNING.
        Approved jobs export to Ansible / Salt / NSO; SafeCadence does
        not push directly (use Tier3 SSH from CLI when explicitly enabled).
      </p>

      {!jobs.length && (
        <div className="bg-panel rounded-lg border border-border p-6 text-center text-muted">
          Queue is empty.
        </div>
      )}

      {jobs.map(j => (
        <div key={j.job_id}
             className="bg-panel rounded-lg border border-border p-4 space-y-2">
          <div className="flex justify-between items-baseline">
            <div>
              <h3 className="font-semibold">{j.name}</h3>
              <code className="text-xs text-muted">{j.job_id}</code>
            </div>
            <div className="flex gap-2">
              <span className="text-xs px-2 py-0.5 rounded bg-panel border border-border">
                {j.status}
              </span>
              <span className={`text-xs px-2 py-0.5 rounded ${
                j.risk === "critical" ? "bg-bad/20 text-bad"
                : j.risk === "high" || j.risk === "medium" ? "bg-warn/20 text-warn"
                : "bg-good/20 text-good"
              }`}>{j.risk}</span>
            </div>
          </div>
          <div className="text-xs text-muted">
            Mode: {j.mode}{" · "}
            Targets: {(j.target_asset_ids?.length || 0)} explicit
            {", "}{(j.target_asset_group_ids?.length || 0)} groups
            {" · "}
            Approvals: {(j.approvers?.length || 0)} / {j.approvals_required ?? "?"}
          </div>
          <div className="flex gap-2">
            {j.status === "approved" && (
              <button onClick={() => dryRun(j.job_id)}
                       className="bg-accent text-white px-3 py-1 rounded text-sm">
                Dry-run
              </button>
            )}
            <button onClick={() => exportJob(j.job_id, "ansible")}
                     className="border border-border px-3 py-1 rounded text-sm">
              ⬇ Ansible
            </button>
            <button onClick={() => exportJob(j.job_id, "raw")}
                     className="border border-border px-3 py-1 rounded text-sm">
              ⬇ Raw
            </button>
            <button onClick={() => exportJob(j.job_id, "markdown")}
                     className="border border-border px-3 py-1 rounded text-sm">
              ⬇ Markdown
            </button>
          </div>
        </div>
      ))}
    </section>
  );
}
