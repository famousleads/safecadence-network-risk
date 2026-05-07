"use client";

import { useEffect, useState } from "react";

interface Job {
  job_id: string; name: string; status: string; risk: string;
  rollback_plan_id?: string;
}

export default function RollbackPage() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [token, setToken] = useState("");

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (t) load(t);
  }, []);

  async function load(t: string) {
    const r = await fetch("/api/execute/jobs",
      { headers: { Authorization: "Bearer " + t } });
    if (!r.ok) return;
    const j = await r.json();
    const eligible = (j.jobs || []).filter((jb: Job) =>
      jb.rollback_plan_id && (jb.status === "done" || jb.status === "failed")
    );
    setJobs(eligible);
  }

  async function rollback(jid: string) {
    if (!confirm("Roll back this job? An audit entry will be created.")) return;
    const r = await fetch(`/api/execute/jobs/${encodeURIComponent(jid)}/rollback`, {
      method: "POST",
      headers: { Authorization: "Bearer " + token },
    });
    if (!r.ok) { alert("Rollback failed: " + (await r.text())); return; }
    const j = await r.json();
    alert(`Rolled back: ${j.status}`);
    load(token);
  }

  if (!token) return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">⏮ Rollback Manager</h2>
      <p className="text-muted text-sm">
        Jobs whose rollback plan was generated at approval time.
        Rolling back marks the job ROLLED_BACK and writes an immutable
        audit row.
      </p>

      {!jobs.length && (
        <div className="bg-panel rounded-lg border border-border p-6 text-center text-muted">
          No jobs are eligible for rollback yet.
        </div>
      )}

      {jobs.map(j => (
        <div key={j.job_id}
             className="bg-panel rounded-lg border border-border p-4
                        flex justify-between items-baseline">
          <div>
            <h3 className="font-semibold">{j.name}</h3>
            <code className="text-xs text-muted">{j.job_id}</code>
            <div className="text-xs text-muted mt-1">
              Status: {j.status} · Plan: <code>{j.rollback_plan_id}</code>
            </div>
          </div>
          <button onClick={() => rollback(j.job_id)}
                   className="bg-panel border border-warn text-warn px-4 py-2
                              rounded text-sm font-semibold">
            Rollback
          </button>
        </div>
      ))}
    </section>
  );
}
