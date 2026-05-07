"use client";

import { useEffect, useState } from "react";

interface Job {
  job_id: string;
  name: string;
  description?: string;
  status: string;
  risk: string;
  mode: string;
  created_by: string;
  created_at: string;
  approvers: string[];
  approvals_required: number;
  inline_commands?: Record<string, string[]>;
}

export default function ApprovalsPage() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState("");
  const [token, setToken] = useState("");

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (t) load(t);
  }, []);

  async function load(t: string) {
    try {
      const r = await fetch("/api/execute/jobs?status=review", {
        headers: { Authorization: "Bearer " + t },
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      setJobs(j.jobs || []);
    } catch (e: any) {
      setError(String(e));
    }
  }

  async function approve(jid: string) {
    const note = prompt("Optional approval note:");
    const r = await fetch(`/api/execute/jobs/${encodeURIComponent(jid)}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json",
                  Authorization: "Bearer " + token },
      body: JSON.stringify({ note: note || "" }),
    });
    if (!r.ok) {
      alert("Approve failed: " + (await r.text()));
      return;
    }
    load(token);
  }

  async function reject(jid: string) {
    const reason = prompt("Reason for rejection:");
    if (!reason) return;
    const r = await fetch(`/api/execute/jobs/${encodeURIComponent(jid)}/reject`, {
      method: "POST",
      headers: { "Content-Type": "application/json",
                  Authorization: "Bearer " + token },
      body: JSON.stringify({ reason }),
    });
    if (!r.ok) {
      alert("Reject failed: " + (await r.text()));
      return;
    }
    load(token);
  }

  if (!token) return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;
  if (error) return <div className="text-bad">{error}</div>;

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">📝 Approval Queue</h2>
      <p className="text-muted text-sm">
        Jobs awaiting review. Authors cannot approve their own jobs.
        Critical-risk jobs require 2 distinct approvers.
      </p>
      {!jobs.length && (
        <div className="bg-panel rounded-lg border border-border p-6
                          text-center text-muted">
          Nothing in the approval queue right now.
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
            <span className={`text-xs px-2 py-0.5 rounded ${
              j.risk === "critical" ? "bg-bad/20 text-bad"
              : j.risk === "high" ? "bg-warn/20 text-warn"
              : j.risk === "medium" ? "bg-warn/20 text-warn"
              : "bg-good/20 text-good"
            }`}>{j.risk}</span>
          </div>
          <div className="text-sm text-muted">
            Author: <strong>{j.created_by}</strong>{" · "}
            Mode: {j.mode}{" · "}
            Approvals: {j.approvers?.length || 0} / {j.approvals_required}
          </div>
          {j.description && (
            <div className="text-sm">{j.description}</div>
          )}
          {j.inline_commands && Object.entries(j.inline_commands).map(([v, cs]) => (
            <details key={v}>
              <summary className="text-xs text-muted cursor-pointer">
                {v} — {cs.length} command{cs.length !== 1 ? "s" : ""}
              </summary>
              <pre className="bg-bg p-2 rounded text-xs overflow-auto mt-1">
                {cs.join("\n")}
              </pre>
            </details>
          ))}
          <div className="flex gap-2">
            <button
              onClick={() => approve(j.job_id)}
              className="bg-accent text-white px-4 py-1.5 rounded text-sm font-semibold"
            >Approve</button>
            <button
              onClick={() => reject(j.job_id)}
              className="bg-panel border border-bad text-bad px-4 py-1.5
                          rounded text-sm font-semibold"
            >Reject</button>
          </div>
        </div>
      ))}
    </section>
  );
}
