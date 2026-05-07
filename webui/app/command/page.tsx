"use client";

import { useEffect, useState } from "react";

interface Plan {
  intent?: string;
  matched_packs?: string[];
  risk?: string;
  risk_reasons?: string[];
  blocked?: boolean;
  block_reasons?: string[];
  commands_by_vendor?: Record<string, string[]>;
  summary?: string;
}

interface Job {
  job_id: string;
  name: string;
  status: string;
  risk: string;
  mode: string;
  approvers: string[];
  approvals_required: number;
}

export default function CommandCenterPage() {
  const [intent, setIntent] = useState("");
  const [plan, setPlan] = useState<Plan | null>(null);
  const [recent, setRecent] = useState<Job[]>([]);
  const [token, setToken] = useState("");

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (t) loadRecent(t);
  }, []);

  async function loadRecent(t: string) {
    try {
      const r = await fetch("/api/execute/jobs", {
        headers: { Authorization: "Bearer " + t },
      });
      if (!r.ok) return;
      const j = await r.json();
      setRecent(j.jobs || []);
    } catch {}
  }

  async function planNow() {
    if (!intent.trim() || !token) return;
    const r = await fetch("/api/execute/builder/plan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
      body: JSON.stringify({ intent }),
    });
    if (!r.ok) {
      alert("Planner refused: " + (await r.text()));
      return;
    }
    setPlan(await r.json());
  }

  async function planAndSubmit() {
    if (!intent.trim() || !token) return;
    const r = await fetch("/api/execute/builder/plan-and-save", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
      body: JSON.stringify({ intent, name: intent.slice(0, 60) }),
    });
    if (!r.ok) {
      alert("Refused: " + (await r.text()));
      return;
    }
    const j = await r.json();
    await fetch(
      `/api/execute/jobs/${encodeURIComponent(j.job.job_id)}/submit`,
      { method: "POST", headers: { Authorization: "Bearer " + token } }
    );
    alert("Job submitted: " + j.job.job_id);
    loadRecent(token);
  }

  if (!token) {
    return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;
  }

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">⚡ Command Center</h2>
      <p className="text-muted text-sm">
        Plan and submit command jobs across your fleet. SafeCadence picks
        the right vendor commands, runs guardrails, routes for approval.
        Real execution happens via Ansible / Salt / NSO (or Tier3 SSH if
        you've explicitly enabled it).
      </p>

      <div className="bg-panel rounded-lg border border-border p-4">
        <input
          placeholder="e.g. check BGP and interface errors on all Cisco routers"
          className="w-full bg-bg border border-border rounded px-3 py-2 text-sm"
          value={intent}
          onChange={e => setIntent(e.target.value)}
        />
        <div className="flex gap-2 mt-3">
          <button
            className="bg-accent text-white px-4 py-2 rounded text-sm font-semibold"
            onClick={planNow}
          >Plan</button>
          <button
            className="bg-panel border border-border px-4 py-2 rounded text-sm font-semibold"
            onClick={planAndSubmit}
          >Plan + Submit for review</button>
        </div>
      </div>

      {plan && <PlanCard plan={plan} />}

      <div className="bg-panel rounded-lg border border-border p-4">
        <h3 className="font-semibold mb-3">Recent jobs</h3>
        {recent.length ? (
          <table className="w-full text-sm">
            <thead className="text-muted text-xs text-left">
              <tr>
                <th className="py-1">Job</th><th>Risk</th>
                <th>Status</th><th>Mode</th><th>Approvals</th>
              </tr>
            </thead>
            <tbody>
              {recent.slice(0, 20).map((j, i) => (
                <tr key={i} className="border-t border-border">
                  <td className="py-1.5">
                    <div>{j.name}</div>
                    <div className="text-muted text-xs font-mono">{j.job_id}</div>
                  </td>
                  <td><RiskPill risk={j.risk} /></td>
                  <td className="text-muted">{j.status}</td>
                  <td className="text-muted">{j.mode}</td>
                  <td className="text-muted">{j.approvers?.length ?? 0} / {j.approvals_required}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-muted text-sm italic">No jobs yet.</div>
        )}
      </div>
    </section>
  );
}

function PlanCard({ plan }: { plan: Plan }) {
  if (plan.blocked) {
    return (
      <div className="bg-panel rounded-lg border-l-4 border-bad border border-border p-4">
        <h3 className="font-semibold mb-2">🚫 BLOCKED</h3>
        {(plan.block_reasons ?? []).map((r, i) => (
          <div key={i} className="text-sm text-bad">{r}</div>
        ))}
      </div>
    );
  }
  return (
    <div className="bg-panel rounded-lg border border-border p-4 space-y-2">
      <div className="font-semibold">{plan.summary}</div>
      <div className="flex gap-2 items-center text-xs">
        {(plan.matched_packs ?? []).map((p, i) => (
          <span key={i} className="bg-bg border border-border px-2 py-0.5 rounded">
            {p}
          </span>
        ))}
        <RiskPill risk={plan.risk || "safe"} />
      </div>
      {Object.entries(plan.commands_by_vendor || {}).map(([v, cs]) => (
        <div key={v}>
          <div className="text-xs text-muted mt-3 mb-1">{v}</div>
          <pre className="bg-bg p-2 rounded text-xs overflow-auto">
            {cs.join("\n")}
          </pre>
        </div>
      ))}
    </div>
  );
}

function RiskPill({ risk }: { risk: string }) {
  const colors: Record<string, string> = {
    safe: "bg-good/20 text-good",
    low: "bg-good/20 text-good",
    medium: "bg-warn/20 text-warn",
    high: "bg-warn/20 text-warn",
    critical: "bg-bad/20 text-bad",
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded ${colors[risk] || "bg-panel"}`}>
      {risk}
    </span>
  );
}
