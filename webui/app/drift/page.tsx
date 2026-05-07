"use client";

import { useEffect, useState } from "react";

interface Drift {
  finding_count?: number;
  detector_count?: number;
  by_severity?: Record<string, number>;
  by_type?: Record<string, number>;
  findings?: {
    type: string;
    severity: string;
    left?: { system: string; asset_id: string };
    right?: { system: string; asset_id: string };
    conflict?: string;
    resolution?: string;
  }[];
}

export default function DriftPage() {
  const [data, setData] = useState<Drift | null>(null);
  const [error, setError] = useState("");
  const [token, setToken] = useState("");

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (!t) return;
    fetch("/api/policy/cross-system-drift", {
      headers: { Authorization: "Bearer " + t },
    })
      .then(r => r.ok ? r.json() : Promise.reject("HTTP " + r.status))
      .then(setData)
      .catch(e => setError(String(e)));
  }, []);

  if (!token) return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;
  if (error) return <div className="text-bad">{error}</div>;
  if (!data) return <div className="text-muted">⏳ Loading…</div>;

  const findings = data.findings || [];
  const sevColor: Record<string, string> = {
    critical: "border-bad", high: "border-warn",
    medium: "border-accent", low: "border-good",
  };

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">📉 Cross-system drift</h2>
      <p className="text-muted text-sm">
        {data.detector_count} detectors found {data.finding_count || 0} cross-
        system policy conflicts. These are findings where one system's
        decision contradicts another's.
      </p>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {Object.entries(data.by_severity || {}).map(([sev, n]) => (
          <div key={sev} className={`bg-panel rounded-lg border border-border p-4`}>
            <div className={`text-3xl font-bold ${
              sev === "critical" ? "text-bad"
              : sev === "high" ? "text-warn"
              : "text-good"
            }`}>{n}</div>
            <div className="text-xs text-muted mt-1 uppercase">{sev}</div>
          </div>
        ))}
      </div>

      {findings.length ? (
        <div className="space-y-2">
          {findings.slice(0, 50).map((f, i) => (
            <div key={i}
                 className={`bg-panel rounded-lg border border-border border-l-4
                              ${sevColor[f.severity] || 'border-muted'} p-4`}>
              <div className="flex justify-between items-baseline">
                <code className="text-sm font-semibold">{f.type}</code>
                <span className={`text-xs px-2 py-0.5 rounded ${
                  f.severity === "critical" ? "bg-bad/20 text-bad"
                  : f.severity === "high" ? "bg-warn/20 text-warn"
                  : "bg-good/20 text-good"
                }`}>{f.severity}</span>
              </div>
              <div className="text-sm mt-2">
                <span className="text-muted">conflict:</span>{" "}
                {f.conflict}
              </div>
              {f.resolution && (
                <div className="text-sm mt-1">
                  <span className="text-accent">resolution:</span>{" "}
                  {f.resolution}
                </div>
              )}
              <div className="text-xs text-muted mt-2 font-mono">
                {f.left?.asset_id} ⇄ {f.right?.asset_id}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-panel rounded-lg border border-border p-6
                          text-center text-muted">
          No cross-system policy conflicts detected.
        </div>
      )}
    </section>
  );
}
