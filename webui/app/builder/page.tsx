"use client";

import { useEffect, useState } from "react";

const ASSET_TYPES = [
  { id: "network", icon: "🌐", label: "Network gear" },
  { id: "server", icon: "🖥", label: "Servers" },
  { id: "storage", icon: "💾", label: "Storage" },
  { id: "hypervisor", icon: "🪄", label: "Virtualization" },
  { id: "cloud", icon: "☁", label: "Cloud" },
  { id: "backup", icon: "🗄", label: "Backup" },
  { id: "identity", icon: "🔐", label: "Identity / NAC" },
];

const FRAMEWORKS = [
  { id: "nist", label: "NIST 800-53 Rev 5" },
  { id: "cis", label: "CIS Controls v8" },
  { id: "pci", label: "PCI-DSS v4" },
  { id: "hipaa", label: "HIPAA Security Rule" },
  { id: "iso", label: "ISO 27001" },
  { id: "zerotrust", label: "NIST 800-207 Zero Trust" },
];

const STRICTNESS = [
  { id: "basic", label: "Basic", desc: "Critical-only. Bare minimum." },
  { id: "standard", label: "Standard", desc: "Critical + high. Recommended." },
  { id: "paranoid", label: "Paranoid", desc: "All severities." },
];

interface Group { group_id: string; name: string; member_count?: number; }
interface Control {
  id: string; description: string; severity: string;
  rationale: string; selected: boolean;
  applies_to: string[]; frameworks: string[];
}

export default function BuilderPage() {
  const [step, setStep] = useState(1);
  const [assetTypes, setAssetTypes] = useState<Set<string>>(new Set());
  const [frameworks, setFrameworks] = useState<Set<string>>(new Set());
  const [strictness, setStrictness] = useState("standard");
  const [groupIds, setGroupIds] = useState<Set<string>>(new Set());
  const [groups, setGroups] = useState<Group[]>([]);
  const [controls, setControls] = useState<Control[]>([]);
  const [policyName, setPolicyName] = useState("");
  const [token, setToken] = useState("");

  useEffect(() => {
    setToken(localStorage.getItem("SC_TOKEN") || "");
  }, []);

  useEffect(() => {
    if (step === 2 && groups.length === 0 && token) {
      fetch("/api/platform/asset-groups",
            { headers: { Authorization: "Bearer " + token } })
        .then(r => r.ok ? r.json() : Promise.reject("HTTP " + r.status))
        .then(j => setGroups(j.groups || []))
        .catch(() => {});
    }
  }, [step, groups.length, token]);

  if (!token) return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;

  async function loadSuggestions() {
    const at = [...assetTypes].join(",");
    const fw = [...frameworks].join(",");
    const r = await fetch(
      `/api/policy/suggest-controls?asset_types=${at}&frameworks=${fw}&strictness=${strictness}`,
      { headers: { Authorization: "Bearer " + token } }
    );
    if (!r.ok) { alert("Failed: " + r.status); return; }
    const j = await r.json();
    setControls(j.controls || []);
    setStep(5);
  }

  async function savePolicy() {
    const body = {
      policy_name: policyName || `${[...assetTypes].join("/")} — ${new Date().toISOString().slice(0,10)}`,
      target_asset_types: [...assetTypes],
      applies_to_groups: [...groupIds],
      compliance_frameworks: [...frameworks],
      severity: "high",
      controls: controls.filter(c => c.selected).map(c => ({
        control_id: c.id, severity: c.severity, parameters: {},
        framework_refs: c.frameworks || [],
      })),
    };
    const r = await fetch("/api/policy/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
      body: JSON.stringify(body),
    });
    if (!r.ok) { alert("Save failed: " + (await r.text())); return; }
    const j = await r.json();
    alert(`Saved policy '${body.policy_name}' (id: ${j.policy_id})`);
    // Reset
    setStep(1); setAssetTypes(new Set()); setFrameworks(new Set());
    setStrictness("standard"); setGroupIds(new Set());
    setControls([]); setPolicyName("");
  }

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">🛠 Policy Builder</h2>

      <div className="flex gap-1">
        {[1,2,3,4,5,6].map(n => (
          <div key={n}
               className={`flex-1 h-1.5 rounded ${
                 n <= step ? "bg-accent" : "bg-border"
               }`}/>
        ))}
      </div>

      {step === 1 && (
        <div className="bg-panel rounded-lg border border-border p-4 space-y-4">
          <h3 className="font-semibold">Step 1 of 6 — What do you want to protect?</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {ASSET_TYPES.map(t => {
              const sel = assetTypes.has(t.id);
              return (
                <button key={t.id}
                  onClick={() => {
                    const s = new Set(assetTypes);
                    sel ? s.delete(t.id) : s.add(t.id);
                    setAssetTypes(s);
                  }}
                  className={`p-3 rounded-lg border text-left ${
                    sel ? "bg-accent/10 border-accent" : "bg-bg border-border"
                  }`}>
                  <div className="text-lg">{t.icon}</div>
                  <div className="font-semibold text-sm">{t.label}</div>
                </button>
              );
            })}
          </div>
          <button
            disabled={!assetTypes.size}
            onClick={() => setStep(2)}
            className="bg-accent text-white px-4 py-2 rounded disabled:opacity-50">
            Next →
          </button>
        </div>
      )}

      {step === 2 && (
        <div className="bg-panel rounded-lg border border-border p-4 space-y-4">
          <h3 className="font-semibold">Step 2 of 6 — Apply to which devices?</h3>
          <div
            onClick={() => setGroupIds(new Set())}
            className={`p-3 rounded-lg border cursor-pointer ${
              groupIds.size === 0 ? "bg-accent/10 border-accent" : "bg-bg border-border"
            }`}>
            <div className="font-semibold text-sm">All assets of those types (fleet-wide)</div>
            <div className="text-xs text-muted">Default — evaluate every asset matching the types from step 1.</div>
          </div>
          {groups.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {groups.map(g => {
                const sel = groupIds.has(g.group_id);
                return (
                  <div key={g.group_id}
                    onClick={() => {
                      const s = new Set(groupIds);
                      sel ? s.delete(g.group_id) : s.add(g.group_id);
                      setGroupIds(s);
                    }}
                    className={`p-3 rounded-lg border cursor-pointer ${
                      sel ? "bg-accent/10 border-accent" : "bg-bg border-border"
                    }`}>
                    <div className="font-semibold text-sm">{g.name}</div>
                    <div className="text-xs text-muted">{g.member_count ?? 0} members</div>
                  </div>
                );
              })}
            </div>
          )}
          <div className="flex gap-2">
            <button onClick={() => setStep(1)} className="border border-border px-4 py-2 rounded">← Back</button>
            <button onClick={() => setStep(3)} className="bg-accent text-white px-4 py-2 rounded">Next →</button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="bg-panel rounded-lg border border-border p-4 space-y-4">
          <h3 className="font-semibold">Step 3 of 6 — Compliance frameworks</h3>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {FRAMEWORKS.map(f => {
              const sel = frameworks.has(f.id);
              return (
                <button key={f.id}
                  onClick={() => {
                    const s = new Set(frameworks);
                    sel ? s.delete(f.id) : s.add(f.id);
                    setFrameworks(s);
                  }}
                  className={`p-3 rounded-lg border text-left text-sm ${
                    sel ? "bg-accent/10 border-accent" : "bg-bg border-border"
                  }`}>{f.label}</button>
              );
            })}
          </div>
          <div className="flex gap-2">
            <button onClick={() => setStep(2)} className="border border-border px-4 py-2 rounded">← Back</button>
            <button onClick={() => setStep(4)} className="bg-accent text-white px-4 py-2 rounded">Next →</button>
          </div>
        </div>
      )}

      {step === 4 && (
        <div className="bg-panel rounded-lg border border-border p-4 space-y-4">
          <h3 className="font-semibold">Step 4 of 6 — Strictness</h3>
          {STRICTNESS.map(s => (
            <button key={s.id}
              onClick={() => setStrictness(s.id)}
              className={`block w-full p-3 rounded-lg border text-left ${
                strictness === s.id ? "bg-accent/10 border-accent" : "bg-bg border-border"
              }`}>
              <div className="font-semibold text-sm">{s.label}</div>
              <div className="text-xs text-muted">{s.desc}</div>
            </button>
          ))}
          <div className="flex gap-2">
            <button onClick={() => setStep(3)} className="border border-border px-4 py-2 rounded">← Back</button>
            <button onClick={loadSuggestions}
                     className="bg-accent text-white px-4 py-2 rounded">
              Suggest controls →
            </button>
          </div>
        </div>
      )}

      {step === 5 && (
        <div className="bg-panel rounded-lg border border-border p-4 space-y-4">
          <h3 className="font-semibold">
            Step 5 of 6 — Suggested controls
            ({controls.filter(c => c.selected).length} of {controls.length})
          </h3>
          {controls.length === 0 ? (
            <div className="text-muted italic">No controls match. Try wider asset types / strictness.</div>
          ) : controls.map((c, i) => (
            <div key={c.id}
                 className="flex gap-3 border-b border-border pb-2 last:border-0">
              <input type="checkbox" checked={c.selected}
                onChange={e => {
                  const cs = [...controls];
                  cs[i] = { ...cs[i], selected: e.target.checked };
                  setControls(cs);
                }}/>
              <div className="flex-1">
                <div className="font-semibold text-sm font-mono">{c.id}</div>
                <div className="text-xs text-muted">{c.description}</div>
                <div className="text-xs text-accent mt-1">{c.rationale}</div>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded h-fit ${
                c.severity === "critical" ? "bg-bad/20 text-bad"
                : c.severity === "high" ? "bg-warn/20 text-warn"
                : "bg-good/20 text-good"
              }`}>{c.severity}</span>
            </div>
          ))}
          <div className="flex gap-2">
            <button onClick={() => setStep(4)} className="border border-border px-4 py-2 rounded">← Back</button>
            <button onClick={() => setStep(6)} className="bg-accent text-white px-4 py-2 rounded">Next →</button>
          </div>
        </div>
      )}

      {step === 6 && (
        <div className="bg-panel rounded-lg border border-border p-4 space-y-4">
          <h3 className="font-semibold">Step 6 of 6 — Save</h3>
          <input
            placeholder="Policy name"
            className="w-full bg-bg border border-border rounded px-3 py-2"
            value={policyName}
            onChange={e => setPolicyName(e.target.value)}/>
          <div className="text-sm text-muted">
            <strong>Targeting:</strong>{" "}
            {groupIds.size === 0 ? "fleet-wide"
              : `${groupIds.size} group(s)`}
            {" · "}
            {controls.filter(c => c.selected).length} controls
            {" · "}
            {[...frameworks].join(", ") || "no framework"}
            {" · "}
            {strictness} strictness
          </div>
          <div className="flex gap-2">
            <button onClick={() => setStep(5)} className="border border-border px-4 py-2 rounded">← Back</button>
            <button onClick={savePolicy} className="bg-accent text-white px-4 py-2 rounded font-semibold">
              💾 Save policy
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
