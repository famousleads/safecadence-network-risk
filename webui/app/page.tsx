"use client";

import { useEffect, useState } from "react";

interface Briefing {
  asset_summary?: { kev_cves_total?: number; crown_jewels?: number; asset_count?: number };
  policy_summary?: {
    policy_count?: number;
    overall_compliance_pct?: number;
    total_failures?: number;
    top_5_failing_policies?: { policy_name: string; fail: number }[];
  };
  top_risks?: { title: string; severity: string; why: string; action: string }[];
}

interface DriftResult {
  finding_count?: number;
  detector_count?: number;
  by_severity?: Record<string, number>;
}

export default function CompliancePage() {
  const [token, setToken] = useState<string>("");
  const [briefing, setBriefing] = useState<Briefing | null>(null);
  const [drift, setDrift] = useState<DriftResult | null>(null);
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState(false);
  // Login form state
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");

  useEffect(() => {
    const t = typeof window !== "undefined"
      ? localStorage.getItem("SC_TOKEN") || ""
      : "";
    setToken(t);
  }, []);

  async function login() {
    setLoginError("");
    try {
      // The SafeCadence backend has shipped two login wire formats over time:
      //   - OAuth2PasswordRequestForm   → application/x-www-form-urlencoded
      //   - Pydantic BaseModel          → application/json
      // We try form-urlencoded first (the modern path), and on 422 ("body must
      // be a dict") we transparently retry with JSON. Either succeeds if the
      // password is right; both fail with 401 if it isn't.
      let r = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ username, password }).toString(),
      });
      if (r.status === 422) {
        r = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });
      }
      if (!r.ok) {
        const txt = await r.text();
        throw new Error(`HTTP ${r.status}: ${txt}`);
      }
      const j = await r.json();
      const t = j.access_token || j.token || j.jwt;
      if (!t) throw new Error("no access_token in response: " + JSON.stringify(j));
      localStorage.setItem("SC_TOKEN", t);
      setToken(t);
    } catch (e: any) {
      setLoginError(String(e.message || e));
    }
  }

  async function load() {
    if (!token) return;
    setLoading(true);
    setError("");
    try {
      const headers = { Authorization: "Bearer " + token };
      const [b, d] = await Promise.all([
        fetch("/api/policy/executive-briefing", { headers })
          .then(r => r.ok ? r.json() : Promise.reject(`briefing: ${r.status}`)),
        fetch("/api/policy/cross-system-drift", { headers })
          .then(r => r.ok ? r.json() : Promise.reject(`drift: ${r.status}`)),
      ]);
      setBriefing(b);
      setDrift(d);
    } catch (e: any) {
      setError(String(e));
      // If 401, token's bad — clear it so the login form reappears.
      if (String(e).includes("401")) {
        localStorage.removeItem("SC_TOKEN");
        setToken("");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { if (token) load(); /* eslint-disable-next-line */ }, [token]);

  // ----- LOGIN VIEW -----
  if (!token) {
    return (
      <section className="space-y-6">
        <div>
          <h2 className="text-3xl font-bold mb-2">Welcome to SafeCadence</h2>
          <p className="text-gray-400">
            Sign in to your local SafeCadence instance to see compliance,
            drift, inventory, and the command center.
          </p>
        </div>

        <div className="bg-panel border border-border rounded-lg p-6 max-w-md space-y-4">
          <h3 className="font-semibold text-lg">Sign in</h3>

          <div>
            <label className="block text-xs text-gray-400 mb-1">
              Username
            </label>
            <input
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="admin"
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm"
              autoComplete="username"
            />
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") login(); }}
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm"
              autoComplete="current-password"
            />
          </div>

          {loginError && (
            <div className="text-bad text-sm bg-bad/10 border border-bad/30
                            rounded px-3 py-2">
              {loginError}
            </div>
          )}

          <button
            onClick={login}
            className="bg-accent hover:opacity-90 text-white font-semibold
                       w-full py-2 rounded">
            Sign in
          </button>

          <details className="text-xs text-gray-400">
            <summary className="cursor-pointer hover:text-white">
              Don't know your password?
            </summary>
            <p className="mt-2 leading-relaxed">
              The first time you ran <code className="bg-bg px-1 rounded">safecadence ui</code>,
              the server printed an admin password to the terminal. Look for
              the line <code className="bg-bg px-1 rounded">[bootstrap] Wrote ... initial login: admin / ...</code>
              in your terminal scroll-back, or check
              <code className="bg-bg px-1 rounded ml-1">~/.safecadence/users.yaml</code>.
            </p>
            <p className="mt-2">
              <strong>Or use SSO:</strong>{" "}
              <a href="/api/auth/oidc/login" className="text-accent hover:underline">
                Sign in with OIDC ↗
              </a>{" "}
              (only works if you've configured <code className="bg-bg px-1 rounded">~/.safecadence/sso.json</code>).
            </p>
          </details>
        </div>

        <div className="bg-panel border border-border rounded-lg p-6
                        max-w-md text-sm text-gray-400">
          <strong className="text-gray-200">No password? No problem.</strong>
          <p className="mt-2">If you're running a fresh local dev install:</p>
          <pre className="bg-bg p-3 rounded mt-2 text-xs overflow-auto">{`# in another terminal
safecadence ui
# look for the printed admin / <password> line
# then come back and sign in here`}</pre>
        </div>
      </section>
    );
  }

  // ----- COMPLIANCE DASHBOARD -----
  if (loading) return <div className="text-gray-400">⏳ Loading…</div>;
  if (error) return (
    <div className="space-y-3">
      <div className="text-bad bg-bad/10 border border-bad/30 rounded px-4 py-3">
        {error}
      </div>
      <button
        onClick={() => { localStorage.removeItem("SC_TOKEN"); setToken(""); }}
        className="border border-border px-4 py-2 rounded text-sm">
        Sign out
      </button>
    </div>
  );

  const kev = briefing?.asset_summary?.kev_cves_total ?? 0;
  const fails = briefing?.policy_summary?.total_failures ?? 0;
  const compliance = briefing?.policy_summary?.overall_compliance_pct ?? 0;
  const findings = drift?.finding_count ?? 0;
  const assets = briefing?.asset_summary?.asset_count ?? 0;

  return (
    <section className="space-y-4">
      <div className="flex items-baseline gap-3">
        <h2 className="text-2xl font-bold">Fleet compliance</h2>
        <span className="text-gray-400 text-sm">{assets} assets</span>
        <button
          onClick={() => { localStorage.removeItem("SC_TOKEN"); setToken(""); }}
          className="ml-auto text-xs text-gray-400 hover:text-white">
          Sign out
        </button>
      </div>

      {assets === 0 && (
        <div className="bg-panel border border-accent rounded-lg p-4">
          <h3 className="font-semibold mb-1">⚠ Your fleet is empty</h3>
          <p className="text-sm text-gray-400 mb-3">
            Load demo data to see what SafeCadence does, or onboard
            real assets via the Inventory tab.
          </p>
          <button
            onClick={async () => {
              const r = await fetch("/api/platform/load-demo?overwrite=false", {
                method: "POST",
                headers: { Authorization: "Bearer " + token },
              });
              if (r.ok) load();
              else alert("Load failed: " + r.status);
            }}
            className="bg-accent text-white px-4 py-2 rounded font-semibold">
            Load demo data (31 realistic assets)
          </button>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat value={compliance} label="overall compliance %" suffix="%"
              color={compliance >= 80 ? "good" : compliance >= 60 ? "warn" : "bad"} />
        <Stat value={kev} label="KEV CVEs in active fleet"
              color={kev > 0 ? "bad" : "good"} />
        <Stat value={fails} label="open policy failures"
              color={fails > 0 ? "warn" : "good"} />
        <Stat value={findings} label="cross-system drift findings"
              color={findings > 0 ? "warn" : "good"} />
      </div>

      <div className="bg-panel rounded-lg border border-border p-4">
        <h3 className="font-semibold mb-2">Top failing policies</h3>
        {briefing?.policy_summary?.top_5_failing_policies?.length ? (
          <table className="w-full text-sm">
            <thead className="text-gray-400 text-xs text-left">
              <tr><th className="py-1">Policy</th><th className="py-1">Failures</th></tr>
            </thead>
            <tbody>
              {briefing.policy_summary.top_5_failing_policies.map((p, i) => (
                <tr key={i} className="border-t border-border">
                  <td className="py-1.5">{p.policy_name}</td>
                  <td className="py-1.5 text-bad">{p.fail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-gray-400 text-sm italic">
            No policies have failures right now.
          </p>
        )}
      </div>

      <div className="bg-panel rounded-lg border border-border p-4">
        <h3 className="font-semibold mb-2">Top risks this week</h3>
        <ul className="space-y-3">
          {(briefing?.top_risks ?? []).map((r, i) => (
            <li key={i} className="border-l-4 border-accent pl-3">
              <div className="font-semibold text-sm">{r.title}</div>
              <div className="text-gray-400 text-xs mt-0.5">{r.why}</div>
              <div className="text-xs mt-1 text-accent">{r.action}</div>
            </li>
          ))}
          {!(briefing?.top_risks ?? []).length && (
            <li className="text-gray-400 text-sm italic">
              No top-priority risks detected.
            </li>
          )}
        </ul>
      </div>
    </section>
  );
}

function Stat({ value, label, suffix = "", color = "muted" }:
  { value: number | string; label: string; suffix?: string; color?: string }) {
  const colorCls = {
    good: "text-good", bad: "text-bad",
    warn: "text-warn", muted: "text-gray-200",
  }[color] ?? "text-gray-200";
  return (
    <div className="bg-panel rounded-lg border border-border p-4">
      <div className={`text-3xl font-bold ${colorCls}`}>{value}{suffix}</div>
      <div className="text-xs text-gray-400 mt-1">{label}</div>
    </div>
  );
}
