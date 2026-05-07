"use client";

import { useEffect, useState, useRef } from "react";

const VIEWS = [
  { id: "global",        label: "Global"        },
  { id: "campus",        label: "Campus"        },
  { id: "subnet",        label: "Subnet"        },
  { id: "security_zone", label: "Security Zone" },
  { id: "cloud",         label: "Cloud"         },
  { id: "risk_heat",     label: "Risk Heat"     },
  { id: "lifecycle",     label: "Lifecycle"     },
  { id: "health",        label: "Health"        },
  { id: "vulnerability", label: "Vulnerability" },
];

interface Envelope {
  view: string;
  elements?: { nodes?: any[]; edges?: any[] };
  layout?: any;
  style?: any[];
  stats?: any;
}

declare global { interface Window { cytoscape: any } }

export default function TopologyPage() {
  const [view, setView] = useState("risk_heat");
  const [data, setData] = useState<Envelope | null>(null);
  const [error, setError] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null);

  // Lazy-load Cytoscape from CDN. Real prod would npm-install it; this
  // keeps the bundle thin for the Phase 2 scaffold.
  useEffect(() => {
    if (window.cytoscape) return;
    const s = document.createElement("script");
    s.src = "https://cdn.jsdelivr.net/npm/cytoscape@3.30.1/dist/cytoscape.min.js";
    s.async = true;
    document.head.appendChild(s);
  }, []);

  const [token, setToken] = useState("");

  useEffect(() => {
    const t = localStorage.getItem("SC_TOKEN") || "";
    setToken(t);
    if (!t) return;
    fetch(`/api/platform/topology/${view}`, {
      headers: { Authorization: "Bearer " + t },
    })
      .then(r => r.ok ? r.json() : Promise.reject("HTTP " + r.status))
      .then(setData)
      .catch(e => setError(String(e)));
  }, [view]);

  // Render the graph whenever data + cytoscape are both available.
  useEffect(() => {
    if (!data || !containerRef.current) return;
    const tryRender = () => {
      if (!window.cytoscape) {
        setTimeout(tryRender, 100);
        return;
      }
      if (cyRef.current) cyRef.current.destroy();
      cyRef.current = window.cytoscape({
        container: containerRef.current,
        elements: data.elements,
        style: data.style,
        layout: data.layout,
      });
    };
    tryRender();
  }, [data]);

  if (!token) return <div className="bg-panel border border-border rounded-lg p-6 max-w-md"><h3 className="font-semibold mb-2">Sign in required</h3><p className="text-gray-400 text-sm mb-3">This page needs a bearer token. Use the home page to sign in first.</p><a href="/" className="bg-accent text-white px-4 py-2 rounded inline-block">Go to sign in →</a></div>;
  if (error) return <div className="text-bad">{error}</div>;

  return (
    <section className="space-y-4">
      <h2 className="text-2xl font-bold">🗺 Topology</h2>
      <p className="text-muted text-sm">
        Nine views over the same asset graph. Color encodes the property
        the view is named after (risk, lifecycle, health, KEV CVEs).
      </p>

      <div className="flex flex-wrap gap-2">
        {VIEWS.map(v => (
          <button
            key={v.id}
            onClick={() => setView(v.id)}
            className={`px-3 py-1.5 rounded text-sm border ${
              view === v.id
                ? "bg-accent text-white border-accent"
                : "bg-panel border-border hover:border-accent"
            }`}
          >{v.label}</button>
        ))}
      </div>

      {data?.stats && (
        <div className="bg-panel rounded-lg border border-border p-3">
          <div className="text-xs text-muted">Stats</div>
          <pre className="text-xs">{JSON.stringify(data.stats, null, 2)}</pre>
        </div>
      )}

      <div
        ref={containerRef}
        className="bg-panel rounded-lg border border-border"
        style={{ width: "100%", height: "640px" }}
      >
        {!data && <div className="text-muted text-center pt-60">⏳</div>}
      </div>
    </section>
  );
}
