import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SafeCadence",
  description: "Local-first network + identity security platform",
};

export default function RootLayout({
  children,
}: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-border px-6 py-3 flex items-center gap-4">
          <h1 className="text-base font-bold">🛡 SafeCadence</h1>
          <span className="text-xs text-muted">v7.1.0 · React UI (Phase 1)</span>
          <nav className="ml-auto flex gap-3 text-xs flex-wrap">
            <a href="/" className="hover:text-white">Compliance</a>
            <a href="/builder" className="hover:text-white">Builder</a>
            <a href="/inventory" className="hover:text-white">Inventory</a>
            <a href="/drift" className="hover:text-white">Drift</a>
            <a href="/topology" className="hover:text-white">Topology</a>
            <a href="/remediation" className="hover:text-white">Remediation</a>
            <a href="/command" className="hover:text-white">Command</a>
            <a href="/approvals" className="hover:text-white">Approvals</a>
            <a href="/queue" className="hover:text-white">Queue</a>
            <a href="/rollback" className="hover:text-white">Rollback</a>
            <a href="/audit" className="hover:text-white">Audit</a>
            <a href="/settings" className="hover:text-white">Settings</a>
          </nav>
        </header>
        <main className="p-6 max-w-7xl mx-auto">{children}</main>
      </body>
    </html>
  );
}
