import type { ReactNode } from "react";
import Link from "next/link";

export function Shell({ children }: { children: ReactNode }) {
  return (
    <main className="min-h-screen px-4 py-4 text-[var(--text)] md:px-8 md:py-6">
      <header className="mb-4 grid grid-cols-1 border border-[var(--line)] bg-black md:grid-cols-[1fr_auto]">
        <div className="border-b border-[var(--line)] p-3 md:border-b-0 md:border-r">
          <p className="text-xs text-[var(--muted)]">CLOUD OSINT / MCP ORCHESTRATION</p>
          <h1 className="mt-1 text-xl font-black uppercase md:text-3xl">OSINT MCP HUB</h1>
        </div>
        <div className="grid grid-cols-4 divide-x divide-[var(--muted-line)] text-center text-xs uppercase">
          <div className="p-3">
            <p className="text-[var(--muted)]">Mode</p>
            <p className="text-[var(--warning)]">Community</p>
          </div>
          <div className="p-3">
            <p className="text-[var(--muted)]">Quota</p>
            <p>10/day</p>
          </div>
          <div className="p-3">
            <p className="text-[var(--muted)]">MCP</p>
            <p>Mock</p>
          </div>
          <div className="p-3">
            <p className="text-[var(--muted)]">Auth</p>
            <Link href="/login" className="text-[var(--warning)] underline">
              Login
            </Link>
          </div>
        </div>
      </header>
      {children}
    </main>
  );
}