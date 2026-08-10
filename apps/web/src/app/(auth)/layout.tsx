import type { ReactNode } from "react";

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-4 py-10 text-[var(--text)]">
      <header className="mb-6 w-full max-w-md border border-[var(--line)] bg-black p-4 text-center">
        <p className="text-xs text-[var(--muted)]">CLOUD OSINT / MCP ORCHESTRATION</p>
        <h1 className="mt-1 text-xl font-black uppercase">OSINT MCP HUB</h1>
      </header>
      <div className="w-full max-w-md">{children}</div>
    </main>
  );
}