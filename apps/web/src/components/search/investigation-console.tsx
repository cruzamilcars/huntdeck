"use client";

import { AlertTriangle, FileText, History, Loader2, Search, User } from "lucide-react";
import { FormEvent, useEffect, useState } from "react";

import { ExportControls } from "@/components/export/export-controls";
import { ResultsGrid } from "@/components/results/results-grid";
import { Shell } from "@/components/layout/shell";
import {
  fetchInvestigationHistory,
  investigateIoc,
  type InvestigationHistoryRow,
} from "@/lib/api/investigations";
import { getSessionContext, type SessionContext } from "@/lib/api/session";
import type { InvestigationResponse } from "@/lib/api/types";

export function InvestigationConsole() {
  const [ioc, setIoc] = useState("8.8.8.8");
  const [result, setResult] = useState<InvestigationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [session, setSession] = useState<SessionContext | null>(null);
  const [history, setHistory] = useState<InvestigationHistoryRow[]>([]);
  const [historyError, setHistoryError] = useState<string | null>(null);

  async function loadHistory() {
    try {
      setHistory(await fetchInvestigationHistory(session, 20));
      setHistoryError(null);
    } catch (err) {
      setHistoryError(err instanceof Error ? err.message : "Failed to load history.");
    }
  }

  useEffect(() => {
    getSessionContext().then(setSession);
  }, []);

  useEffect(() => {
    if (session) {
      let cancelled = false;
      fetchInvestigationHistory(session, 20)
        .then((rows) => {
          if (!cancelled) {
            setHistory(rows);
          }
        })
        .catch((err) => {
          if (!cancelled) {
            setHistoryError(err instanceof Error ? err.message : "Failed to load history.");
          }
        });
      return () => {
        cancelled = true;
      };
    }
  }, [session]);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      setResult(await investigateIoc(ioc, session));
      loadHistory();
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Investigation failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Shell>
      <section className="scanline brutal-panel mb-4 p-4 md:p-6">
        <form onSubmit={onSubmit} className="relative z-10">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <label htmlFor="ioc" className="block text-xs uppercase text-[var(--muted)]">
              IOC input
            </label>
            <p className="flex items-center gap-2 text-xs uppercase text-[var(--muted)]">
              <User size={12} />
              {session?.email ?? "Anonymous dev mode"}
            </p>
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_180px]">
            <div className="flex min-w-0 items-center border border-[var(--line)] bg-black">
              <span className="border-r border-[var(--muted-line)] px-3 text-[var(--warning)]">
                &gt;
              </span>
              <input
                id="ioc"
                value={ioc}
                onChange={(event) => setIoc(event.target.value)}
                className="h-16 min-w-0 flex-1 bg-transparent px-3 text-lg font-bold uppercase text-white outline-none md:text-2xl"
                placeholder="PASTE IOC"
                spellCheck={false}
              />
            </div>
            <button
              type="submit"
              disabled={loading || !ioc.trim()}
              className="flex h-16 items-center justify-center gap-2 border border-[var(--line)] bg-[var(--line)] px-4 font-black uppercase text-black disabled:border-[var(--muted-line)] disabled:bg-[var(--panel-2)] disabled:text-[var(--muted)]"
            >
              {loading ? <Loader2 size={18} className="animate-spin" /> : <Search size={18} />}
              Investigate
            </button>
          </div>
        </form>
      </section>

      {error ? (
        <div className="mb-4 flex items-start gap-3 border border-[var(--danger)] bg-black p-4 text-[var(--danger)]">
          <AlertTriangle size={20} />
          <p className="text-sm uppercase">{error}</p>
        </div>
      ) : null}

      {result ? (
        <>
          <section className="mb-4 grid grid-cols-1 border border-[var(--line)] bg-black md:grid-cols-[1fr_auto]">
            <div className="min-w-0 p-4">
              <p className="text-xs uppercase text-[var(--muted)]">Normalized target</p>
              <p className="mt-1 break-all text-lg font-black uppercase md:text-2xl">
                {result.ioc.normalized}
              </p>
            </div>
            <div className="grid grid-cols-2 divide-x divide-[var(--muted-line)] border-t border-[var(--line)] md:border-l md:border-t-0">
              <div className="p-4">
                <p className="text-xs uppercase text-[var(--muted)]">Type</p>
                <p className="text-xl font-black uppercase">{result.ioc.type}</p>
              </div>
              <div className="p-4">
                <p className="text-xs uppercase text-[var(--muted)]">Risk</p>
                <p className="text-xl font-black uppercase text-[var(--warning)]">
                  {result.risk.severity} / {result.risk.score}
                </p>
              </div>
            </div>
          </section>
          <ExportControls result={result} />
          <ResultsGrid result={result} />
        </>
      ) : (
        <div className="muted-panel grid min-h-[320px] place-items-center p-8 text-center">
          <div>
            <FileText className="mx-auto mb-4 text-[var(--muted)]" size={36} />
            <p className="text-sm uppercase text-[var(--muted)]">
              Submit an IOC to render reputation, geolocation, relationship graph and community
              reports.
            </p>
            <p className="mt-3 text-xs uppercase text-[var(--muted)]">
              Backend expected at {process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"}
            </p>
          </div>
        </div>
      )}

      {result ? (
        <div className="fixed bottom-4 right-4 hidden border border-[var(--line)] bg-black px-3 py-2 text-xs uppercase text-[var(--muted)] md:block">
          <FileText size={14} className="mr-2 inline" />
          Export ready
        </div>
      ) : null}

      <section className="brutal-panel mb-4 p-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 className="flex items-center gap-2 text-xs uppercase text-[var(--muted)]">
            <History size={12} />
            Recent investigations
          </h2>
          <p className="text-xs uppercase text-[var(--muted)]">Last 20</p>
        </div>
        {historyError ? (
          <p className="text-xs uppercase text-[var(--danger)]">{historyError}</p>
        ) : history.length === 0 ? (
          <p className="text-xs uppercase text-[var(--muted)]">
            No investigations yet. Submit an IOC to populate history.
          </p>
        ) : (
          <ul className="divide-y divide-[var(--muted-line)]">
            {history.map((row) => (
              <li key={`${row.created_at}-${row.normalized_ioc}`} className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2">
                <span className="min-w-0 flex-1 truncate font-bold uppercase">{row.normalized_ioc}</span>
                <span className="w-16 text-right text-xs uppercase text-[var(--muted)]">{row.ioc_type}</span>
                <span className="w-24 text-right text-xs uppercase text-[var(--warning)]">
                  {row.severity ?? "unknown"} / {row.risk_score ?? "-"}
                </span>
                <span className="hidden w-32 text-right text-xs uppercase text-[var(--muted)] md:inline">
                  {new Date(row.created_at).toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </Shell>
  );
}