"use client";

import { AlertTriangle, ChevronLeft, ChevronRight, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";

import { ModulePanel } from "@/components/results/module-panel";
import {
  fetchInvestigationHistory,
  type InvestigationHistoryRow,
} from "@/lib/api/investigations";
import { getSessionContext, type SessionContext } from "@/lib/api/session";

const PAGE_SIZE = 8;

const SEVERITY_CLASS: Record<string, string> = {
  critical: "text-[var(--danger)] border-[var(--danger)]",
  high: "text-[var(--danger)] border-[var(--danger)]",
  medium: "text-[var(--warning)] border-[var(--warning)]",
  low: "text-[var(--accent)] border-[var(--accent)]",
};

export function HistoryPanel() {
  const [rows, setRows] = useState<InvestigationHistoryRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState<SessionContext | null>(null);
  const [page, setPage] = useState(0);

  useEffect(() => {
    getSessionContext().then(setSession);
  }, []);

  useEffect(() => {
    if (!session) {
      return;
    }
    let cancelled = false;
    fetchInvestigationHistory(session, PAGE_SIZE, page * PAGE_SIZE)
      .then((data) => {
        if (!cancelled) {
          setRows(data);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load history.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [session, page]);

  if (error) {
    return (
      <div className="flex items-start gap-3 border border-[var(--danger)] bg-black p-4 text-[var(--danger)]">
        <AlertTriangle size={20} />
        <p className="text-sm uppercase">{error}</p>
      </div>
    );
  }

  if (!rows) {
    return (
      <div className="muted-panel grid min-h-[120px] place-items-center p-6">
        <Loader2 className="animate-spin text-[var(--muted)]" size={24} />
      </div>
    );
  }

  return (
    <ModulePanel
      title="Investigation history"
      meta={`page ${page + 1}`}
    >
      {rows.length === 0 ? (
        <p className="p-4 text-xs uppercase text-[var(--muted)]">No records on this page.</p>
      ) : (
        <ul className="space-y-2">
          {rows.map((row) => (
            <li
              key={`${row.normalized_ioc}-${row.created_at}`}
              className="flex items-center justify-between gap-3 border border-[var(--muted-line)] px-3 py-2"
            >
              <span className="min-w-0 flex-1 truncate font-bold uppercase text-xs">{row.raw_ioc}</span>
              <span className="hidden shrink-0 border border-[var(--muted-line)] px-2 py-0.5 text-[10px] uppercase text-[var(--muted)] sm:inline">
                {row.ioc_type}
              </span>
              <span
                className={`shrink-0 border px-2 py-0.5 text-[10px] font-black uppercase ${
                  SEVERITY_CLASS[row.severity ?? "unknown"] ??
                  "border-[var(--muted-line)] text-[var(--muted)]"
                }`}
              >
                {row.severity ?? "?"} {row.risk_score ?? "-"}
              </span>
              <span className="hidden shrink-0 text-[10px] uppercase text-[var(--muted)] md:inline">
                {String(row.created_at).slice(0, 16).replace("T", " ")}
              </span>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-3 flex items-center justify-between gap-2">
        <button
          type="button"
          disabled={page === 0}
          onClick={() => setPage((current) => Math.max(current - 1, 0))}
          className="flex items-center gap-1 border border-[var(--muted-line)] px-3 py-1 text-xs uppercase enabled:hover:border-[var(--warning)] disabled:opacity-30"
        >
          <ChevronLeft size={14} /> Prev
        </button>
        <button
          type="button"
          disabled={rows.length < PAGE_SIZE}
          onClick={() => setPage((current) => current + 1)}
          className="flex items-center gap-1 border border-[var(--muted-line)] px-3 py-1 text-xs uppercase enabled:hover:border-[var(--warning)] disabled:opacity-30"
        >
          Next <ChevronRight size={14} />
        </button>
      </div>
    </ModulePanel>
  );
}
