"use client";

import { Loader2, Plus, RefreshCw, Trash2 } from "lucide-react";
import { FormEvent, useEffect, useState } from "react";

import {
  addToWatchlist,
  fetchWatchlist,
  removeFromWatchlist,
  recheckWatchItem,
  type WatchItem,
} from "@/lib/api/investigations";
import { getSessionContext, type SessionContext } from "@/lib/api/session";
import type { InvestigationResponse } from "@/lib/api/types";

export function WatchlistPanel({
  onRecheckResult,
}: {
  onRecheckResult: (result: InvestigationResponse) => void;
}) {
  const [items, setItems] = useState<WatchItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [newIoc, setNewIoc] = useState("");
  const [adding, setAdding] = useState(false);
  const [session, setSession] = useState<SessionContext | null>(null);

  useEffect(() => {
    getSessionContext().then(setSession);
  }, []);

  useEffect(() => {
    if (!session) {
      return;
    }
    let cancelled = false;
    fetchWatchlist(session)
      .then((rows) => {
        if (!cancelled) {
          setItems(rows);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load watchlist.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [session]);

  async function onAdd(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!newIoc.trim()) {
      return;
    }
    setAdding(true);
    setError(null);
    try {
      const created = await addToWatchlist(newIoc, session);
      setItems((prev) => [created, ...prev.filter((item) => item.normalized_ioc !== created.normalized_ioc)]);
      setNewIoc("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add to watchlist.");
    } finally {
      setAdding(false);
    }
  }

  async function onRecheck(item: WatchItem) {
    setBusy(item.normalized_ioc);
    setError(null);
    try {
      const result = await recheckWatchItem(item.normalized_ioc, session);
      onRecheckResult(result);
      setItems((prev) =>
        prev.map((row) =>
          row.normalized_ioc === item.normalized_ioc
            ? {
                ...row,
                last_checked_at: new Date().toISOString(),
                last_risk_score: result.risk.score,
                last_severity: result.risk.severity,
              }
            : row
        )
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Recheck failed.");
    } finally {
      setBusy(null);
    }
  }

  async function onRemove(item: WatchItem) {
    setBusy(item.normalized_ioc);
    setError(null);
    try {
      await removeFromWatchlist(item.normalized_ioc, session);
      setItems((prev) => prev.filter((row) => row.normalized_ioc !== item.normalized_ioc));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove item.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="brutal-panel p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-xs font-black uppercase">Watchlist</h2>
        <span className="text-xs uppercase text-[var(--muted)]">{items.length} items</span>
      </div>

      <form onSubmit={onAdd} className="mb-3 flex gap-2">
        <input
          value={newIoc}
          onChange={(event) => setNewIoc(event.target.value)}
          className="h-10 min-w-0 flex-1 border border-[var(--line)] bg-black px-3 text-sm font-bold uppercase text-white outline-none"
          placeholder="ADD IOC (ip, domain, hash, email, phone, @handle)"
          spellCheck={false}
        />
        <button
          type="submit"
          disabled={adding || !newIoc.trim()}
          className="flex h-10 items-center gap-1 border border-[var(--line)] bg-[var(--line)] px-3 font-black uppercase text-black disabled:border-[var(--muted-line)] disabled:bg-[var(--panel-2)] disabled:text-[var(--muted)]"
        >
          {adding ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
          Track
        </button>
      </form>

      {error ? <p className="mb-2 text-xs uppercase text-[var(--danger)]">{error}</p> : null}

      {items.length === 0 ? (
        <p className="text-xs uppercase text-[var(--muted)]">
          Watchlist empty. Track IOCs for periodic re-investigation.
        </p>
      ) : (
        <ul className="divide-y divide-[var(--muted-line)]">
          {items.map((item) => (
            <li key={String(item.id)} className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2">
              <div className="min-w-0 flex-1">
                <p className="truncate font-bold uppercase">{item.raw_ioc}</p>
                <p className="text-xs uppercase text-[var(--muted)]">
                  {item.ioc_type}
                  {item.last_severity
                    ? ` · last: ${item.last_severity} / ${item.last_risk_score ?? "-"}`
                    : " · never checked"}
                </p>
              </div>
              <button
                type="button"
                onClick={() => onRecheck(item)}
                disabled={busy === item.normalized_ioc}
                className="flex items-center gap-1 border border-[var(--line)] px-2 py-1 text-xs font-black uppercase text-[var(--warning)] hover:bg-[var(--panel-2)] disabled:opacity-40"
              >
                {busy === item.normalized_ioc ? (
                  <Loader2 size={12} className="animate-spin" />
                ) : (
                  <RefreshCw size={12} />
                )}
                Recheck
              </button>
              <button
                type="button"
                onClick={() => onRemove(item)}
                disabled={busy === item.normalized_ioc}
                className="flex items-center gap-1 border border-[var(--line)] px-2 py-1 text-xs font-black uppercase text-[var(--danger)] hover:bg-[var(--panel-2)] disabled:opacity-40"
              >
                <Trash2 size={12} />
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}