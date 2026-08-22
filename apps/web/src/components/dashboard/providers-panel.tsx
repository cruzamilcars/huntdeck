"use client";

import { AlertTriangle, KeyRound, Loader2, PlugZap } from "lucide-react";
import { useEffect, useState } from "react";

import { ModulePanel } from "@/components/results/module-panel";
import { fetchSystemProviders } from "@/lib/api/investigations";
import { getSessionContext, type SessionContext } from "@/lib/api/session";
import type { ProviderStatus } from "@/lib/api/types";

export function ProvidersPanel() {
  const [providers, setProviders] = useState<ProviderStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState<SessionContext | null>(null);

  useEffect(() => {
    getSessionContext().then(setSession);
  }, []);

  useEffect(() => {
    if (!session) {
      return;
    }
    let cancelled = false;
    fetchSystemProviders(session)
      .then((data) => {
        if (!cancelled) {
          setProviders(data);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load providers.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [session]);

  if (error) {
    return (
      <div className="flex items-start gap-3 border border-[var(--danger)] bg-black p-4 text-[var(--danger)]">
        <AlertTriangle size={20} />
        <p className="text-sm uppercase">{error}</p>
      </div>
    );
  }

  if (!providers) {
    return (
      <div className="muted-panel grid min-h-[120px] place-items-center p-6">
        <Loader2 className="animate-spin text-[var(--muted)]" size={24} />
      </div>
    );
  }

  const liveCount = providers.filter((provider) => provider.mode === "real").length;

  return (
    <ModulePanel
      title="Provider status"
      meta={`${liveCount}/${providers.length} live`}
    >
      <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {providers.map((provider) => (
          <li
            key={provider.name}
            title={
              provider.mode === "mock"
                ? `Set ${provider.key_env_var} in apps/api/.env to enable`
                : "Live adapter"
            }
            className="flex items-center justify-between gap-3 border border-[var(--muted-line)] px-3 py-2 text-xs uppercase"
          >
            <span className="flex min-w-0 items-center gap-2">
              <PlugZap
                size={14}
                className={provider.mode === "real" ? "text-[var(--accent)]" : "text-[var(--warning)]"}
              />
              <span className="truncate font-bold">{provider.name.replace("mcp-", "")}</span>
            </span>
            {provider.configured ? (
              <span className="shrink-0 border border-[var(--accent)] px-2 py-0.5 text-[10px] font-black text-[var(--accent)]">
                LIVE
              </span>
            ) : (
              <span className="flex shrink-0 items-center gap-1 border border-[var(--warning)] px-2 py-0.5 text-[10px] font-black text-[var(--warning)]">
                <KeyRound size={10} />
                {provider.key_env_var ?? "MOCK"}
              </span>
            )}
          </li>
        ))}
      </ul>
    </ModulePanel>
  );
}
