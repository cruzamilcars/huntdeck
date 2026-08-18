"use client";

import { Activity, AlertTriangle, BarChart3, Loader2, ShieldAlert, TrendingUp } from "lucide-react";
import { useEffect, useState } from "react";

import { ModulePanel } from "@/components/results/module-panel";
import { fetchInvestigationStats, type InvestigationStats } from "@/lib/api/investigations";
import { getSessionContext, type SessionContext } from "@/lib/api/session";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-[var(--danger)]",
  high: "bg-[var(--danger)]",
  medium: "bg-[var(--warning)]",
  low: "bg-[var(--accent)]",
  unknown: "bg-[var(--muted-line)]",
};

export function MetricsPanel() {
  const [stats, setStats] = useState<InvestigationStats | null>(null);
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
    fetchInvestigationStats(session, 14)
      .then((data) => {
        if (!cancelled) {
          setStats(data);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load metrics.");
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

  if (!stats) {
    return (
      <div className="muted-panel grid min-h-[200px] place-items-center p-8">
        <Loader2 className="animate-spin text-[var(--muted)]" size={28} />
      </div>
    );
  }

  const maxDaily = Math.max(...stats.daily.map((day) => day.count), 1);
  const totalSeverity = Object.values(stats.by_severity).reduce((sum, count) => sum + count, 0);

  return (
    <div className="space-y-4">
      <section className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <StatCard
          icon={<Activity size={16} />}
          label="Total investigations"
          value={String(stats.total)}
        />
        <StatCard
          icon={<BarChart3 size={16} />}
          label="Avg risk score"
          value={stats.avg_risk_score === null ? "-" : String(stats.avg_risk_score)}
        />
        <StatCard
          icon={<ShieldAlert size={16} />}
          label="High+ severity"
          value={String(
            (stats.by_severity.high ?? 0) + (stats.by_severity.critical ?? 0)
          )}
        />
        <StatCard
          icon={<TrendingUp size={16} />}
          label="BYOK queries"
          value={String(stats.byok_count)}
        />
      </section>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ModulePanel title="Daily volume" meta="last 14 days">
          <div className="flex h-40 items-end gap-1">
            {stats.daily.map((day) => (
              <div
                key={day.date}
                className="flex min-w-0 flex-1 flex-col items-center gap-1"
                title={`${day.date}: ${day.count}`}
              >
                <div
                  className="w-full bg-[var(--warning)]"
                  style={{ height: `${Math.max((day.count / maxDaily) * 100, 4)}%` }}
                />
                <span className="hidden text-[10px] uppercase text-[var(--muted)] sm:inline">
                  {day.date.slice(5)}
                </span>
              </div>
            ))}
          </div>
        </ModulePanel>

        <ModulePanel title="Severity distribution" meta={`${totalSeverity} rows`}>
          <ul className="space-y-2">
            {Object.entries(stats.by_severity).map(([severity, count]) => (
              <li key={severity} className="flex items-center gap-3 text-xs uppercase">
                <span className="w-20 text-[var(--muted)]">{severity}</span>
                <div className="h-3 flex-1 border border-[var(--muted-line)] bg-black">
                  <div
                    className={`h-full ${SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.unknown}`}
                    style={{ width: `${(count / totalSeverity) * 100}%` }}
                  />
                </div>
                <span className="w-8 text-right font-black">{count}</span>
              </li>
            ))}
          </ul>
        </ModulePanel>

        <ModulePanel title="Top IOCs" meta="most investigated">
          <ul className="space-y-2">
            {stats.top_iocs.map(({ ioc, count }) => (
              <li
                key={ioc}
                className="flex items-center justify-between gap-3 border border-[var(--muted-line)] px-3 py-2 text-xs uppercase"
              >
                <span className="min-w-0 flex-1 truncate font-bold">{ioc}</span>
                <span className="text-[var(--warning)]">{count}×</span>
              </li>
            ))}
          </ul>
        </ModulePanel>

        <ModulePanel title="Sources used" meta={`${stats.sources_used.length} providers`}>
          <ul className="space-y-2">
            {stats.sources_used.map(({ source, count }) => (
              <li
                key={source}
                className="flex items-center justify-between gap-3 border border-[var(--muted-line)] px-3 py-2 text-xs uppercase"
              >
                <span className="break-all">{source}</span>
                <span className="text-[var(--warning)]">{count}</span>
              </li>
            ))}
          </ul>
        </ModulePanel>
      </div>
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="brutal-panel p-4">
      <div className="mb-2 flex items-center gap-2 text-xs uppercase text-[var(--muted)]">
        {icon}
        {label}
      </div>
      <p className="text-3xl font-black uppercase text-[var(--warning)]">{value}</p>
    </div>
  );
}