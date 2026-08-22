import { HistoryPanel } from "@/components/dashboard/history-panel";
import { MetricsPanel } from "@/components/dashboard/metrics-panel";
import { ProvidersPanel } from "@/components/dashboard/providers-panel";
import { Shell } from "@/components/layout/shell";

export default function DashboardPage() {
  return (
    <Shell>
      <div className="space-y-4">
        <MetricsPanel />
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <HistoryPanel />
          <ProvidersPanel />
        </div>
      </div>
    </Shell>
  );
}
