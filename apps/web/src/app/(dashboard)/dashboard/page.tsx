import { MetricsPanel } from "@/components/dashboard/metrics-panel";
import { ProvidersPanel } from "@/components/dashboard/providers-panel";
import { Shell } from "@/components/layout/shell";

export default function DashboardPage() {
  return (
    <Shell>
      <div className="space-y-4">
        <MetricsPanel />
        <ProvidersPanel />
      </div>
    </Shell>
  );
}
