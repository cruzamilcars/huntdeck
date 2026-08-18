import { MetricsPanel } from "@/components/dashboard/metrics-panel";
import { Shell } from "@/components/layout/shell";

export default function DashboardPage() {
  return (
    <Shell>
      <MetricsPanel />
    </Shell>
  );
}