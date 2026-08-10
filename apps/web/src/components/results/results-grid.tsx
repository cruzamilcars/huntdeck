import type { InvestigationResponse } from "@/lib/api/types";

import { ModulePanel } from "./module-panel";

export function ResultsGrid({ result }: { result: InvestigationResponse }) {
  const reputationEntries = Object.entries(result.modules.reputation);
  const geolocationEntries = Object.entries(result.modules.geolocation);
  const graph = result.modules.relationship_graph;

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <ModulePanel title="Reputation" meta={`${reputationEntries.length} sources`}>
        <div className="space-y-3">
          {reputationEntries.map(([source, value]) => (
            <div key={source} className="border border-[var(--muted-line)] p-3">
              <div className="mb-2 flex items-center justify-between gap-3">
                <p className="break-all text-xs font-black uppercase text-[var(--warning)]">
                  {source}
                </p>
                <p className="text-xs uppercase">{String(value.verdict ?? "unknown")}</p>
              </div>
              <pre className="overflow-auto whitespace-pre-wrap break-words text-xs text-[var(--muted)]">
                {JSON.stringify(value, null, 2)}
              </pre>
            </div>
          ))}
        </div>
      </ModulePanel>

      <ModulePanel title="Geolocation" meta={`${geolocationEntries.length} hits`}>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {geolocationEntries.map(([source, value]) => (
            <div key={source} className="border border-[var(--muted-line)] p-3">
              <p className="mb-2 break-all text-xs font-black uppercase text-[var(--warning)]">
                {source}
              </p>
              <dl className="space-y-2 text-xs">
                {Object.entries(value).map(([key, item]) => (
                  <div key={key} className="grid grid-cols-[90px_1fr] gap-2">
                    <dt className="uppercase text-[var(--muted)]">{key}</dt>
                    <dd className="break-all">{String(item)}</dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>
      </ModulePanel>

      <ModulePanel title="Relationship Graph" meta={`${graph.edges.length} edges`}>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <p className="mb-2 text-xs uppercase text-[var(--muted)]">Nodes</p>
            <ul className="space-y-2">
              {graph.nodes.map((node) => (
                <li key={node.id} className="border border-[var(--muted-line)] px-2 py-1 text-xs">
                  <span className="text-[var(--warning)]">{node.type}</span> {node.id}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="mb-2 text-xs uppercase text-[var(--muted)]">Edges</p>
            <ul className="space-y-2">
              {graph.edges.map((edge, index) => (
                <li
                  key={`${edge.source}-${edge.target}-${index}`}
                  className="border border-[var(--muted-line)] px-2 py-1 text-xs"
                >
                  <span className="break-all">{edge.source}</span>
                  <span className="px-2 text-[var(--warning)]">{edge.kind}</span>
                  <span className="break-all">{edge.target}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </ModulePanel>

      <ModulePanel title="Community Reports" meta={`${result.modules.community_reports.length} rows`}>
        <div className="space-y-3">
          {result.modules.community_reports.map((report, index) => (
            <article key={index} className="border border-[var(--muted-line)] p-3 text-xs">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <span className="bg-[var(--warning)] px-2 py-1 font-black uppercase text-black">
                  {String(report.confidence ?? "unknown")}
                </span>
                <span className="uppercase text-[var(--muted)]">{String(report.source)}</span>
              </div>
              <h3 className="mb-2 font-black uppercase">{String(report.title ?? "Untitled")}</h3>
              <p className="break-words text-[var(--muted)]">{String(report.summary ?? "")}</p>
            </article>
          ))}
        </div>
      </ModulePanel>

      <ModulePanel title="MITRE / NIST / ISO" meta="mapped">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <MappingList title="MITRE" rows={result.mappings.mitre_attack} />
          <MappingList title="NIST" rows={result.mappings.nist} />
          <MappingList title="ISO" rows={result.mappings.iso} />
        </div>
      </ModulePanel>
    </div>
  );
}

function MappingList({ title, rows }: { title: string; rows: Array<Record<string, string>> }) {
  return (
    <div>
      <p className="mb-2 text-xs font-black uppercase text-[var(--warning)]">{title}</p>
      <ul className="space-y-2">
        {rows.map((row) => (
          <li key={`${title}-${row.id}`} className="border border-[var(--muted-line)] p-2 text-xs">
            <p className="font-black uppercase">{row.id}</p>
            <p className="mt-1 uppercase">{row.name}</p>
            <p className="mt-2 text-[var(--muted)]">{row.reason}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

