import jsPDF from "jspdf";

import type { InvestigationResponse } from "@/lib/api/types";

export function exportInvestigationCsv(result: InvestigationResponse): void {
  const rows = [
    ["field", "value"],
    ["ioc.raw", result.ioc.raw],
    ["ioc.normalized", result.ioc.normalized],
    ["ioc.type", result.ioc.type],
    ["risk.score", String(result.risk.score)],
    ["risk.severity", result.risk.severity],
    ["sources", result.sources.join(";")],
    ["mcp_servers_queried", result.mcp_servers_queried.join(";")],
    ["used_byok", String(result.used_byok)],
  ];
  const csv = rows.map((row) => row.map(escapeCsv).join(",")).join("\n");
  downloadBlob(csv, `ioc-${result.ioc.type}.csv`, "text/csv;charset=utf-8");
}

export function exportInvestigationPdf(result: InvestigationResponse): void {
  const doc = new jsPDF();
  doc.setFont("courier", "bold");
  doc.setFontSize(14);
  doc.text("OSINT MCP HUB / IOC REPORT", 14, 18);

  doc.setFont("courier", "normal");
  doc.setFontSize(10);
  const lines = [
    `RAW: ${result.ioc.raw}`,
    `NORMALIZED: ${result.ioc.normalized}`,
    `TYPE: ${result.ioc.type}`,
    `RISK: ${result.risk.severity.toUpperCase()} / ${result.risk.score}`,
    `SOURCES: ${result.sources.join(", ")}`,
    `MITRE: ${result.mappings.mitre_attack.map((item) => item.id).join(", ")}`,
    `NIST: ${result.mappings.nist.map((item) => item.id).join(", ")}`,
    `ISO: ${result.mappings.iso.map((item) => item.id).join(", ")}`,
  ];

  let y = 32;
  for (const line of lines) {
    doc.text(line.slice(0, 96), 14, y);
    y += 8;
  }

  doc.save(`ioc-${result.ioc.type}.pdf`);
}

function escapeCsv(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

function downloadBlob(content: string, filename: string, type: string): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

