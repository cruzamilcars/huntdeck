"use client";

import { FileDown, Table } from "lucide-react";

import { exportInvestigationCsv, exportInvestigationPdf } from "@/lib/api/exports";
import type { InvestigationResponse } from "@/lib/api/types";

export function ExportControls({ result }: { result: InvestigationResponse }) {
  return (
    <div className="mb-4 flex flex-wrap gap-2">
      <button
        type="button"
        onClick={() => exportInvestigationPdf(result)}
        className="inline-flex items-center gap-2 border border-[var(--line)] bg-black px-3 py-2 text-xs font-bold uppercase text-white"
      >
        <FileDown size={16} />
        PDF
      </button>
      <button
        type="button"
        onClick={() => exportInvestigationCsv(result)}
        className="inline-flex items-center gap-2 border border-[var(--line)] bg-black px-3 py-2 text-xs font-bold uppercase text-white"
      >
        <Table size={16} />
        CSV
      </button>
    </div>
  );
}

