"use client";

import { FileDown, Loader2, Table } from "lucide-react";
import { memo, useState } from "react";

import { exportInvestigationCsv, exportInvestigationPdf } from "@/lib/api/exports";
import type { InvestigationResponse } from "@/lib/api/types";

function ExportControlsBase({ result }: { result: InvestigationResponse }) {
  const [busy, setBusy] = useState(false);

  async function onPdf() {
    setBusy(true);
    try {
      await exportInvestigationPdf(result);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mb-4 flex flex-wrap gap-2">
      <button
        type="button"
        onClick={onPdf}
        disabled={busy}
        className="inline-flex items-center gap-2 border border-[var(--line)] bg-black px-3 py-2 text-xs font-bold uppercase text-white disabled:opacity-40"
      >
        {busy ? <Loader2 size={16} className="animate-spin" /> : <FileDown size={16} />}
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

export const ExportControls = memo(ExportControlsBase);