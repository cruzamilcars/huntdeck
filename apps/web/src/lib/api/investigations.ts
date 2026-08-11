import type { InvestigationResponse } from "@/lib/api/types";
import type { SessionContext } from "@/lib/api/session";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export async function investigateIoc(
  ioc: string,
  session: SessionContext | null = null
): Promise<InvestigationResponse> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (session?.accessToken) {
    headers.Authorization = `Bearer ${session.accessToken}`;
  }
  if (session?.orgId) {
    headers["X-Org-Id"] = session.orgId;
  }

  const response = await fetch(`${API_BASE_URL}/api/v1/investigations`, {
    method: "POST",
    headers,
    body: JSON.stringify({ ioc }),
  });

  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    throw new Error(detail?.detail ?? "Investigation failed.");
  }

  return response.json();
}

export interface InvestigationHistoryRow {
  raw_ioc: string;
  normalized_ioc: string;
  ioc_type: string;
  risk_score: number | null;
  severity: string | null;
  sources: string;
  used_byok: number;
  created_at: string;
}

export async function fetchInvestigationHistory(
  session: SessionContext | null = null,
  limit = 20
): Promise<InvestigationHistoryRow[]> {
  const headers: Record<string, string> = {};
  if (session?.accessToken) {
    headers.Authorization = `Bearer ${session.accessToken}`;
  }
  if (session?.orgId) {
    headers["X-Org-Id"] = session.orgId;
  }

  const response = await fetch(
    `${API_BASE_URL}/api/v1/investigations/history?limit=${limit}`,
    { headers }
  );

  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    throw new Error(detail?.detail ?? "Failed to load history.");
  }

  return response.json();
}