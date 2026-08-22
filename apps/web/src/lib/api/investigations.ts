import type {
  InvestigationResponse,
  ProviderStatus,
} from "@/lib/api/types";
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

export interface InvestigationStats {
  total: number;
  avg_risk_score: number | null;
  byok_count: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  top_iocs: Array<{ ioc: string; count: number }>;
  daily: Array<{ date: string; count: number }>;
  sources_used: Array<{ source: string; count: number }>;
}

async function apiGet(
  path: string,
  session: SessionContext | null = null
): Promise<unknown> {
  const headers: Record<string, string> = {};
  if (session?.accessToken) {
    headers.Authorization = `Bearer ${session.accessToken}`;
  }
  if (session?.orgId) {
    headers["X-Org-Id"] = session.orgId;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, { headers });
  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    throw new Error(detail?.detail ?? "Request failed.");
  }
  return response.json();
}

export async function fetchInvestigationHistory(
  session: SessionContext | null = null,
  limit = 20
): Promise<InvestigationHistoryRow[]> {
  const rows = await apiGet(`/api/v1/investigations/history?limit=${limit}`, session);
  return rows as InvestigationHistoryRow[];
}

export async function fetchInvestigationStats(
  session: SessionContext | null = null,
  days = 14
): Promise<InvestigationStats> {
  const stats = await apiGet(`/api/v1/investigations/stats?days=${days}`, session);
  return stats as InvestigationStats;
}

export async function fetchSystemProviders(
  session: SessionContext | null = null
): Promise<ProviderStatus[]> {
  const providers = await apiGet("/api/v1/system/providers", session);
  return providers as ProviderStatus[];
}

export interface WatchItem {
  id: string | number;
  raw_ioc: string;
  normalized_ioc: string;
  ioc_type: string;
  note: string | null;
  created_at: string;
  last_checked_at: string | null;
  last_risk_score: number | null;
  last_severity: string | null;
}

async function apiRequest(
  path: string,
  session: SessionContext | null,
  init: RequestInit = {}
): Promise<unknown> {
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string> | undefined),
  };
  if (session?.accessToken) {
    headers.Authorization = `Bearer ${session.accessToken}`;
  }
  if (session?.orgId) {
    headers["X-Org-Id"] = session.orgId;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });
  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    throw new Error(detail?.detail ?? "Request failed.");
  }
  return response.json();
}

export async function fetchWatchlist(
  session: SessionContext | null = null
): Promise<WatchItem[]> {
  const rows = await apiRequest("/api/v1/watchlist", session);
  return rows as WatchItem[];
}

export async function addToWatchlist(
  ioc: string,
  session: SessionContext | null = null
): Promise<WatchItem> {
  const item = await apiRequest("/api/v1/watchlist", session, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc }),
  });
  return item as WatchItem;
}

export async function removeFromWatchlist(
  normalizedIoc: string,
  session: SessionContext | null = null
): Promise<void> {
  await apiRequest(
    `/api/v1/watchlist/${encodeURIComponent(normalizedIoc)}`,
    session,
    { method: "DELETE" }
  );
}

export async function recheckWatchItem(
  normalizedIoc: string,
  session: SessionContext | null = null
): Promise<InvestigationResponse> {
  const result = await apiRequest(
    `/api/v1/watchlist/${encodeURIComponent(normalizedIoc)}/recheck`,
    session,
    { method: "POST" }
  );
  return result as InvestigationResponse;
}