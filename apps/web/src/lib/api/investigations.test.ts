/**
 * Smoke test for the money path: paste IOC -> POST /investigations -> report.
 * fetch is mocked; no network, no backend required.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  fetchInvestigationHistory,
  investigateIoc,
} from "@/lib/api/investigations";
import type { InvestigationResponse } from "@/lib/api/types";
import type { SessionContext } from "@/lib/api/session";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

function mockFetchOnce(jsonBody: unknown, ok = true, status = 200) {
  const json = vi.fn().mockResolvedValue(jsonBody);
  const response = { ok, status, json } as unknown as Response;
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
  return { fetchMock: globalThis.fetch as unknown as ReturnType<typeof vi.fn>, json };
}

function reportFixture(): InvestigationResponse {
  return {
    ioc: { raw: "8.8.8.8", normalized: "8.8.8.8", type: "ipv4" },
    risk: { score: 18, severity: "low" },
    modules: {
      reputation: {},
      geolocation: {},
      relationship_graph: { nodes: [], edges: [] },
      community_reports: [],
    },
    mappings: { mitre_attack: [], nist: [], iso: [] },
    playbooks: [],
    sources: ["mcp-virustotal"],
    mcp_servers_queried: ["mcp-virustotal"],
    used_byok: false,
    quota: { reason: "platform_quota" },
  };
}

describe("investigateIoc", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts the IOC and returns the tactical report", async () => {
    const fixture = reportFixture();
    const { fetchMock } = mockFetchOnce(fixture);

    const result = await investigateIoc("8.8.8.8");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${API_BASE_URL}/api/v1/investigations`);
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ ioc: "8.8.8.8" }));
    expect(result.ioc.normalized).toBe("8.8.8.8");
    expect(result.risk.severity).toBe("low");
  });

  it("forwards session auth headers when a session is present", async () => {
    mockFetchOnce(reportFixture());

    const session: SessionContext = {
      accessToken: "test-jwt",
      email: null,
      orgId: "org-1",
    };
    await investigateIoc("example.com", session);

    const [, init] = (globalThis.fetch as unknown as ReturnType<typeof vi.fn>)
      .mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer test-jwt");
    expect(headers["X-Org-Id"]).toBe("org-1");
  });

  it("throws the API detail message on failure", async () => {
    mockFetchOnce({ detail: "Quota exhausted." }, false, 402);

    await expect(investigateIoc("8.8.8.8")).rejects.toThrow("Quota exhausted.");
  });
});

describe("fetchInvestigationHistory", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("requests the scoped history page", async () => {
    const { fetchMock } = mockFetchOnce([]);

    const rows = await fetchInvestigationHistory(null, 20, 0);

    expect(rows).toEqual([]);
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit?];
    expect(url).toBe(
      `${API_BASE_URL}/api/v1/investigations/history?limit=20&offset=0`
    );
  });
});
