/**
 * Canonical HuntDeck tactical-report contract.
 *
 * Single source of truth for the frontend. Mirrors the backend Pydantic
 * models in `apps/api/app/schemas/investigation.py` (plus
 * `app/domain/ioc/types.py` for `ParsedIoc`).
 *
 * Rule: if the backend adds/renames a field, update this file in the same
 * commit. `apps/web/src/lib/api/types.ts` re-exports everything from here.
 */

export type IocType =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "md5"
  | "sha1"
  | "sha256"
  | "email"
  | "phone"
  | "social_handle"
  | "unknown";

export type Severity = "unknown" | "low" | "medium" | "high" | "critical";

export interface ParsedIoc {
  raw: string;
  normalized: string;
  type: IocType;
}

export interface InvestigationResponse {
  ioc: ParsedIoc;
  risk: {
    score: number;
    severity: Severity;
  };
  modules: {
    reputation: Record<string, Record<string, unknown>>;
    geolocation: Record<string, Record<string, unknown>>;
    relationship_graph: {
      nodes: Array<Record<string, string>>;
      edges: Array<Record<string, string>>;
    };
    community_reports: Array<Record<string, unknown>>;
  };
  mappings: {
    mitre_attack: Array<Record<string, string>>;
    nist: Array<Record<string, string>>;
    iso: Array<Record<string, string>>;
  };
  playbooks: Array<{
    title: string;
    source: string;
    reference: string;
    summary: string;
    steps: Array<{ title: string; detail: string; tool: string }>;
  }>;
  sources: string[];
  mcp_servers_queried: string[];
  used_byok: boolean;
  /** Quota context echoed by the backend (e.g. `{ reason: "platform_quota" }`). */
  quota: Record<string, string | number | boolean>;
}

export interface ProviderStatus {
  name: string;
  mode: "real" | "mock";
  ioc_types: string[];
  key_env_var: string | null;
  configured: boolean;
}
