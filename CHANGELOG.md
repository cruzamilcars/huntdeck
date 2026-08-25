# Changelog

All notable changes to HuntDeck are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versioning
follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-08-24

First public release.

### Added
- IOC console (Next.js, brutalist dark theme) accepting IPv4, IPv6, domain,
  URL, MD5/SHA-1/SHA-256 hashes, email, phone numbers and social handles.
- FastAPI orchestrator with an MCP-style adapter protocol and a unified
  tactical JSON contract: risk score/severity, per-source evidence,
  relationship graph, community reports.
- **10 real provider adapters** — VirusTotal, Shodan, AbuseIPDB, RDAP,
  urlscan.io (anonymous fallback), Have I Been Pwned, OpenCNAM, AlienVault
  OTX, GreyNoise Community and keyless Social Presence. Keyless adapters run
  without any account; the rest fall back to deterministic mocks until their
  free API key is configured in `apps/api/.env`.
- MITRE ATT&CK technique mappings curated per IOC type, plus tiered NIST CSF
  2.0 and ISO 27001 controls that escalate with severity.
- Analyst playbooks distilled from the open-source Anthropic Cybersecurity
  Skills library (Apache 2.0), with per-step tooling suggestions and source
  citations; rendered as a "Next Steps / Playbook" panel and included in
  PDF/CSV exports.
- Dashboard with investigation metrics (daily volume, severity distribution,
  top IOCs, sources used), server-side paginated history and a provider
  status panel reporting live vs mocked adapters with the env var that
  unlocks each one.
- Watchlist with lazy auto-recheck: stale items refresh on TTL (default 24h),
  bounded by a per-request budget so listing can never exhaust quota.
- Persistence layer with SQLite by default (`data/huntdeck.db`) and optional
  Supabase PostgREST store behind `SUPABASE_URL`/`SUPABASE_SERVICE_ROLE_KEY`.
- Freemium quota (10/day) with BYOK awareness, service API keys for SIEM/CI
  (SHA-256 hashed, CLI-managed) and identity-aware rate limiting (per-IP for
  anonymous traffic, dedicated high-budget buckets for service keys).
- PDF/CSV exports, security headers, CORS allow-list and health endpoint.
- Ops tooling: `scripts/verify-integrations.py` live probes for all ten
  integrations, Dockerfiles + compose with healthchecks, Cirrus CI config,
  local pre-push quality gate (`.githooks`).

[0.1.0]: https://github.com/cruzamilcars/huntdeck/releases/tag/v0.1.0
