# Security Policy

## Scope

OSINT MCP Hub is an investigation platform for **authorized security operations**:
threat intelligence analysts, SOC teams, red/blue teams and researchers. Only use
it against infrastructure and data you own or are explicitly authorized to analyze.

## Reporting a vulnerability

Do **not** open a public issue for security problems. Report privately via the
repository's **private vulnerability reporting** feature (Security tab →
"Report a vulnerability").

Include:

- Affected component (API, web, Supabase schema, dependencies)
- Steps to reproduce
- Impact and suggested fix, if known

We will acknowledge reports within 5 business days and publish a fix through a
release. Sensitive disclosures are coordinated with maintainers before any public
write-up.

## Security notes for operators

- Never commit `.env` files. `SUPABASE_SERVICE_ROLE_KEY` and `SUPABASE_JWT_SECRET`
  must only exist server-side.
- BYOK provider keys are stored encrypted in Supabase Vault. Never log them, and
  never expose `vault.decrypted_secrets` to `anon`/`authenticated` roles.
- Enable Row Level Security in production; the migration does this for every
  public table.
- The API rate-limits by IP (default 60 req/min) and enforces a daily free quota
  (default 10). Tune these per deployment.
- Run the API behind TLS (reverse proxy) in any shared deployment.

## Responsible disclosure expectations

This is an OSINT tool by design. Misuse (stalking, unauthorized surveillance,
attacks on third parties) is outside the accepted use of the project. Reports
of abuse should be addressed to the maintainers directly.