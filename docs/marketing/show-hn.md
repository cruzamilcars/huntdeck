# Show HN template — HuntDeck

## Title

```
Show HN: HuntDeck – Paste an IOC, get one tactical report from 12 threat-intel sources
```

## Post (first comment)

```
Hi HN! I built HuntDeck because every IOC triage meant the same ritual:
open VirusTotal, Shodan, AbuseIPDB, urlscan and a breach DB in five tabs,
copy-paste the indicator between them, then translate findings into MITRE
techniques by hand before writing a single line of the report.

HuntDeck does that in one request: paste an IP, domain, URL, file hash,
email, phone number or social handle and get back a normalized tactical
report — risk score with severity, per-source reputation, relationship
graph, community reports, MITRE ATT&CK techniques plus tiered NIST CSF /
ISO 27001 controls, and an analyst playbook of concrete next steps.

Technical decisions I'd love feedback on:

1. Provider layer is an adapter protocol (MCP-style clients). Each provider
   normalizes into one Pydantic contract, so the orchestrator never knows
    what VirusTotal vs Shodan look like. Adding a source = one file. Twelve
    real adapters today; three run without any API key (RDAP, urlscan
    anonymous search, social-presence checks against GitHub/Reddit/Telegram).

2. Risk scoring is deliberately boring: max score across sources with
   severity bands. No magic ML — analysts distrust black-box verdicts, so
   every score is traceable to the raw evidence shown next to it.

3. Mappings are curated per IOC type, not generated: each ATT&CK technique
   carries the reason it applies. NIST/ISO controls tier up with severity.

4. Playbooks are distilled from Anthropic's open-source Cybersecurity Skills
   library (Apache 2.0) — each step cites its source SKILL.md and suggests
   the actual tool to run. It's the "what do I do now" layer most enrichers
   skip.

5. Persistence is local SQLite by default (quota, history, watchlist);
   Supabase/Postgres is opt-in for teams. BYOK keys live server-side only —
   the frontend never sees provider credentials.

Known limits: rate-limit tiers are those of free accounts (VT 4 req/min),
encrypted-traffic analysis obviously out of scope, and the UI is opinionated
brutalist — you'll love or hate it.

Repo (MIT): https://github.com/cruzamilcars/huntdeck
Quick start: two terminals, no accounts needed — mock providers included so
you can evaluate before registering any API key.

Most interested in: which sources you'd add next (MISP? OpenCTI? Greynoise?),
and whether the playbook format is useful or would you rather have raw
evidence only.
```

## Timing

Martes–jueves, 7–10am ET. Responder comentarios las primeras 4h.
