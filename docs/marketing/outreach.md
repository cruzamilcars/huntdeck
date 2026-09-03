# Awesome lists PRs + newsletter outreach — HuntDeck

## 1. awesome-osint (PR template)

**Target list:** https://github.com/joejoseph007/awesome-osint (or the most
active fork — check last commit before submitting)

```markdown
## Add HuntDeck to "Tools / Threat Intelligence"

Hi! Adding [HuntDeck](https://github.com/cruzamilcars/huntdeck) — an open
source IOC investigation hub that unifies VirusTotal, Shodan, AbuseIPDB,
RDAP, urlscan.io, HIBP, OpenCNAM, AlienVault OTX and social-presence lookups
into one normalized report with MITRE/NIST/ISO mappings and analyst
playbooks. Local-first (FastAPI + Next.js), MIT licensed.

Proposed entry (alphabetical under the section):

- [HuntDeck](https://github.com/cruzamilcars/huntdeck) - IOC investigation console: paste an IP/domain/hash/email and get unified enrichment from 9 threat-intel sources with framework mappings and next-step playbooks

Checklist:
- [x] Free / open source (MIT)
- [x] Working project (CI green locally, 127 tests)
- [x] README with screenshot and quick start
- [x] Not a paid product or trialware

Happy to adjust wording to match the list's style.
```

## 2. awesome-threat-intelligence (PR template)

```markdown
## Add HuntDeck under "Related Tools"

Adding [HuntDeck](https://github.com/cruzamilcars/huntdeck): an open source
analyst console that orchestrates twelve threat-intel providers behind a single
adapter protocol and normalizes output into one tactical JSON contract,
including MITRE ATT&CK technique mappings per indicator type. Useful as a
lightweight desktop-grade alternative to stitching together enrichment
scripts; BYOK, local-first, MIT.
```

## 3. Newsletter pitch (3 líneas — TLDR Info Security, Week in OSINT, Console.dev)

```
Subject: HuntDeck — paste an IOC, get 12-source enrichment + MITRE mapping in one report

1) HuntDeck is an open source IOC investigation console: paste any indicator
   (IP/domain/URL/hash/email/phone/social handle) and get risk score, evidence
   from 12 threat-intel sources, relationship graph and framework mappings in a
   single local dashboard.
2) It runs local-first (FastAPI + Next.js, SQLite), works without accounts for
   three sources out of the box, and every verdict stays traceable to raw
   evidence — no black-box scoring.
3) MIT at https://github.com/cruzamilcars/huntdeck — happy to provide a demo
   walkthrough or screenshots if you'd like coverage.
```

Envío por formulario cuando exista (TLDR usa form, Week in OSINT acepta email a
los curadores de OSINTCurious, Console.dev tiene botón "Submit your tool").

## Timing global recomendado

| Día | Acción |
| --- | --- |
| 0 | Release v0.1.0 publicado + README/GIF pulidos |
| 1 | r/blueteam post (feedback-first) |
| 3–4 | Responder feedback, arreglar lo rápido que salga |
| 5 | Show HN con el post ya endurecido por el feedback |
| 7+ | PRs a awesome lists (con estrellas/tracción reales ya visibles) + newsletters |

Las primeras 48–72h tras Show HN pesan más para GitHub Trending que cualquier
otra cosa: ten tiempo bloqueado para responder issues y comentarios.
