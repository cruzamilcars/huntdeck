# Reddit templates — HuntDeck

## Target subreddits

| Subreddit | Ángulo | Nota de reglas |
| --- | --- | --- |
| r/cybersecurity (~1M) | Herramienta para analistas SOC/Blue Team | Permitido compartir herramientas con contexto; evita tono vendedor |
| r/blueteam (~100k) | Triage y enriquecimiento de IOCs | Público técnico ideal; feedback de calidad |
| r/osint (~200k) | Correlación de fuentes OSINT (RDAP, urlscan, social presence) | Enfatiza las fuentes sin key |

## Post draft — r/blueteam (feedback-first)

**Title:**

```
How do you triage IOCs today? I got tired of 5 browser tabs and built a
single-console enricher — feedback wanted
```

**Body:**

```
Every alert I handled started the same way: paste the indicator into
VirusTotal, then Shodan, then AbuseIPDB, then urlscan, keep mental track of
what agreed with what, and manually write "maps to T1566.002" in the ticket.
So I built HuntDeck — a local console where you paste ANY indicator type
(IP, domain, URL, hash, email, phone, even a social handle) and get one
normalized report back.

What it does:

- Queries 12 sources in one request (VirusTotal, Shodan, AbuseIPDB, RDAP,
  urlscan.io, HaveIBeenPwned, OpenCNAM, AlienVault OTX, GreyNoise, URLhaus,
  MISP, plus GitHub/Reddit/Telegram presence for handles)
- Returns risk score + per-source evidence, relationship graph
- Maps findings to MITRE techniques (with the reason), NIST CSF and ISO
  controls tiered by severity
- Suggests next steps per IOC type — e.g. hashes get a PE-studio static
  triage checklist, emails get BEC checks. Steps are distilled from
  Anthropic's open-source Cybersecurity Skills library with citations

Honest state: it's an MVP. Three sources work without any account (RDAP,
urlscan anonymous, social presence); the rest need your own free API keys.
Everything runs locally (FastAPI + Next.js, SQLite storage) — no data leaves
your machine except the queries to the providers themselves.

Repo (MIT): https://github.com/cruzamilcars/huntdeck

What I actually want from this post:

1. Which source would you add first — MISP, Greynoise, OpenCTI, something
   else?
2. Do playbook-style "next steps" belong in a tool like this, or do they
   belong in your runbooks instead?
3. What would make you actually trust the risk score?

Not selling anything — free and open source, roast away.
```

## Comment strategy

- Responde TODOS los comentarios técnicos en las primeras 24h
- Si preguntan por comparación con MISP/OpenCTI: son complementarios (enricher
  de analyst desktop vs plataformas de threat intel compartido)
- No publiques el mismo texto en los 3 subreddits el mismo día: espacia 3–4
  días y ajusta el ángulo
