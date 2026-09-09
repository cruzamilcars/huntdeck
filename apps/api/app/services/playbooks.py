"""Next-step playbooks for investigated IOCs.

Playbooks are distilled from the open-source Anthropic Cybersecurity Skills
library (https://github.com/mukul975/Anthropic-Cybersecurity-Skills, Apache
2.0). Each playbook references the source skill it was derived from so
analysts can drill into the full workflow. They are advisory guidance for
the human analyst — never autonomous actions.
"""

from __future__ import annotations

from typing import Any

from app.domain.ioc.types import IocType

SKILLS_BASE_URL = "https://github.com/mukul975/Anthropic-Cybersecurity-Skills/blob/main/skills"


def _skill_url(skill: str) -> str:
    return f"{SKILLS_BASE_URL}/{skill}/SKILL.md"


def playbook_for(ioc_type: IocType, severity: str) -> list[dict[str, Any]]:
    playbooks = _by_ioc_type(ioc_type)
    if severity in {"high", "critical"}:
        playbooks.append(_escalation_playbook(ioc_type))
    return playbooks


def _by_ioc_type(ioc_type: IocType) -> list[dict[str, Any]]:
    match ioc_type:
        case IocType.MD5 | IocType.SHA1 | IocType.SHA256:
            return [_hash_playbook()]
        case IocType.IPV4 | IocType.IPV6:
            return [_ip_playbook()]
        case IocType.DOMAIN:
            return [_domain_playbook()]
        case IocType.URL:
            return [_url_playbook()]
        case IocType.EMAIL:
            return [_email_playbook()]
        case IocType.PHONE:
            return [_phone_playbook()]
        case IocType.SOCIAL_HANDLE:
            return [_social_playbook()]
        case IocType.ETHEREUM_ADDRESS | IocType.BITCOIN_ADDRESS | IocType.SOLANA_ADDRESS:
            return [_crypto_wallet_playbook()]
        case IocType.TX_HASH:
            return [_transaction_playbook()]
        case IocType.ENS_NAME:
            return [_ens_playbook()]
        case _:
            return [_enrichment_playbook_entry()]


def _step(title: str, detail: str, tool: str = "") -> dict[str, str]:
    return {"title": title, "detail": detail, "tool": tool}


def _hash_playbook() -> dict[str, Any]:
    return {
        "title": "Static malware triage (PE)",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("performing-static-malware-analysis-with-pe-studio"),
        "summary": (
            "Triage a suspicious Windows executable without executing it: "
            "header analysis, entropy, imports, strings and resources."
        ),
        "steps": [
            _step(
                "Verify sample integrity",
                "Confirm the file matches the investigated hash (md5sum / sha1sum / sha256sum) "
                "and check file type with `file` before trusting the enrichment verdict.",
                "coreutils",
            ),
            _step(
                "Inspect PE headers and sections",
                "Check compile timestamp (future dates or 1970 indicate forging), subsystem, and "
                "section entropy; entropy > 7.0 in .text/.rsrc suggests packing.",
                "pefile",
            ),
            _step(
                "Categorize imports",
                "Look for process injection (VirtualAllocEx + WriteProcessMemory + "
                "CreateRemoteThread), keylogging, persistence (RegSetValueExA, CreateServiceA) "
                "and network imports (URLDownloadToFileA, HttpSendRequestA).",
                "PEStudio",
            ),
            _step(
                "Extract strings and indicators",
                "Run strings (ASCII + Unicode) and FLOSS; grep for URLs, IPs, registry run keys "
                "and embedded file paths; feed extracted IOCs back into the hub.",
                "FLOSS",
            ),
            _step(
                "Check packing and resources",
                "Detect packers (UPX/ASPack/VMProtect section names, tiny import table) and scan "
                "resources for embedded PE payloads (MZ signature, high entropy).",
                "Detect It Easy",
            ),
            _step(
                "Detonate in a sandbox",
                "If verdicts point to malicious: submit to a sandbox (ANY.RUN/CAPE) for dynamic "
                "behavior before writing detection rules.",
                "sandbox",
            ),
        ],
    }


def _ip_playbook() -> dict[str, Any]:
    return {
        "title": "IP infrastructure assessment",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("automating-ioc-enrichment"),
        "summary": (
            "Correlate the IP with passive DNS, hosting history and abuse channels before "
            "blocking decisions."
        ),
        "steps": [
            _step(
                "Correlate across sources",
                "Cross-check VirusTotal resolutions, Shodan host data and AbuseIPDB reports; a "
                "composite score below the alert threshold should not auto-block shared "
                "infrastructure.",
                "hub adapters",
            ),
            _step(
                "Check hosting reputation",
                "Look up the ASN and hosting provider; cloud ranges and anonymous VPNs raise "
                "suspicion for C2 or scanning activity.",
                "Shodan/RDAP",
            ),
            _step(
                "Query abuse channels",
                "Search the ASN abuse contact and public blocklists (Spamhaus, CINS) for prior "
                "abuse reports tied to the IP.",
                "abuse contact",
            ),
            _step(
                "Monitor for C2 beaconing",
                "If verdict is high risk, add the IP to the watchlist and look for regular "
                "beaconing intervals in egress logs (every N minutes, low data volume).",
                "SIEM",
            ),
        ],
    }


def _domain_playbook() -> dict[str, Any]:
    return {
        "title": "Domain phishing & typosquatting check",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("analyzing-typosquatting-domains-with-dnstwist"),
        "summary": (
            "Assess whether the domain is a lookalike or attacker infrastructure: permutations, "
            "passive DNS and mail authentication posture."
        ),
        "steps": [
            _step(
                "Generate permutations",
                "Run dnstwist against the domain to find registered lookalikes and homoglyph "
                "variants used in phishing campaigns.",
                "dnstwist",
            ),
            _step(
                "Check mail authentication",
                "Verify SPF/DKIM/DMARC records; a hard-fail DMARC with missing DKIM on a "
                "lookalike domain is a strong phishing signal.",
                "dig",
            ),
            _step(
                "Review passive DNS",
                "Check resolution history for rapid IP rotation or DNS-only infrastructure "
                "(no mail/web servers) typical of malicious domains.",
                "hub adapters",
            ),
            _step(
                "Look for phishing kits",
                "Search urlscan.io and public phishing feeds for the domain; block at DNS level "
                "and file a takedown if confirmed.",
                "urlscan",
            ),
        ],
    }


def _url_playbook() -> dict[str, Any]:
    return {
        "title": "URL deep scan",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("analyzing-malicious-url-with-urlscan"),
        "summary": (
            "Submit the URL to urlscan.io for a full page scan: verdicts, screenshot, DOM "
            "analysis and related domains."
        ),
        "steps": [
            _step(
                "Submit a fresh scan",
                "Trigger a urlscan.io scan of the exact URL; historical search results may be "
                "stale or cover a rewritten page.",
                "urlscan.io",
            ),
            _step(
                "Read vendor verdicts",
                "Compare the scan's malicious/suspicious/clean verdict counts and the list of "
                "detecting engines with the hub enrichment.",
                "urlscan.io",
            ),
            _step(
                "Analyze the page",
                "Review the rendered screenshot, detected technologies and DOM for credential "
                "harvesting forms or crypto-wallet prompts.",
                "urlscan.io",
            ),
            _step(
                "Trace infrastructure",
                "Follow the page IP, ASN and related domains into a new hub investigation to map "
                "the full campaign.",
                "hub pivot",
            ),
        ],
    }


def _email_playbook() -> dict[str, Any]:
    return {
        "title": "Business Email Compromise check",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("detecting-business-email-compromise"),
        "summary": (
            "BEC attacks often carry no malicious links: validate headers, urgency language and "
            "payment-instruction changes instead."
        ),
        "steps": [
            _step(
                "Analyze message headers",
                "Check SPF/DKIM/DMARC alignment, Reply-To vs From mismatch and whether the "
                "display name matches an executive while the domain differs.",
                "email gateway",
            ),
            _step(
                "Flag urgency and secrecy",
                "BEC language combines urgency with confidentiality ('confidential', 'do not "
                "discuss'); flag first-time senders to finance/accounting.",
                "SIEM rules",
            ),
            _step(
                "Verify payment changes",
                "Confirm any changed payment details or new beneficiary via out-of-band "
                "verification (phone callback) before action.",
                "finance controls",
            ),
            _step(
                "Check for account compromise",
                "Review forwarding rules and mailbox delegation changes — attackers often "
                "exfiltrate replies quietly (T1114.003).",
                "mailbox audit",
            ),
        ],
    }


def _phone_playbook() -> dict[str, Any]:
    return {
        "title": "Phone-number attribution & fraud check",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("building-threat-actor-profile-from-osint"),
        "summary": (
            "Attribute the number via OSINT and assess SIM-swap or vishing risk before "
            "contacting the owner."
        ),
        "steps": [
            _step(
                "Attribute carrier and porting history",
                "Identify the carrier and check for recent port-outs or number-range transfers — "
                "a SIM-swap precursor in fraud cases.",
                "carrier lookup",
            ),
            _step(
                "Search OSINT footprints",
                "Correlate the number across public profiles and breach corpora; match handles "
                "and emails discovered to build the actor profile.",
                "OSINT",
            ),
            _step(
                "Assess vishing risk",
                "If the number appears in scam reports or is a virtual/VoIP range, treat "
                "incoming calls as potential vishing.",
                "reputation feeds",
            ),
        ],
    }


def _social_playbook() -> dict[str, Any]:
    return {
        "title": "Social profile impersonation check",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("building-threat-actor-profile-from-osint"),
        "summary": (
            "Profile the account for impersonation or use as a fraud persona: account age, "
            "engagement patterns and linked identities."
        ),
        "steps": [
            _step(
                "Check account age and history",
                "Newly created accounts with zero history are common fraud personas; capture "
                "creation date and original handle before any takedown.",
                "platform",
            ),
            _step(
                "Look for impersonation",
                "Compare display name/avatar with the legit entity; count similar handles — "
                "attackers register multiple lookalikes in parallel.",
                "OSINT",
            ),
            _step(
                "Map linked identities",
                "Collect linked emails, phone numbers and other handles into a new hub "
                "investigation to pivot across the persona.",
                "hub pivot",
            ),
        ],
    }


def _crypto_wallet_playbook() -> dict[str, Any]:
    return {
        "title": "Crypto wallet fraud triage",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("building-threat-actor-profile-from-osint"),
        "summary": (
            "Assess whether the wallet is attacker infrastructure: on-chain scam flags, "
            "liquidity and token behaviour before money movement."
        ),
        "steps": [
            _step(
                "Check explorer scam signals",
                "Read is_scam / reputation flags and GoPlus security on the chain explorer; a "
                "flagged address should be correlated before blocking on it.",
                "hub adapters",
            ),
            _step(
                "Inspect token liquidity",
                "Thin liquidity, extreme 24h moves or micro-valuation point to honeypot or "
                "rug-pull behaviour for ERC-20 holdings.",
                "Dexscreener",
            ),
            _step(
                "Trace fund flows",
                "Walk sent_from/received_by relationships into a new hub investigation of the "
                "counterparty wallets; look for exit to exchanges or mixers.",
                "hub pivot",
            ),
            _step(
                "Notify exchange & chain-analysis contact",
                "If confirmed fraud: report the address to the relevant CEX compliance channel "
                "and a chain-analysis provider for contaminating taint labels.",
                "compliance",
            ),
        ],
    }


def _transaction_playbook() -> dict[str, Any]:
    return {
        "title": "On-chain transaction tracing",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("automating-ioc-enrichment"),
        "summary": (
            "Correlate the transaction with the active campaign: confirm value flow, method "
            "and counterparties before adding addresses to the watchlist."
        ),
        "steps": [
            _step(
                "Confirm the transaction on-chain",
                "Verify status, block and method across two independent explorers (Etherscan + "
                "Blockscout) to rule out spoofed or reorged data.",
                "hub adapters",
            ),
            _step(
                "Extract counterparties",
                "Follow sent_from/received_by into address investigations; a single campaign "
                "often fans out to many destination wallets.",
                "hub pivot",
            ),
            _step(
                "Flag the flow pattern",
                "Detect immediate onward transfers or chained approvals — classic drainer "
                "behaviour after a phishing approval.",
                "chain analysis",
            ),
        ],
    }


def _ens_playbook() -> dict[str, Any]:
    return {
        "title": "ENS name attribution",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("building-threat-actor-profile-from-osint"),
        "summary": (
            "Resolve the ENS name to its controlling address, then investigate the wallet as "
            "any other on-chain IOC."
        ),
        "steps": [
            _step(
                "Resolve the controlling address",
                "Look up the ENS name against a registry-aware API and note the resolved "
                "address, plus any records the controller exposed.",
                "hub adapters",
            ),
            _step(
                "Investigate the wallet",
                "Pivot to the resolved address with a full on-chain investigation (scam flags, "
                "liquidity, activity).",
                "hub pivot",
            ),
            _step(
                "Watch for lookalikes",
                "Attackers register visually similar ENS names; compare squeezes/hyphens and "
                "expiration dates with the legitimate name.",
                "registry",
            ),
        ],
    }


def _enrichment_playbook_entry() -> dict[str, Any]:
    return {
        "title": "Cross-source enrichment & correlation",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("automating-ioc-enrichment"),
        "summary": (
            "Standardize enrichment before decisions: cross-reference a TIP, cache results and "
            "escalate only on composite scores."
        ),
        "steps": [
            _step(
                "Cross-reference a TIP",
                "Match the IOC against MISP/OpenCTI events for context tags and linked "
                "campaigns the hub adapters do not cover.",
                "MISP/OpenCTI",
            ),
            _step(
                "Cache enrichment",
                "Persist results for 24h to avoid re-querying paid APIs for repeat alerts.",
                "hub store",
            ),
            _step(
                "Escalate on composite score",
                "Require human confirmation before blocking shared infrastructure; automated "
                "actions are only safe on unambiguous verdicts.",
                "review",
            ),
        ],
    }


def _escalation_playbook(ioc_type: IocType) -> dict[str, Any]:
    label = {
        IocType.IPV4: "IP",
        IocType.IPV6: "IP",
        IocType.DOMAIN: "domain",
        IocType.URL: "URL",
        IocType.EMAIL: "mailbox",
        IocType.PHONE: "number",
        IocType.SOCIAL_HANDLE: "account",
        IocType.ETHEREUM_ADDRESS: "wallet address",
        IocType.BITCOIN_ADDRESS: "wallet address",
        IocType.SOLANA_ADDRESS: "wallet address",
        IocType.TX_HASH: "transaction",
        IocType.ENS_NAME: "ENS name",
    }.get(ioc_type, "IOC")
    return {
        "title": "High-risk escalation",
        "source": "Anthropic Cybersecurity Skills",
        "reference": _skill_url("conducting-phishing-incident-response"),
        "summary": f"Confirmed high-risk {label}: contain, notify and document for the IR playbook.",
        "steps": [
            _step(
                "Contain",
                "Block at the perimeter (DNS/firewall/mail gateway) and isolate affected assets; "
                "do not rely on the IOC alone — hunt for the full campaign.",
                "perimeter",
            ),
            _step(
                "Notify",
                "Escalate to the incident-response team with the hub report as evidence and "
                "define a communication window per the IR plan.",
                "IR plan",
            ),
            _step(
                "Document",
                "Export the investigation (PDF/CSV) and record the disposition in the watchlist "
                "for post-incident review.",
                "hub exports",
            ),
        ],
    }
