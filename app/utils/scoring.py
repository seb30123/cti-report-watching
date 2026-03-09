from __future__ import annotations

import re
from typing import Optional

HIGH_KEYWORDS = [
    "remote code execution", " rce ", "authentication bypass", "privilege escalation",
    "actively exploited", "ongoing exploitation", "in the wild",
    "zero-day", "0-day", "wormable", "critical", "unauthenticated", "pre-auth",
    "default credential", "default password", "no authentication",
]

MEDIUM_KEYWORDS = [
    "denial of service", " dos ", "information disclosure", "path traversal",
    "cross-site scripting", " xss ", "sql injection", "ssrf",
    "open redirect", "buffer overflow", "heap overflow", "use after free",
]

KEV_KEYWORDS = [
    "known exploited vulnerabilities", "kev catalog", "added to catalog",
    "known exploited", "cisa kev",
]

RESEARCH_DOWNGRADE_KEYWORDS = [
    "proof of concept", "poc", "research", "analysis", "writeup",
    "technical deep dive", "reverse engineering",
]


def score_item(
    cves: list[str],
    iocs: dict,
    text: str,
    source_category: str = "advisory",
    cvss_scores: Optional[list[float]] = None,
) -> tuple[float, str]:
    """
    Returns (score, severity).

    cvss_scores: optional list of CVSS floats for the CVEs detected, fetched from NVD/cve_context.
    """
    t = (text or "").lower()
    cves = cves or []

    ioc_urls = iocs.get("urls", []) or []
    ips = iocs.get("ips", []) or []
    domains = iocs.get("domains", []) or []
    hashes = iocs.get("hashes", []) or []

    score = 0.0

    # Base
    score += 3.0

    # CVE signal — if CVSS available, use it for weighting; else flat bonus
    if cvss_scores:
        for cvss in cvss_scores[:6]:
            if cvss >= 9.0:
                score += 5.0
            elif cvss >= 7.0:
                score += 3.0
            elif cvss >= 4.0:
                score += 1.5
            else:
                score += 0.5
    else:
        score += min(len(set(cves)) * 2.0, 12.0)

    # IOC signal (only actionable IOCs)
    score += min(len(set(ioc_urls)) * 0.5, 6.0)
    score += min(len(set(domains)) * 0.5, 3.0)
    score += min(len(set(ips)) * 1.0, 6.0)
    score += min(len(set(hashes)) * 1.0, 6.0)

    # High-signal keywords
    for kw in HIGH_KEYWORDS:
        if kw in t:
            score += 4.0

    # Medium-signal keywords
    for kw in MEDIUM_KEYWORDS:
        if kw in t:
            score += 1.5

    # KEV boost
    if source_category == "kev" or any(kw in t for kw in KEV_KEYWORDS):
        score += 8.0

    # Research: downgrade slightly (not actionable right now)
    if source_category == "research":
        score *= 0.8
        for kw in RESEARCH_DOWNGRADE_KEYWORDS:
            if kw in t:
                score -= 1.0

    # No actionable IOC + no CVE → reduce noise
    if len(set(cves)) == 0 and len(set(ioc_urls)) == 0 and len(set(ips)) == 0 and len(set(hashes)) == 0:
        score -= 2.0

    score = max(score, 0.0)

    # Severity thresholds
    if score >= 22:
        sev = "critical"
    elif score >= 13:
        sev = "high"
    elif score >= 7:
        sev = "medium"
    else:
        sev = "low"

    return round(score, 1), sev
