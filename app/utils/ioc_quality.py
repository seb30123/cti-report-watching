from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode

# Domaines "références/doc" très fréquents dans les advisories (pas des IOCs de compromission)
REFERENCE_DOMAINS = {
    "www.cve.org", "cve.org",
    "nvd.nist.gov",
    "github.com", "raw.githubusercontent.com",
    "www.cisa.gov",
    "cert.ssi.gouv.fr", "www.cert.ssi.gouv.fr",
}

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "ref", "fbclid"
}

def normalize_url(u: str) -> str:
    u = (u or "").strip().rstrip("\\,")
    if not u:
        return ""
    try:
        p = urlparse(u)
        q = [(k, v) for (k, v) in parse_qsl(p.query, keep_blank_values=True) if k not in TRACKING_PARAMS]
        new_query = urlencode(q)
        # drop fragment, normalize host
        return urlunparse((p.scheme, (p.netloc or "").lower(), p.path, p.params, new_query, ""))
    except Exception:
        return u

def url_domain(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""

def classify_url(u: str) -> tuple[str, int]:
    """
    Return (class, confidence)
      class: 'reference' or 'ioc'
    """
    d = url_domain(u)
    if not d:
        return ("reference", 0)
    if d in REFERENCE_DOMAINS:
        return ("reference", 30)
    return ("ioc", 70)
