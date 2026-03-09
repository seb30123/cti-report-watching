from __future__ import annotations

import re
from ipaddress import ip_address, AddressValueError
from urllib.parse import urlparse

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>()]+", re.IGNORECASE)

MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Known-benign hash blacklist (e.g. empty file hashes)
HASH_BLACKLIST = {
    "d41d8cd98f00b204e9800998ecf8427e",           # MD5 empty
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",   # SHA1 empty
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 empty
}

# Private / reserved IP ranges to filter out
PRIVATE_PATTERNS = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1|fc|fd)"
)

# Hash false-positive: sequences that look like hashes but are version strings or IDs
HASH_FP_PATTERNS = re.compile(r"^0{8,}|f{8,}|1{8,}$")


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except (AddressValueError, ValueError):
        return False


def _is_valid_hash(h: str) -> bool:
    if h in HASH_BLACKLIST:
        return False
    if HASH_FP_PATTERNS.match(h):
        return False
    return True


def extract_cves(text: str) -> list[str]:
    return sorted(set(m.upper() for m in CVE_RE.findall(text or "")))


def extract_urls(text: str) -> list[str]:
    return sorted(set(URL_RE.findall(text or "")))


def extract_ipv4(text: str) -> list[str]:
    """Extract public IPv4 only — filters out private/reserved ranges."""
    raw = set(IPV4_RE.findall(text or ""))
    return sorted(ip for ip in raw if not _is_private_ip(ip))


def extract_hashes(text: str) -> dict[str, list[str]]:
    t = text or ""
    md5 = [h for h in set(MD5_RE.findall(t)) if _is_valid_hash(h)]
    sha1 = [h for h in set(SHA1_RE.findall(t)) if _is_valid_hash(h) and h not in md5]
    sha256 = [h for h in set(SHA256_RE.findall(t)) if _is_valid_hash(h) and h not in sha1]
    return {
        "md5": sorted(md5),
        "sha1": sorted(sha1),
        "sha256": sorted(sha256),
    }


def extract_domains_from_urls(urls: list[str]) -> list[str]:
    out = set()
    for u in urls:
        try:
            host = urlparse(u).hostname
            if not host:
                continue
            host = host.lower()
            if host.endswith(".html") or host.endswith(".php"):
                continue
            out.add(host)
        except Exception:
            continue
    return sorted(out)
