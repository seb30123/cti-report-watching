"""
Unit tests for app.utils.extractors — the most critical module.
These run without any database or network connection.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.utils.extractors import (
    extract_cves,
    extract_ipv4,
    extract_hashes,
    extract_urls,
    extract_domains_from_urls,
)


# ── CVE extraction ─────────────────────────────────────────────────────────────
class TestExtractCVEs:
    def test_basic(self):
        assert extract_cves("Affects CVE-2021-44228 and CVE-2023-20198") == [
            "CVE-2021-44228", "CVE-2023-20198"
        ]

    def test_case_insensitive(self):
        result = extract_cves("cve-2021-44228 CVE-2021-44228")
        assert result == ["CVE-2021-44228"]

    def test_dedup(self):
        result = extract_cves("CVE-2021-44228 CVE-2021-44228 CVE-2021-44228")
        assert result == ["CVE-2021-44228"]

    def test_empty(self):
        assert extract_cves("") == []
        assert extract_cves(None) == []

    def test_no_false_positives(self):
        assert extract_cves("version 2021-44228 not a CVE") == []

    def test_long_cve(self):
        # CVE IDs can have up to 7 digits
        assert extract_cves("CVE-2021-1234567") == ["CVE-2021-1234567"]


# ── IP extraction ──────────────────────────────────────────────────────────────
class TestExtractIPv4:
    def test_public_ip(self):
        assert extract_ipv4("C2 server at 185.220.101.45") == ["185.220.101.45"]

    def test_filters_private(self):
        text = "10.0.0.1 172.16.0.1 192.168.1.1 127.0.0.1"
        assert extract_ipv4(text) == []

    def test_filters_loopback(self):
        assert extract_ipv4("localhost 127.0.0.1") == []

    def test_multiple_public(self):
        result = extract_ipv4("IPs: 45.32.111.204 and 91.215.85.209")
        assert "45.32.111.204" in result
        assert "91.215.85.209" in result

    def test_empty(self):
        assert extract_ipv4("") == []

    def test_no_false_positives(self):
        # Version strings should not be matched
        result = extract_ipv4("version 10.0.0")
        # 10.0.0 is not a full IP — should not match as private (only 3 octets)
        assert result == []


# ── Hash extraction ────────────────────────────────────────────────────────────
class TestExtractHashes:
    MD5_REAL    = "a3f2c1d4e5b6789012345678abcdef01"
    SHA1_REAL   = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a901234567"
    SHA256_REAL = "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"

    def test_md5(self):
        result = extract_hashes(f"MD5: {self.MD5_REAL}")
        assert self.MD5_REAL in result["md5"]

    def test_sha1(self):
        result = extract_hashes(f"SHA1: {self.SHA1_REAL}")
        assert self.SHA1_REAL in result["sha1"]

    def test_sha256(self):
        result = extract_hashes(f"SHA256: {self.SHA256_REAL}")
        assert self.SHA256_REAL in result["sha256"]

    def test_empty_file_md5_filtered(self):
        empty_md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = extract_hashes(empty_md5)
        assert empty_md5 not in result["md5"]

    def test_empty_text(self):
        result = extract_hashes("")
        assert result == {"md5": [], "sha1": [], "sha256": []}


# ── URL extraction ─────────────────────────────────────────────────────────────
class TestExtractURLs:
    def test_basic(self):
        urls = extract_urls("Visit https://example.com/path?q=1 for details")
        assert "https://example.com/path?q=1" in urls

    def test_http_and_https(self):
        urls = extract_urls("http://malware.example.com https://cve.org/ref")
        assert any("http://malware.example.com" in u for u in urls)
        assert any("https://cve.org/ref" in u for u in urls)

    def test_empty(self):
        assert extract_urls("") == []


# ── Domain extraction ──────────────────────────────────────────────────────────
class TestExtractDomains:
    def test_basic(self):
        urls = ["https://malware-c2.net/beacon", "http://evil.example.com/payload"]
        domains = extract_domains_from_urls(urls)
        assert "malware-c2.net" in domains
        assert "evil.example.com" in domains

    def test_dedup(self):
        urls = ["https://evil.com/a", "https://evil.com/b", "https://evil.com/c"]
        domains = extract_domains_from_urls(urls)
        assert domains.count("evil.com") == 1

    def test_empty(self):
        assert extract_domains_from_urls([]) == []
