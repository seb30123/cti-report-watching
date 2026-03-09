"""
Unit tests for app.utils.scoring
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.utils.scoring import score_item


BASE_IOCS = {"urls": [], "ips": [], "domains": [], "hashes": [], "ref_urls": []}


class TestScoring:
    def test_base_score(self):
        score, sev = score_item(cves=[], iocs=BASE_IOCS, text="")
        # Base 3.0 - 2.0 (no IOC/CVE penalty) = 1.0 → low
        assert score == 1.0
        assert sev == "low"

    def test_cve_increases_score(self):
        s1, _ = score_item(cves=[], iocs=BASE_IOCS, text="nothing")
        s2, _ = score_item(cves=["CVE-2021-44228"], iocs=BASE_IOCS, text="nothing")
        assert s2 > s1

    def test_kev_category_boost(self):
        score, sev = score_item(
            cves=["CVE-2021-44228"],
            iocs=BASE_IOCS,
            text="known exploited vulnerability",
            source_category="kev",
        )
        assert score >= 13  # should be at least high

    def test_critical_keywords(self):
        score, sev = score_item(
            cves=["CVE-2021-44228"],
            iocs=BASE_IOCS,
            text="remote code execution actively exploited zero-day",
        )
        assert sev in ("high", "critical")

    def test_research_downgrade(self):
        score_adv, _ = score_item(
            cves=["CVE-2021-44228"],
            iocs=BASE_IOCS,
            text="exploit proof of concept analysis",
            source_category="advisory",
        )
        score_res, _ = score_item(
            cves=["CVE-2021-44228"],
            iocs=BASE_IOCS,
            text="exploit proof of concept analysis",
            source_category="research",
        )
        assert score_res < score_adv

    def test_severity_thresholds(self):
        _, s = score_item(cves=[], iocs=BASE_IOCS, text="")
        assert s == "low"

        iocs_with_ips = {**BASE_IOCS, "ips": ["1.2.3.4", "5.6.7.8", "9.10.11.12"]}
        score, s2 = score_item(
            cves=["CVE-2021-44228", "CVE-2022-1234"],
            iocs=iocs_with_ips,
            text="remote code execution",
        )
        assert s2 in ("medium", "high", "critical")

    def test_cvss_weighting(self):
        score_no_cvss, _ = score_item(
            cves=["CVE-2021-44228"],
            iocs=BASE_IOCS,
            text="exploit",
        )
        score_cvss10, _ = score_item(
            cves=["CVE-2021-44228"],
            iocs=BASE_IOCS,
            text="exploit",
            cvss_scores=[10.0],
        )
        assert score_cvss10 >= score_no_cvss
