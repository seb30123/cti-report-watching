from __future__ import annotations

"""
NVD API collector — fetches CVSS / EPSS / KEV data for a list of CVE IDs.
Uses the NVD 2.0 API (no API key required, but rate-limited to 5 req/30s).
"""

import time
import logging
from typing import Dict, Optional

import requests

logger = logging.getLogger("cti-watch")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

REQUEST_DELAY = 6.5   # seconds between NVD requests (5 req/30s limit)
TIMEOUT = 15


def fetch_nvd_cve(cve_id: str) -> Optional[Dict]:
    """
    Fetch CVE details from NVD API 2.0.
    Returns dict with keys: cve, cvss, vector, cwe or None on failure.
    """
    url = f"{NVD_API_BASE}?cveId={cve_id.upper()}"
    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "cti-watch/1.0"})
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        vuln = vulns[0].get("cve", {})
        metrics = vuln.get("metrics", {})

        # Prefer CVSS v3.1 > v3.0 > v2
        cvss = None
        vector = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss = cvss_data.get("baseScore")
                vector = cvss_data.get("vectorString")
                break

        # CWE
        cwe = None
        weaknesses = vuln.get("weaknesses", [])
        if weaknesses:
            descs = weaknesses[0].get("description", [])
            for d in descs:
                if d.get("lang") == "en":
                    cwe = d.get("value")
                    break

        return {
            "cve": cve_id.upper(),
            "cvss": float(cvss) if cvss is not None else None,
            "vector": vector,
            "cwe": cwe,
        }

    except requests.exceptions.RequestException as e:
        logger.warning(f"[NVD] Failed to fetch {cve_id}: {e}")
        return None


def fetch_epss_scores(cve_ids: list[str]) -> Dict[str, float]:
    """
    Fetch EPSS scores for a list of CVEs from FIRST API.
    Returns dict {cve_id: epss_score}.
    """
    if not cve_ids:
        return {}
    try:
        ids_param = ",".join(cve_ids[:100])
        url = f"{EPSS_API_BASE}?cve={ids_param}"
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "cti-watch/1.0"})
        resp.raise_for_status()
        data = resp.json()
        result = {}
        for item in data.get("data", []):
            cve = item.get("cve", "").upper()
            epss = item.get("epss")
            if cve and epss is not None:
                result[cve] = float(epss)
        return result
    except Exception as e:
        logger.warning(f"[EPSS] Failed to fetch EPSS scores: {e}")
        return {}


def enrich_cves_from_nvd(cve_ids: list[str], db_session, delay: float = REQUEST_DELAY) -> Dict[str, Dict]:
    """
    For each CVE, fetch NVD data + EPSS and upsert into cve_context table.
    Returns dict {cve_id: {cvss, vector, cwe, epss}}.
    """
    from sqlalchemy import text

    if not cve_ids:
        return {}

    # Check which CVEs are already cached
    placeholders = ",".join(f"'{c.upper()}'" for c in cve_ids)
    cached_rows = db_session.execute(
        text(f"SELECT cve, cvss FROM cve_context WHERE cve IN ({placeholders})")
    ).fetchall()
    cached = {r[0]: r[1] for r in cached_rows}

    # Only fetch uncached CVEs
    to_fetch = [c for c in cve_ids if c.upper() not in cached]

    # Fetch EPSS for all (cheap, batch)
    epss_map = fetch_epss_scores(cve_ids)

    now_str = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = {}

    for i, cve in enumerate(to_fetch):
        if i > 0:
            time.sleep(delay)

        nvd = fetch_nvd_cve(cve)
        if nvd:
            epss = epss_map.get(cve.upper())
            kev = 0  # KEV detection handled by patch_backlog
            try:
                db_session.execute(text("""
                    INSERT INTO cve_context (cve, cvss, vector, epss, cwe, kev, updated_at)
                    VALUES (:cve, :cvss, :vector, :epss, :cwe, :kev, :updated_at)
                    ON CONFLICT(cve) DO UPDATE SET
                      cvss=excluded.cvss, vector=excluded.vector,
                      epss=excluded.epss, cwe=excluded.cwe, updated_at=excluded.updated_at
                """), {
                    "cve": nvd["cve"],
                    "cvss": nvd.get("cvss"),
                    "vector": nvd.get("vector"),
                    "epss": epss,
                    "cwe": nvd.get("cwe"),
                    "kev": kev,
                    "updated_at": now_str,
                })
                db_session.commit()
            except Exception as e:
                logger.warning(f"[NVD] DB upsert failed for {cve}: {e}")
                db_session.rollback()

            results[cve.upper()] = {
                "cvss": nvd.get("cvss"),
                "vector": nvd.get("vector"),
                "cwe": nvd.get("cwe"),
                "epss": epss_map.get(cve.upper()),
            }
            logger.info(f"[NVD] {cve}: CVSS={nvd.get('cvss')} EPSS={epss_map.get(cve.upper())}")

    # Add cached results
    for cve in cve_ids:
        cu = cve.upper()
        if cu in cached and cu not in results:
            results[cu] = {"cvss": cached[cu]}

    return results
