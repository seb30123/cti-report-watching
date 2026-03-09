from __future__ import annotations

"""
CISA KEV (Known Exploited Vulnerabilities) JSON collector.

The KEV catalog is published as a JSON file, not an RSS feed.
This collector fetches it and normalises entries into the same
dict format that rss_collector returns, so save_raw_items()
works without any changes.

KEV JSON structure:
{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2024.03.04",
  "dateReleased": "2024-03-04",
  "count": 1234,
  "vulnerabilities": [
    {
      "cveID":             "CVE-2021-44228",
      "vendorProject":     "Apache",
      "product":           "Log4j",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded":         "2021-12-10",
      "shortDescription":  "...",
      "requiredAction":    "Apply updates...",
      "dueDate":           "2022-01-10",
      "knownRansomwareCampaignUse": "Known",
      "notes":             "..."
    }, ...
  ]
}
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("cti-watch")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FETCH_TIMEOUT = 30
MAX_RETRIES   = 3
RETRY_BACKOFF = 3


def _fetch_json(url: str) -> Optional[Dict]:
    """Fetch and parse JSON with retry."""
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, timeout=FETCH_TIMEOUT,
                                headers={"User-Agent": "cti-watch/1.0"})
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            logger.warning(f"[KEV] Timeout (attempt {attempt}/{MAX_RETRIES})")
            last_exc = "timeout"
        except requests.exceptions.RequestException as e:
            logger.warning(f"[KEV] Request error (attempt {attempt}/{MAX_RETRIES}): {e}")
            last_exc = str(e)
        except ValueError as e:
            logger.error(f"[KEV] JSON parse error: {e}")
            return None
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_BACKOFF * attempt)

    logger.error(f"[KEV] Failed after {MAX_RETRIES} attempts: {last_exc}")
    return None


def _dedup_hash(source_name: str, cve_id: str) -> str:
    base = f"{source_name}|{cve_id.strip().upper()}".encode("utf-8", errors="ignore")
    return hashlib.sha256(base).hexdigest()


def _parse_date(date_str: str) -> Optional[datetime]:
    """Parse YYYY-MM-DD date string to UTC datetime."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def fetch_kev_items(
    url: str = KEV_URL,
    source_name: str = "CISA KEV",
    max_items: int = 100,
    recent_days: int = 90,
) -> List[Dict[str, Any]]:
    """
    Fetch CISA KEV catalog and return normalised items.

    By default returns only entries added in the last `recent_days` days
    (to avoid inserting the entire ~1000-entry catalog on first run).
    Set recent_days=0 to import everything.

    Each returned dict has keys:
      title, url, published_at, content, raw_json, dedup_hash
    """
    data = _fetch_json(url)
    if not data:
        return []

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        logger.warning("[KEV] No vulnerabilities found in JSON response.")
        return []

    catalog_version = data.get("catalogVersion", "?")
    date_released   = data.get("dateReleased", "")
    logger.info(f"[KEV] Catalog v{catalog_version} — {len(vulns)} total entries, released {date_released}")

    # Cutoff: only recent entries (sorted by dateAdded desc)
    cutoff_dt = None
    if recent_days > 0:
        from datetime import timedelta
        cutoff_dt = datetime.now(tz=timezone.utc) - timedelta(days=recent_days)

    # Sort by dateAdded descending (most recent first)
    try:
        vulns_sorted = sorted(
            vulns,
            key=lambda v: v.get("dateAdded", ""),
            reverse=True,
        )
    except Exception:
        vulns_sorted = vulns

    items: List[Dict[str, Any]] = []

    for vuln in vulns_sorted:
        cve_id          = (vuln.get("cveID") or "").strip().upper()
        vendor          = (vuln.get("vendorProject") or "").strip()
        product         = (vuln.get("product") or "").strip()
        vuln_name       = (vuln.get("vulnerabilityName") or "").strip()
        date_added      = (vuln.get("dateAdded") or "").strip()
        short_desc      = (vuln.get("shortDescription") or "").strip()
        required_action = (vuln.get("requiredAction") or "").strip()
        due_date        = (vuln.get("dueDate") or "").strip()
        ransomware_use  = (vuln.get("knownRansomwareCampaignUse") or "").strip()
        notes           = (vuln.get("notes") or "").strip()

        if not cve_id:
            continue

        published_at = _parse_date(date_added)

        # Apply recency filter
        if cutoff_dt and published_at and published_at < cutoff_dt:
            break  # list is sorted desc, so we can stop early

        # Build a rich title
        title = f"[KEV] {cve_id} — {vuln_name or f'{vendor} {product}'}"

        # Build content blob (used by enrich.py for CVE/IOC extraction)
        content_parts = [short_desc]
        if required_action:
            content_parts.append(f"Required action: {required_action}")
        if ransomware_use == "Known":
            content_parts.append("Known ransomware campaign use confirmed.")
        if notes:
            content_parts.append(f"Notes: {notes}")
        content = " ".join(p for p in content_parts if p)

        # Canonical URL for this CVE on CISA website
        item_url = (
            f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            f"?search_api_fulltext={cve_id}"
        )

        raw_json = json.dumps({
            "cveID":          cve_id,
            "vendorProject":  vendor,
            "product":        product,
            "vulnerabilityName": vuln_name,
            "dateAdded":      date_added,
            "dueDate":        due_date,
            "shortDescription": short_desc,
            "requiredAction": required_action,
            "knownRansomwareCampaignUse": ransomware_use,
            "notes":          notes,
            "source":         source_name,
        }, ensure_ascii=False)

        items.append({
            "title":        title,
            "url":          item_url,
            "published_at": published_at,
            "content":      content,
            "raw_json":     raw_json,
            "dedup_hash":   _dedup_hash(source_name, cve_id),
        })

        if max_items and len(items) >= max_items:
            break

    logger.info(f"[KEV] {len(items)} items selected (recent_days={recent_days})")
    return items
