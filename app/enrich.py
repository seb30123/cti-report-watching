from __future__ import annotations

import json
import logging

from app.utils.text import html_to_text
from app.utils.extractors import (
    extract_cves, extract_urls, extract_ipv4,
    extract_hashes, extract_domains_from_urls,
)
from app.utils.scoring import score_item
from app.utils.entities import extract_vendor_product
from app.utils.entities_advanced import extract_versions, extract_apts, extract_malware
from app.utils.ioc_quality import normalize_url, classify_url
from app.utils.log import info, warn
from app.db.database import SessionLocal
from app.db.enrich_repository import (
    get_unprocessed_raw_items, save_enrichment, mark_processed,
)

logger = logging.getLogger("cti-watch")


def _get_cvss_for_cves(cves: list[str], db) -> list[float]:
    """Fetch CVSS scores from cve_context table for given CVEs."""
    if not cves:
        return []
    from sqlalchemy import text
    placeholders = ",".join(f"'{c.upper()}'" for c in cves)
    try:
        rows = db.execute(
            text(f"SELECT cvss FROM cve_context WHERE cve IN ({placeholders}) AND cvss IS NOT NULL")
        ).fetchall()
        return [float(r[0]) for r in rows if r[0] is not None]
    except Exception:
        return []


def enrich_batch(limit: int = 200):
    raws = get_unprocessed_raw_items(limit=limit)
    info(f"Enrich: found {len(raws)} unprocessed raw items")

    with SessionLocal() as cvss_db:
        for r in raws:
            try:
                content_text = html_to_text(r.content or "")
                blob = content_text + "\n" + (r.raw_json or "")

                cves = extract_cves(blob)
                urls_raw = extract_urls(blob)
                ips = extract_ipv4(blob)  # private IPs already filtered

                hashes_dict = extract_hashes(blob)
                all_hashes = sorted(
                    set(hashes_dict["md5"] + hashes_dict["sha1"] + hashes_dict["sha256"])
                )

                urls_norm = [normalize_url(u) for u in urls_raw]
                urls_norm = [u for u in urls_norm if u and len(u) <= 400]

                ioc_urls: list[str] = []
                ref_urls: list[str] = []
                for u in urls_norm:
                    cls, _conf = classify_url(u)
                    if cls == "ioc":
                        ioc_urls.append(u)
                    else:
                        ref_urls.append(u)

                ioc_urls = sorted(set(ioc_urls))[:20]
                ref_urls = sorted(set(ref_urls))[:15]

                domains = extract_domains_from_urls(ioc_urls)
                domains = [d for d in domains if d and len(d) <= 255]
                domains = sorted(set(domains))[:15]

                iocs = {
                    "urls": ioc_urls,
                    "ref_urls": ref_urls,
                    "ips": sorted(set(ips))[:20],
                    "domains": domains,
                    "hashes": all_hashes[:10],
                }

                vendor, product = extract_vendor_product(r.title or "", content_text)
                versions = extract_versions(blob)
                threat_actors = extract_apts(blob)
                malware = extract_malware(blob)

                # Use CVSS from cve_context if available (enriched by NVD collector)
                cvss_scores = _get_cvss_for_cves(cves, cvss_db)

                source_category = getattr(r, "source_category", "advisory")
                score, sev = score_item(
                    cves=cves,
                    iocs=iocs,
                    text=blob,
                    source_category=source_category,
                    cvss_scores=cvss_scores if cvss_scores else None,
                )

                save_enrichment(
                    raw_item=r,
                    content_text=content_text,
                    score=score,
                    severity=sev,
                    cves=cves,
                    iocs=iocs,
                    vendor=vendor,
                    product=product,
                    versions_json=json.dumps(versions, ensure_ascii=False),
                    threat_actors_json=json.dumps(threat_actors, ensure_ascii=False),
                    malware_json=json.dumps(malware, ensure_ascii=False),
                )

                mark_processed(r.id)
                info(
                    f"Enriched raw_item_id={r.id} score={score:.1f} severity={sev} "
                    f"cves={len(set(cves))} ioc_urls={len(ioc_urls)} ref_urls={len(ref_urls)}"
                )

            except Exception as e:
                warn(f"Failed to enrich raw_item_id={getattr(r, 'id', '?')} ({e})")


if __name__ == "__main__":
    enrich_batch(limit=200)
