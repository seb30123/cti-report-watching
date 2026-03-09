from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.db.database import SessionLocal
from app.db.tables import RawItem
from app.db.enriched_tables import EnrichedItem, EnrichedIOC, EnrichedCVE, EnrichedRef


def get_unprocessed_raw_items(limit: int = 100) -> list[RawItem]:
    with SessionLocal() as db:
        return (
            db.query(RawItem)
            .filter(RawItem.processed == 0)
            .order_by(RawItem.id.asc())
            .limit(limit)
            .all()
        )


def mark_processed(raw_item_id: int):
    with SessionLocal() as db:
        db.execute(text("UPDATE raw_items SET processed=1 WHERE id=:id"), {"id": raw_item_id})
        db.commit()


def save_enrichment(
    raw_item: RawItem,
    content_text: str,
    score: float,
    severity: str,
    cves: list[str],
    iocs: dict,
    vendor: str | None = None,
    product: str | None = None,
    versions_json: str | None = None,
    threat_actors_json: str | None = None,
    malware_json: str | None = None,
):
    with SessionLocal() as db:
        ei = EnrichedItem(
            raw_item_id=raw_item.id,
            source_name=raw_item.source_name,
            source_category=getattr(raw_item, "source_category", "advisory"),
            title=raw_item.title,
            url=raw_item.url,
            published_at=raw_item.published_at,
            content_text=content_text,
            vendor=vendor,
            product=product,
            versions=versions_json,
            threat_actors=threat_actors_json,
            malware=malware_json,
            score=score,
            severity=severity,
        )

        db.add(ei)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return

        # CVEs
        for cve in sorted(set(cves or [])):
            db.add(EnrichedCVE(raw_item_id=raw_item.id, cve=cve))

        # IOCs (actionnables)
        for ip in sorted(set(iocs.get("ips", []) or [])):
            db.add(EnrichedIOC(raw_item_id=raw_item.id, ioc_type="ip", value=ip))

        for u in sorted(set(iocs.get("urls", []) or [])):
            db.add(EnrichedIOC(raw_item_id=raw_item.id, ioc_type="url", value=u))

        for d in sorted(set(iocs.get("domains", []) or [])):
            db.add(EnrichedIOC(raw_item_id=raw_item.id, ioc_type="domain", value=d))

        for h in sorted(set(iocs.get("hashes", []) or [])):
            db.add(EnrichedIOC(raw_item_id=raw_item.id, ioc_type="hash", value=h))

        # Refs (documentation / références)
        for u in sorted(set(iocs.get("ref_urls", []) or [])):
            db.add(EnrichedRef(raw_item_id=raw_item.id, ref_type="url", value=u))

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return
