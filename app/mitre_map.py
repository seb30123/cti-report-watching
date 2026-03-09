from __future__ import annotations

"""
MITRE ATT&CK mapping — applies mitre_rules to enriched items and stores matches.
"""

import logging
from app.utils.log import info, warn
from app.mitre_rules import RULES
from app.db.database import SessionLocal, Base, ENGINE
import app.db.tables           # noqa: F401 — registers raw_items in metadata
import app.db.enriched_tables  # noqa: F401 — registers enriched_items in metadata
from app.db.enriched_tables import EnrichedItem
from app.db.mitre_tables import MitreMatch
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger("cti-watch")


def _already_mapped(db, raw_item_id: int) -> bool:
    row = db.execute(
        text("SELECT 1 FROM mitre_matches WHERE raw_item_id=:id LIMIT 1"),
        {"id": raw_item_id}
    ).fetchone()
    return row is not None


def map_item(raw_item_id: int, text_blob: str, db) -> int:
    """Apply MITRE rules to a text blob and store matches. Returns number of matches inserted."""
    t = text_blob.lower()
    inserted = 0

    for keywords, technique_id, technique_name, tactic, confidence in RULES:
        matched_kws = [kw for kw in keywords if kw in t]
        if not matched_kws:
            continue

        evidence = ", ".join(matched_kws[:5])
        try:
            db.add(MitreMatch(
                raw_item_id=raw_item_id,
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                confidence=confidence,
                evidence=evidence,
            ))
            db.commit()
            inserted += 1
        except IntegrityError:
            db.rollback()
        except Exception as e:
            db.rollback()
            warn(f"[MITRE] Failed to insert {technique_id} for item {raw_item_id}: {e}")

    return inserted


def run_mitre_mapping(limit: int = 300):
    """Map all enriched items that don't yet have MITRE matches."""
    # Ensure all tables are created (idempotent)
    Base.metadata.create_all(bind=ENGINE)
    with SessionLocal() as db:
        items = (
            db.query(EnrichedItem)
            .order_by(EnrichedItem.id.asc())
            .limit(limit)
            .all()
        )
        info(f"[MITRE] Processing {len(items)} enriched items")

        total_matched = 0
        total_skipped = 0

        for it in items:
            if _already_mapped(db, it.raw_item_id):
                total_skipped += 1
                continue

            blob = " ".join(filter(None, [
                it.title or "",
                it.content_text or "",
                it.vendor or "",
                it.product or "",
            ]))

            n = map_item(it.raw_item_id, blob, db)
            total_matched += n

        info(f"[MITRE] Done — {total_matched} matches inserted, {total_skipped} items already mapped")


if __name__ == "__main__":
    run_mitre_mapping()
