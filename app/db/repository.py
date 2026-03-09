from __future__ import annotations

from sqlalchemy.exc import IntegrityError

from app.db.database import SessionLocal
from app.db.tables import RawItem


def save_raw_items(source_name: str, source_category: str, items: list[dict]) -> tuple[int, int]:
    inserted = 0
    skipped = 0

    with SessionLocal() as db:
        for it in items:
            row = RawItem(
                source_name=source_name,
                source_category=source_category or "advisory",
                title=it.get("title"),
                url=it["url"],
                published_at=it.get("published_at"),
                content=it.get("content"),
                raw_json=it.get("raw_json", "{}"),
                dedup_hash=it["dedup_hash"],
                processed=0,
            )
            db.add(row)
            try:
                db.commit()
                inserted += 1
            except IntegrityError:
                db.rollback()
                skipped += 1

    return inserted, skipped
