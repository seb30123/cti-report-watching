from __future__ import annotations

from datetime import datetime

from sqlalchemy import text, bindparam

from app.db.database import SessionLocal


def run():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with SessionLocal() as db:
        kev_ids_rows = db.execute(text("""
            SELECT raw_item_id
            FROM enriched_items
            WHERE source_category='kev'
               OR lower(title) LIKE '%known exploited%'
               OR lower(content_text) LIKE '%known exploited vulnerabilities%'
               OR lower(content_text) LIKE '%active exploitation%'
               OR lower(content_text) LIKE '%ongoing exploitation%'
        """)).fetchall()

        kev_ids = [r[0] for r in kev_ids_rows]
        if not kev_ids:
            print("[INFO] No KEV-like items found, nothing to do.")
            return

        stmt = text("""
            SELECT DISTINCT c.cve, e.vendor, e.product
            FROM enriched_cves c
            JOIN enriched_items e ON e.raw_item_id = c.raw_item_id
            WHERE c.raw_item_id IN :ids
        """).bindparams(bindparam("ids", expanding=True))

        rows = db.execute(stmt, {"ids": kev_ids}).fetchall()

        inserted = 0
        for cve, vendor, product in rows:
            db.execute(text("""
                INSERT INTO todo_patch (cve, vendor, product, status, first_seen, last_seen)
                VALUES (:cve, :vendor, :product, 'todo', :now, :now)
                ON CONFLICT(cve) DO UPDATE SET
                  vendor=COALESCE(excluded.vendor, todo_patch.vendor),
                  product=COALESCE(excluded.product, todo_patch.product),
                  last_seen=:now
            """), {"cve": cve, "vendor": vendor, "product": product, "now": now})
            inserted += 1

        db.commit()
        print(f"[OK] Patch backlog updated: {inserted} CVEs (from KEV-like items)")


if __name__ == "__main__":
    run()
