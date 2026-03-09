from datetime import datetime, timedelta

# ensure models registered
import app.db.tables  # noqa: F401
import app.db.enriched_tables  # noqa: F401
import app.db.mitre_tables  # noqa: F401

from app.db.database import SessionLocal
from sqlalchemy import text
from app.utils.logger import setup_logger

def main(days: int = 30):
    logger = setup_logger("logs/cti-watch.log")
    cutoff = datetime.now() - timedelta(days=days)
    logger.info(f"Cleanup: deleting items older than {cutoff}")

    with SessionLocal() as db:
        # On supprime en cascade "manuellement" (SQLite sans FK cascade fiable selon config)
        # 1) récupérer ids à supprimer
        ids = db.execute(
            text("SELECT id FROM raw_items WHERE published_at IS NOT NULL AND published_at < :cutoff"),
            {"cutoff": cutoff},
        ).fetchall()
        ids = [r[0] for r in ids]

        if not ids:
            logger.info("Cleanup: nothing to delete.")
            return

        id_list = ",".join(str(i) for i in ids)

        db.execute(text(f"DELETE FROM enriched_iocs WHERE raw_item_id IN ({id_list})"))
        db.execute(text(f"DELETE FROM enriched_cves WHERE raw_item_id IN ({id_list})"))
        db.execute(text(f"DELETE FROM enriched_items WHERE raw_item_id IN ({id_list})"))
        db.execute(text(f"DELETE FROM mitre_matches WHERE raw_item_id IN ({id_list})"))
        db.execute(text(f"DELETE FROM raw_items WHERE id IN ({id_list})"))

        db.commit()
        logger.info(f"Cleanup: deleted {len(ids)} raw items (+ linked rows).")

if __name__ == "__main__":
    main(days=30)