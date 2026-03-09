from __future__ import annotations
import csv
from datetime import datetime
from sqlalchemy import text
from app.db.database import SessionLocal

def import_csv(path: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, newline="", encoding="utf-8") as f, SessionLocal() as db:
        r = csv.DictReader(f)
        for row in r:
            db.execute(text("""
                INSERT INTO cve_context (cve, cvss, vector, epss, cwe, kev, updated_at)
                VALUES (:cve, :cvss, :vector, :epss, :cwe, :kev, :updated_at)
                ON CONFLICT(cve) DO UPDATE SET
                  cvss=excluded.cvss, vector=excluded.vector, epss=excluded.epss,
                  cwe=excluded.cwe, kev=excluded.kev, updated_at=excluded.updated_at
            """), {
                "cve": row["cve"].strip().upper(),
                "cvss": float(row["cvss"]) if row.get("cvss") else None,
                "vector": row.get("vector"),
                "epss": float(row["epss"]) if row.get("epss") else None,
                "cwe": row.get("cwe"),
                "kev": int(row.get("kev", "0")),
                "updated_at": now,
            })
        db.commit()

if __name__ == "__main__":
    import_csv("cve_context.csv")
    print("[OK] imported cve_context.csv")
