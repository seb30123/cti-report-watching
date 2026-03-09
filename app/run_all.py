from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from pathlib import Path

from app.utils.logger import setup_logger


def run_cmd(cmd: list[str], logger, step_name: str = "") -> int:
    label = step_name or " ".join(cmd)
    logger.info(f">>> {label}")
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.stdout.strip():
        logger.info(p.stdout.strip())
    if p.stderr.strip():
        logger.warning(p.stderr.strip())
    if p.returncode != 0:
        logger.error(f"[FAIL] {label} exited with code {p.returncode}")
    return p.returncode


def main():
    ts = datetime.now().strftime("%Y-%m-%d_%H%M")
    logger = setup_logger("logs/cti-watch.log")
    logger.info(f"=== CTI Watch pipeline start ({ts}) ===")

    # 1) Collecte RSS
    rc = run_cmd([sys.executable, "main.py"], logger, "1) RSS Collect")
    if rc != 0:
        logger.error("Collect failed, stopping.")
        sys.exit(rc)

    # 2) Enrichissement
    rc = run_cmd([sys.executable, "-m", "app.enrich"], logger, "2) Enrich")
    if rc != 0:
        logger.error("Enrich failed, stopping.")
        sys.exit(rc)

    # 3) Mapping MITRE ATT&CK
    rc = run_cmd([sys.executable, "-m", "app.mitre_map"], logger, "3) MITRE mapping")
    if rc != 0:
        logger.error("MITRE mapping failed, stopping.")
        sys.exit(rc)

    # 4) Patch backlog (KEV → todo_patch)
    rc = run_cmd([sys.executable, "-m", "app.patch_backlog"], logger, "4) Patch backlog")
    if rc != 0:
        logger.warning("Patch backlog step failed (non-blocking, continuing).")

    # 5) Génération du rapport PDF
    rc = run_cmd([sys.executable, "-m", "app.report_pdf"], logger, "5) PDF report")
    if rc != 0:
        logger.error("PDF generation failed.")
        sys.exit(rc)

    # 6) Nettoyage (optionnel — items > 60 jours)
    rc = run_cmd([sys.executable, "-c",
                  "from app.cleanup_db import main; main(days=60)"],
                 logger, "6) Cleanup (60d)")
    if rc != 0:
        logger.warning("Cleanup failed (non-blocking).")

    logger.info(f"=== CTI Watch pipeline end ({datetime.now().strftime('%Y-%m-%d_%H%M')}) ===")


if __name__ == "__main__":
    main()
