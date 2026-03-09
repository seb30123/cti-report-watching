from __future__ import annotations

from app.utils.config import load_sources_config
from app.utils.log import info, warn
from app.db.database import init_db
from app.db.repository import save_raw_items
from app.collectors.rss_collector import fetch_rss_items
from app.collectors.kev_collector import fetch_kev_items

KEV_SOURCE_NAME = "CISA KEV"


def run():
    init_db()
    cfg = load_sources_config()

    rss_sources = cfg.get("rss", [])
    info(f"RSS sources found: {len(rss_sources)}")

    for s in rss_sources:
        name = s["name"]
        url  = s["url"]
        cat  = s.get("category", "advisory")

        # ── CISA KEV : JSON feed, not RSS ───────────────────────────────────
        if cat == "kev" or name == KEV_SOURCE_NAME:
            info(f"KEV collect: {name} -> {url} (JSON catalog)")
            items = fetch_kev_items(
                url=url,
                source_name=name,
                recent_days=90,   # import entries added in the last 90 days
                max_items=150,    # safety cap per run
            )
            info(f"Fetched {len(items)} KEV items from {name}")
            ins, skip = save_raw_items(name, "kev", items)
            info(f"Saved: inserted={ins} skipped_dup={skip}")
            continue

        # ── Regular RSS/Atom sources ────────────────────────────────────────
        info(f"RSS collect: {name} -> {url} (category={cat})")
        items = fetch_rss_items(url, source_name=name)
        info(f"Fetched {len(items)} items from {name}")
        ins, skip = save_raw_items(name, cat, items)
        info(f"Saved: inserted={ins} skipped_dup={skip}")

    api_sources = cfg.get("api", [])
    info(f"API sources found: {len(api_sources)}")


if __name__ == "__main__":
    run()
