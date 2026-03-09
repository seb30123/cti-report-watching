from __future__ import annotations

import hashlib
import json
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import feedparser
import requests

logger = logging.getLogger("cti-watch")

STALE_THRESHOLD_DAYS = 3
FETCH_TIMEOUT = 20
MAX_RETRIES = 3
RETRY_BACKOFF = 2


def _parse_dt(entry: Any) -> Optional[datetime]:
    for key in ("published_parsed", "updated_parsed"):
        if getattr(entry, key, None):
            try:
                dt = datetime(*getattr(entry, key)[:6], tzinfo=timezone.utc)
                return dt
            except Exception:
                pass
    return None


def _dedup_hash(source_name: str, link: str, title: str) -> str:
    base = f"{source_name}|{link.strip()}|{title.strip()}".encode("utf-8", errors="ignore")
    return hashlib.sha256(base).hexdigest()


def _fetch_with_retry(url: str, source_name: str = "") -> Optional[str]:
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, timeout=FETCH_TIMEOUT, headers={"User-Agent": "cti-watch/1.0"})
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.Timeout:
            logger.warning(f"[RSS] Timeout on {source_name} (attempt {attempt}/{MAX_RETRIES})")
            last_exc = "timeout"
        except requests.exceptions.RequestException as e:
            logger.warning(f"[RSS] Error fetching {source_name} (attempt {attempt}/{MAX_RETRIES}): {e}")
            last_exc = str(e)
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_BACKOFF * attempt)
    logger.error(f"[RSS] Failed to fetch {source_name} after {MAX_RETRIES} attempts: {last_exc}")
    return None


def check_stale(source_name: str, items: List[Dict[str, Any]]) -> None:
    if not items:
        logger.warning(f"[STALE] {source_name}: feed returned 0 items — source may be down or broken.")
        return
    dates = [it["published_at"] for it in items if it.get("published_at")]
    if not dates:
        return
    most_recent = max(dates)
    now = datetime.now(tz=timezone.utc)
    mr = most_recent if most_recent.tzinfo else most_recent.replace(tzinfo=timezone.utc)
    age = now - mr
    if age > timedelta(days=STALE_THRESHOLD_DAYS):
        logger.warning(
            f"[STALE] {source_name}: most recent item is {age.days}d old "
            f"(last: {most_recent.strftime('%Y-%m-%d')}). Source may be stale."
        )


def fetch_rss_items(url: str, source_name: str = "") -> List[Dict[str, Any]]:
    if not url or url.strip() in ("...", "", "null"):
        logger.error(f"[RSS] {source_name}: URL missing/invalid ('{url}'). Skipping.")
        return []

    raw_text = _fetch_with_retry(url, source_name=source_name)
    if raw_text is None:
        return []

    feed = feedparser.parse(raw_text)
    if getattr(feed, "bozo", False):
        bozo_exc = getattr(feed, "bozo_exception", None)
        if bozo_exc:
            logger.warning(f"[RSS] {source_name}: feedparser bozo — {bozo_exc}")

    items: List[Dict[str, Any]] = []
    for e in feed.entries:
        title = (getattr(e, "title", None) or "").strip()
        link = (getattr(e, "link", None) or "").strip()

        if not link and getattr(e, "links", None):
            try:
                link = e.links[0].get("href", "").strip()
            except Exception:
                link = ""
        if not link:
            continue

        published_at = _parse_dt(e)
        content = None
        if getattr(e, "summary", None):
            content = e.summary
        elif getattr(e, "content", None):
            try:
                content = e.content[0].get("value")
            except Exception:
                content = None

        raw_json = json.dumps(dict(e), ensure_ascii=False, default=str)
        items.append({
            "title": title or None,
            "url": link,
            "published_at": published_at,
            "content": content,
            "raw_json": raw_json,
            "dedup_hash": _dedup_hash(source_name, link, title or link),
        })

    check_stale(source_name, items)
    return items
