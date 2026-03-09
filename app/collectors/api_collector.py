import json 
import requests

from app.utils.hashing import sha256_hex
from app.utils.dates import parse_dt

def fetch_generic_json(base_url: str, headers: dict | None= None ) -> list[dict]:
    r = requests.get(base_url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()

    items = []

    for x in data if isinstance(data, list) else data.get("items", []) : 
        title = x.get("title")
        url = x.get("url") or x.get("link")
        content = x.get("summary") or x.get("description")
        published = parse_dt(x.get("published_at") or x.get("date"))

        if not url : 
            continue

        raw = x 
        dedup = sha256_hex(f"{url} | {title or ''}")

        items.append({
            "title" : title, 
            "url" : url, 
            "published_at" : published, 
            "content" : content, 
            "raw_json" : json.dumps(raw, ensure_ascii=False) , 
            "dedup_json" : dedup, 
        })

    return items