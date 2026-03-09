from __future__ import annotations

from pathlib import Path
import yaml


def load_sources_config(path: str = "sources.yaml") -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Missing {path}")

    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    data.setdefault("rss", [])
    data.setdefault("api", [])
    return data
