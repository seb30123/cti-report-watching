from __future__ import annotations

from sqlalchemy import Column, Integer, String, Text, DateTime, UniqueConstraint
from app.db.database import Base


class RawItem(Base):
    __tablename__ = "raw_items"

    id = Column(Integer, primary_key=True)

    source_name = Column(String(255), nullable=False)
    source_category = Column(String(50), nullable=False, default="advisory")  # NEW

    title = Column(Text, nullable=True)
    url = Column(Text, nullable=False)
    published_at = Column(DateTime, nullable=True)

    content = Column(Text, nullable=True)
    raw_json = Column(Text, nullable=False)
    dedup_hash = Column(String(64), nullable=False)

    processed = Column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("dedup_hash", name="uq_raw_items_dedup_hash"),
    )
