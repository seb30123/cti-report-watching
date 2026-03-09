from __future__ import annotations

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Float, ForeignKey, UniqueConstraint
)

from app.db.database import Base


class EnrichedItem(Base):
    __tablename__ = "enriched_items"

    id = Column(Integer, primary_key=True)

    raw_item_id = Column(Integer, ForeignKey("raw_items.id"), nullable=False)
    source_name = Column(String(255), nullable=False)
    source_category = Column(String(50), nullable=True)

    title = Column(Text, nullable=True)
    url = Column(Text, nullable=False)
    published_at = Column(DateTime, nullable=True)

    content_text = Column(Text, nullable=True)

    vendor = Column(String(255), nullable=True)
    product = Column(String(255), nullable=True)

    # NEW FIELDS (must exist here or SQLAlchemy won't write them)
    versions = Column(Text, nullable=True)        # JSON string
    malware = Column(Text, nullable=True)         # JSON string
    threat_actors = Column(Text, nullable=True)   # JSON string

    score = Column(Float, nullable=False, default=0.0)
    severity = Column(String(20), nullable=False, default="low")

    __table_args__ = (
        UniqueConstraint("raw_item_id", name="uq_enriched_raw_item_id"),
    )


class EnrichedCVE(Base):
    __tablename__ = "enriched_cves"

    id = Column(Integer, primary_key=True)
    raw_item_id = Column(Integer, ForeignKey("raw_items.id"), nullable=False)
    cve = Column(String(32), nullable=False)

    __table_args__ = (
        UniqueConstraint("raw_item_id", "cve", name="uq_cve_per_item"),
    )


class EnrichedIOC(Base):
    __tablename__ = "enriched_iocs"

    id = Column(Integer, primary_key=True)
    raw_item_id = Column(Integer, ForeignKey("raw_items.id"), nullable=False)

    ioc_type = Column(String(16), nullable=False)  # ip/domain/url/hash
    value = Column(Text, nullable=False)

    __table_args__ = (
        UniqueConstraint("raw_item_id", "ioc_type", "value", name="uq_ioc_per_item"),
    )


class EnrichedRef(Base):
    __tablename__ = "enriched_refs"

    id = Column(Integer, primary_key=True)
    raw_item_id = Column(Integer, ForeignKey("raw_items.id"), nullable=False)

    ref_type = Column(String(50), nullable=False)  # "url"
    value = Column(Text, nullable=False)

    __table_args__ = (
        UniqueConstraint("raw_item_id", "ref_type", "value", name="uq_ref_per_item"),
    )
