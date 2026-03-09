from sqlalchemy import Column, Integer, String, Text, ForeignKey, UniqueConstraint
from app.db.database import Base

class MitreMatch(Base):
    __tablename__ = "mitre_matches"
    id = Column(Integer, primary_key=True)

    raw_item_id = Column(Integer, ForeignKey("raw_items.id"), nullable=False)

    technique_id = Column(String(20), nullable=False)   # ex: T1190
    technique_name = Column(Text, nullable=False)       # ex: Exploit Public-Facing Application
    tactic = Column(String(50), nullable=True)          # ex: initial-access

    confidence = Column(Integer, nullable=False, default=50)  # 0-100
    evidence = Column(Text, nullable=True)                   # mots-clés trouvés / raison

    __table_args__ = (
        UniqueConstraint("raw_item_id", "technique_id", name="uq_mitre_per_item"),
    )
