from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from backend.database.db import Base

class EvidenceEvent(Base):
    __tablename__ = "evidence_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    host = Column(String(255), nullable=False)
    user = Column(String(255), nullable=True)
    source_ip = Column(String(100), nullable=True)
    destination_ip = Column(String(100), nullable=True)

    event_type = Column(String(255), nullable=False)
    process_name = Column(String(255), nullable=True)
    parent_process = Column(String(255), nullable=True)
    command_line = Column(Text, nullable=True)
    file_path = Column(Text, nullable=True)
    file_hash = Column(String(255), nullable=True)

    mitre_stage = Column(String(255), nullable=True)
    mitre_technique = Column(String(255), nullable=True)

    risk_score = Column(Integer, default=0)
    severity = Column(String(50), default="low")
    detection_reason = Column(Text, nullable=True)

    evidence_hash = Column(String(255), nullable=True)