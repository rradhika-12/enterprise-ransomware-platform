import hashlib
import json
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database.db import Base, engine, SessionLocal
from backend.models.event import EvidenceEvent

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Enterprise Ransomware Early Interception Platform",
    version="1.0.0"
)

class EvidenceEventCreate(BaseModel):
    host: str
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    event_type: str
    process_name: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    mitre_stage: str | None = None
    mitre_technique: str | None = None
    risk_score: int = 0
    severity: str = "low"
    detection_reason: str | None = None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_evidence_hash(data: dict) -> str:
    encoded = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(encoded).hexdigest()

@app.get("/")
def root():
    return {
        "message": "Enterprise Ransomware Early Interception Platform Running"
    }

@app.post("/events")
def create_event(event: EvidenceEventCreate, db: Session = Depends(get_db)):
    event_data = event.model_dump()
    evidence_hash = generate_evidence_hash(event_data)

    db_event = EvidenceEvent(
        **event_data,
        evidence_hash=evidence_hash
    )

    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    return {
        "status": "stored",
        "event_id": db_event.id,
        "evidence_hash": db_event.evidence_hash
    }

@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    events = db.query(EvidenceEvent).order_by(EvidenceEvent.timestamp.desc()).all()
    return events