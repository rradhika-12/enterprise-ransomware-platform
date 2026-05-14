from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database.db import SessionLocal
from backend.models.event import EvidenceEvent

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):

    total_events = db.query(EvidenceEvent).count()

    critical_alerts = db.query(EvidenceEvent).filter(
        EvidenceEvent.severity == "critical"
    ).count()

    high_alerts = db.query(EvidenceEvent).filter(
        EvidenceEvent.severity == "high"
    ).count()

    suspicious_processes = db.query(EvidenceEvent).filter(
        EvidenceEvent.process_name.isnot(None)
    ).count()

    return {
        "total_events": total_events,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "suspicious_process_activity": suspicious_processes
    }


@router.get("/dashboard/recent-alerts")
def recent_alerts(db: Session = Depends(get_db)):

    alerts = db.query(EvidenceEvent).order_by(
        desc(EvidenceEvent.timestamp)
    ).limit(25).all()

    return alerts


@router.get("/dashboard/critical")
def critical_alerts(db: Session = Depends(get_db)):

    alerts = db.query(EvidenceEvent).filter(
        EvidenceEvent.severity == "critical"
    ).order_by(
        desc(EvidenceEvent.timestamp)
    ).all()

    return alerts


@router.get("/dashboard/high-risk")
def high_risk_alerts(db: Session = Depends(get_db)):

    alerts = db.query(EvidenceEvent).filter(
        EvidenceEvent.risk_score >= 70
    ).order_by(
        desc(EvidenceEvent.timestamp)
    ).all()

    return alerts


@router.get("/dashboard/mitre-map")
def mitre_map(db: Session = Depends(get_db)):

    alerts = db.query(EvidenceEvent).filter(
        EvidenceEvent.mitre_technique.isnot(None)
    ).all()

    result = []

    for alert in alerts:
        result.append({
            "timestamp": alert.timestamp,
            "host": alert.host,
            "process": alert.process_name,
            "stage": alert.mitre_stage,
            "technique": alert.mitre_technique,
            "severity": alert.severity
        })

    return result