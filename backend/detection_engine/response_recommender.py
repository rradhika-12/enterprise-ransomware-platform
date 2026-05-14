def recommend_action(risk_score: int, stage: str | None) -> str:
    if risk_score >= 85:
        return "Critical: isolate endpoint, block SMB/RDP, preserve evidence, enable deception/shadow routing."
    
    if risk_score >= 70:
        return "High: restrict network access, enable enhanced monitoring, investigate process lineage."
    
    if risk_score >= 45:
        return "Medium: monitor closely, verify user activity, check file/process provenance."
    
    return "Low: store evidence and continue monitoring."