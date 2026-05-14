from backend.detection_engine.rules import (
    SUSPICIOUS_PROCESSES,
    HIGH_RISK_COMMAND_KEYWORDS,
    OFFICE_PROCESSES,
    RANSOMWARE_FILE_INDICATORS
)
from backend.detection_engine.response_recommender import recommend_action


def analyze_event(event_data: dict) -> dict:
    process = (event_data.get("process_name") or "").lower()
    parent = (event_data.get("parent_process") or "").lower()
    command = (event_data.get("command_line") or "").lower()
    file_path = (event_data.get("file_path") or "").lower()

    risk_score = event_data.get("risk_score", 0) or 0
    reasons = []

    mitre_stage = event_data.get("mitre_stage")
    mitre_technique = event_data.get("mitre_technique")
    signature_difference = []

    if process in SUSPICIOUS_PROCESSES:
        rule = SUSPICIOUS_PROCESSES[process]
        risk_score += rule["risk"]
        mitre_stage = mitre_stage or rule["stage"]
        mitre_technique = mitre_technique or rule["technique"]
        reasons.append(rule["reason"])
        signature_difference.append(
            f"Process {process} is not always malicious, but is commonly abused in ransomware TTPs."
        )

    for keyword, score in HIGH_RISK_COMMAND_KEYWORDS.items():
        if keyword in command:
            risk_score += score
            reasons.append(f"High-risk command keyword detected: {keyword}")
            signature_difference.append(
                f"Command contains ransomware-relevant behavior marker: {keyword}"
            )

    if parent in OFFICE_PROCESSES and process in ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"]:
        risk_score += 45
        mitre_stage = "Initial Access / Execution"
        mitre_technique = "T1204 + T1059"
        reasons.append(
            "Office application spawned a scripting/command process, commonly seen in phishing-based ransomware execution."
        )
        signature_difference.append(
            "Normal office document activity should not spawn command shells or script interpreters."
        )

    if "vssadmin" in command or "delete shadows" in command or process == "vssadmin.exe":
        risk_score += 40
        mitre_stage = "Recovery Inhibition"
        mitre_technique = "T1490"
        reasons.append("Possible shadow copy deletion behavior detected.")
        signature_difference.append(
            "Legitimate users rarely delete shadow copies during normal daily work."
        )

    if "\\\\" in command or "net use" in command:
        risk_score += 30
        mitre_stage = "Lateral Movement"
        mitre_technique = "T1021"
        reasons.append("Possible network share or lateral movement behavior detected.")
        signature_difference.append(
            "Network share/admin path usage may indicate movement across enterprise systems."
        )

    for indicator in RANSOMWARE_FILE_INDICATORS:
        if indicator in file_path:
            risk_score += 35
            mitre_stage = "Impact / Pre-Encryption"
            mitre_technique = "T1486"
            reasons.append(f"Ransomware-like file indicator observed: {indicator}")
            signature_difference.append(
                f"File path/name contains ransomware-style marker: {indicator}"
            )

    risk_score = min(risk_score, 100)

    if risk_score >= 85:
        severity = "critical"
    elif risk_score >= 70:
        severity = "high"
    elif risk_score >= 45:
        severity = "medium"
    else:
        severity = "low"

    event_data["risk_score"] = risk_score
    event_data["severity"] = severity
    event_data["mitre_stage"] = mitre_stage or "Monitoring"
    event_data["mitre_technique"] = mitre_technique
    event_data["detection_reason"] = " | ".join(reasons) if reasons else event_data.get("detection_reason")
    event_data["recommended_action"] = recommend_action(risk_score, mitre_stage)
    event_data["signature_difference"] = " | ".join(signature_difference) if signature_difference else "No strong signature difference identified yet."

    return event_data