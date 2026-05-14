SUSPICIOUS_PROCESSES = {
    "powershell.exe": {
        "risk": 45,
        "stage": "Execution",
        "technique": "T1059",
        "reason": "PowerShell execution observed; commonly abused in ransomware intrusion chains."
    },
    "cmd.exe": {
        "risk": 30,
        "stage": "Execution",
        "technique": "T1059",
        "reason": "Command shell execution observed."
    },
    "wscript.exe": {
        "risk": 50,
        "stage": "Execution",
        "technique": "T1059",
        "reason": "Windows Script Host execution observed."
    },
    "mshta.exe": {
        "risk": 60,
        "stage": "Execution",
        "technique": "T1218",
        "reason": "MSHTA execution observed; often abused for malicious script execution."
    },
    "rundll32.exe": {
        "risk": 55,
        "stage": "Defense Evasion",
        "technique": "T1218",
        "reason": "Rundll32 execution observed; often abused for proxy execution."
    },
    "regsvr32.exe": {
        "risk": 60,
        "stage": "Defense Evasion",
        "technique": "T1218",
        "reason": "Regsvr32 execution observed; may indicate signed binary proxy execution."
    },
    "wmic.exe": {
        "risk": 65,
        "stage": "Lateral Movement",
        "technique": "T1047",
        "reason": "WMIC execution observed; may indicate remote execution or lateral movement."
    },
    "schtasks.exe": {
        "risk": 55,
        "stage": "Persistence",
        "technique": "T1053",
        "reason": "Scheduled task activity observed; commonly used for persistence."
    },
    "vssadmin.exe": {
        "risk": 80,
        "stage": "Recovery Inhibition",
        "technique": "T1490",
        "reason": "Vssadmin observed; ransomware often uses it to delete shadow copies."
    }
}

HIGH_RISK_COMMAND_KEYWORDS = {
    "-enc": 30,
    "encodedcommand": 30,
    "downloadstring": 35,
    "invoke-expression": 35,
    "iex": 25,
    "vssadmin delete shadows": 60,
    "delete shadows": 60,
    "wbadmin delete": 55,
    "bcdedit": 40,
    "wevtutil cl": 50,
    "schtasks": 35,
    "net user": 30,
    "net use": 35,
    "nltest": 30,
    "whoami /priv": 25,
    "taskkill": 25,
    "stop-service": 35,
    "\\\\": 25
}

OFFICE_PROCESSES = [
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe"
]

RANSOMWARE_FILE_INDICATORS = [
    "readme",
    "recover",
    "decrypt",
    "ransom",
    ".locked",
    ".encrypted",
    ".akira",
    ".lockbit",
    ".blackcat"
]