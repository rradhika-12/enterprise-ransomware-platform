import json
import time
import socket
import getpass
from datetime import datetime

import psutil
import requests
import win32evtlog


CONFIG_PATH = "agents/windows_agent/config.json"


def load_config():
    with open(CONFIG_PATH, "r") as file:
        return json.load(file)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def send_event(event, backend_url):
    try:
        response = requests.post(backend_url, json=event, timeout=5)
        print(f"[SENT] {event['event_type']} | Status: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Could not send event: {e}")


def collect_process_snapshot():
    hostname = socket.gethostname()
    username = getpass.getuser()
    local_ip = get_local_ip()

    suspicious_processes = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "wmic.exe"
    ]

    events = []

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        try:
            name = (proc.info["name"] or "").lower()

            if name in suspicious_processes:
                event = {
                    "host": hostname,
                    "user": proc.info.get("username") or username,
                    "source_ip": local_ip,
                    "destination_ip": None,
                    "event_type": "suspicious_process_observed",
                    "process_name": proc.info.get("name"),
                    "parent_process": None,
                    "command_line": " ".join(proc.info.get("cmdline") or []),
                    "file_path": proc.info.get("exe"),
                    "file_hash": None,
                    "mitre_stage": "Execution",
                    "mitre_technique": "T1059",
                    "risk_score": 45,
                    "severity": "medium",
                    "detection_reason": "Suspicious Windows execution utility observed on endpoint"
                }

                events.append(event)

        except Exception:
            continue

    return events


def collect_windows_event_log(log_name="System", max_events=10):
    hostname = socket.gethostname()
    username = getpass.getuser()
    local_ip = get_local_ip()

    events = []

    try:
        handle = win32evtlog.OpenEventLog(None, log_name)

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        records = win32evtlog.ReadEventLog(handle, flags, 0)

        count = 0

        while records and count < max_events:
            for record in records:
                if count >= max_events:
                    break

                event_id = record.EventID & 0xFFFF
                source_name = record.SourceName

                event = {
                    "host": hostname,
                    "user": username,
                    "source_ip": local_ip,
                    "destination_ip": None,
                    "event_type": f"windows_event_{event_id}",
                    "process_name": source_name,
                    "parent_process": None,
                    "command_line": None,
                    "file_path": None,
                    "file_hash": None,
                    "mitre_stage": "Monitoring",
                    "mitre_technique": None,
                    "risk_score": 10,
                    "severity": "low",
                    "detection_reason": f"Real Windows event collected from {log_name} log"
                }

                events.append(event)

                count += 1

            records = win32evtlog.ReadEventLog(handle, flags, 0)

        win32evtlog.CloseEventLog(handle)

    except Exception as e:
        print(f"[WARNING] Could not read {log_name}: {e}")

    return events


def main():
    config = load_config()
    backend_url = config["backend_url"]
    interval = config.get("collection_interval_seconds", 10)

    print("[AGENT STARTED] Windows Endpoint Agent running...")
    print(f"[BACKEND] {backend_url}")

    while True:
        print(f"\n[COLLECTING] {datetime.now()}")

        all_events = []

        all_events.extend(collect_process_snapshot())
        all_events.extend(collect_windows_event_log("System", max_events=5))
        all_events.extend(collect_windows_event_log("Application", max_events=5))

        for event in all_events:
            send_event(event, backend_url)

        time.sleep(interval)


if __name__ == "__main__":
    main()