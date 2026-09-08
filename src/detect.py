import json
import sys
from collections import defaultdict

RISK = {
    "remote_logon": 2,
    "admin_share_access": 3,
    "remote_process": 4,
    "rdp_logon": 2,
    "wmi_execution": 4,
}


def analyze_events(events):
    relationships = defaultdict(lambda: {"score": 0, "events": [], "users": set()})
    for event in events:
        key = (event.get("source_host"), event.get("destination_host"))
        bucket = relationships[key]
        event_type = event.get("event_type", "unknown")
        bucket["score"] += RISK.get(event_type, 0)
        bucket["events"].append(event_type)
        if event.get("user"):
            bucket["users"].add(event["user"])

    findings = []
    for (source, destination), details in relationships.items():
        score = details["score"]
        if score >= 7:
            severity = "High"
        elif score >= 4:
            severity = "Medium"
        else:
            severity = "Low"
        findings.append({
            "source_host": source,
            "destination_host": destination,
            "score": score,
            "severity": severity,
            "events": details["events"],
            "users": sorted(details["users"]),
        })
    return sorted(findings, key=lambda item: item["score"], reverse=True)


def load_events(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python src/detect.py data/events.json")
    for finding in analyze_events(load_events(sys.argv[1])):
        print(json.dumps(finding))
