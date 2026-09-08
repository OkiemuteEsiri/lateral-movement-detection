# Lateral Movement Detection Lab

Defensive detection-engineering project for identifying suspicious remote execution, administrative share usage, and identity-driven lateral movement patterns in synthetic endpoint telemetry.

## Objectives

- Correlate remote logon and process activity across hosts
- Highlight unusual administrative-share and remote-service behavior
- Map detections to MITRE ATT&CK
- Separate signal generation from analyst validation
- Document containment and remediation paths

## ATT&CK coverage

- T1021 - Remote Services
- T1021.002 - SMB/Windows Admin Shares
- T1021.001 - Remote Desktop Protocol
- T1047 - Windows Management Instrumentation
- T1078 - Valid Accounts

ATT&CK mappings describe behavioral relevance only; they do not prove malicious activity.

## Structure

- `src/detect.py` - correlation and risk-scoring logic
- `data/events.json` - synthetic endpoint/network events
- `tests/test_detect.py` - unit tests
- `docs/triage-and-response.md` - analyst validation and containment playbook

## Detection approach

The analyzer groups events into short source/destination relationships and increases risk when remote logons are followed by remote process execution, administrative-share access, or multiple host pivots. Legitimate administration must be validated against approved management tools, user role, source host, change activity, and expected maintenance windows.

## Run

```bash
python src/detect.py data/events.json
```

## Safety

This project contains defensive analytics and synthetic telemetry only. It does not provide lateral-movement execution instructions or credentials.