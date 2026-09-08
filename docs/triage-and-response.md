# Lateral Movement Triage and Response

## Validate the signal

Confirm the user identity, source host, destination host, authentication type, remote-management mechanism, process lineage, and whether activity matches an approved administrative workflow.

## High-confidence indicators

Escalate when multiple remote techniques occur in sequence, a non-management workstation initiates administrative access, a privileged account appears on an unusual source host, or one identity touches several systems in a short period without an operational explanation.

## Containment options

Depending on evidence and business impact: isolate affected endpoints, disable or reset exposed identities, revoke active sessions, block malicious infrastructure, restrict remote administration, and preserve volatile evidence.

## Remediation

- Enforce privileged access from controlled management hosts.
- Remove unnecessary local-administrator rights.
- Segment administrative protocols.
- Strengthen MFA and privileged access controls.
- Reduce NTLM and legacy authentication where feasible.
- Improve logging for authentication, process creation, remote services, and network connections.

## Validation

After remediation, reproduce the approved synthetic test in a lab or purple-team exercise and verify both prevention controls and expected telemetry. Document residual risk and tune detections only after confirming false-positive causes.
