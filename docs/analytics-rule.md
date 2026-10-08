# Microsoft Sentinel Analytics Rule

## Rule Name
Multiple Failed Sign-In Attempts

## Purpose
This analytics rule detects repeated failed Microsoft Entra ID authentication attempts originating from the same IP address against the same user account.

The detection is designed to identify activity that may indicate password guessing or brute-force authentication attempts.

## Data Source
- Microsoft Entra ID Sign-in Logs
- Log Analytics table: `SigninLogs`

## Detection Logic
The rule identifies users with three or more failed sign-in attempts from the same IP address during the configured detection period.

```kusto
SigninLogs
| where ResultType != 0
| summarize
    FailedAttempts=count(),
    FirstAttempt=min(TimeGenerated),
    LastAttempt=max(TimeGenerated)
    by UserPrincipalName, IPAddress
| where FailedAttempts >= 3
| project
    TimeGenerated=LastAttempt,
    UserPrincipalName,
    IPAddress,
    FailedAttempts,
    FirstAttempt,
    LastAttempt

```

## Rule Configuration
- Severity: Medium
- Query frequency: 1 hour
- Lookup period: 1 hour
- Trigger threshold: 3 or more failed authentication attempts
- Grouping entities: User account and source IP address

## MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique: Brute Force
- Technique ID: T1110

## Alert Grouping
Repeated authentication failures associated with the same user and source IP are correlated to reduce duplicate alerts and provide analysts with a consolidated incident for investigation.

## Investigation
The generated incident was investigated using Microsoft Sentinel and Microsoft Defender. The investigation included:

- Reviewing the affected user account
- Examining the source IP address
- Reviewing individual failed authentication events
- Examining Microsoft Entra ID result codes
- Reviewing Conditional Access status
- Correlating the alert with the generated incident
- Reviewing the incident graph and related entities

## Detection Tuning
The detection threshold was configured to identify three or more failed sign-in attempts while grouping events by user and source IP address.

This approach demonstrates how SOC analysts can balance detection sensitivity with alert noise reduction.

## Incident Resolution
The activity generated a Microsoft Sentinel incident as expected. After investigation, the incident was resolved and classified as:

**False positive - Not malicious**

The incident was exported as a PDF to preserve investigation evidence and demonstrate the complete incident-response workflow.

## Skills Demonstrated
Microsoft Sentinel, Microsoft Defender, Microsoft Entra ID, KQL, SIEM monitoring, analytics rules, alert triage, incident investigation, detection engineering, MITRE ATT&CK mapping, and incident response.
