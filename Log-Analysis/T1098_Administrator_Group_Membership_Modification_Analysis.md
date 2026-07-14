# Windows EVTX Forensic Analysis: Administrator Group Membership Modification

- **Author:** CypherX
- **Category:** Windows Security / DFIR / SOC Analysis
- **Host Analyzed:** MSEDGEWIN10
- **Operating System:** Windows
- **Log Source:** [Dataset](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES?)
- **MITRE ATT&CK Mapping:** T1098 — Account Manipulation
- **Related Techniques:** T1078 — Valid Accounts | T1068 — Exploitation for Privilege Escalation (Potential)
- **Relevant Event IDs:** 4732 — Member Added to a Security-Enabled Local Group | 4733 — Member Removed from a Security-Enabled Local Group (Verification Required)
- **Severity:** High
- **Analysis Type:** Privilege Escalation & Account Manipulation Investigation  

---

## Executive Summary

The analyzed Windows Event Log fragment contains security auditing records associated with the local **Builtin\Administrators** group on the host **MSEDGEWIN10**.

The extracted data references the low-privileged **IEUser** account in conjunction with the highly privileged **Administrators** group, suggesting a potential account manipulation event. Although the raw EVTX fragment does not conclusively confirm whether the account was added, removed, or enumerated, the correlation warrants investigation because unauthorized modification of privileged group memberships is a common post-exploitation technique used to establish persistence and elevate privileges.

From a defensive perspective, this activity aligns with **MITRE ATT&CK T1098 (Account Manipulation)** and may represent an attempt to grant administrative rights to a previously unprivileged account. Verification of the associated Windows Security Event ID and current group membership is recommended to determine whether the observed activity reflects legitimate administrative operations or malicious privilege escalation.


---


# 1. Log Classification
- **Log Type:** Windows Event Log binary format (.evtx)
- **Source System:** Local Windows Host (**MSEDGEWIN10**)
- **Structure:** Structured binary format containing XML schemas ([http://schemas.microsoft.com/win/2004/08/events/event](http://schemas.microsoft.com/win/2004/08/events/event))

# 2. Normalized Data Table:

| Entity | Property | Extracted Value |
|---------|----------|----------------|
| Log Provider | Microsoft-Windows-Security-Auditing |
| Channel | Security |
| Computer/Hostname | MSEDGEWIN10 |
| Target Group Name | Administrators |
| Target Domain | Builtin |
| Target User Name | IEUser |
| Subject User Name | Located in block (Schema structural padding obscures direct clean text, maps structurally near IEUser) |
| Event Schema XMLNS | [http://schemas.microsoft.com/win/2004/08/events/event](http://schemas.microsoft.com/win/2004/08/events/event) |

# 3. Event Timeline

While explicit, human-readable ISO-8601 timestamps are encapsulated inside the raw binary fields (`TimeCreated` / `SystemTime`), structural sequencing highlights the following timeline chain:

<br>

```
[Event Record Initialization]
              │
              ▼
[Provider: Microsoft-Windows-Security-Auditing initialized via Security Channel]
              │
              ▼
[Target Security Context Evaluated: Builtin\Administrators Group]
              │
              ▼
[Target User Context Evaluated: MSEDGEWIN10\IEUser]
              │
              ▼
[Event Modification Commit / Audit Log Generation]
```
<br>

> Cause → Effect: A process or user session initiated a security group structural query or modification targeting the Builtin\Administrators group. The system responded by generating a Security Auditing record mapping IEUser against the local administrative structure.

# 4. Threat / Anomaly Analysis

## Privilege Escalation Risk (Confidence Level: Medium)
The `IEUser` account is the default low-privilege user account found inside Microsoft Edge testing environments and virtual machines. Finding `IEUser` correlated directly inside an event structure containing `Builtin\Administrators` indicates either an explicit attempt to add `IEUser` to the local administrators group, or an intentional execution sequence running under administrative privileges.

## Suspicious Context (Confidence Level: Medium)
If this activity was not actively performed by a laboratory administrator, it suggests an automated script or exploit payload (such as a local privilege escalation vector) attempting to ensure persistence or break out of a restricted sandbox environment.

# 5. Operational Analysis
There are no network performance records, latency metrics, or `4xx/5xx` HTTP errors visible within this specific log snippet.
The raw dump contains explicit structural repetitions of ElfChnk headers, confirming that the Windows Event Log system is actively writing security descriptors to disk without storage degradation.

# 6. Root Cause Analysis

## Confirmed Facts
- The system involved is a Windows environment named `MSEDGEWIN10`.
- The logs are native Windows Security Auditing logs.
- The security context explicitly inspects or alters the local Administrators group with reference to the account `IEUser`.

## Inferred Hypotheses
- **Hypothesis 1 (High Probability):** A local privilege escalation attempt occurred, or a deployment engineer ran a setup script to grant administrative privileges to the default testing profile (`IEUser`).
- **Hypothesis 2 (Low Probability):** Routine operating system background auditing occurred; however, typical background tasks do not frequently map low-privilege runtime accounts to `Builtin\Administrators` without an operational trigger.

# 7. Recommendations
To verify whether this activity signifies a true incident or an expected environment configuration, execute the following pragmatic remediation and investigation steps:

## Immediate Investigation & Triage:
### Query Local Group Memberships
Run the following command via PowerShell on `MSEDGEWIN10` to see if `IEUser` was successfully added to the high-privilege group:
```powershell
Get-LocalGroupMember -Group "Administrators"
```
### Extract Full Event IDs
Extract the full EVTX file from the host and convert it to XML to parse the exact Event ID. Look specifically for:
- Event ID **4732**: *A member was added to a security-enabled local group*
- Event ID **4720**: *A user account was created*

## Security Hardening & Monitoring
- If `IEUser` is found in the `Administrators` group and this environment is exposed to untrusted code execution (like a malware analysis sandbox or a public VM), immediately isolate the host.
- Implement SIEM alert rules triggering on any event source matching `Microsoft-Windows-Security-Auditing` with an Event ID of **4732** targeting the `Builtin\Administrators` group.
