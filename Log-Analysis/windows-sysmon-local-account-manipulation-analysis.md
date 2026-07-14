# Windows Sysmon Local Account Manipulation & Privilege Group Modification Analysis

- **Author:** CypherX
- **Category:** Windows Security / DFIR / SOC Analysis
- **Source System:** LAPTOP-JU4M3I0E
- **Operating System:** Windows
- **Log Source:** [Dataset](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES?)
- **Event Type:** Registry Activity / Local Account Management / Security Configuration Changes
- **Analysis Scope:** Local Account Creation, Deletion & Administrator Group Modification Investigation
- **Severity:** Medium (Requires Validation)
- **MITRE ATT&CK Mapping:**
  - **T1136.001 — Create Account: Local Account**
  - **T1098 — Account Manipulation**
  - **T1078 — Valid Accounts (Potential)**
  - **T1069.001 — Permission Groups Discovery: Local Groups (Potential)**
- **Analysis Type:** Endpoint Forensics & Privilege Escalation Detection

---

## Executive Summary

A forensic analysis of the provided Microsoft Sysmon Operational logs identified a sequence of local account management and privilege-related activities on the Windows endpoint **LAPTOP-JU4M3I0E**. The dataset primarily contains registry activity performed by the **Local Security Authority Subsystem Service (lsass.exe)**, including the creation, modification, and deletion of local user account entries, as well as changes affecting the local Administrators group.

The investigation identified repeated lifecycle activity involving a local account named **support**, where the account was created, removed, and recreated multiple times within a short period. Additionally, a new service-style account named **sqlsvc** was created, followed by several modifications to the local Administrators group registry structure. These actions occurred alongside legitimate Windows operations such as Sysmon telemetry logging, Windows Update trace generation, and credential store access.

While no direct indicators of compromise, malware execution, or malicious payloads were identified within the provided log segment, the rapid creation and removal of privileged accounts combined with administrator group modifications represent behavior commonly associated with persistence mechanisms and privilege escalation attempts. The activity may indicate either authorized administrative operations, such as software deployment or temporary support access provisioning, or unauthorized account manipulation by a threat actor.

Further investigation is required to determine whether these account changes align with approved administrative activity. Recommended next steps include correlating Sysmon Process Creation events (Event ID 1), reviewing authentication logs, validating change management records, and examining network activity around the account modification timeframe.

**Overall Assessment:** The endpoint exhibits **suspicious account management behavior requiring validation**, with a moderate risk of unauthorized privilege manipulation if the activity cannot be attributed to legitimate administrative processes.

---

# 1. Pre-Analysis Phase
Before extracting entities, the raw log data was evaluated to determine its schema and structure:

- **Log Type(s):** Windows Event Viewer Log / Sysmon Operational Logs (`Microsoft-Windows-Sysmon/Operational`).
- **Source System(s):** A single Windows host named `LAPTOP-JU4M3I0E`.
- **Structure:** Semi-structured data. The raw file appears to be an ElfFile/ElfChnk formatted file (typical of Windows `.evtx` or `.etl` trace structures) containing embedded XML event data with Sysmon schema properties.

# 2. Normalized Data Table
The following table extracts and normalizes the core entities discovered within the log data:

| Timestamp (UTC) | Process Image (Image) | Target Object / Filename | Action / Rule Name |
|-------------------|------------------------|--------------------------|-------------------|
| 2020-09-01 16:21:32.541 | System | `C:\Windows\System32\LogFiles\WMI\RtBackup\EtwRTSYSMON TRACE.etl` | File Access |
| 2020-09-04 09:28:22.279 | `C:\windows\system32\lsass.exe` | `HKLM\SAM\SAM\Domains\Account\Users\Names\support` | CreateKey (Local Account Created/Deleted) |
| 2020-09-04 09:28:22.279 | `C:\windows\system32\lsass.exe` | `HKLM\SAM\SAM\Domains\Account\Users\Names\support\\(Default)` | SetValue (Local Account Created/Deleted) |
| 2020-09-04 09:28:42.976 | `C:\windows\system32\lsass.exe` | `HKLM\SAM\SAM\Domains\Account\Users\Names\support` | DeleteKey (Local Account Created/Deleted) |
| 2020-09-04 09:42:33.602 | System | `C:\Usersouss\AppData\Local\Microsoft\Credentials\

# 3. Event Timeline

The chronology demonstrates a structured sequence of account management and logging:

- **Trace Logging Initiated:** On 2020-09-01, the System process interacts with WMI Event Trace logs for Sysmon (`EtwRTSYSMON TRACE.etl`).
- **Initial Account Activity (09:28 UTC):** `lsass.exe` creates the registry key for user support and sets its default value. Exactly 20 seconds later, the key is deleted.
- **Routine Operations (09:42 UTC):** `lsass.exe` interacts with credential stores for user `bouss`, followed closely by Windows Update trace file generation by the System process.
- **Re-creation of Support Account (10:03 UTC):** `lsass.exe` again creates the support user key and sets the default value.
- **Service Account Creation (10:33 UTC):** `lsass.exe` creates a new key for an account named `sqlsvc`.
- **Administrator Group Modifications (10:45 UTC - 11:02 UTC):** Between 10:45:30 and 11:02:16, `lsass.exe` modifies the `00000220\C` alias (Local Administrators) four distinct times. During this window, the support account is deleted and re-created twice (at 10:54 and 11:00).
- **Later Activity (11:54 UTC - 16:31 UTC):** The logs show sporadic but repeated access to `bouss`'s credential cache by `lsass.exe` and further Windows Update log generation by System.

# 4. Threat & Anomaly Detection

Based on the raw evidence, the following patterns were analyzed:

- **[Medium Confidence] Anomalous Account Lifecycle Management:** The local support account is created, deleted, and re-created multiple times within a two-hour window (09:28 to 11:00). While this could be an automated IT provisioning script (such as LAPS or a helpdesk tool granting temporary access), it is also a common tactic for attackers attempting to maintain temporary persistence without raising long-term alarms.

- **[Medium Confidence] Privileged Group Modification:** The modifications to the Local Administrators group (`00000220\C`) coincide with the lifecycle of the support and `sqlsvc` accounts. Attackers frequently add newly created accounts to the administrators group to escalate privileges.

- **[Low Confidence] Credential Access Patterns:** `lsass.exe` repeatedly interacts with `C:\Users\bouss\AppData\Local\Microsoft\Credentials\8AFF5736C4573C0E0530F61DD93C6F89`. While `lsass.exe` legitimately handles credentials, if user `bouss` was not actively logging in or accessing network resources during these exact timestamps, this could indicate credential dumping or pass-the-hash reconnaissance. However, without process injection logs, this must be treated as benign baseline activity.

- **Absence of Specific IoCs:** There are no observable SQL injections, directory traversals, Nmap signatures, or malicious payloads in the provided data.

# 5. Operational & Performance Analysis

- **System Stability:** There are no indicators of resource exhaustion, latency spikes, or repeated 4xx/5xx HTTP errors in the provided dataset.

- **Normal Background Services:** The System process consistently generated and interacted with standard Windows trace files (`EtwRTSYSMON TRACE.etl`, `EtwRTNT Kernel Logger.etl`, and `WindowsUpdate.*.etl`), indicating that baseline OS telemetry and update mechanisms were functioning normally and without interruption.

# 6. Root Cause Hypothesis

## Confirmed Facts:
- Local accounts support and `sqlsvc` were modified/created on the endpoint `LAPTOP-JU4M3I0E` by the local security subsystem (`lsass.exe`).
- The **Local Administrators** group was updated multiple times in conjunction with these account changes.
- User `bouss`'s local credential files were accessed repeatedly by `lsass.exe`.

## Inferred Hypotheses:
### Hypothesis 1 (High Probability - Benign Admin Activity):
An IT administrator or automated configuration management script (e.g., Ansible, SCCM) was executing a playbook to deploy an SQL service (`sqlsvc`) and utilize a temporary support account for setup, which required adding/removing users from the **Local Administrators** group.

### Hypothesis 2 (Medium Probability - Malicious Persistence):
A threat actor successfully compromised the machine (possibly via user `bouss`), accessed local credential caches, and executed `"net user"` or similar commands to create a temporary support account, grant it Admin privileges for lateral movement or persistence, and subsequently scrub the account to evade detection.

# 7. Recommendations

To complete the picture and address potential security risks, the following actionable steps are recommended:

## Immediate Investigation Steps:
- **Verify Authorization:** Cross-reference the creation of the support and `sqlsvc` accounts on `LAPTOP-JU4M3I0E` with known IT change control tickets.
- **Correlate Process Logs:** Pull Sysmon Event ID 1 (`Process Creation`) logs for the identical time frame (`2020-09-04 09:20 - 11:10 UTC`). Look for `net.exe`, `net1.exe`, or PowerShell commands executed by user `bouss` or System that correspond to the CreateKey and SetValue operations.
- **Review Network Traffic:** Check network telemetry for RDP (Port 3389) or SMB (Port 445) connections originating from or targeting `LAPTOP-JU4M3I0E` around the time the support account was active.

## Security Hardening Recommendations:
- Implement Microsoft Local Administrator Password Solution (**LAPS**) if temporary local admin access is required, rather than relying on creating and deleting generic accounts like support.
- Ensure Sysmon configurations are tuned to capture Event ID 10 (`Process Access`) specifically targeting `lsass.exe` to differentiate between benign system credential requests and malicious credential dumping tools like Mimikatz.
