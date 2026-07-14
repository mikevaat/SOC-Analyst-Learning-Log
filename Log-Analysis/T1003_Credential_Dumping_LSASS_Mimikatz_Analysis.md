# Windows EVTX Forensic Analysis: LSASS Credential Dumping & Mimikatz Activity

- **Author:** CypherX
- **Category:** Windows Security / DFIR / SOC Analysis
- **Source:** EVTX Attack Samples Repository
- **Host Analyzed:** MSEDGEWIN10
- **Operating System:** Windows 10
- **Log Source:** [Dataset](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES?)
- **MITRE ATT&CK Mapping:** T1003.001 — OS Credential Dumping: LSASS Memory
- **Related Techniques:** T1003.002 — SAM Database | T1003.003 — NTDS | T1070.004 — File Deletion
- **Severity:** Critical
- **Analysis Type:** Endpoint Credential Theft Investigation  

---

## Executive Summary

The analyzed Windows Event Log data indicates a high-probability credential dumping incident targeting the Local Security Authority Subsystem Service (`lsass.exe`) on the host **MSEDGEWIN10**.

Following a successful interactive user logon, `lsass.exe` was observed creating a suspicious file named `mimilsa.log` within the protected `C:\Windows\System32\` directory. This behavior is strongly associated with credential extraction utilities such as Mimikatz, which commonly interact with LSASS memory to obtain authentication material.

Immediately following this activity, a large volume of Microsoft-Windows-VolumeSnapshot-Driver events was observed, indicating potential abuse of Volume Shadow Copy technology to access protected credential databases such as the SAM, SYSTEM, SECURITY registry hives, or potentially the NTDS database.

The combined evidence suggests a likely credential theft operation involving LSASS access followed by attempts to obtain offline credential stores.


---


# 1. Pre-Analysis Phase: Log Classification & Assumptions

**Log Types:** Windows Event Logs (EVTX format, rendered as a raw ASCII/Hex dump).  
**Source Systems:** A single Windows host identified as `MSEDGEWIN10`.  
**Log Providers:** Microsoft-Windows-Sysmon/Operational and Microsoft-Windows-VolumeSnapshot-Driver/Operational.  
**Structure:** Unstructured raw hex/ASCII payload.

# 2. Normalized Data Extraction

The following entities have been successfully extracted and normalized:

| Timestamp (UTC) | Source System | Log Provider | Process / Image | Target Object / Filename | Event Details / Action |
|-------------------|----------------|--------------|-----------------|--------------------------|----------------------|
| 2020-09-11 12:09:05.743 | MSEDGEWIN10 | Sysmon | C:\Windows\system32\svchost.exe / lsass.exe | N/A | Process Access / RPC Call Trace observed |
| 2020-09-11 12:09:05.764 | MSEDGEWIN10 | Sysmon | C:\Windows\system32\LogonUI.exe | HKLM\...\SessionData\2\LoggedOnUser | SetValue contains `MSEDGEWIN10\IEUser` |
| 2020-09-11 12:09:05.764 | MSEDGEWIN10 | Sysmon | C:\Windows\system32\LogonUI.exe | HKLM\...\SessionData\2\LoggedOnSAMUser | SetValue contains `MSEDGEWIN10\IEUser` |
| 2020-09-11 12:10:22.357 | MSEDGEWIN10 | Sysmon | C:\Windows\system32\lsass.exe | C:\Windows\System32\mimilsa.log | File Creation |
| Unknown/Truncated   | MSEDGEWIN10   | VSS Driver   | N/A             | N/A                     | Rapid, repeated Volume Snapshot operations |


> [!NOTE]
> Missing HTTP status codes, session IDs, and IP addresses are due to their absence in the logs itself.


# 3. Chronological Reconstruction

The following maps the cause-and-effect timeline based on the exact sequence of events:

- **[12:09:05.743] Background Service Access:** svchost.exe and lsass.exe interact. The call trace references `ntdll.dll`, `SspiSrv.dll`, and `RPCRT4.dll`, representing standard RPC authentication handling preceding a user logon.
- **[12:09:05.764] Interactive Logon Completes:** LogonUI.exe updates the registry to set LoggedOnUser and LoggedOnSAMUser to `MSEDGEWIN10\IEUser`, confirming a user successfully logged into the console or via RDP.
- **[12:10:22.357] Anomaly/Malicious Action:** Approximately 77 seconds after the logon, lsass.exe creates a file named `mimilsa.log` within the highly privileged `C:\Windows\System32` directory.
- **[Subsequent Activity] VSS Flood:** A high volume of operational logs from the Microsoft-Windows-VolumeSnapshot-Driver triggers, indicating the creation or manipulation of volume shadow copies.

# 4. Threat & Anomaly Detection

### [Critical] Indicators of Compromise (IoC) - Credential Dumping:
The file `mimilsa.log` being written by `lsass.exe` is a massive deviation from baseline system behavior. The `lsass.exe` process does not natively write files with this naming convention. This strongly correlates with Mimikatz (or a closely related variant) interacting with LSASS memory and outputting its log to disk.

### [High] Suspicious VSS Activity:
The rapid succession of `VolumeSnapshot-Driver` events immediately surrounding a credential dumping IoC is heavily indicative of an attacker attempting to back up locked files. Attackers frequently use `vssadmin` or WMI to create a shadow copy to extract the SAM, SYSTEM, and SECURITY registry hives for offline password cracking.

### [Medium] Missing Context:
No network connections or parent process creations are visible in this specific snippet to determine how the attacker executed the payload.

# 5. Operational & Performance Analysis

### Resource Spikes (Hypothesized):
The sheer volume of `VolumeSnapshot-Driver` logs at the end of the dump suggests intense disk I/O. Creating volume shadow copies rapidly can cause noticeable latency and disk thrashing on the host machine

### Process Stability:
There are no 5xx/4xx errors, backend timeouts, or service crash indicators (e.g., Event ID 1000/7036) present in this isolated data set.

# 6. Root Cause Hypothesis

Based strictly on the provided logs, the following hypotheses are formed:

### Confirmed Facts:
- A user named **IEUser** successfully logged onto **MSEDGEWIN10**.
- `lsass.exe` abnormally created a file named `C:\Windows\System32\mimilsa.log`.
- The Volume Snapshot service was heavily active during the recorded timeframe.

### Inferred Hypotheses:
- **[Critical Confidence]** The system **MSEDGEWIN10** is compromised. An attacker executed a credential dumping utility (**Mimikatz**) locally.
- **[High Confidence]** The attacker utilized Volume Shadow Copies to attempt offline extraction of local SAM/SYSTEM hives to bypass file locks.
- **[Medium Confidence]** The initial access vector may be tied to the **IEUser** account, given that the exploitation occurred merely a minute after this account logged in.

# 7. Actionable Intelligence & Remediation

### Immediate Containment Steps:
- **Isolate the Host:** Immediately disconnect **MSEDGEWIN10** from the network to prevent lateral movement using the compromised credentials.
- **Preserve Volatile Data:** Capture a live memory dump of the machine before rebooting it, as `lsass.exe` memory will contain the injected malicious threads and potentially the attacker's toolkit.

### Investigation Steps:
- **Query Process Creation Logs:** Pull Sysmon Event ID 1 (`Process Creation`) or Windows Security Event ID 4688 for the exact timeframe (12:09:05 to 12:10:25) to identify what process spawned the Mimikatz execution.
- **Acquire Artifacts:** Retrieve `C:\Windows\System32\mimilsa.log` for static analysis.
- **Review Network Telemetry:** Check Sysmon Event ID 3 (`Network Connections`) to see if IEUser logged in remotely (RDP) and where the C2 communication is flowing.

### Security Hardening Recommendations:
- Enable Windows Defender Credential Guard to protect `lsass.exe` from memory reads.
- Implement ASR (Attack Surface Reduction) rules to block credential stealing from the Windows local security authority subsystem.

