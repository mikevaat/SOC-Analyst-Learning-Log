# Windows EVTX Forensic Analysis: PowerShell-Based Process Injection & Local Privilege Escalation

- **Author:** CypherX
- **Category:** Windows Security / DFIR / SOC Analysis
- **Source:** EVTX Attack Samples Repository
- **Host Analyzed:** MSEDGEWIN10
- **Log Sources:** Sysmon Operational & Microsoft-Windows-SmbClient/Connectivity
- **MITRE ATT&CK Mapping:** T1055 — Process Injection
- **Severity:** Critical
- **Analysis Type:** Endpoint Detection & Incident Investigation  

---

## Executive Summary

The analyzed Windows Event Log data reveals a highly suspicious sequence of endpoint activities consistent with a probable **Local Privilege Escalation (LPE)** or **Process Injection** attack.

A `powershell.exe` process was observed accessing the critical Windows authentication process `winlogon.exe`, followed milliseconds later by the creation of a `cmd.exe` process running under the highly privileged `NT AUTHORITY\SYSTEM` account.

Additional telemetry revealed extensive SMB communication involving a VirtualBox shared folder interface (`VBOXSVR`), suggesting a possible staging or execution path within the virtualized environment.

The evidence indicates that further investigation into the origin, parent process, and script content behind the PowerShell execution is required.

---

# 1. Pre-Analysis Phase

### Log Classification & Structure
- **Log Type(s):** Windows Event Log (`.evtx`) raw binary extract. The file header indicators (`ElfFile`, `ElfChnk`) confirm this format.
- **Source System(s):** A Windows 10 host named `MSEDGEWIN10`.
- **Log Providers:**
  - `Microsoft-Windows-Sysmon/Operational` (System Monitor)
  - `Microsoft-Windows-SmbClient/Connectivity` (SMB Client)
- **Structure:** Unstructured binary extraction containing semi-structured XML schema fragments.

# 2. Normalized Data Table:
| Timestamp (UTC) | Source / Process | Target / Destination | User | Action / Event | Extracted Artifacts |
|------------------|-------------------|----------------------|-------|----------------|---------------------|
| 2020-07-26 22:13:19.375 | powershell.exe | 127.0.0.1:microsoft-ds | MSEDGEWIN10\IEUser | Network Connection (TCP) | Protocol: tcp, Dest: microsoft-ds (Port 445) |
| 2020-07-26 22:13:19.375 | System | 127.0.0.1:microsoft-ds | NT AUTHORITY\SYSTEM | Network Connection (TCP) | Protocol: tcp, Dest: microsoft-ds (Port 445) |
| 2020-07-26 22:26:14.517 | powershell.exe | winlogon.exe | Unknown Process Access / API Call | CallTrace: ntdll.dll, KERNELBASE.dll |
| 2020-07-26 22:26:14.521 | winlogon.exe (inferred parent) | cmd.exe | NT AUTHORITY\SYSTEM | Process Creation | SHA256: `3656F37A...`
| Various / Un-timestamped SMBClient VBOXSVR | Unknown SMB Connectivity Interface: \Device\NetBT_Tcpip_{...} |

# 3. Event Timeline

This chronological reconstruction highlights the cause-and-effect relationship mapped from the logs:

- **2020-07-26 22:13:19.375** - *Localhost Network Activity:* A local standard user account (`MSEDGEWIN10\IEUser`) executes `powershell.exe`, which initiates a TCP connection to `127.0.0.1` over the `microsoft-ds` service (SMB, port 445). Simultaneously, the System process does the same.
- **Continuous SMB Polling:** Multiple un-timestamped `Microsoft-Windows-SMBClient` logs indicate heavy interaction with `VBOXSVR`, which is a VirtualBox Shared Folder service.
- **2020-07-26 22:26:14.517** - *Critical Process Access:* Thirteen minutes later, `powershell.exe` accesses `winlogon.exe`. The CallTrace involves memory management/execution APIs from `ntdll.dll` and `KERNELBASE.dll`.
- **2020-07-26 22:26:14.521** - *Escalation Effect:* Just 4 milliseconds after the process access event, `cmd.exe` is spawned running as `NT AUTHORITY\SYSTEM`.

# 4. Threat & Anomaly Analysis

### Process Injection / Privilege Escalation (Confidence: Critical)
The transition from a `powershell.exe` process manipulating `winlogon.exe` (a protected SYSTEM process responsible for Windows logon) directly into a `cmd.exe` shell running as SYSTEM is a textbook Indicator of Compromise (IoC) for Process Injection or Token Impersonation.

### Suspicious Localhost SMB (Confidence: Medium)
Running under a standard user, initiating local SMB connections (`127.0.0.1` on `microsoft-ds`) is anomalous. While not inherently malicious, combined with the presence of `VBOXSVR` (VirtualBox), it suggests potential staging of payloads or execution of tools mounted via shared drives.

# 5. Operational & Performance Analysis

### SMB Protocol Overhead
The volume of `Microsoft-Windows-SmbClient/Connectivity` entries pointing to \Device\NetBT_Tcpip... and Ethernet indicates heavy, persistent polling or data transfer over SMB within a Virtual Machine environment.

### Resource Constraints
No explicit 4xx/5xx HTTP codes, database timeouts, or resource exhaustion signals are present in this localized endpoint data extract.

# 6. Root Cause Hypothesis

### Confirmed Facts:
- Powershell.exe accessed the winlogon.exe process memory space utilizing low-level DLLs (`ntdll.dll`, `KERNELBASE.dll`).
- A command prompt (`cmd.exe`) was spawned with SYSTEM privileges milliseconds later.
- The host is a Virtual Machine (evident by VBOXSVR).

### Inferred Hypothesis (High Probability):
An attacker or automated exploit script executed a Local Privilege Escalation (LPE) technique. The initial access or payload delivery likely originated from a script hosted on a VirtualBox shared folder (`VBOXSVR`), which was executed via PowerShell. The script utilized API calls to inject code into `winlogon.exe`, effectively hijacking its SYSTEM token to spawn a root-level command prompt.

# 7. Actionable Intelligence & Remediation

### Immediate Containment Steps:
- Isolate the host (`MSEDGEWIN10`) from the broader network immediately to prevent potential lateral movement.
- Suspend the Virtual Machine state to preserve volatile memory (RAM) for deeper forensic analysis, particularly to dump the memory of `powershell.exe` and `winlogon.exe`.

### Investigation Steps:
- **Log Retrieval:** Pull the complete, uncorrupted `.evtx` files for Microsoft-Windows-Sysmon/Operational and Security.
- **Query the PowerShell Logs:** Review Microsoft-Windows-PowerShell/Operational (Event ID 4104 - Script Block Logging) to see the exact script executed by IEUser at 22:13:19 and 22:26:14.
- **Identify the Parent Process:** Determine what launched the initial powershell.exe process for MSEDGEWIN10\IEUser.

### Security Hardening Recommendations:
- Implement application control (e.g., AppLocker or Windows Defender Application Control) to restrict powershell.exe execution for standard users like IEUser.
- Ensure Sysmon is configured to monitor and block anomalous Process Access (Event ID 10) targeting LSASS, Winlogon, and SVCHOST.

---

# Dataset Source

[LogHub Apache Log Dataset](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES?)



