# Windows Scheduled Task Privilege Escalation & Lateral Movement Analysis

- **Author:** CypherX
- **Category:** Windows Security / DFIR / SOC Analysis
- **Source:** Windows EVTX Security Log Dataset
- **Host Analyzed:** 01566s-win16-ir.threebeesco.com
- **Operating System:** Windows Server
- **Log Source:** [Dataset](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES?)
- **Log Format:** Windows Event Log (.evtx) Raw Binary Extraction
- **MITRE ATT&CK Mapping:** 
  - T1053.005 — Scheduled Task/Job: Scheduled Task
  - T1021 — Remote Services
  - T1078 — Valid Accounts
  - T1548 — Abuse Elevation Control Mechanism
- **Severity:** Critical
- **Analysis Type:** Privilege Escalation, Lateral Movement & Post-Exploitation Investigation

---

## Executive Summary

Forensic analysis of the provided Windows Event Log (.evtx) fragments reveals a high-confidence privilege escalation and lateral movement event involving the creation and execution of a malicious or unauthorized Scheduled Task. The activity originated from the account **a-jbrown**, which authenticated remotely to the target host **01566s-win16-ir.threebeesco.com** from the source address **172.16.66.142** using Windows authentication protocols including **NTLMv2** and **Kerberos**.

Following successful authentication, the account created a scheduled task named **\LMST** configured to execute with **SYSTEM-level privileges** using the highest available execution context. The task launched **cmd.exe** and executed the command:

```cmd
/c echo testing > c:\users\public\out.txt

```


---


# 1. Pre-Analysis Phase: Log Classification
- **Log Type(s):** Windows Event Log (.evtx) file extraction. Evidenced by the ElfFile and ElfChnk magic headers and Microsoft XML schemas.
- **Source(s):** Microsoft-Windows-Security-Auditing (Channel: Security) from the host `01566s-win16-ir.threebeesco.com`.
- **Structure:** Unstructured/Semi-structured hex/string dump containing embedded, structured Windows XML event payloads.

# 2. Normalized Data Table:
| Timestamp | Source IP / Host | Dest IP / Host | Username | Domain | Target Object / Endpoint | Context / Details |
| --- | --- | --- | --- | --- | --- | --- |
| Fragmented | 172.16.66.142 : 60726 | NTLM04246W-WIN10 | a-jbrown | 3B | N/A | Authentication: NTLM V2 |
| Fragmented | 172.16.66.142 : 60728, 60726 | 01566s-win16-ir.threebeesco.com | a-jbrown | THREEBEESCO.COM | N/A | Authentication: Kerberos |
| 2020-09-02T04:47:49.74-07:00 Local | 01566s-win16-ir.threebeesco.com | N/A | a-jbrown | THREEBEESCO.COM | Task: \LMST Task Authored. RunLevel: HighestAvailable |
| Fragmented Local | 01566s-win16-ir.threebeesco.com | SYSTEM Local cmd.exe Payload: `/c echo testing > c:\users\public\out.txt` |
| Fragmented Local | 01566s-win16-ir.threebeesco.com N/A N/A C:\Windows\debug Repeated directory access |
| Fragmented Local | 01566s-win16-ir.threebeesco.com N/A N/A C:\Windows\SYSVOL\domain Access to Group Policy Object: `9792B5A7-A20C-4DE0-A659-C46DFD657291` |

> [!NOTE]
> The timeline was reconstructed due to file fragmentation.


# 3. Chronological Reconstruction

- **Network Authentication:** The user account `a-jbrown` initiates network authentication to the target system from the source IP `172.16.66.142`. The connection utilizes both NTLMv2 and Kerberos authentication protocols across ephemeral ports `60726` and `60728`.

- **Task Registration:** At exactly `2020-09-02T04:47:49.74-07:00`, the account `a-jbrown` authors and registers a Scheduled Task named `\LMST`.

- **Privilege Escalation Definition:** The task is configured to execute as the SYSTEM user with HighestAvailable privileges. The task is set with a Time Trigger bounded between `2020-02-09T04:47:48` and `2020-02-09T04:47:58`. *(Note:* The start/end boundaries are significantly earlier than the registration date, indicating either a timestamp anomaly, timezone mismatch, or a misconfigured payload).

- **Payload Execution:** The task executes `cmd.exe` with the arguments `/c echo testing > c:\users\public\out.txt`.

- **Post-Exploitation / Enumeration:** Subsequent to the core events, the raw data shows repeated localized access to `C:\Windows\debug` and Active Directory Group Policy configurations within `C:\Windows\SYSVOL\domain`."} }

# 4. Threat & Anomaly Detection

**[Critical] Privilege Escalation via Scheduled Task:** The creation of a scheduled task (`\LMST`) running as SYSTEM by a standard user account (`a-jbrown`) is a definitive indicator of compromise (IoC) related to lateral movement and privilege escalation.

**[High] Proof of Concept Payload Execution:** The argument `/c echo testing > c:\users\public\out.txt` is not a standard administrative command. Dropping output files into `C:\users\public` (a universally writable directory) is a highly common technique used by threat actors and penetration testers to silently verify remote code execution (RCE) success before deploying primary malware or C2 beacons.

**[Medium] System/Domain Enumeration:** The repeated access to `C:\Windows\SYSVOL\domain` and specific GPO GUIDs (e.g., `47CDF2D9-D94D-4D89-9AAD-AC10CDB72779`) suggests the actor may have been parsing Group Policy Objects for plaintext credentials (`cPasswords`), startup scripts, or network mapping.

**[Low] Mixed Authentication Protocols:** The use of both NTLM V2 and Kerberos from the same source IP (`172.16.66.142`) may indicate the use of automated attack frameworks (like Impacket) which often fallback across protocols.

# 5. Operational Analysis

**Performance/System Issues:** Insufficient Data. The provided log excerpt strictly contains Security auditing events. There are no HTTP server logs, backend connection failure codes, or application crash dumps present in this file segment to evaluate performance bottlenecks or latency.

# 6. Root Cause Analysis

## Confirmed Facts:
- A user named `a-jbrown` authenticated to `01566s-win16-ir.threebeesco.com` from IP address `172.16.66.142`.
- A scheduled task named `\LMST` was authored by `a-jbrown` and programmed to run under the SYSTEM context.
- The system executed a command prompt designed to write a text file to a public directory.

## Inferred Hypotheses:
- **[Critical Confidence]** The endpoint `172.16.66.142` is either compromised or under the control of an adversary. The `a-jbrown` account's credentials have been compromised.
- **[High Confidence]** The adversary used the compromised credentials to move laterally to `01566s-win16-ir` and attempted to execute commands with elevated privileges (`SYSTEM`) to bypass local access controls.
- **[Medium Confidence]** The payload was a preliminary test. If the actor confirmed the text file was successfully created in the public directory, they likely followed up with a secondary payload (e.g., a reverse shell) shortly after.

# 7. Recommendations

## Immediate Containment:
- **Account Suspension:** Immediately disable the `a-jbrown` account in Active Directory to sever the actor's current authentication vector.
- **Host Isolation:** Quarantine `01566s-win16-ir.threebeesco.com` and `172.16.66.142` (if it is an internal asset) from the network to prevent further lateral movement.
- **Task Neutralization:** Terminate and delete the `\LMST` scheduled task on the affected server.

## Investigation Steps (Pivots):
- **File System Review:** Inspect `C:\users\public\` on `01566s-win16-ir` for the presence of `out.txt`. Look for subsequent anomalous files (`*.ps1`, `.exe`, `.dll`) created around `2020-09-02.`
- **Source IP Tracing:** Identify the asset assigned to `172.16.66.142`. If this is a VPN IP, review VPN authentication logs to find the true external IP address of the attacker.
- **Log Parsing:** Extract the complete `.evtx` file and parse it properly using tools like Event Log Explorer or an SIEM to restore exact millisecond timestamps and reveal Event IDs (e.g., 4624, 4698, 4688) surrounding the event window.

## Security Hardening:
- Implement Group Policy settings to strictly limit which accounts possess the "Log on as a batch job" right, preventing standard users from creating local scheduled tasks.
- Monitor and alert on any scheduled task creation where the execution principal is SYSTEM.


