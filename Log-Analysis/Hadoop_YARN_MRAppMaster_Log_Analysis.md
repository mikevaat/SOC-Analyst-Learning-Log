# Hadoop MRAppMaster Log — Forensic & SOC Analysis
- **Source dataset:** [Dataset](https://github.com/logpai/loghub)
- **Capture window:** 2015-10-18 18:01:47.978 → 18:10:55.202 (9 min 7 sec)

---

## Executive Summary (TL;DR)

This log file is a **single Hadoop MapReduce ApplicationMaster (AM) log**, not a network/web/auth log — there are no IPs of external origin, no HTTP traffic, and no login events to threat-hunt against in the way the request template anticipates. The job (`job_1445144423722_0020`) starts cleanly and assigns all 10 map containers within 15 seconds. About **3.5 minutes in, the AM's connection to the cluster's master node (`msra-sa-41`) begins degrading**, and by minute 4.5 it fails outright with `NoRouteToHostException` — a network-layer fault, not an application or credential failure. Two map attempts fail as a direct result; one task had already succeeded; seven remain `RUNNING` when the excerpt ends. From that point until the log cuts off, the AM is stuck in a continuous reconnect loop, unable to reach the ResourceManager or renew its HDFS lease — **147 "ERROR IN CONTACTING RM" and 326 lease-renewal failures**, roughly one per second, with no recovery visible in the provided data.

**No indicators of compromise were found.** Every IP is private/internal, there's no injection, brute-force, or recon signature, and the single keyword-sweep hit for "nmap" was verified to be a false positive (a coincidental substring inside Hadoop's own `DFSClient_NONMAPREDUCE_...` identifier, not a tool reference). This reads as an **internal network/infrastructure outage**, not a security incident — though the affected host's network health at 18:05–18:11 on 2015-10-18 is worth confirming.

---

## 1. Log Classification

| Attribute | Assessment |
|---|---|
| **Type** | Apache Hadoop MapReduce v2 **ApplicationMaster (MRAppMaster)** application log (Log4j pattern layout) |
| **Structure** | Semi-structured: `<timestamp,ms> <LEVEL> [<thread>] <fully.qualified.ClassName>: <free-text message>` |
| **Source(s)** | One process (the AM for `application_1445144423722_0020`), running on host `MININT-FNANLI5`. It *references* — but does not itself emit logs from — a ResourceManager/NameNode (`msra-sa-41`) and a NodeManager (`MSRA-SA-39`). Only the AM's own perspective is present; this is a **single log source**, not multiple sources requiring segmentation. |
| **Domain** | `fareast.corp.microsoft.com` — internal corporate research cluster naming (consistent with public LogHub-style Hadoop benchmark log samples), not a customer-facing or internet-facing system |

**Assumptions made (stated per directive):**
- `msrabi` is treated as a legitimate internal service/job-submission account based on context (staging paths, lease-renewer thread naming) — this was **not** independently verified against an identity system, since none is available here.
- The private IP ranges (`10.190.173.170`, `10.86.169.121`, `172.22.149.145`) are assumed to be legitimate internal cluster infrastructure based on hostname correlation (`msra-sa-41`, `MININT-FNANLI5`, `MSRA-SA-39`) — again inferential, not verified against a CMDB/asset inventory.
- This appears to be a **truncated excerpt** (1,999 lines is a round, benchmark-sample-style number) rather than a complete job lifecycle — confirmed by the fact that the job never reaches a terminal state (`SUCCEEDED`/`FAILED`/`KILLED`) anywhere in the file.

---

## 2. Normalized Entity Table

| Category | Value | Notes |
|---|---|---|
| Application ID | `application_1445144423722_0020` | |
| Job ID | `job_1445144423722_0020` | 10 map splits, 1 reducer, input size 1,256,521,728 bytes |
| Submitting user | `msrabi` | HDFS staging: `/tmp/hadoop-yarn/staging/msrabi/.staging/...` |
| AM host | `MININT-FNANLI5.fareast.corp.microsoft.com` | `10.86.169.121`, ports 62260 (client svc), 62267 (webapp), 62270 (task umbilical) |
| Cluster master host | `msra-sa-41` | `10.190.173.170` — serves as HDFS NameNode (`:9000`), YARN RM scheduler (`:8030`), **and** a DataNode (`:50010`) |
| NodeManager host | `MSRA-SA-39.fareast.corp.microsoft.com` | `172.22.149.145`, ports 28345 (container), 8042 (NM webapp) |
| Other addresses seen | `0.0.0.0` (bind-all, not a peer), `127.0.0.1` (see §6) | |
| DFS client ID | `DFSClient_NONMAPREDUCE_1537864556_1` | Job-history file writer |
| Containers allocated | `container_1445144423722_0020_01_000002` → `_000011` (10 total) | 1:1 mapped to map attempts, see §3 |
| Container `_000012` | Offered by RM, never used | Benign scheduler artifact — see §4 |
| Task attempts (map) | `attempt_..._m_000000_0` → `m_000009_0` | 10 total; 1 succeeded, 2 failed, 7 unresolved in-window |
| Reduce-side attempts | None assigned a container in this window | Reduce phase had not started |
| Log level counts | INFO 1,040 · WARN 808 · ERROR 150 · FATAL 2 | |
| HTTP entities (methods/status codes) | **None present** | Confirms this is not a web/access log |

---

## 3. Event Timeline

| Time (2015-10-18) | Event | Type |
|---|---|---|
| 18:01:47.978 | MRAppMaster starts for `application_1445144423722_0020` | Confirmed |
| 18:01:48–51 | Job token registered; uberization declined ("not enabled; too many maps; too much input"); job `NEW → INITED` | Confirmed |
| 18:01:51–56 | Job `INITED → SETUP → RUNNING` | Confirmed |
| 18:01:56–18:02:0x | All 10 map containers assigned (`_000002`…`_000011`) to attempts `m_000000`…`m_000009` | Confirmed |
| 18:04:10.002 | RM offers container `_000012`; AM logs it can't be used — no pending maps remain (benign) | Confirmed |
| 18:04:11.034 | ERROR: "Container complete event for unknown container id `_000012`" | Confirmed (linked to prior line — same surplus container) |
| **18:05:27.570** | **First anomaly**: "Address change detected" — resolution of `msra-sa-41` starts flapping between `msra-sa-41/10.190.173.170:9000` and bare `msra-sa-41:9000` | Confirmed — incident onset |
| 18:05:57.009–024 | HDFS `ResponseProcessor`/`DataStreamer` for the job-history block report a 65,020 ms slow read (threshold 30,000 ms) and "bad datanode `10.190.173.170:50010`" in the write pipeline → `DataStreamer Exception` | Confirmed |
| **18:06:26.029** | **FATAL**: attempt `m_000002_0` exits — `java.net.NoRouteToHostException` from `MININT-FNANLI5/127.0.0.1` to `msra-sa-41:9000` | Confirmed |
| 18:06:26.139 | Task cleanup fails for `m_000002_0`; job-history write for the failure event itself fails; `YarnUncaughtExceptionHandler` logs an uncaught exception on `eventHandlingThread`; attempt marked `FAILED`; retry `m_000002_1` queued | Confirmed |
| **18:06:28.217** | **FATAL**: attempt `m_000001_0` exits with the identical `NoRouteToHostException` | Confirmed |
| 18:06:28.248 | Task cleanup fails for `m_000001_0`; marked `FAILED`; retry `m_000001_1` queued | Confirmed |
| 18:06:26 → 18:10:55 (end of file) | Sustained outage loop: `RMCommunicator Allocator` logs **"ERROR IN CONTACTING RM"** 147×; `LeaseRenewer` logs **"Failed to renew lease"** 326× (counter climbs 30s → 356s) and **"Address change detected"** 476× total — cadence ≈ 1/second throughout | Confirmed |
| 18:10:55.202 (last line) | Log excerpt ends **mid-outage** — no recovery, no job termination, no AM restart visible | Confirmed |

**Cause → effect chain (as evidenced):** hostname-resolution flapping (18:05:27) → slow/bad datanode on the same host in the HDFS write path (18:05:57) → full route loss to that host (18:06:26–28) → the two in-flight map attempts talking to that host over the umbilical/HDFS path fail → cleanup and history-logging themselves fail (because they also need the now-unreachable host) → AM enters a steady reconnect loop for the remainder of the capture.

---

## 4. Threat & Anomaly Analysis

| Finding | Confidence | Evidence |
|---|---|---|
| No external/attacker-origin IPs present | **High** | All addresses are RFC 1918 private ranges (`10.190.173.170`, `10.86.169.121`, `172.22.149.145`) plus loopback/bind-all; no public IPs anywhere in the file |
| No authentication, injection, or web-attack indicators | **High** | Full keyword sweep for SQLi/XSS/traversal/brute-force/credential terms, plus a check for any HTTP method/status code, returned **zero genuine hits** — this log contains no HTTP layer at all |
| "nmap" keyword hit is a false positive | **High** | Verified by isolated testing: it matches only inside the literal Hadoop identifier `DFSClient_**NONMAP**REDUCE_1537864556_1` (Hadoop's label for a non-MapReduce HDFS client), not an actual tool reference. Flagging this explicitly rather than silently dropping it, per the "no assumed malicious intent without evidence" rule — and equally, not silently dropping the initial hit without investigating it. |
| No lateral movement / privilege escalation signatures | **High** | Single user (`msrabi`) throughout; no account switching, no new principals, no ACL/permission-denied events |
| Sole confirmed anomaly: AM ↔ cluster-master network reachability failure | **High** (that it occurred) / **Low** (root trigger) | See timeline; `NoRouteToHostException` is a kernel/OS-level routing failure — it fires when there's no route to the destination at all, which is categorically different from an auth or application error |
| Repeated hostname/IP flapping for `msra-sa-41` | **Medium** | 476 "Address change detected" events losing the cached `10.190.173.170` and falling back to bare hostname — consistent with a DNS cache expiry + failed re-resolution, or the remote process restarting on a re-resolved address; **cannot be disambiguated from this log alone** |

**No malicious intent is assumed.** The evidence pattern (internal-only IPs, one host losing routability while a co-located DataNode simultaneously reports slow/bad I/O, zero auth or injection signal) points to an infrastructure fault, not an intrusion.

---

## 5. Operational & Performance Analysis

- **Latency:** One explicit slow-I/O event — HDFS ack read took 65,020 ms against a 30,000 ms threshold, immediately preceding the outage (18:05:57).
- **Errors:** 150 ERROR-level entries, **98% (147/150) are a single repeating message** ("ERROR IN CONTACTING RM") — this is one incident hammering the log, not 150 distinct problems.
- **Service impact:** 2 of 10 map tasks (20%) confirmed `FAILED`; 1 of 10 confirmed `SUCCEEDED`; 7 of 10 left in `RUNNING` with no terminal state recorded in this excerpt. Reduce phase had not begun.
- **Compounding failure:** when the two map attempts failed, the AM's attempt to durably log that failure to job history *also* failed ("Error writing History Event") — because that write itself depends on the now-unreachable host. This is a real operational risk worth noting: history/audit records for this incident may be incomplete on disk, not just in this log excerpt.
- **Resource exhaustion:** none observed — no OOM, no disk-full, no container-memory-exceeded messages.
- **Retry behavior:** the AM's `RMCommunicator Allocator` keeps retrying per a configured policy (`RetryUpToMaximumCountWithFixedSleep`, maxRetries=10, sleepTime=1000ms) but each cycle logs "Already tried 0 time(s)" — meaning it's continuously re-entering the retry loop from scratch rather than escalating or giving up. It never crashes or exits in this window; it just spins.

---

## 6. Root Cause Analysis

**Confirmed facts:**
- The AM lost IP-level reachability to `msra-sa-41` (both port 9000/NameNode and port 8030/RM-scheduler) starting ~18:05:27, hardening into an explicit `NoRouteToHostException` by 18:06:26, persisting unresolved through the end of the capture (18:10:55) — **at least 5 min 28 sec of confirmed impact**.
- The same host (`msra-sa-41`) was simultaneously acting as a DataNode reporting slow/bad I/O on that same connection path, just before the hard failure.
- The job never reaches a terminal state in this file — **the ultimate outcome (recovery, AM restart, or job failure) is not contained in this data.**

**Inferred hypotheses (Medium–High confidence):** This is a genuine network-layer fault (routing, firewall/security-group, interface, or DNS) on the path to `msra-sa-41` — not a credential, authentication, or application-logic problem, and not indicative of an active attacker given the total absence of any auth/injection/recon signal among the entities involved.

**Inferred, lower confidence — specific trigger (cannot be confirmed from this data alone):**
- `msra-sa-41` itself going down or its NameNode/RM daemons restarting (would explain both the address-flapping and the eventual hard route failure)
- A network/switch/firewall/VLAN change affecting the path to that host
- A DNS/DHCP change altering `msra-sa-41`'s resolved address (directly consistent with the repeated "Address change detected" pattern)
- **One specific detail worth flagging for the investigating engineer:** the `NoRouteToHostException` messages report the source as `MININT-FNANLI5/127.0.0.1` (loopback), while the AM's own service was earlier bound to its real routable address (`10.86.169.121`) at startup. This could simply be how the JVM formats the local endpoint in that exception, or it could indicate the AM host's own hostname resolves to loopback locally (a known Hadoop `/etc/hosts` misconfiguration pattern) — **worth checking `hostname -i` and `/etc/hosts` on `MININT-FNANLI5`** as a cheap way to rule this in or out.

**Data gaps — what's needed to complete this picture:**
- `msra-sa-41`'s own NameNode/ResourceManager/syslog logs for 18:05–18:11 on 2015-10-18
- Network/firewall/switch change logs and DNS/DHCP logs for the same window
- The remainder of this AM's log past line 1,999, to see whether/when it recovered or was ultimately killed
- Confirmation of `msrabi`'s account status (out of scope for this file, but standard IR hygiene)

---

## 7. Recommendations

**Immediate:**
- Check `msra-sa-41` host/process health (NameNode, ResourceManager daemons, NIC/interface state) specifically for the 18:05–18:11 window on 2015-10-18.
- Pull the RM UI / full job history for `application_1445144423722_0020` to determine the actual final outcome — this log alone does not show it.

**Investigation:**
- Correlate with `msra-sa-41`'s own logs, switch/firewall change logs, and DNS/DHCP logs for the same timestamps.
- Check `/etc/hosts` and `hostname -i` on `MININT-FNANLI5` to rule in/out the loopback-resolution detail above.
- Retrieve the full (untruncated) log to see the eventual resolution.

**Hardening:**
- Consider HDFS NameNode HA if not already in place — this single host is a single point of failure for both HDFS and (co-located) YARN RM traffic.
- Review AM/RM retry and connect-timeout tuning (`yarn.resourcemanager.connect.max-wait.ms` and related) so a prolonged RM outage surfaces as a clear alert/fail-fast rather than a silent multi-minute retry loop.

**Monitoring:**
- Alert on sustained "ERROR IN CONTACTING RM" or repeated `LeaseRenewer` failures beyond a short threshold (e.g., 30 seconds) rather than discovering this only via post-hoc log review.
- Treat `NoRouteToHostException` as a distinct network-health signal in dashboards, separate from application-level task failures.

---

### Note on scope
Several categories in the original request template (brute force/credential stuffing, SQLi/XSS/LFI, unusual user agents, geo/IP mismatch) do not apply to this file — it contains no authentication events and no HTTP layer at all. Rather than force those sections to contain speculative content, they're reflected above as **confirmed absent**, consistent with the instruction not to invent findings where none exist.
