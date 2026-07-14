# OpenStack Nova Log — Forensic & Operational Analysis

**Source file:** `OpenStack_2k_log.txt` | **Analyst:** Claude (SOC/Forensics mode) | **Analysis date:** 2026-07-06

---

## Executive Summary (TL;DR)

This file contains **2,000 OpenStack Nova log entries** spanning **14 minutes 47.68 seconds** (2017‑05‑16 00:00:00.008 → 00:14:47.687), covering three Nova services (`nova-api`, `nova-compute`, `nova-scheduler`) on a **single compute node** (`cp-1.slowvm1.tcloud-pg0.utah.cloudlab.us`).

- **What happened:** A homogeneous, automated instance-churn workload — **22 virtual machines** created, spawned, and destroyed one after another at a near-perfectly regular **~41.4-second cadence**, using one image and one flavor. This is characteristic of a benchmark/load-test harness, not organic user activity.
- **Security verdict: No evidence of compromise.** Zero ERROR/CRITICAL entries, zero authentication failures, zero injection/reconnaissance signatures, zero lateral-movement indicators. All client IPs are private (RFC1918) address space.
- **31 WARNING entries** were found and fully explained by evidence in the log: 30 are a cosmetic, recurring image-cache message tied to a single base file, and 1 is a transient, self-resolving DB/hypervisor sync race during a VM spawn.
- **One operational pattern worth monitoring (not an incident):** the scheduler's periodic host sync mismatched 5 of 7 times — most plausibly because the high instance churn rate outpaces its ~2-minute sync interval.
- **Bottom line:** Healthy, expected behavior for a test/benchmark environment. No containment action required. See §7 for monitoring hygiene suggestions and the data still needed for a fully complete picture.

---

## 1. Log Classification

| Attribute | Finding |
|---|---|
| **Log type** | OpenStack **Nova** (compute service) logs only — no Keystone, Neutron, Glance, or Cinder native log entries present (Nova's own log lines *reference* interactions with those services, e.g. image lookups, network events) |
| **Source components** | `nova-api.log` (1,060 lines), `nova-compute.log` (933 lines), `nova-scheduler.log` (7 lines) — identified from the first whitespace-delimited token on each line |
| **Compute host** | Exactly one: `cp-1.slowvm1.tcloud-pg0.utah.cloudlab.us` |
| **Structure** | **Semi-structured**: fixed positional preamble (`source-file token · timestamp · PID · level · logger`) followed by a free-text message body whose sub-format varies by logger (HTTP-access-log style for `*.wsgi.server`; `[instance: <uuid>]`-tagged for compute/libvirt; `key: value` for resource/claims accounting) |
| **Record count nuance** | `wc -l` reports 1,999 lines; level-count cross-validation (1,969 INFO + 31 WARNING = **2,000**) confirms the true entry count — the final line simply lacks a trailing newline |
| **Line endings** | CRLF throughout |

**Assumptions stated (per directive):**
- The **first token** on each line (e.g. `nova-api.log.1.2017-05-16_13:53:08`) is a **log-rotation filename artifact** (rotation/creation time of that file), *not* the event time. The **second field** is the actual per-event timestamp and is what all chronological work in this report uses.
- No timezone marker is present; timestamps are treated as recorded, with no UTC/local conversion applied.
- The file appears to be a **pre-merged, chronologically-sorted interleaving** of three separate service logs (verified: a strict timestamp sort of the file produces no reordering).
- The `_2k` filename suffix, the CloudLab-style hostname, and the templated dummy UUIDs are consistent with the well-known public **LogHub-style OpenStack benchmark log sample** used in log-parsing/anomaly-detection research — noted as background context from the naming convention, not asserted as verified provenance.

---

## 2. Normalized Data Table

*(Given 2,000 raw entries, results are grouped into scannable categorical tables rather than a row-per-line dump. Any specific slice can be pulled on request.)*

**A — Volume & Levels**

| Field | Value |
|---|---|
| Time span | 2017‑05‑16 00:00:00.008 – 00:14:47.687 |
| Log levels | INFO 1,969 · WARNING 31 · ERROR 0 · CRITICAL 0 |
| Unique request IDs (`req-*`) | 938 |
| Unique instance UUIDs | 22 |

**B — Identity Entities** (user_id / project_id pairs found in request context brackets)

| User ID | Project ID | Lines | Apparent role |
|---|---|---|---|
| `113d3a99c3da401fbd62cc2caa5b96d2` | `54fadb412c4e40cdbaed9335e4c35a9e` | 1,101 | Primary automation account — all create/delete/poll traffic |
| `f7b8d1f1d4d44643b07fa10ca7d021fb` | `e9746973ac574c6b8a9e8857f56a7608` | 86 | Service account — `os-server-external-events` (network-vif callbacks) |
| `d16a600c5e2a47fe98aee00ee4cb9743` | `e9746973ac574c6b8a9e8857f56a7608` | 4 | Admin/audit account — one-off `all_tenants=True` sync query |

Remaining lines are system/periodic-task entries that carry placeholder `-` fields instead of a user/project pair (expected for background tasks with no human/API caller).

**C — Network Entities** (all RFC1918 private space — no public IPs observed)

| IP / range | Occurrences | Role |
|---|---|---|
| `10.11.10.1` | 806 | Primary API client — the automation/benchmark driver |
| `10.11.10.2` | 3 | Secondary admin/monitoring client |
| `10.11.21.122` – `10.11.21.143` (22 contiguous addresses) | 1 per instance | Per-VM source IP for its own cloud-init metadata-service self-queries — **exactly 1:1 with the 22 unique instance UUIDs** |

**D — HTTP Entities**

| Method | Count | | Status | Count | Meaning |
|---|---|---|---|---|---|
| GET | 931 | | 200 OK | 933 | Normal success |
| POST | 64 | | 404 Not Found | 41 | Both causes benign — see §4 |
| DELETE | 22 | | 204 No Content | 22 | Successful instance delete |
| | | | 202 Accepted | 21 | Async instance-create accepted |

No 4xx codes other than 404; **zero 401/403/5xx codes anywhere in the file.**

Top endpoints (project/instance IDs masked for readability):
- `GET /v2/{project}/servers/detail` — 698 (polling)
- `GET /openstack/*/meta_data.json`, `/latest/meta-data/*` — ~208 (cloud-init)
- `POST /v2/{project}/os-server-external-events` — 43
- `POST /v2/{project}/servers` — 21 (create)
- `DELETE /v2/{project}/servers/{id}` — 22
- `GET /v2/{project}/servers/{id}` — 21
- One-off admin calls: `servers/detail?all_tenants=True&changes-since=...`, `images/{id}`, `flavors/2`

**E — Compute/Resource Entities**

| Entity | Value |
|---|---|
| Image ID (100% of instances) | `0673dd71-34c5-4fbb-86c4-40623fbe45b4` |
| Flavor (21 of 22 instances' claims captured) | 2,048 MB RAM / 1 vCPU / 20 GB disk (matches `flavors/2`) |
| Node capacity | 64,172 MB RAM · 16 vCPUs · 15 GB disk pool |
| Peak observed utilization | ~2,560 MB RAM (4%) · 1 vCPU (6%) |
| Avg spawn time | 19.72 s (range 18.98–20.47 s, n=22) |
| Avg build time | 20.52 s (range 19.79–21.25 s, n=22) |
| Instance-create cadence | every 41.40 s avg (range 40.16–42.03 s, n=20 intervals) |

**Ports/Protocol:** Only `HTTP/1.1` appears in the text; no port numbers are present in the log lines themselves. (Nova's default API/metadata ports 8774/8775 are standard OpenStack convention, *not* something extracted from this file — flagged per guardrails rather than invented as observed data.)

---

## 3. Event Timeline — Chronological Reconstruction

**Pre-existing state at window start:** instance `b9000564-fe1a-409b-b8cc-1e88b294cd1d` is already mid-spawn at 00:00:04.500 with no preceding `POST /servers` in this file — its creation call occurred **before** the capture window began. This explains why 22 instances show a full lifecycle but only 21 `POST /servers` calls appear (fact, cross-validated).

**Canonical per-instance lifecycle** (worked example: `b9000564...`, line refs approximate):
1. `00:00:04.500` — `VM Started (Lifecycle Event)`
2. `00:00:04.562` — `VM Paused (Lifecycle Event)`
3. `00:00:04.693` — sync_power_state finds a pending spawning task → skips
4. `00:00:10.296` — `VM Resumed (Lifecycle Event)`
5. `00:00:10.302` — `nova.virt.libvirt.driver`: **Instance spawned successfully**
6. `00:00:10.303` — `Took 19.05 seconds to spawn the instance on the hypervisor`
7. `00:00:10.470` — `Took 19.84 seconds to build instance` (build complete)
8. *(instance runs; interleaved with background periodic-task noise — see below)*
9. `POST /servers` → `202` starts the *next* instance while cleanup of the current one proceeds
10. `DELETE /v2/{project}/servers/{id}` → `204`, then `Terminating instance` → `Instance destroyed successfully`

This exact 10-step pattern repeats **22 times** end-to-end with no deviation.

**Background periodic tasks** running independently of any single instance:
- `nova.virt.libvirt.imagecache` — base-file check cycle, roughly every 35–90 s
- `nova.compute.resource_tracker` — "Auditing locally available compute resources," roughly every 60 s
- `nova.scheduler.host_manager` — host sync, roughly every 2 minutes (7 total)

**Cross-service correlation:** the shared `req-*` ID propagates across services — e.g. `req-8e64797b-fb99-4c8a-87e5-9a8de673412f` appears in both the `nova-compute.log` spawn-completion lines, confirming Nova's request-ID propagation is intact and letting a single logical operation be traced across process/service boundaries.

**Automation signature (high confidence):** successive `POST /servers` timestamps are spaced **40.16–42.03 s apart (avg 41.40 s, n=20 measured intervals)** — a level of regularity that does not occur in organic human usage and is the signature of a scripted benchmark/test loop (create → wait ~40 s for build → delete → repeat).

**Closing state:** the log ends cleanly — the 22nd instance (`faf974ea-cba5-4e1b-93f4-3a3bc606006f`) is deleted (`204`) at `00:14:47.410`, `Terminating instance` at `00:14:47.447`, `Instance destroyed successfully` at `00:14:47.663`, followed by one final polling `GET` at `00:14:47.687`. No orphaned or leaked instances at end of capture.

---

## 4. Threat & Anomaly Analysis

| Category | Finding | Confidence |
|---|---|---|
| Indicators of Compromise (IoCs) | None found | — |
| Reconnaissance (Nmap/Dirb/fuzzing) | None — no sequential path-guessing or fuzzing patterns | High (absence) |
| Injection (SQLi/XSS/LFI/traversal) | 0 matches across a signature sweep (`../`, `<script`, `union select`, `/etc/passwd`, etc.) | High (absence) |
| Brute force / credential stuffing | Not applicable — Keystone auth is not in this log; 0 occurrences of `401`/`403` | High (absence, within scope) |
| Lateral movement | None — single compute host, workload confined to one primary tenant | High (absence) |
| Unusual user agents | **Not evaluable** — this Nova WSGI access-log format has no `User-Agent` field (unlike Apache combined format). Flagged as a data-completeness gap, not a finding. | N/A |
| Geo/IP anomalies | None — every client IP is RFC1918 private space; no public/external addresses at all | High |
| Baseline deviations | Two 404 clusters below, fully explained by evidence in the file | — |

**Explained anomaly #1 — 21× `404` on `POST .../os-server-external-events`:** each is immediately preceded by `nova.api.openstack.wsgi`: *"HTTP exception thrown: No instances found for any event."* This is the documented, benign OpenStack race where a `network-vif-plugged` notification (from the networking side) references an instance UUID Nova cannot yet — or no longer — correlate at that exact instant. Originates entirely from an internal service account; no external actor involved. **Confidence: High that this is benign.**

**Explained anomaly #2 — 20× `404` on `GET /openstack/2013-10-17/user_data`:** standard cloud-init behavior — instances probing for optional user-data that was never supplied. Universally benign and expected.

**Explained anomaly #3 — the single WARNING** *"While synchronizing instance power states, found 1 instances in the database and 0 instances on the hypervisor"* (`00:09:41.850`, source line ~1297): occurs 1.5 seconds before a **new** instance (`bf8c824d-f099-4433-a41e-e3da7578262e`) begins its `VM Started` sequence at `00:09:43.328`, and the very next sync_power_state line explicitly logs *"the instance has a pending task (spawning). Skip"* for that same instance. This is a transient timing artifact of the periodic sync task overlapping an in-flight spawn — **not** evidence of a lost or crashed VM. **Confidence: High (directly evidenced by adjacent log lines, not inferred from absence).**

---

## 5. Operational & Performance Analysis

- **Recurring cosmetic warning (30 occurrences):** `nova.virt.libvirt.imagecache` logs *"Unknown base file: .../a489c868f0c37da93b76227c91bb03908ac0e742"* for the same single base image at irregular ~35–90 s intervals across the entire window. No downstream failure ever correlates with it across all 22 successful spawns. **Confidence: Medium-High that this is purely cosmetic** (a known characteristic of Nova's image-cache periodic scan racing its own "in use" correlation pass).
- **Scheduler host-sync drift (fact):** of 7 periodic `nova.scheduler.host_manager` sync attempts, **2 succeeded cleanly** (`00:00:57`, `00:02:58`) and **5 required rebuilding the InstanceList** due to a mismatch (`00:04:59`, `00:07:00`, `00:09:04`, `00:11:05`, `00:13:09` — a consistent ~2-minute cadence). Every rebuild succeeded; no scheduler errors or crashes occurred. **Inferred hypothesis (Medium confidence):** the sustained ~41 s instance-churn rate most plausibly outpaces what a ~2-minute sync window can track without drift — this reads as workload-induced, self-healing behavior rather than a scheduler defect, but it is a real, repeatable pattern worth a monitoring metric (see §7).
- **Latency:** API response times range 0.0005–0.7117 s (avg 0.234 s); spawn times 18.98–20.47 s (avg 19.72 s); build times 19.79–21.25 s (avg 20.52 s). All tightly clustered around their respective means — **no latency spikes or outliers**, and **zero** database-timeout or backend-connection-failure messages anywhere in the file.
- **Resource exhaustion:** none. Peak utilization on the single compute node was ~4% RAM and ~6% vCPU (one instance's worth of claim at a time). The single `nova-compute` process (PID 2931) ran continuously for the full window with no restarts.
- **Minor watch item (Low-Medium confidence, insufficient data to confirm):** one `resource_tracker` snapshot (`00:00:14.266`) shows `phys_disk=15GB` against `used_disk=20GB` for a single flavor claim — i.e., the flavor's nominal disk allocation exceeds the node's reported disk pool. Nova's own claims log explicitly notes *"disk limit not specified, defaulting to unlimited"* for this flavor, which is the most likely explanation (thin-provisioned/unlimited accounting rather than a real capacity breach), but this log alone doesn't contain actual physical disk-consumption data to confirm either way.

---

## 6. Root Cause Analysis

**Confirmed facts:**
- 2,000 total entries across 3 Nova services on 1 compute host over 14m47.68s; 1,969 INFO / 31 WARNING / 0 ERROR / 0 CRITICAL.
- 22 unique instances, all sharing one image and one flavor, each following an identical create→spawn→run→delete→destroy pattern with no exceptions.
- Instance-create calls occur at a highly regular 41.40 s average cadence (40.16–42.03 s range).
- Zero authentication failures, zero injection/recon signatures, zero non-private IPs, zero 5xx codes.
- All 41 `404`s and the single power-state-mismatch `WARNING` are directly explained by adjacent log evidence in the same file.
- 5 of 7 scheduler host-syncs required an InstanceList rebuild.

**Inferred hypotheses (facts vs. inference kept separate, as directed):**
- **High confidence:** This is an automated benchmark/load-test workload, not organic user traffic (regularity of cadence, single image/flavor, single primary account).
- **High confidence:** The 404 clusters and the single power-state WARNING are benign timing artifacts, not signs of failure or attack (directly evidenced, not merely assumed).
- **Medium confidence:** The scheduler sync mismatches are caused by the workload's churn rate outpacing the sync interval, rather than a scheduler bug — plausible and consistent with the data, but this file alone cannot rule out an underlying scheduler-tuning issue without scheduler-side DEBUG logs.
- **Low-Medium confidence:** The disk-accounting figure (20 GB claimed vs. 15 GB reported pool) is nominal/thin-provisioned rather than a real shortage — insufficient data in this file to fully confirm.

**Overall assessment:** No security incident. This is healthy, expected behavior for a single-tenant test/benchmark environment, with only minor, well-explained, non-critical log noise.

---

## 7. Recommendations & Actionable Intelligence

**Immediate containment:** None required — no security finding in this dataset.

**Investigation steps (to close remaining gaps, not because anything here is alarming):**
- Pull **Keystone** authentication logs for the 3 user/project pairs identified in §2B — this file only shows already-authenticated request context, not the authentication events themselves.
- Pull **Neutron** logs around the 21 explained `os-server-external-events` 404 timestamps to independently confirm the vif-plugged timing-race hypothesis from the networking side.
- Pull **libvirt/qemu** logs on `cp-1.slowvm1.tcloud-pg0.utah.cloudlab.us` to cross-check the `00:09:41.850` DB/hypervisor mismatch against the hypervisor's own domain list at that instant.
- If retained, pull **nova-scheduler DEBUG-level** logs (this file is INFO-only for that service) to quantify the exact instance-count delta at each of the 5 "did not match" events and test the churn-rate hypothesis directly.

**Security hardening / monitoring recommendations:**
- Add a monitoring metric for scheduler host-sync mismatch **rate** (e.g., alert if >30% of syncs mismatch in a rolling window) — currently benign here, but worth tracking as workload scales.
- Encode a detection rule for the *dangerous version* of the power-state warning: alert only when a *"0 instances on the hypervisor"* WARNING is **not** followed within a few seconds by a matching *"pending task...Skip"* line for the same instance — that combination (mismatch **without** the spawning explanation) would be the real signature of a genuinely lost/crashed VM.
- If this API is ever exposed beyond trusted internal automation, add client identification (e.g., a `User-Agent` or client-ID header at a reverse proxy) — the current format has no way to fingerprint calling clients beyond source IP.
- Continue capturing at least WARNING level (already in place); reserve DEBUG for targeted scheduler-sync investigations given its verbosity cost.
- No firewall/network-boundary changes indicated — all observed traffic is internal, private-range, and expected for this topology.

**Data still required for a fully complete picture** (per guardrails — nothing below is assumed or invented):
- Keystone (identity/auth) logs
- Neutron (networking) logs
- Libvirt/qemu hypervisor-level logs
- Cinder (block storage) logs, if volumes were ever attached (none referenced in this file)
- Any reverse-proxy/load-balancer logs sitting in front of the Nova API, if one exists in the real topology
