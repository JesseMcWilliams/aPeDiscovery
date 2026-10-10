# Target coverage

> **Stage: Planning.** One view of every target type aPeDiscovery covers, or could cover: its status, how it's collected, what access the scan needs, and a proposed order. Detail per target is in the `Planning_Targets-*.md` docs; the architecture is in [Planning_Collector-Architecture.md](Planning_Collector-Architecture.md). Keep this table current as targets move from Researched to Built. Questions referenced as (Qnn) are in [Planning_Questions.md](Planning_Questions.md).

**Last updated:** 2026-10-09

## Status key

| Status | Meaning |
|---|---|
| **Built** | Implemented and verified live. |
| **Built (unverified)** | Implemented; live verification pending (LT test listed). |
| **Designed** | A design doc exists; not built. |
| **Researched** | Method researched in a `Planning_Targets-*.md` doc; no design yet. |
| **Not started** | Named only. |

Effort is a rough size for one target type once the collector core exists: **S** (days), **M** (1–2 weeks), **L** (several weeks, or needs external teams).

## Coverage matrix

### Directories

| Target | Status | Method / transport | Scan access | New ports | Effort | Proposed wave |
|---|---|---|---|---|---|---|
| Active Directory: groups, members, computers | Built (computers unverified, LT-AD-02) | ADWS 9389 | Domain user | — | — | — |
| Active Directory: redesign (users, filters, store) | Designed | ADWS 9389 | Domain user, plus delegated reads | — | M | 1 |
| Entra ID (roles, PIM, apps) | Researched | Graph HTTPS | App with read-only application permissions | 443 to Microsoft | M | 2 |
| FreeIPA / Red Hat IdM | Researched | IdM API HTTPS / LDAPS | Read-only IdM role | 443 or 636 | S | 3 |
| OpenLDAP | Researched | LDAPS (+ SSH for `cn=config`) | Read-only bind DN | 636 | S | 4 |
| 389 DS / RHDS, OUD, Ping | Researched | LDAPS | Read-only bind DN | 636 | S | 4 |

### Operating systems

| Target | Status | Method / transport | Scan access | New ports | Effort | Proposed wave |
|---|---|---|---|---|---|---|
| Windows (local accounts, services) | Built | SMB/ADSI 445 | Local admin (F4) | — | — | — |
| Windows via collector (WinRM/JEA) | Researched | WinRM HTTPS 5986 | JEA role, no local admin | 5986 (Q72) | M | 2 |
| Linux (RHEL, Ubuntu/Debian, SUSE, Amazon, Oracle) | Built; F1–F3 fixes unverified (LT-LNX-06/07); `BadPasswordAttempts` unverified (LT-LNX-02/03) | SSH 22 | SSH plus scoped sudo | — | — | — |
| Linux via pushed collector | Designed (architecture doc) | SSH 22 | Same | — | M | 2 |
| AIX | Researched | SSH 22 collector | RBAC role with `aix.security.user.audit` | — | M | 3 |
| Solaris 11 | Researched | SSH 22 collector | Rights profile | — | S | 4 |
| HP-UX | Researched | SSH 22 collector | sudo | — | S | 5 (only if present) |
| macOS | Researched | MDM API or SSH | MDM API read role | Depends on MDM | S | 4 |
| z/OS (RACF / ACF2 / Top Secret) | Researched | Batch unload extract, CMS-encrypted hand-off | Batch ID with RACF DB read | File transfer (Q78) | L | 4 |
| IBM i | Researched | SQL over DRDA/ODBC | `QIBM_DB_SECADM` function usage | 446/8471 (to confirm) | S | 5 |

### Databases

| Target | Status | Method / transport | Scan access | New ports | Effort | Proposed wave |
|---|---|---|---|---|---|---|
| Instance detection (Windows/Linux services, listening) | Built (MySQL/MariaDB/MongoDB on Linux unverified, LT-LNX-05) | Part of the OS scans | — | — | — | — |
| SQL Server | Researched | TDS 1433 + TLS | `VIEW ANY DEFINITION`, `VIEW SERVER STATE` | 1433 | S | 2 |
| Oracle | Researched | Oracle Net 1521 / TCPS 2484 | `CREATE SESSION`, `SELECT_CATALOG_ROLE` | 1521/2484 | M | 3 |
| PostgreSQL | Researched | 5432 + TLS | `pg_monitor` | 5432 | S | 3 |
| MySQL / MariaDB | Researched | 3306 + TLS | `SELECT` on `mysql` schema | 3306 | S | 3 |
| Db2 LUW | Researched | DRDA 50000 + SSL | `CONNECT` plus catalog read | 50000 | M | 4 |

### Network devices

| Target | Status | Method / transport | Scan access | New ports | Effort | Proposed wave |
|---|---|---|---|---|---|---|
| Cisco IOS / IOS XE / NX-OS | Researched | SSH CLI (or RESTCONF) | TACACS+ with `show`-only command authorization | 22 (443) | M | 3 |
| Juniper Junos | Researched | NETCONF over SSH | Read-only login class | 22/830 | S | 4 |
| Palo Alto (PAN-OS, Panorama) | Researched | XML API HTTPS | Read-only admin role | 443 | S | 3 |
| Fortinet FortiGate | Researched | REST API HTTPS | Read-only REST API admin | 443 | S | 3 |
| F5, Arista, Check Point, Aruba | Researched | Vendor REST API | Read-only roles | 443 | S each | 4 |

### Hypervisors

| Target | Status | Method / transport | Scan access | New ports | Effort | Proposed wave |
|---|---|---|---|---|---|---|
| VMware vCenter / ESXi | Researched | vSphere API HTTPS (PowerCLI) | Read-only role at root | 443 | M | 2 |
| Nutanix Prism Central / AHV | Researched | v4 REST API HTTPS (+ SSH for CVM local accounts) | Prism Viewer | 9440 (22) | M | 3 |
| Hyper-V hosts | Partly built (the Windows scan covers local groups) | Windows scan, plus `Get-VM` over WinRM/JEA | JEA | 5986 | S | 2 |
| SCVMM | Researched | VMM PowerShell | Read-only VMM role | 8100 (to confirm) | S | 3 |
| Proxmox, OpenShift Virtualization, XenServer | Researched (brief) | REST APIs | Auditor/Read-only roles | Varies | S each | 5 (only if present) |

## Proposed waves

The waves are ordered by privilege tier first (what an attacker most wants), then by how many systems a wave covers, then by effort. All of this depends on what you actually have (Q70).

| Wave | Content | Why |
|---|---|---|
| **1** | AD redesign, SQLite store, collector core (`Core\`, plug-in structure) | Foundation for everything else; AD is Tier 0. |
| **2** | Entra ID; vCenter; Linux and Windows ported to collectors (Windows via JEA if allowed); SQL Server; Hyper-V `Get-VM` | Tier 0 cloud identity and hypervisors; the largest server populations; the most common database. |
| **3** | IdM; AIX; Oracle, PostgreSQL, MySQL; Cisco; Palo Alto; Fortinet; Nutanix; SCVMM | Remaining common enterprise platforms. |
| **4** | OpenLDAP/389 DS; Solaris; macOS; z/OS; Db2; Juniper and other network vendors | Narrower populations, or dependent on external teams (mainframe). |
| **5** | HP-UX, IBM i, Proxmox and other niche platforms | Only where present. |

## Cross-cutting dependencies

| Dependency | Needed by | Tracked in |
|---|---|---|
| Collector core and the plug-in structure | Every wave after 1 | [Planning_Collector-Architecture.md](Planning_Collector-Architecture.md) |
| Credential lookup workflow (bootstrap identity, then per-target account) | Every target | Same doc, Section 6; Q73–Q75 |
| New firewall rules per target type | Each new type | [Reference_Network-Firewall-Requirements.md](Reference_Network-Firewall-Requirements.md) (add `HR-NET-*` rows as types are built) |
| New client libraries (database drivers, PowerCLI) | Databases, vCenter | `Install-aPeDiscovery.ps1`, [Reference_Scanning-Host-Requirements.md](Reference_Scanning-Host-Requirements.md) |
| Security review of each collector's command list | Every collector | [Reference_Security-Team-Brief.md](Reference_Security-Team-Brief.md) |
| Lab targets for live tests | Every type | `Live-Testing.local.md`, [Testing_Live-Test-Definitions.md](Testing_Live-Test-Definitions.md) |
