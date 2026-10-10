# Collector architecture: pushed scripts, modular target types, secrets

> **Stage: Planning.** How aPeDiscovery should collect from operating systems and other targets as coverage grows: (1) send a small collector script to the target, run it there, and get back one signed, encrypted result bundle; (2) a modular structure where each target type is a self-contained plug-in; (3) how scan credentials are found and secured. Nothing here is built. Per-target detail is in the `Planning_Targets-*.md` docs; what's covered and when is in [Planning_Target-Coverage.md](Planning_Target-Coverage.md); open questions are in [Planning_Questions.md](Planning_Questions.md).

**Status:** research draft, 2026-10-09.

## 1. Why change

Today each scanner builds one long remote command (Linux, over SSH) or makes many small remote calls (Windows, over SMB/RPC with ADSI). That has worked, but:
- **The logic is split.** It lives partly on the scanning host and partly as text embedded in PowerShell strings, which is hard to test and hard to extend.
- **Data isn't processed where it lives.** Work that belongs on the target, such as classifying password hashes, was being done on the scanning host. The fix for Security brief F2 moved it to the target.
- **Each new target type means a new scanner module,** with its own copy of the runspace, retry and error-CSV code (an existing Open-Item).

## 2. The collector model

A **collector** is a small, read-only script for one target type and platform, such as `linux.sh`, `windows.ps1` or `aix.sh`. The orchestrator on the scanning host:

1. **Connects** to the target over the target type's transport (Section 3).
2. **Sends the collector over the session's input stream** and runs it in memory: for example `sh -s` over SSH, or a script block over PowerShell remoting. It's never written to the target's disk. Any secret the collector needs (such as a sudo password) follows on the same input stream, never in a command line. This is the pattern already used for the Linux sudo fix (F1).
3. **The collector gathers and classifies locally on the target,** keeping only the derived facts: state names, flags, counts. It never returns raw secrets or hashes.
4. **The collector writes one result envelope to its output stream** (Section 4). The orchestrator verifies it, decrypts it, checks it against the target type's schema, and stores it.

**Why this is better:**
- **One round trip per target.**
- **The collector can be tested on its own,** by running it locally on a test host and comparing its JSON output to a saved sample.
- **Adding a platform means adding a collector,** not a new scanner.
- **Nothing is left on the target.**

**Limits:**
- **Windows needs remote execution,** which means PowerShell remoting (WinRM). Today's SMB/ADSI scan doesn't execute anything remotely. See Section 3 and question 72.
- **Network devices, hypervisors and databases usually can't run scripts.** For those, the "collector" runs on the scanning host and talks to the target's API or SQL interface (Section 3). The same envelope and plug-in structure still apply.

## 3. Transports

| Transport | Used for | Runs collector where | Notes |
|---|---|---|---|
| **SSH, script over stdin** | Linux, Unix (AIX, Solaris, HP-UX), macOS | Target | No files on the target; a POSIX `sh` collector for portability. Host keys must be pre-trusted (F3). |
| **PowerShell remoting (WinRM, HTTPS 5986)** | Windows | Target | Script block over remoting; it can be limited to a **JEA** endpoint that exposes only the collector's commands (Section 5.2). Needs WinRM enabled on targets (new port, question 72). |
| **SMB/RPC (today's ADSI)** | Windows, fallback | Scanning host | No remote execution; limited to what remote SAM/ADSI exposes. Keep as the fallback where WinRM isn't allowed. |
| **LDAP/ADWS** | AD, OpenLDAP, 389 DS, IdM | Scanning host | Query only. |
| **REST/HTTPS API** | Entra ID (Microsoft Graph), Nutanix Prism, vCenter, firewalls (PAN-OS, FortiOS), F5 | Scanning host | API-token or OAuth credentials, kept in CyberArk. |
| **NETCONF/RESTCONF, or SSH CLI** | Network devices | Scanning host | Read the running config; parse local users and AAA settings. |
| **SQL (TDS, Oracle Net, PostgreSQL, MySQL, DRDA)** | Databases | Scanning host | Catalog queries as a dedicated read-only login. Needs a client driver per engine (Section 6.3). |
| **Mainframe (TSO/batch job, or RACF LDAP SDBM)** | z/OS RACF, ACF2, Top Secret; IBM i | Target (batch) or scanning host (LDAP/SQL) | Usually a scheduled unload job on the mainframe (RACF IRRDBU00) that hands a file to the scanner; see the OS targets doc. |

## 4. Result envelope: integrity and confidentiality

The collector's output is a single JSON envelope:

```json
{
  "schema": "aped.linux.v1",
  "target": "lnx-app01.contoso.com",
  "collector": { "name": "linux.sh", "version": "1.4.0", "sha256": "..." },
  "runId": "8f1c...",
  "nonce": "d41d...",
  "collectedUtc": "2026-10-09T23:41:00Z",
  "sections": { "users": [ ... ], "groups": [ ... ], "sudo": [ ... ] },
  "errors": [ { "section": "faillock", "message": "pam_faillock not configured" } ]
}
```

Protection, in layers. Each layer has its own job; layers 1 and 2 are the baseline, 3 and 4 are opt-in.

| # | Layer | Protects against | How |
|---|---|---|---|
| 1 | **Encrypted, authenticated transport** (SSH, WinRM over HTTPS, TLS) | Eavesdropping and changes in transit | Already true for SSH; requires HTTPS for WinRM and every API. |
| 2 | **A per-run nonce plus HMAC** | A replayed or substituted result (for example an old envelope, or one from a different host) | The orchestrator sends a random `runId`, a `nonce` and a per-target **HMAC key** over the input stream, together with the script. The collector returns `HMAC-SHA256(key, envelope)`, and the orchestrator rejects any mismatch. The key exists only in memory for that session. |
| 3 | **Envelope encrypted to the scanning host's certificate** (CMS) | Results staged on the target's disk being read there | Only needed when a collector must write to disk first (mainframe batch jobs, an agent mode, an air-gapped hand-off). The target holds only the **public** certificate; Windows uses `Protect-CmsMessage`, Unix uses `openssl cms -encrypt`. Only the scanning host's private key can decrypt. |
| 4 | **Code signing of collectors** | Running a modified collector on targets | Collectors are signed with a code-signing certificate held by the release process. The orchestrator verifies the signature before sending anything. On Windows, targets can also require it (`AllSigned` for the JEA endpoint). On Unix, a target-side check (`openssl dgst -sha256 -verify pub.pem -signature linux.sh.sig`) needs the public key placed on each target in advance, so it's optional. |

**About signing on the target:** a target can't usefully *sign* its results with a certificate. That would put a private key on every target, and anyone with root there could then sign forged data. The HMAC in layer 2 gives the same assurance with nothing left behind: the key is used once and known only to the orchestrator and that one live session. Certificates are the right tool for layers 3 and 4: the scanning host's **encryption** certificate, and the release process's **code-signing** certificate.

**Restricting access with certificates:**
- the store and its exports are readable only by the task account (HR-DIR-03);
- CMS envelopes (layer 3) can only be opened by the holder of the scanning host's private key, which should live in the machine's certificate store as non-exportable, or in an HSM;
- the code-signing private key never sits on the scanning host.

## 5. Modular target types

### 5.1 Plug-in layout

```
Targets\
  Linux\
    target.json            Manifest (below)
    collectors\linux.sh    Runs on the target; prints the envelope
    collectors\linux.sh.sig
    schema.json            JSON Schema for the envelope's sections
    Mapping.psm1           Optional: envelope sections -> store tables, when not 1:1
    tests\                 Sample envelopes and Pester tests for Mapping.psm1
  Windows\  AIX\  MSSQL\  Oracle\  CiscoIOS\  vCenter\  ...
Core\
  Orchestrator.psm1        Runspace pool, retries, timeouts, run records, error rows
  Transports\Ssh.psm1  WinRm.psm1  Ldap.psm1  Rest.psm1  Sql.psm1
  Envelope.psm1            Nonce/HMAC, CMS, schema validation
  Credentials.psm1         Credential lookup (Section 6), wraps aPeSecrets
  DiscoveryStore.psm1      SQLite (Planning_Discovery-Data-Store.md)
```

`target.json` declares everything the core needs, so adding a type requires no change to `Core\`:

```json
{
  "name": "Linux",
  "version": "1.0.0",
  "transport": "Ssh",
  "collector": "collectors/linux.sh",
  "interpreter": "sh -s",
  "elevation": "sudo",
  "requires": { "ports": [22], "accountPrivilege": "ssh login + read-only sudo command list" },
  "tables": ["os_users", "os_groups", "os_group_members", "os_sudo_rights", "os_services"],
  "searchConfigType": "LinuxHosts",
  "defaultTimeoutSeconds": 120
}
```

### 5.2 Contracts

- **A collector** is read-only, idempotent and quiet. It prints exactly one envelope and exits 0, even when individual sections fail, recording those failures in `errors`. It needs only the platform's built-in tools. Each collector's **exact command list** is published in the security brief, so the commands can be allow-listed: sudoers `NOPASSWD` limited to those commands, the JEA role capabilities, and the EDR exceptions.
- **A transport** connects with a credential object, runs a collector or a query with a timeout, streams secrets on stdin when needed, and returns raw output. It never logs secrets.
- **The core** owns concurrency, retries, run records, error rows, envelope checks and storage. A plug-in owns only what's specific to its target.
- **The store** uses shared table families (`os_users`, `os_groups`, `db_logins`, `db_role_members`, `net_local_users`, `hv_role_assignments`, ...), keyed by target and type, rather than one table set per product. That keeps cross-target reports ("every privileged local account") to a single query.

### 5.3 Migration

1. Build `Core\` and the SQLite store with the Phase 1 AD redesign. AD becomes the first plug-in, with an LDAP transport and no remote collector.
2. Port Linux to a pushed `linux.sh` collector. This reuses today's tested shell logic, with the fixes for F1–F3 already applied.
3. Port Windows: a WinRM/JEA collector where allowed, and today's ADSI path as the fallback transport.
4. Add new types in coverage order ([Planning_Target-Coverage.md](Planning_Target-Coverage.md)).

## 6. Credentials: from a secrets provider to each target's logon account

### 6.1 The workflow (two stages)

1. **Bootstrap:** the scanning host gets **one** credential from a secrets provider. This is a CyberArk application identity that's allowed to read the scan-account Safes.
2. **Per target:** that identity looks up **which** account to use for this target in CyberArk, then retrieves its password or key just before connecting, and discards it afterwards.

This removes per-target credential settings from the configs. The configs then hold only the lookup rule, not a pointer for every host.

### 6.2 Options for the bootstrap secret

| Option | How the scanning host proves who it is | Strengths | Weaknesses |
|---|---|---|---|
| **A. Credential Provider (CP) on the scanning host** | Application ID plus machine and OS-user checks, optionally a path/hash check of the caller | No secret stored on the host; local cache for availability; proven here (2026-09-17) | Agent install and Vault port 1858; path/hash checks change when moving to `pwsh.exe` (F7). |
| **B. Central Credential Provider (CCP) over HTTPS** | Application ID plus a **client certificate** (mutual TLS) and allowed source address | No agent; certificate private key can be non-exportable or in a TPM; proven in aPeSecrets | Needs a certificate lifecycle; the CCP web service is a dependency. |
| **C. Conjur (or Secrets Hub)** | Host identity plus API key, or a platform authenticator (cloud IAM, certificate) | Suits cloud and container scanners | An API key on disk is a bootstrap secret to protect; never tested here (F5). |
| **D. PVWA REST API as a named application user** | Username and password (or OAuth client credentials in Privilege Cloud) | Can **search** accounts as well as retrieve them (Section 6.3) | The user's own credential must be stored somewhere: put it in A or B, never in a file. |
| **E. DPAPI file or Windows Credential Manager** | The Windows account and machine | Simple; no CyberArk dependency | The secret sits on disk, tied to one account; no central rotation or audit. Lab and fallback use only. |

**Recommendation: A or B as the bootstrap.** Use B (CCP with a client certificate whose private key is non-exportable) where agents are discouraged, and A where the Credential Provider is already the standard. Use D only through A or B, so no password is ever stored on the scanning host. Avoid E outside the lab.

### 6.3 Options for finding each target's logon account

| Option | How | Fit |
|---|---|---|
| **1. A naming convention, fetched with CP/CCP queries** | A query like `Safe=Scan-Linux;Object=<address>-svc_scan` built from the target's address | Simplest and fastest, with no search API. Needs strict naming in the Vault. |
| **2. Search by address through the REST API** | PVWA/Privilege Cloud `GET /Accounts?search=<address>&filter=safeName eq <Safe>`, then pick by `userName`/platform, then retrieve the password | Flexible, and finds whatever account is onboarded for the target. Needs the application user (D) and search permission on the Safes; one extra call per target. |
| **3. A per-group mapping** | Config maps groups of targets (by domain, OU, subnet or tag) to one shared scan account | Few accounts to manage. A shared account widens the damage if it leaks. |
| **4. Per-target settings** (today) | Each row in `*ComputersToScan.csv` names its own source and object | Exact, but scales badly; this is what the workflow replaces. |

**Recommendation:** 2, with 1 as a fast path. Search once per run and keep the address-to-account mapping in memory (never the secrets), then retrieve each secret just before it's needed. Require Safe-level permissions of **List and Retrieve only**, on dedicated scan-account Safes.

### 6.4 Securing the credentials

- **Dedicated scan accounts per target class,** for example `svc_scan_linux` and `svc_scan_win`, each managed and rotated by CyberArk, with the least privilege in the target docs. They shouldn't be personal accounts or the targets' own admin accounts.
- **Separate Safes for scan accounts.** Only the scanning application identity has Retrieve. Enable CyberArk's "Require users to specify reason" if policy wants a reason recorded; the orchestrator can send `Reason=aPeDiscovery run <runId>`.
- **Restrict where the scan accounts can log on,** wherever the target supports it: AD logon-workstations restrictions or authentication policy silos, sshd `AllowUsers svc_scan@<scanning host IP>`, database login triggers or `pg_hba.conf` source restrictions, device ACLs.
- **Prefer keys and certificates to passwords:**
  - SSH keys stored in CyberArk and retrieved per run, with `from="<scanner IP>"` and limited `command=`/sudoers rules on the target;
  - client-certificate authentication for APIs.
- **Short-lived secrets in memory:** retrieve, use, clear. They're never written to disk, logs (LogaPe masking stays on) or the store.
- **Prefer just-in-time access where the platform supports it:** CyberArk dynamic or ephemeral access, Entra PIM eligible roles, short-lived database credentials, so the scan accounts hold no standing privilege between runs.
- **Rotate after each run (optional, strongest):** have CyberArk rotate scan-account passwords after use ("one-time password" policy). It costs a rotation per target per run.

### 6.5 Securing the collected data

The data-store doc and the security brief cover the basics. On top of those:
- **Encrypt the store at rest:** BitLocker on the data volume as a minimum. SQLite has no built-in encryption, so an encrypted library build or encrypting sensitive columns are options (question 79).
- **Export files** can be CMS-encrypted to the recipient's certificate (`Protect-CmsMessage`) when they leave the scanning host, and signed (detached CMS) so the importer can verify they came from this scanner unchanged.
- **The store holds no secrets:** account names and states only. Make that a test assertion when the store is built.
- **Access logging:** the store and exports are read only by the task account; Windows object-access auditing on the data folder records any other reader.
