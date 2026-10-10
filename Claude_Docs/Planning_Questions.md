# Open questions

> **Stage: Planning.** Questions waiting on a decision or information from you, collected so they can be reviewed in one sitting. Numbers continue the conversation's numbering and never change. Answer by number. When a question is answered, record the answer in the doc that raised it, then move the question to "Answered" below with a one-line summary.

**Last updated:** 2026-10-09

## Environment and scope

70. **Which target types and products exist in your environment, and roughly how many of each?** This includes:
    - directories (OpenLDAP, IdM, Entra ID);
    - OS versions (Linux distributions, AIX, Solaris, HP-UX, macOS, z/OS, IBM i);
    - database engines and versions;
    - network vendors;
    - hypervisors.

    The answer reorders the waves in [Planning_Target-Coverage.md](Planning_Target-Coverage.md).
71. **Build the collector core alongside the current scanners, or replace them?** My recommendation is alongside: port Linux and Windows to collectors in wave 2, and retire the old scanners once the new ones pass the same live tests.
72. **Is WinRM over HTTPS (TCP 5986) with a JEA endpoint acceptable on Windows targets?** It removes the need for local Administrator (F4) and gives a full audit transcript, but it adds a port and endpoint configuration on every Windows target. The alternative is staying agentless over SMB.
92. **Should cloud platforms be in scope** (AWS IAM, Azure RBAC subscriptions, GCP IAM)? None are covered or researched yet.

## Credentials (Planning_Collector-Architecture.md Section 6)

73. **Bootstrap secret: Credential Provider (CP) on the scanning host, or CCP with a client certificate?** I recommend CCP with a non-exportable certificate where agents are discouraged, otherwise CP.
74. **Account lookup:** is there an existing naming convention for scan accounts in the Vault? If yes, use it (fast path). If no, use REST search by target address, which needs a PVWA/Privilege Cloud application user with List and Retrieve on the scan Safes.
75. **Rotate scan-account passwords after every run** (CyberArk one-time password policy)? It's strongest, but costs a rotation per target per run.
76. **Should collectors be code-signed, and who issues the code-signing certificate** (internal PKI, or a commercial CA)?
77. **Should targets verify collector signatures themselves?** That requires placing the public key on every Unix target. The orchestrator verifies before sending either way.

## Data protection

79. **Is BitLocker on the data volume enough for the SQLite store at rest,** or is database or column encryption required (an encrypted SQLite build, or encrypting sensitive columns)?
87. **Network devices: parse device configs in memory only** (my recommendation), **or keep the config text?** It contains password hashes and keys, so keeping it would need its own encryption and retention rules.
91. **Do you need a single cross-platform "privileged accounts" view** for CyberArk onboarding (one row per account, with its target, platform and why it's privileged)? If yes, it becomes a store view and an export.
90. **Linux accounts with an empty password field** (no password at all) are currently reported as `PasswordState = Unknown`, the same as before the F2 fix. Add an explicit `NoPassword` state? It's a high-risk condition worth surfacing.

## Per target type

78. **Mainframe:** which security manager (RACF, ACF2, Top Secret)? Is a scheduled unload/extract job, sent CMS-encrypted to the scanner, acceptable to the mainframe team?
80. **Entra ID:** is creating an app registration with read-only Graph **application** permissions (`Directory.Read.All`, `RoleManagement.Read.Directory`, `RoleEligibilitySchedule.Read.Directory`, `Application.Read.All`), using certificate authentication, acceptable?
81. **OpenLDAP:** can the scan bind DN be given read access to `cn=config`? If not, is a small SSH collector on the LDAP servers acceptable for the root-DN and ACL data?
82. **Unix:** which AIX, Solaris and HP-UX versions are present? Are any HP-UX systems in trusted mode?
83. **macOS:** is the fleet managed by an MDM (Jamf Pro, Intune)? Using its API is my recommendation over SSH.
84. **Databases:** which engines and versions? Is a dedicated read-only scan login acceptable on every instance? For PostgreSQL, can it be granted read on `pg_hba_file_rules` (normally superuser-only)?
85. **Database drivers:** is copying the vendors' .NET drivers into the repo acceptable (Npgsql and MySqlConnector are open source; Oracle's managed driver and IBM's Db2 driver have their own licenses)? Or must they be installed separately?
86. **Network devices:**
    - Is central AAA (TACACS+/ISE) in place, and can it give the scan account `show`-only command authorization?
    - Are NETCONF/RESTCONF enabled anywhere?
    - Which vendors and central managers (Panorama, FortiManager) are used?
88. **Hypervisors:** which vCenter and Prism Central versions are deployed (the Nutanix v4 API needs a recent Prism Central)? Are Hyper-V hosts managed by SCVMM or Windows Admin Center? Is a read-only role on each management plane acceptable?
89. **ESXi:** read host-level data (local accounts, lockdown exceptions) only through vCenter, which works with lockdown mode, or also connect to hosts directly?

## Carried over

21. **Lab access:** `Live-Testing.local.md` exists; CyberArk access is still in progress. Also needed for the PowerShell 7 checks on the AD and Linux scans (RSAT and Posh-SSH), and for LT-LNX-06/07 (F1–F3) and LT-INST-01.

## Answered

| # | Answer (summary) | Recorded in |
|---|---|---|
| 60 | `KeepRuns` defaults to 90 | Planning_Discovery-Data-Store.md §9 |
| 61 | Credentials for scan-target exports wait for Phase 2 | Same |
| 62 | Minimum PowerShell 7.6 | Same |
| 68 | Host setup on its own branch; committed, no PR | Git: `2026-10-09-host-setup` |
| 69 | Fix F1–F3 | Git: `2026-10-09-linux-security-fixes` |
