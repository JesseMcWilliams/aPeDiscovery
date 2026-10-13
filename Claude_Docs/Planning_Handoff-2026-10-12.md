# Handoff: aPeDiscovery (2026-10-12)

> **Stage: Planning (point-in-time snapshot).** Where aPeDiscovery stands, so work can be picked up without re-reading the history. It covers this project only: LogaPe, aPeSecrets and LABaPe are separate projects with their own handoffs and backlogs. This replaces [Archive_Planning_Handoff-2026-10-10.md](Archive_Planning_Handoff-2026-10-10.md); once a newer handoff exists, rename this one `Archive_Planning_Handoff-2026-10-12.md`.

## 1. Start here

1. Read this file, then [Planning_Questions.md](Planning_Questions.md). Most next steps wait on answers there (70-92) or on lab access (21).
2. For context, in this order:
   - [Planning_Target-Coverage.md](Planning_Target-Coverage.md): what's covered, and the build waves;
   - [Planning_Collector-Architecture.md](Planning_Collector-Architecture.md): the target architecture and the credential workflow;
   - [Planning_AD-Object-Filters.md](Planning_AD-Object-Filters.md) and [Planning_Discovery-Data-Store.md](Planning_Discovery-Data-Store.md): the wave 1 designs;
   - [Planning_Open-Items.md](Planning_Open-Items.md): the full backlog.
3. Live testing: `Live-Testing.local.md` (gitignored) in the project root. Read it **only** for live-testing tasks. CyberArk access was still being arranged.

## 2. Where things stand

- `main` only; no open PRs or extra worktrees. Nothing changed in the code since 2026-10-10. The 2026-10-12 work was this handoff and its predecessor's scope note (PR #11).
- Dependencies: the scripts import LogaPe from the sibling folder `..\LogaPe` (e.g. `Export-ADObjects.ps1`). LogaPe is now at **v0.7.0** (adds a syslog sink; no breaking changes). aPeSecrets is unchanged.

## 3. Next steps

**Waiting on the user** (questions in [Planning_Questions.md](Planning_Questions.md)):
1. 70 (target types and counts), 71 (build the collector core alongside or replace), 72 (WinRM HTTPS + JEA), 73-74 (bootstrap secret, account lookup). The rest of 70-92 refine later waves.

**Waiting on the lab** (definitions in [Testing_Live-Test-Definitions.md](Testing_Live-Test-Definitions.md)):
2. LT-LNX-06/07: verify security fixes F1-F3.
3. LT-LNX-02/03: faillock `BadPasswordAttempts`.
4. LT-AD-01/02: AD exports against a real DC, including `ADComputers.csv`.
5. LT-CRED-01/02: credential sources; Conjur has never been tested live (F5).
6. LT-INST-01: the install script's elevated paths (only run with `-WhatIf` so far).
7. The AD and Linux scans on PowerShell 7.

**Ready now, needs neither:**
8. Wave 1: `Modules\DiscoveryStore.psm1` with the SQLite libraries in `Lib\`, the schema and migrations, and Pester tests ([Planning_Discovery-Data-Store.md](Planning_Discovery-Data-Store.md)).
9. Wave 1: `New-ADObjectLdapFilter` with escaping and `Get-ScopedSearchBase`, plus this repo's first Pester suite ([Planning_AD-Object-Filters.md](Planning_AD-Object-Filters.md) §7).
10. Config JSON schemas (`Config\Schemas\`) for general, search and export configs.
11. Start `Core\` and the plug-in layout ([Planning_Collector-Architecture.md](Planning_Collector-Architecture.md) §5), with AD as the first plug-in.
12. Optional: send scan logs to syslog with LogaPe 0.7.0's `Add-LoggerSyslogSink` (e.g. to a SIEM), configured in the general config. Needs a decision on whether that's wanted.

## 4. Findings register

Every aPeDiscovery finding so far, where it's documented, and its status (carried over from the 2026-10-10 handoff, unchanged since). "Verify" means it's done but awaits a live test.

### 4.1 Security

| ID | Finding | Status | Documented in |
|---|---|---|---|
| F1 | The Linux sudo password was embedded (base64) in the remote command line, visible in the process list and command auditing | Fixed; verify LT-LNX-06 | Security brief §7; Sudo-Elevation doc §5a; Open-Items |
| F2 | Linux `/etc/shadow` hashes were sent to the scanning host for classification | Fixed (classified on the target); verify LT-LNX-06 | Security brief §7; Data-Model doc §6 |
| F3 | SSH host keys were trusted on first use by default | Fixed (`AcceptNewHostKey` defaults to false); verify LT-LNX-07 | Security brief §7; Reference_Configuration |
| F4 | The Windows scan needs local Administrator on targets | Accepted; JEA option researched (Q72) | Security brief §7; Targets-Operating-Systems §1 |
| F5 | The Conjur source was never tested live | Open (LT-CRED-02) | Security brief §7; Open-Items |
| F6 | FIPS support never run on a FIPS host | Open | Security brief §7; HR-SEC-02 |
| F7 | CP path/hash application authentication may change under `pwsh.exe` | Open; check in the PowerShell 7 rollout | Security brief §7; HR-CA-02 |
| — | MD5 mutex name breaks on FIPS hosts (LogaPe and the old `Logging.psm1`) | Fixed and merged (LogaPe #7) | LogaPe CHANGELOG and Lessons-Learned |
| — | The install script hashes with `SHA256CryptoServiceProvider`, because `Get-FileHash`'s managed SHA-256 fails under FIPS on .NET Framework | Built in | `Install-aPeDiscovery.ps1` comments |

### 4.2 Functional and design

| Finding | Status | Documented in |
|---|---|---|
| The AD export never searches default containers (`CN=Users`, `CN=Computers`, `CN=Builtin`), so the built-in Administrators group and accounts left in `CN=Users` are missed | Open; fixed by the AD redesign | Planning_AD-Object-Filters §2; Open-Items |
| `MemberCount` is capped at 1,500 (no ranged retrieval) | Open; fixed by the redesign | Planning_AD-Object-Filters §2/§6.4 |
| AD `ADComputers.csv` never tested against a real DC | Open (LT-AD-02) | Open-Items |
| Primary-group membership isn't in `memberOf`; `adminCount` stays set after removal | Designed around | Planning_AD-Object-Filters §5.2 |
| Linux accounts with an empty password field are reported `Unknown` | Open (Q90) | Planning_Questions |
| Linux `BadPasswordAttempts` built but not live-tested; `pam_tally2` not read | Open (LT-LNX-02/03) | Open-Items; Reference_CSV-Schemas |
| The aPeDiscovery backlog wrongly listed CCP as unverified; aPeSecrets verified it 2026-09-21 | Corrected | Open-Items |

### 4.3 PowerShell 7 and libraries

| Finding | Status | Documented in |
|---|---|---|
| `Export-Csv -Encoding UTF8` writes no BOM on 7 (Excel misreads non-ASCII text) | Fixed (aPeDiscovery #7) | aPeDiscovery-ps7 README/CLAUDE.md |
| On .NET Framework, `SHA256.Create()` returns the non-FIPS `SHA256Managed` | Avoided everywhere | LogaPe Lessons-Learned |
| Microsoft.Data.Sqlite 10.0.12 needs **SQLitePCLRaw 2.1.x**, not 3.x | Recorded | Planning_Discovery-Data-Store §4.1 |
| The native `e_sqlite3.dll` must be pre-loaded by full path (`NativeLibrary.Load`) | Recorded | Planning_Discovery-Data-Store §4.1 |
| The SQLite prototype's VC++ runtime dependency is unconfirmed | Open | HR-MOD-04 |
| The F1/F3 fixes need Posh-SSH ≥ 4.0.0 (not checked below that) | Recorded | HR-MOD-02 |
| The AD module and Posh-SSH haven't been run on PowerShell 7 | Open (lab) | Planning_Discovery-Data-Store §8 |
| The install script's elevated paths (PowerShell 7 MSI, Posh-SSH, RSAT) have only run as `-WhatIf` | Open (LT-INST-01) | Open-Items |

### 4.4 Network

| Finding | Status | Documented in |
|---|---|---|
| AD needs TCP 9389 (ADWS) and Kerberos 88; LDAP TCP 389/636 aren't used | Recorded | Reference_Network-Firewall-Requirements |
| Windows targets need their own firewall to allow SMB 445 from the scanner; Linux `sshd` must allow the scan account | Recorded | Same |

### 4.5 Research highlights (affect future design)

| Finding | Documented in |
|---|---|
| Cisco IOS XE NETCONF/RESTCONF need privilege 15, so a read-only scan should use SSH with TACACS+ `show`-only command authorization | Planning_Targets-Network-Devices §1 |
| Entra ID PIM **eligible** assignments aren't active role members, so they must be read separately | Planning_Targets-Directories §2 |
| Oracle `SYSDBA` (OS `dba` group) and Db2 `SYSADM_GROUP` grant admin rights through OS groups, outside database logins | Planning_Targets-Databases §2, §5 |
| OpenLDAP's root DN never appears in ACLs; `cn=config` is root-only by default | Planning_Targets-Directories §3 |
| ESXi lockdown mode blocks direct reads, so read hosts through vCenter | Planning_Targets-Hypervisors §1 |
| Nutanix Prism Element `admin` and CVM `nutanix` passwords are often identical or default | Planning_Targets-Hypervisors §2 |
| Mainframe coverage is best done with an IRRDBU00 (RACF) batch extract, handed over CMS-encrypted | Planning_Targets-Operating-Systems §5 |
| Targets shouldn't hold signing keys; use a per-run HMAC for result integrity, and certificates for encryption and code signing | Planning_Collector-Architecture §4 |

## 6. Environment notes (this development machine)

| Item | Detail |
|---|---|
| PowerShell 7 | **7.6.6 is installed** at `C:\Program Files\PowerShell\7\pwsh.exe`, but **not on PATH**, so `pwsh` alone isn't found; use the full path. (A portable copy used during the session was in a temporary scratch folder and is gone.) |
| Pester | 6.1.0 in `C:\Users\ladmin\Documents\WindowsPowerShell\Modules` (Windows PowerShell's path only). In `pwsh`, import it by path, or prepend that folder to `PSModulePath`. |
| Not installed here | RSAT ActiveDirectory module, Posh-SSH, CyberArk Credential Provider. AD, Linux and CP paths can only be tested in the lab. |
| Install-script testing | Safe locally with `-WhatIf`, `-DownloadOnly -PackagePath <scratch>`, or `-Components Repositories -InstallRoot <scratch>`. Elevated components change the machine. |
| Smoke test | `Export-LocalGroups.ps1` against this machine's own name with `CurrentUser` credentials works on 5.1 and 7. `localhost` fails (an ADSI WinNT limitation, not a bug). |

## 7. Conventions in force

- Numbered lists for actions, options and questions, with stable numbers. Questions continue from 93; record them in Planning_Questions.md.
- Commit, push, PR or merge only when asked.
- Topic branches `YYYY-MM-DD-<topic>`; never work on `main`. Merge with `--delete-branch`.
- Track only aPeDiscovery items here; other projects' items go in their own repositories.
- Never write secrets anywhere; the placeholder password is `ThisIsMy_FAKE_Password6!`.
- Commands handed to the user use full paths and say which user runs them.
- Keep the Reference docs current: host requirements (`HR-*`), network (`HR-NET-*`), security brief (findings), coverage matrix. See CLAUDE.md's docs table.
