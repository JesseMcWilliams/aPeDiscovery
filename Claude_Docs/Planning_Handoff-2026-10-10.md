# Handoff: aPeDiscovery, LogaPe, aPeSecrets (2026-10-10)

> **Stage: Planning (point-in-time snapshot).** Where the work stands at the end of the 2026-10-09 session, so it can be picked up later without re-reading the history. It covers all three sibling repositories. Superseded by any later `Planning_Handoff-*.md`; once a newer one exists, rename this one `Archive_Planning_Handoff-2026-10-10.md`.

> **Update 2026-10-10: everything below is merged.** Every branch and PR in Sections 2–3 is merged into `main` in all three repositories: aPeDiscovery PRs #6–#10, LogaPe #8, aPeSecrets #3. The topic branches and the two extra worktrees are deleted, and every checkout is on `main`. Sections 2–3 are kept as history; the findings, questions and next steps (Sections 4–7) still apply. In Section 5, skip "Merge or review the open PRs".

## 1. Start here

1. Read this file, then [Planning_Questions.md](Planning_Questions.md). Most next steps wait on answers there (70–92) or on lab access (21).
2. Check the PRs in Section 3; merging them in order unblocks the stacked branches.
3. For context, in this order:
   - [Planning_Target-Coverage.md](Planning_Target-Coverage.md): what's covered, and the build waves;
   - [Planning_Collector-Architecture.md](Planning_Collector-Architecture.md): the target architecture and the credential workflow;
   - [Planning_AD-Object-Filters.md](Planning_AD-Object-Filters.md) and [Planning_Discovery-Data-Store.md](Planning_Discovery-Data-Store.md): the wave 1 designs;
   - [Planning_Open-Items.md](Planning_Open-Items.md): the full backlog.
4. Live testing: `Live-Testing.local.md` (gitignored) now exists in the aPeDiscovery root. Read it **only** for live-testing tasks. CyberArk access was still being arranged.

## 2. What was done (2026-10-09)

| # | Work | Repo / branch | State |
|---|---|---|---|
| 1 | `Export-ADGroups.ps1` renamed to `Export-ADObjects.ps1`; logging moved to LogaPe with default masking; Linux `BadPasswordAttempts` (pam_faillock); 12 `LT-*` live tests | aPeDiscovery `main` (PR #5) | **Merged** |
| 2 | LogaPe mutex name uses a FIPS-validated hash (SHA256CryptoServiceProvider, not MD5) | LogaPe `main` (PR #7) | **Merged** |
| 3 | PowerShell 7 support: LogaPe Event Log sink (`*-EventLog` cmdlets removed in 7), examples tested on 7 | LogaPe `2026-10-09-ps7-support` (PR #8) | Open |
| 4 | PowerShell 7 support: aPeSecrets CP checks `AppID` before the SDK (test CR10 always failed without CP) | aPeSecrets `2026-10-09-ps7-support` (PR #3) | Open |
| 5 | Identical CSV bytes on 5.1 and 7 (`$csvEncoding`: `utf8BOM` on 7) | aPeDiscovery `2026-10-09-ps7-support` (PR #7) | Open |
| 6 | AD export redesign and data-store designs, decisions 25–62, SQLite prototype | aPeDiscovery `2026-10-09-ad-object-filters` (PR #6) | Open |
| 7 | `Install-aPeDiscovery.ps1`; host requirements, network/firewall and security-team docs | aPeDiscovery `2026-10-09-host-setup` | Pushed, no PR |
| 8 | Linux security fixes F1–F3 | aPeDiscovery `2026-10-09-linux-security-fixes` | Pushed, no PR |
| 9 | Collector architecture, target research (5 docs), coverage matrix, questions doc, this handoff | aPeDiscovery `2026-10-09-target-research` | Pushed, no PR |

## 3. Branches, PRs and merge order

```
main
├── 2026-10-09-ps7-support            PR #7   (independent)
├── 2026-10-09-linux-security-fixes   no PR   (independent, from main)
└── 2026-10-09-ad-object-filters      PR #6
    └── 2026-10-09-host-setup         no PR   (built on #6)
        └── 2026-10-09-target-research  no PR (built on host-setup)
```

**Merge order:**
1. LogaPe #8 and aPeSecrets #3 (any time).
2. aPeDiscovery #6, then #7. #7's CLAUDE.md refers to `Planning_Discovery-Data-Store.md`, which #6 adds.
3. Open PRs for `host-setup`, then `target-research`, after #6 is merged. Each then shows only its own commits.
4. `linux-security-fixes` after LT-LNX-06 and LT-LNX-07 pass in the lab (or merge first and verify after, by choice).

Expect small conflicts:
- `Planning_Open-Items.md` and `Planning_User-Docs-Backlog.md` are touched by several branches. Keep every added line.
- `CLAUDE.md`'s runtime line differs between `ps7-support` and the stack. Keep the `ps7-support` wording.

**Local checkouts (this machine):**

| Folder | Branch | Notes |
|---|---|---|
| `C:\Code\aPeDiscovery` | `2026-10-09-target-research` | Main checkout; worktrees below share its `.git` |
| `C:\Code\aPeDiscovery-ps7` | `2026-10-09-ps7-support` | Git worktree. Remove after merge: `git worktree remove C:\Code\aPeDiscovery-ps7` |
| `C:\Code\aPeDiscovery-linuxfix` | `2026-10-09-linux-security-fixes` | Git worktree. Remove after merge |
| `C:\Code\LogaPe` | `2026-10-09-ps7-support` | Switch to `main` after #8 merges |
| `C:\Code\aPeSecrets` | `2026-10-09-ps7-support` | Switch to `main` after #3 merges; cloned this session |

## 4. Findings register

Every finding from this session, where it's documented, and its status. "Verify" means it's done but awaits a live test.

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
| — | The old `Logging.psm1` wrote unguarded if its mutex wait timed out | Gone (replaced by LogaPe) | Design_Local-Windows-Discovery |
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
| PowerShell 7 removed `New-EventLog`/`Write-EventLog`, so LogaPe's Event Log sink failed on 7 | Fixed (LogaPe #8) | LogaPe CHANGELOG and Lessons-Learned |
| `Export-Csv -Encoding UTF8` writes no BOM on 7 (Excel misreads non-ASCII text) | Fixed (aPeDiscovery #7) | aPeDiscovery-ps7 README/CLAUDE.md |
| aPeSecrets test CR10 failed on any host without CP | Fixed (aPeSecrets #3) | aPeSecrets backlog |
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

## 5. Next steps

**Blocked on you:** the questions in [Planning_Questions.md](Planning_Questions.md), especially 70 (environment), 72 (WinRM), 73–74 (credentials), 71 (replace vs. alongside).

**Blocked on the lab:**
- LT-LNX-06/07 (F1–F3);
- LT-LNX-02/03 (faillock);
- LT-AD-01/02;
- LT-CRED-01/02;
- LT-INST-01;
- the AD and Linux scans on PowerShell 7.

**Ready to do without either:**
1. Merge or review the open PRs (Section 3).
2. **Wave 1 build start:** `Modules\DiscoveryStore.psm1` with the SQLite libraries in `Lib\`, the schema and migrations, and Pester tests. The design is in Planning_Discovery-Data-Store.
3. **Wave 1:** `New-ADObjectLdapFilter` with escaping and `Get-ScopedSearchBase`, plus this repo's first Pester suite. Pure functions, offline-testable (Planning_AD-Object-Filters §7).
4. Config JSON schemas (`Config\Schemas\`) for general, search and export configs.
5. Start `Core\` and the plug-in layout (Planning_Collector-Architecture §5), with AD as the first plug-in.

## 6. Environment notes (this development machine)

| Item | Detail |
|---|---|
| PowerShell 7 | **7.6.6 is installed** at `C:\Program Files\PowerShell\7\pwsh.exe`, but **not on PATH**, so `pwsh` alone isn't found; use the full path. (A portable copy used during the session was in a temporary scratch folder and is gone.) |
| Pester | 6.1.0 in `C:\Users\ladmin\Documents\WindowsPowerShell\Modules` (Windows PowerShell's path only). In `pwsh`, import it by path, or prepend that folder to `PSModulePath`. |
| LogaPe tests on 7 | Set `$env:LOGAPE_PWSH` to the pwsh path; `Invoke-Pester -Path .\Tests` then runs every example on 5.1 and 7. |
| aPeSecrets tests on 7 | Prepend the Pester folder to `PSModulePath`, then `& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -File .\Tests\Run-Tests.ps1`. |
| Not installed here | RSAT ActiveDirectory module, Posh-SSH, CyberArk Credential Provider. AD, Linux and CP paths can only be tested in the lab. |
| Install-script testing | Safe locally with `-WhatIf`, `-DownloadOnly -PackagePath <scratch>`, or `-Components Repositories -InstallRoot <scratch>`. Elevated components change the machine. |
| Smoke test | `Export-LocalGroups.ps1` against this machine's own name with `CurrentUser` credentials works on 5.1 and 7. `localhost` fails (an ADSI WinNT limitation, not a bug). |

## 7. Conventions in force

- Numbered lists for actions, options and questions, with stable numbers. Questions continue from 93; record them in Planning_Questions.md.
- Commit, push, PR or merge only when asked. The user asked for commit-and-push at each stopping point, **no PRs yet**, for the current research work.
- Topic branches `YYYY-MM-DD-<topic>`; never work on `main`.
- Never write secrets anywhere; the placeholder password is `ThisIsMy_FAKE_Password6!`.
- Keep the Reference docs current: host requirements (`HR-*`), network (`HR-NET-*`), security brief (findings), coverage matrix. See CLAUDE.md's docs table.
