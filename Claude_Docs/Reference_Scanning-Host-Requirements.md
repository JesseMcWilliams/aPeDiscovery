# Scanning host requirements

> **Stage: Reference.** Everything the Windows host that runs aPeDiscovery needs: software, files, accounts, network access and settings. Keep it current: when a change adds or removes a host requirement, update this file in the same change. `User_Docs/` will eventually get an installation guide written from it.

**Last updated:** 2026-10-09

## How to read this

- **ID** (`HR-<area>-<NN>`) is stable. Refer to items by ID in checklists, tickets and `Live-Testing.local.md`; never reuse or renumber one.
- **Needed for** says which scripts need the item:
  - **All** means every script.
  - **AD** is `Export-ADObjects.ps1`.
  - **Win** is `Export-LocalGroups.ps1`.
  - **Linux** is `Export-LocalLinuxGroups.ps1`.
  - **Store** is the planned SQLite store and exports.
- **When:**
  - **Now:** needed by the scripts as they are today.
  - **Phase 1:** needed by the AD export redesign ([Planning_AD-Object-Filters.md](Planning_AD-Object-Filters.md), [Planning_Discovery-Data-Store.md](Planning_Discovery-Data-Store.md)).
  - **Phase 2+:** later phases.
- **Verified:**
  - **Yes:** confirmed on a real host.
  - **Dev:** confirmed on a development machine only.
  - **No:** not yet confirmed.

The checks in [Section 10](#10-setup-checklist) confirm most items on a new host.

## 1. Operating system and runtime

| ID | Requirement | Needed for | When | Verified |
|---|---|---|---|---|
| HR-OS-01 | 64-bit Windows. The SQLite native library is `win-x64` only. | All | Phase 1 | Dev |
| HR-OS-02 | A Windows version that PowerShell 7.6 supports. Check Microsoft's supported-OS list for 7.6 before choosing the host. | All | Phase 1 | No |
| HR-OS-03 | **PowerShell 7.6 or later**, installed system-wide (MSI) so every account can run `pwsh.exe`. New code declares `#Requires -Version 7.6`. | All | Phase 1 | Dev (7.6.6 portable) |
| HR-OS-04 | Windows PowerShell 5.1 (built into Windows). The existing scripts still run on it during the move to 7; nothing new depends on it. | AD, Win, Linux | Now | Yes |
| HR-OS-05 | Disk space for output, logs and the store. To be sized after the first full run against a real domain. | All | Phase 1 | No |

## 2. Project files

| ID | Requirement | Needed for | When | Verified |
|---|---|---|---|---|
| HR-FS-01 | `aPeDiscovery`, `aPeSecrets` and `LogaPe` checked out (or copied) as **sibling folders under one parent**, for example `C:\aPe\aPeDiscovery`, `C:\aPe\aPeSecrets`, `C:\aPe\LogaPe`. The scripts import the other two by relative path. | All | Now | Yes |
| HR-FS-02 | Matching versions of the three: each from `main` at the same point, or a tagged release once releases exist. | All | Now | No |
| HR-FS-03 | Repository files unblocked, so PowerShell doesn't treat them as downloaded from the internet. `Install-aPeDiscovery.ps1` does this; after a manual download, run `Get-ChildItem -Recurse | Unblock-File` on each folder. | All | Now | Dev |
| HR-FS-04 | The SQLite libraries in `aPeDiscovery\Lib\` (shipped in the repo; nothing to install), with their license files. | Store | Phase 1 | Dev |

## 3. PowerShell modules and tools

| ID | Requirement | Needed for | When | Verified |
|---|---|---|---|---|
| HR-MOD-01 | **ActiveDirectory module (RSAT).** Windows Server: `Install-WindowsFeature RSAT-AD-PowerShell`. Windows 10/11: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`. | AD | Now | No (not yet on PowerShell 7) |
| HR-MOD-02 | **Posh-SSH**, installed for all users so the scheduled task's account sees it: `Install-Module Posh-SSH -Scope AllUsers`. On an offline host, run `Save-Module` on a connected machine and copy the folder into `C:\Program Files\PowerShell\Modules\`. **Version:** the Linux security fixes (F1, F3) use SSH.NET's `SshCommand.CreateInputStream()` and `New-SSHSession -ErrorOnUntrusted`. Both were confirmed in **Posh-SSH 4.0.0** (SSH.NET 2025.1.0); older versions weren't checked, so treat 4.0.0 as the minimum until they are. | Linux | Now | Yes on 5.1 (older version); No on 7 |
| HR-MOD-03 | **Pester 5 or later.** Only needed to run the test suites, not for scanning. Leave it off production hosts. | Dev only | Now | Dev |
| HR-MOD-04 | Possibly the **Microsoft Visual C++ runtime** for the native SQLite library. The prototype ran on a development machine that may already have it; confirm on a clean host. | Store | Phase 1 | No |

## 4. CyberArk and credential sources

Install or configure only the sources your configs actually use.

| ID | Requirement | Needed for | When | Verified |
|---|---|---|---|---|
| HR-CA-01 | **CP:** the CyberArk Credential Provider installed on this host, with `CLIPasswordSDK.exe` at `C:\Program Files\CyberArk\ApplicationPasswordSdk\` (or `ClipasswordsdkPath` set), and the provider able to reach the Vault. | All (CP rows) | Now | Yes on 5.1 |
| HR-CA-02 | **CP:** each AppID authorized for this host, and given access to the Safes holding the scan accounts. If the AppID authenticates the calling application by **path or hash**, check whether running under `pwsh.exe` instead of `powershell.exe` changes what the provider sees; it may need re-authorizing. | All (CP rows) | Phase 1 | No |
| HR-CA-03 | **CCP:** HTTPS access to the CCP `BaseUrl`, and the CCP server's certificate trusted by this host. The AppID needs **CCP-side** authorization on each Safe; it's separate from CP-side authorization (a known `APPAP004E` cause). | All (CCP rows) | Now | Yes in aPeSecrets (2026-09-21), on 5.1 |
| HR-CA-04 | **CCP with client certificates:** the certificate in `LocalMachine\My` or `CurrentUser\My`, with its private key readable by the scheduled task's account. | All (CCP rows) | Now | No |
| HR-CA-05 | **Conjur:** HTTPS access to `ApplianceUrl`, a host identity (`AuthnLogin`), and its API key in a file (`ApiKeyPath`) readable **only** by the task account, or in an environment variable. | All (Conjur rows) | Now | No (never tested against a real Conjur) |
| HR-CA-06 | **PSCredential files:** created **by the task account, on this host** (`Get-Credential | Export-Clixml`). The encryption ties them to that account and machine, so files from another account or host can't be read. | All (PSCredential rows) | Now | Yes |
| HR-CA-07 | **Windows Credential Manager:** entries created **as the task account** on this host. | All (WCM rows) | Now | Yes in aPeSecrets |

## 5. Accounts and rights

| ID | Requirement | Needed for | When | Verified |
|---|---|---|---|---|
| HR-ACC-01 | **A dedicated task account** (for example `CONTOSO\svc-apediscovery`) to run the scheduled tasks. | All | Now | No |
| HR-ACC-02 | The task account has **"Log on as a batch job"** on this host. The task is registered with a stored password (`-LogonType Password`), not "Do not store password". Without a stored password, the account's encryption keys aren't available, so PSCredential files and Credential Manager entries can't be read. | All | Now | No |
| HR-ACC-03 | The task account can read `Config\`, and can write to the output, log and data folders (Section 7). | All | Now | No |
| HR-ACC-04 | **AD scan identity** (per domain, from the credential source): a domain account with ordinary read access. Some planned attributes are often restricted and may need delegated read rights: LAPS expiration dates, `msDS-User-Account-Control-Computed` (locked-out filter), `msDS-GroupMSAMembership`. | AD | Phase 1 | No |
| HR-ACC-05 | **Windows scan identity** (per computer): local Administrator on each target, or a domain account in its local Administrators group. Since Windows 10 1607 and Server 2016, Windows lets only administrators list local users and groups remotely, unless policy allows others. | Win | Now | No |
| HR-ACC-06 | **Windows scan identity using a *local* account** (not domain): Windows strips admin rights from local accounts connecting over the network, unless `LocalAccountTokenFilterPolicy` is set on the target. Prefer a domain account. | Win | Now | No |
| HR-ACC-07 | **Linux scan identity** (per computer): SSH login (password or key), plus sudo for the password-state, sudo-rights, listening-port, sshd and faillock data. `NOPASSWD` works directly; password-required sudo needs a password credential or `SudoCredentialSource`. Without sudo, those fields are left blank and the scan still succeeds. | Linux | Now | Yes on 5.1 |

## 6. Network access (from this host)

The full list, with detail for the firewall team, is in [Reference_Network-Firewall-Requirements.md](Reference_Network-Firewall-Requirements.md). That doc uses the same `HR-NET-*` IDs. Summary:

| ID | Destination | Port | Needed for | When | Verified |
|---|---|---|---|---|---|
| HR-NET-01 | Each domain's DCs: **AD Web Services** | TCP 9389 | AD | Now | No |
| HR-NET-02 | Each domain's DCs: CLDAP DC locator, only when a domain's `Server` isn't set (LDAP/LDAPS on TCP 389/636 aren't used) | UDP 389 | AD | Now | No |
| HR-NET-03 | DNS servers that resolve every scanned domain and target | UDP/TCP 53 | AD, Win | Now | No |
| HR-NET-04 | Each Windows target: SMB | TCP 445 | Win | Now | Yes |
| HR-NET-05 | Each Linux target: SSH | TCP 22 | Linux | Now | Yes |
| HR-NET-06 | CCP web service | TCP 443 | CCP rows | Now | Yes on 5.1 |
| HR-NET-07 | Conjur appliance or tenant | TCP 443 | Conjur rows | Now | No |
| HR-NET-08 | The Credential Provider's connection to the Vault (made by the provider service, not by the scripts) | TCP 1858 (default) | CP rows | Now | Yes |
| HR-NET-09 | Each database server's default port, when database detection is configured (probed only to report `Listening`) | Varies | Win | Now | Yes |
| HR-NET-10 | DCs of scanned domains and of target computers' domains: Kerberos | TCP/UDP 88 | AD, Win | Now | No |
| HR-NET-11 | GitHub (API, downloads, repository archives) | TCP 443 | Install/update | Now | Dev |
| HR-NET-12 | PowerShell Gallery | TCP 443 | Install/update | Now | Dev |
| HR-NET-13 | Windows Update or WSUS (RSAT on Windows 10/11) | TCP 443/80 | Install | Now | No |
| HR-NET-14 | Target MSSQL server | TCP 1433 | Store | Phase 3 | No |
| HR-NET-15 | Inbound to the web interface | TCP 443 | Web interface | Phase 4 | No |

## 7. Folders and storage

| ID | Requirement | Needed for | When | Verified |
|---|---|---|---|---|
| HR-DIR-01 | Output, log and archive folders, as set in the configs (`OutputDirectory`, `LogDirectory`). Today they default to under `OutputDirectory`. | All | Now | Yes |
| HR-DIR-02 | **The SQLite store on a local disk, not a network share.** SQLite's concurrent-access mode (WAL) only works when every process is on the same machine. | Store | Phase 1 | No |
| HR-DIR-03 | Permissions on `Config\`, the data folder, any API key or credential files, and the output: the task account and administrators only. The output lists privileged accounts and is sensitive. | All | Now | No |
| HR-DIR-04 | Backups of the store file. Back it up with the scripts stopped, or with SQLite's backup command; copying it mid-run can capture a half-written file. | Store | Phase 1 | No |

## 8. Security tooling and policy

| ID | Requirement | Needed for | When | Verified |
|---|---|---|---|---|
| HR-SEC-01 | The security team has reviewed [Reference_Security-Team-Brief.md](Reference_Security-Team-Brief.md): the accounts, the activity that looks like reconnaissance (EDR/IDS exceptions for this host and its accounts), the data sensitivity, and open findings F1–F7. | Win, Linux, AD | Now | No |
| HR-SEC-02 | **FIPS mode works** once the LogaPe FIPS fix is deployed (merged 2026-10-09). Not yet run on a host with FIPS enforced. | All | Now | No |
| HR-SEC-03 | The execution policy allows the scripts: the scheduled tasks pass `-ExecutionPolicy Bypass`, or the policy is `RemoteSigned` with the files unblocked (HR-FS-03). | All | Now | Yes |
| HR-SEC-04 | No secrets in configs, logs or the store. Configs hold only pointers to credential sources, and logs mask secret-looking text. Nothing to install, but review configs before deployment. | All | Now | Yes |

## 9. Scheduling

| ID | Requirement | Needed for | When | Verified |
|---|---|---|---|---|
| HR-SCH-01 | One scheduled task per search or export config, running as the task account (HR-ACC-01/02). Phase 1 tasks run `pwsh.exe` instead of `powershell.exe`. See [User_Docs/Scheduled-Task-Setup.md](../User_Docs/Scheduled-Task-Setup.md). | All | Now | No |
| HR-SCH-02 | Alerting on each task's exit code (`1` means at least one domain or computer failed). | All | Now | No |

## 10. Setup checklist

**Install and update with `Install-aPeDiscovery.ps1`** (repository root). Run it from an elevated Windows PowerShell 5.1 or PowerShell 7 session. It handles:
- PowerShell 7 (HR-OS-03);
- the three repositories, pinned to a commit and unblocked (HR-FS-01..03);
- Posh-SSH (HR-MOD-02);
- the ActiveDirectory module (HR-MOD-01).

It also reports whether the CyberArk Credential Provider is present (HR-CA-01). The same command updates an existing install. On a new host, download just the script first:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/JesseMcWilliams/aPeDiscovery/main/Install-aPeDiscovery.ps1 -OutFile .\Install-aPeDiscovery.ps1 -UseBasicParsing
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-aPeDiscovery.ps1 -InstallRoot C:\aPe
```

For hosts without internet access, build a bundle elsewhere with `-DownloadOnly -PackagePath <folder>`, copy it over, and install with `-PackagePath <folder>`. `Get-Help .\Install-aPeDiscovery.ps1 -Full` lists every option, including `-Ref` (a branch, tag or commit), `-Components` and `-WhatIf`.

The script doesn't cover accounts, CyberArk, folders, permissions or firewall rules (Sections 4–9). Afterwards, run these as the task account, from the `aPeDiscovery` folder:

```powershell
$PSVersionTable.PSVersion                                        # HR-OS-03: 7.6 or later
[Environment]::Is64BitOperatingSystem                            # HR-OS-01: True
'..\aPeSecrets\Modules\CredentialResolver.psm1', '..\LogaPe\LogaPe\LogaPe.psd1' | ForEach-Object { Test-Path $_ }   # HR-FS-01
Get-Module -ListAvailable ActiveDirectory, Posh-SSH | Select-Object Name, Version                                   # HR-MOD-01/02
Test-Path 'C:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe'                                     # HR-CA-01
Test-NetConnection <dc> -Port 9389; Test-NetConnection <windows-target> -Port 445; Test-NetConnection <linux-target> -Port 22   # HR-NET-*
```

Then run the matching `LT-*` tests in [Testing_Live-Test-Definitions.md](Testing_Live-Test-Definitions.md) against one domain and one computer of each type.

## 11. Still to confirm

| Item | IDs |
|---|---|
| Supported Windows versions for PowerShell 7.6 | HR-OS-02 |
| Disk sizing after a first full run | HR-OS-05 |
| Whether the native SQLite library needs the VC++ runtime | HR-MOD-04 |
| ActiveDirectory module and Posh-SSH on PowerShell 7 | HR-MOD-01/02 |
| CP AppID path/hash authentication under `pwsh.exe` | HR-CA-02 |
| Which AD attributes the scan identity can read without delegation | HR-ACC-04 |
| A run on a FIPS-enforced host | HR-SEC-02 |
