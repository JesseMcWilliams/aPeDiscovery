# aPeDiscovery

PowerShell scripts that export Active Directory group/membership data and
per-computer local user/group/membership data to CSV, for import into another
tool. Designed to run unattended (nightly, via Scheduled Task) across multiple
domains — including domains with no trust relationship to the host running the
scripts — by resolving credentials per target from CyberArk (CP, CCP, or
Conjur) or a pre-exported `PSCredential` file, rather than relying on a single
identity. Credential resolution itself lives in the sibling
[aPeSecrets](../aPeSecrets) project (`Modules\CredentialResolver.psm1`,
`Get-ResolvedCredential`) — this repo depends on it rather than carrying its
own copy.

## Features

- **Export-ADGroups.ps1** — AD group/membership export, with optional per-domain computer object discovery.
- **Export-LocalGroups.ps1** — per-computer local Windows user/group/membership export, plus database/software/service-account detection.
- **Export-LocalLinuxGroups.ps1** — per-computer local Linux user/group/membership export over SSH, plus sudo rights discovery/elevation and database/software/service-account detection.
- All three scan concurrently, continue past a failed domain/computer (logging the error and exiting `1` at the end if anything failed, so a Scheduled Task can alert), and write a stable fixed-name CSV set plus a timestamped archive copy.

See [Claude_Docs/Reference_CSV-Schemas.md](Claude_Docs/Reference_CSV-Schemas.md) for the full per-script/per-file breakdown and exact column layouts.

## Prerequisites

- Windows PowerShell 5.1 (or PowerShell 7+).
- **Export-ADGroups.ps1** requires the RSAT `ActiveDirectory` PowerShell
  module on the host running it, and network line-of-sight to a DC in each
  target domain (a trust relationship is not required — only `-Server` +
  explicit credentials are used).
- **Export-LocalGroups.ps1** requires no AD module; it talks to each target
  computer directly via the ADSI WinNT provider, which needs RPC/SAM
  connectivity (the same access Computer Management's "Local Users and
  Groups" snap-in needs against a remote machine) rather than WinRM. It scans
  computers concurrently via a `RunspacePool` (no extra module dependency,
  works on both PowerShell 5.1 and 7+), throttled by `MaxConcurrency`.
- **Export-LocalLinuxGroups.ps1** requires the `Posh-SSH` PowerShell module
  (`Install-Module Posh-SSH`) on the host running it, and SSH (port 22)
  connectivity to each target. It scans computers concurrently via the same
  kind of `RunspacePool` as `Export-LocalGroups.ps1`, throttled by
  `MaxConcurrency`. Sudo-derived fields (`PasswordState`/`PasswordLastSet`/
  `PasswordNeverExpires`, and any sudo rights beyond "no access") need the
  connecting account to have usable `sudo` rights on the target; without it,
  those fields/rows are simply left blank rather than failing the scan.
- For `CP`/`CCP`/`Conjur` credential sources: the relevant CyberArk client
  component installed/reachable from the host running the scripts (the
  Credential Provider for `CP`, network access to the CCP web service for
  `CCP`, network access to the Conjur appliance/Follower for `Conjur`).

## Quick start

1. Copy `Config\ScanConfig.example.json` to `Config\ScanConfig.json` and edit
   the `Domains` list.
2. Copy `Config\ComputersToScan.example.csv` to `Config\ComputersToScan.csv`
   and `Config\LocalScanConfig.example.json` to
   `Config\LocalScanConfig.json`, and edit both.
3. For Linux targets, copy `Config\LinuxComputersToScan.example.csv` to
   `Config\LinuxComputersToScan.csv` and `Config\LinuxScanConfig.example.json`
   to `Config\LinuxScanConfig.json`, and edit both.
4. Run a single domain/computer first to validate credentials before scanning
   everything:
   ```powershell
   .\Export-ADGroups.ps1 -DomainFilter 'contoso.com'
   .\Export-LocalGroups.ps1 -ComputerFilter 'SRV-APP01'
   .\Export-LocalLinuxGroups.ps1 -ComputerFilter 'lnx-app01.contoso.com'
   ```
5. Once validated, wire the scripts into Scheduled Tasks — see
   [User_Docs/Scheduled-Task-Setup.md](User_Docs/Scheduled-Task-Setup.md).

## Repository layout

```
Export-ADGroups.ps1            Domain group + membership export
Export-LocalGroups.ps1         Per-computer local Windows user/group/membership discovery
Export-LocalLinuxGroups.ps1    Per-computer local Linux user/group/membership/sudo-rights discovery
Modules\
  ADHelpers.psm1                 OU-depth-scoped search helper
  Logging.psm1                   Shared timestamped file+console logging (thread-safe)
  NetworkHelpers.psm1            TCP-connect reachability probe
  LocalComputerScanner.psm1      Per-computer local Windows scan (run in a runspace pool)
  LocalLinuxComputerScanner.psm1 Per-computer local Linux scan over SSH (run in a runspace pool)
Config\
  ScanConfig.example.json                Template for Export-ADGroups.ps1
  ComputersToScan.example.csv            Template for Export-LocalGroups.ps1 input
  LocalScanConfig.example.json           Template for Export-LocalGroups.ps1 run settings
  LinuxComputersToScan.example.csv       Template for Export-LocalLinuxGroups.ps1 input
  LinuxScanConfig.example.json           Template for Export-LocalLinuxGroups.ps1 run settings
Claude_Docs\
  Reference_Configuration.md                     Full config/credential-source reference
  Reference_CSV-Schemas.md                       Script/output column reference
  Testing_Guide.md                     Step-by-step validation procedures for every feature
  Planning_Open-Items.md                        Project-wide backlog: open decisions, unbuilt features, verification gaps
  Design_AD-Discovery.md               Design doc - AD group export (implemented)
  Design_Local-Windows-Discovery.md    Design doc - local Windows discovery (implemented)
  Design_Local-Linux-Discovery.md      Design doc - local Linux discovery, plus split-out
                                        Sudo-Elevation/Data-Model docs (mostly implemented)
User_Docs\
  Scheduled-Task-Setup.md              Unattended scheduling guidance
Output\                     Default (gitignored) output/log/archive location
```

Credential resolution (`CredentialResolver.psm1`, `Get-ResolvedCredential`) lives in the sibling
[..\aPeSecrets](../aPeSecrets) project, not in this repo's own `Modules\` — every script here
imports it via a relative `..\aPeSecrets\Modules\CredentialResolver.psm1` path, so both projects
need to stay checked out as siblings under the same parent folder.

`Config\*.json` and `Config\ComputersToScan.csv`/`Config\LinuxComputersToScan.csv`
(the real, non-`.example` files) are gitignored since they carry real
domain/computer names and credential-source parameters — commit only the
`.example` templates.

## Documentation

- [Claude_Docs/Reference_CSV-Schemas.md](Claude_Docs/Reference_CSV-Schemas.md) — per-script behavior and exact output column layouts.
- [Claude_Docs/Reference_Configuration.md](Claude_Docs/Reference_Configuration.md) — every config/credential option, plus known limitations and things to verify for your environment.
- [Claude_Docs/Testing_Guide.md](Claude_Docs/Testing_Guide.md) — step-by-step validation procedures for every feature.
- [Claude_Docs/Planning_Open-Items.md](Claude_Docs/Planning_Open-Items.md) — current project-wide backlog.
- [User_Docs/Scheduled-Task-Setup.md](User_Docs/Scheduled-Task-Setup.md) — unattended scheduling setup.
- Design documents (how each discovery target works):
  - [Claude_Docs/Design_AD-Discovery.md](Claude_Docs/Design_AD-Discovery.md) — implemented.
  - [Claude_Docs/Design_Local-Windows-Discovery.md](Claude_Docs/Design_Local-Windows-Discovery.md) — implemented.
  - [Claude_Docs/Design_Local-Linux-Discovery.md](Claude_Docs/Design_Local-Linux-Discovery.md) — Phases 1-5
    implemented and verified live against a real Ubuntu VM (see also its split-out
    [Sudo-Elevation](Claude_Docs/Design_Local-Linux-Discovery-Sudo-Elevation.md) and
    [Data-Model](Claude_Docs/Design_Local-Linux-Discovery-Data-Model.md) docs).
    `BadPasswordAttempts` remains designed but not yet built — the only unbuilt item left.
