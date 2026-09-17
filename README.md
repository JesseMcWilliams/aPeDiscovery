# aPeDiscovery

PowerShell scripts that export Active Directory group/membership data and
per-computer local user/group/membership data to CSV, for import into another
tool. Designed to run unattended (nightly, via Scheduled Task) across multiple
domains — including domains with no trust relationship to the host running the
scripts — by resolving credentials per target from CyberArk (CP, CCP, or
Conjur) or a pre-exported `PSCredential` file, rather than relying on a single
identity.

## Scripts

- **Export-ADGroups.ps1** — reads `Config\ScanConfig.json`, scans one or more
  domains for groups (optionally scoped to a base OU and OU depth, with
  optional per-domain `ExcludeOUs`/`IncludeGroupCategories`/
  `IncludeGroupScopes`/`ExcludeGroupNames` filters), and writes
  `ADGroups.csv` / `ADGroupMembers.csv`.
- **Export-LocalGroups.ps1** — reads a list of computers from
  `Config\ComputersToScan.csv` (each row can point at a different credential
  source), scans them concurrently (throttled by `MaxConcurrency`, with a
  TCP-445 reachability check and optional `ExcludeUserNames`/
  `ExcludeGroupNames` filters), and writes `LocalUsers.csv` / `LocalGroups.csv`
  / `LocalGroupMembers.csv` / `LocalDatabases.csv` (known database engines
  recognized by Windows service name, each with a live check of whether its
  default port is actually listening) / `LocalSoftware.csv` (same mechanism,
  for any other software you configure via `SoftwareSignatures` — empty by
  default) / `LocalScanErrors.csv` (one row per computer that still failed
  after any configured `RetryCount` retries) / `LocalServiceAccounts.csv`
  (every service running as a real local/domain user or suspected gMSA/MSA —
  answers "what services run as this account" across the estate). Local
  accounts also get `PasswordLastSet`/`PasswordExpired`/`BadPasswordAttempts`
  in `LocalUsers.csv`. Two derived, filtered views are also written — every
  row in each still appears in its source file too: `LocalDatabasesListening.csv`
  (only `Listening = True` rows) and `LocalGmsaServiceAccounts.csv` (only
  `AccountType = LikelyGmsaOrMsa` rows, meant to feed a downstream AD
  cross-reference that flags any account not actually a real gMSA/MSA).

Both scripts:
- take direct membership only (no recursive/nested-group expansion — the
  downstream tool can walk nesting itself using the groups + members files);
- continue past a failed domain/computer, log the error, and exit `1` at the
  end if anything failed (so a Scheduled Task can alert on partial failure);
- write a stable, fixed-name set of CSVs (overwritten each run) plus a
  timestamped copy under `Output\Archive` for history, with a configurable
  retention count.

See [Docs/CSV-Schemas.md](Docs/CSV-Schemas.md) for exact column layouts and
[Docs/Configuration.md](Docs/Configuration.md) for every config/credential
option.

## Design documents

- [Docs/Design-AD-Discovery.md](Docs/Design-AD-Discovery.md) — implemented.
- [Docs/Design-Local-Windows-Discovery.md](Docs/Design-Local-Windows-Discovery.md) — implemented.
- [Docs/Design-Local-Linux-Discovery.md](Docs/Design-Local-Linux-Discovery.md) — proposed, not yet
  built. Connectivity is decided (`Posh-SSH`, verified live); still open: shared vs. separate
  input/output files with the Windows tool, default host-key trust policy, and validation against a
  real SSH target (none was available in this environment).

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
3. Run a single domain/computer first to validate credentials before scanning
   everything:
   ```powershell
   .\Export-ADGroups.ps1 -DomainFilter 'contoso.com'
   .\Export-LocalGroups.ps1 -ComputerFilter 'SRV-APP01'
   ```
4. Once validated, wire both scripts into Scheduled Tasks — see
   [Docs/Scheduled-Task-Setup.md](Docs/Scheduled-Task-Setup.md).

## Repository layout

```
Export-ADGroups.ps1        Domain group + membership export
Export-LocalGroups.ps1     Per-computer local user/group/membership discovery
Modules\
  CredentialResolver.psm1     CurrentUser / PSCredential / CP / CCP / Conjur resolution
  ADHelpers.psm1              OU-depth-scoped search helper
  Logging.psm1                Shared timestamped file+console logging (thread-safe)
  NetworkHelpers.psm1         TCP-connect reachability probe
  LocalComputerScanner.psm1   Per-computer local user/group/membership scan (run in a runspace pool)
Config\
  ScanConfig.example.json          Template for Export-ADGroups.ps1
  ComputersToScan.example.csv      Template for Export-LocalGroups.ps1 input
  LocalScanConfig.example.json     Template for Export-LocalGroups.ps1 run settings
Docs\
  Configuration.md                     Full config/credential-source reference
  CSV-Schemas.md                       Output column reference
  Scheduled-Task-Setup.md              Unattended scheduling guidance
  Design-AD-Discovery.md               Design doc - AD group export (implemented)
  Design-Local-Windows-Discovery.md    Design doc - local Windows discovery (implemented)
  Design-Local-Linux-Discovery.md      Design doc - local Linux discovery (proposed)
Output\                     Default (gitignored) output/log/archive location
```

`Config\*.json` and `Config\ComputersToScan.csv` (the real, non-`.example`
files) are gitignored since they carry real domain/computer names and
credential-source parameters — commit only the `.example` templates.

## Known limitations / things to verify for your environment

- **CP/CCP/Conjur integration** implements each product's documented calling
  convention (`CLIPasswordSDK.exe`, the CCP `AIMWebService` REST API, Conjur's
  `authn` + `secrets` REST API), but exact details vary by product version and
  environment (install paths, web service virtual directory names, TLS/cert
  requirements). Validate against your own deployment before production use —
  see the note at the top of [Modules\CredentialResolver.psm1](Modules/CredentialResolver.psm1).
- **AD's 1,500-value range limit** on the `member` attribute can make
  `MemberCount` (and the raw-DN membership fallback path) incomplete for
  groups with very large direct membership; the primary membership-resolution
  path (`Get-ADGroupMember`) is not affected.
- **DN parsing for OU depth** treats a comma preceded by `\` as an escaped
  literal rather than a component separator, which covers the common case of
  commas inside OU/CN names but is not a full LDAP DN parser.
- `Export-ADGroups.ps1` still scans domains sequentially (no concurrency).
  `Export-LocalGroups.ps1` scans computers concurrently via `MaxConcurrency`,
  but launches one `PowerShell` instance per computer up front rather than
  trickling them in — fine at the scale this has been tested at, worth
  revisiting for a single run covering tens of thousands of computers.
- Local Windows discovery deliberately does not resolve primary-group
  membership (tested live: local accounts' `primaryGroupID` resolves to no
  real local group, so the column would be blank almost everywhere) or
  distinguish GPO-managed local admin membership from manually-set membership
  (the tool already captures the effective result either way) — see
  [Docs/Design-Local-Windows-Discovery.md](Docs/Design-Local-Windows-Discovery.md)
  §7 for the reasoning behind both decisions.
- Database and software detection only recognize the specific service-name
  patterns configured in `DatabaseSignatures` (SQL Server, MySQL, MariaDB,
  PostgreSQL, Oracle, MongoDB by default) and `SoftwareSignatures` (empty by
  default — see [Docs/Configuration.md](Docs/Configuration.md#database-and-other-software-detection)
  for the steps to add your own). Anything outside those lists, or installed
  with unusual service naming, won't be detected. `Listening = False` does not
  mean "not installed" (confirmed live: a `Running` SQL Server showed
  `Listening = False`, likely TCP/IP protocol disabled), and a listening port
  doesn't guarantee it's actually that engine/software.
- **`DatabaseSignatures`/`SoftwareSignatures` in config replace the built-in
  default list rather than merging with it** — adding one engine to the
  defaults means copying the full default list into your config first (see
  Configuration.md).
- **`PasswordLastSet` is approximate**, derived from the target's own
  `PasswordAge` applied against the scanning host's clock — fine for spotting
  a stale password, not precise to the minute given ordinary clock skew.
- **Retry (`RetryCount`) re-runs the entire per-computer scan**, not just the
  step that failed, and `LocalScanErrors.csv` records only the final outcome
  per computer, not one row per attempt (per-attempt detail is in the log).
- **`LocalServiceAccounts.csv`'s gMSA/MSA flag is a naming-convention
  heuristic** (a trailing `$`), not an authoritative AD lookup — see
  [Docs/Configuration.md](Docs/Configuration.md#service-account-discovery).
  This file always lists every non-built-in/non-virtual service account
  across the estate; there's currently no way to narrow it to specific
  account name(s) of interest.
- Scheduled Task Run As credential storage, secrets-at-rest for
  `ApiKeyPath`/`CredentialFilePath` files, and file-system ACLs on
  `Config\`/`Output\`/any secrets directory are the operator's
  responsibility — this project does not manage those.
