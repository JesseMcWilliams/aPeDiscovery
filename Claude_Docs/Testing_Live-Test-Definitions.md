# aPeDiscovery: Live Test Definitions

> **Stage: Testing.** Repeatable live tests against a real environment, each with a short label. This file is tracked, so it holds **no lab details**: every environment-specific value is a `{Placeholder}`. The gitignored `Live-Testing.local.md` supplies the values for each environment and lists which labels to run. Live tests run only when asked (see CLAUDE.md, "Live testing").

## How to use
1. Pick a label below and an environment from `Live-Testing.local.md`.
2. Replace each `{Placeholder}` with that environment's value.
3. Run the command from the repo root, and check every "Pass when" item.
4. Record the result (date, pass/fail) in `Live-Testing.local.md`'s "Tests to run" table, and in the matching `Testing_` checklist row if the project has one.

Every test runs against the real, gitignored `Config\` files (`ScanConfig.json`, `ComputersToScan.csv`, `LinuxComputersToScan.csv`, and the matching `*ScanConfig.json`), narrowed with `-DomainFilter`/`-ComputerFilter`. The sibling `..\aPeSecrets` and `..\LogaPe` checkouts must be present. "Latest log" means `Get-ChildItem '<dir>\Logs\*.log' | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content`.

## Placeholders

| Placeholder | Meaning | Example (fake) |
|---|---|---|
| `{Shell}` | The PowerShell edition to run under: `powershell.exe -NoProfile -ExecutionPolicy Bypass` (5.1) or `pwsh -NoProfile` (7) | `pwsh -NoProfile` |
| `{ScratchDir}` | A scratch folder outside the repo, for generated input files | `C:\Temp\live-test` |
| `{Domain}` | A `DomainName` in `ScanConfig.json` with a `Computers` block | `contoso.com` |
| `{AdOutputDir}` | `OutputDirectory` from `ScanConfig.json` | `C:\aPeDiscovery\Output\AD` |
| `{WinHost}` | A Windows `ComputerName` row in `ComputersToScan.csv` that scans successfully | `SRV-APP01` |
| `{WinOutputDir}` | `OutputDirectory` from `LocalScanConfig.json` | `C:\aPeDiscovery\Output\Local` |
| `{UnreachableHost}` | A `ComputersToScan.csv` row name with nothing listening on 445 | `SRV-GONE01` |
| `{CcpWinHost}` | A `ComputersToScan.csv` row whose `CredentialSource` is `CCP` | `SRV-APP02` |
| `{ConjurWinHost}` | A `ComputersToScan.csv` row whose `CredentialSource` is `Conjur` | `SRV-APP03` |
| `{LinuxHost}` | A `LinuxComputersToScan.csv` row: sudo-capable connecting account, pam_faillock enabled | `lnx-app01.contoso.com` |
| `{LinuxOutputDir}` | `OutputDirectory` from `LinuxScanConfig.json` | `C:\aPeDiscovery\Output\Linux` |
| `{FaillockUser}` | A disposable local account on `{LinuxHost}` used to generate failed logins | `svc_example` |
| `{FailCount}` | How many wrong-password attempts to make; must stay below `deny` in `/etc/security/faillock.conf` | `2` |
| `{LinuxNoFaillockHost}` | A `LinuxComputersToScan.csv` row whose PAM stack has no `pam_faillock` | `lnx-app02.contoso.com` |
| `{LinuxKeySudoHost}` | A `LinuxComputersToScan.csv` row with `KeyFilePath` **and** `SudoCredentialSource` set; its account needs password-required sudo | `lnx-app03.contoso.com` |
| `{LinuxDbHost}` | A `LinuxComputersToScan.csv` row running MySQL, MariaDB or MongoDB | `lnx-db01.contoso.com` |
| `{InstallRoot}` | Install folder for `Install-aPeDiscovery.ps1` | `C:\aPe` |
| `{DbEngine}` | The engine installed on `{LinuxDbHost}`, as `Engine` appears in `Get-DefaultLinuxDatabaseSignatures` | `MySQL/MariaDB` |

## Tests

### AD discovery (`Export-ADObjects.ps1`)

#### LT-AD-01: Group and membership export for one domain
Proves credential resolution, OU scoping and the group/member CSVs against a real DC.

```powershell
{Shell} -File .\Export-ADObjects.ps1 -DomainFilter '{Domain}'; $LASTEXITCODE
```

- **Pass when:** exit code is 0; `{AdOutputDir}\ADGroups.csv` and `ADGroupMembers.csv` have rows, all with `DomainName` = `{Domain}`; the latest log under `{AdOutputDir}` has no `| Error |` lines.

#### LT-AD-02: Computer object discovery
Closes the open item "ADComputers.csv has never been tested against a live DC". Needs a `Computers` block on `{Domain}` (start with `{}`).

```powershell
{Shell} -File .\Export-ADObjects.ps1 -DomainFilter '{Domain}'; $LASTEXITCODE
Import-Csv '{AdOutputDir}\ADComputers.csv' | Select-Object ComputerName, OperatingSystem, LastLogonTimestamp -First 10 | Format-Table
```

- **Pass when:** exit code is 0; `ADComputers.csv` has one row per computer object (spot-check the count against `(Get-ADComputer -Filter * -Server {Domain}).Count` run with the same credential); `ComputerName` has no trailing `$`; `LastLogonTimestamp` is a real date, not a large integer.
- **Notes:** then set `NameFilter`/`OSTypeFilter` and re-run, per Testing_Guide.md 1.4.

### Local Windows discovery (`Export-LocalGroups.ps1`)

#### LT-WIN-01: Single-host scan and LogaPe log format
Proves the scan and the LogaPe-based run log.

```powershell
{Shell} -File .\Export-LocalGroups.ps1 -ComputerFilter '{WinHost}'; $LASTEXITCODE
```

- **Pass when:** exit code is 0; `{WinOutputDir}\LocalUsers.csv`, `LocalGroups.csv` and `LocalGroupMembers.csv` have rows for `{WinHost}`; the newest file in `{WinOutputDir}\Logs` is named `Export-LocalGroups_<yyyyMMdd_HHmmss>.log` and its lines read `<timestamp> | Information | ...`, including `Completed scan of '{WinHost}'`.

#### LT-WIN-02: Unreachable host and retry
Proves the failure path: retries, error CSV row, non-zero exit. Set `RetryCount` to 1 or more first.

```powershell
{Shell} -File .\Export-LocalGroups.ps1 -ComputerFilter '{UnreachableHost}'; $LASTEXITCODE
```

- **Pass when:** exit code is 1; `LocalScanErrors.csv` has exactly one row for `{UnreachableHost}` mentioning port 445; the latest log has one `| Warning |` attempt line per retry, then one `| Error |` line for that host.

#### LT-WIN-03: Concurrent scans and log integrity
Proves runspaces don't share state, and that LogaPe serializes their log writes. Needs `MaxConcurrency` 3 or more.

```powershell
$row = Import-Csv .\Config\ComputersToScan.csv | Where-Object ComputerName -eq '{WinHost}'
1..3 | ForEach-Object { $row } | Export-Csv '{ScratchDir}\win-dup.csv' -NoTypeInformation
{Shell} -File .\Export-LocalGroups.ps1 -ComputersCsvPath '{ScratchDir}\win-dup.csv'; $LASTEXITCODE
```

- **Pass when:** exit code is 0; `LocalUsers.csv` has exactly 3x the rows LT-WIN-01 produced; the latest log has three `Starting scan of computer '{WinHost}'` lines within about a second of each other, and every line starts with a timestamp (no split or merged lines).

### Local Linux discovery (`Export-LocalLinuxGroups.ps1`)

#### LT-LNX-01: Single-host scan
Baseline for the other LT-LNX tests.

```powershell
{Shell} -File .\Export-LocalLinuxGroups.ps1 -ComputerFilter '{LinuxHost}'; $LASTEXITCODE
```

- **Pass when:** exit code is 0; `{LinuxOutputDir}\LinuxLocalUsers.csv` row count equals the line count of `/etc/passwd` on `{LinuxHost}`; every row has a non-blank `PasswordState`; the latest log has no `| Warning |` lines about shadow, sshd or pam_faillock data.

#### LT-LNX-02: BadPasswordAttempts counts failures
Proves the pam_faillock tally is read and attributed per account. Run after LT-LNX-01 passes.

1. From any machine, run `ssh {FaillockUser}@{LinuxHost}` and enter a wrong password (for example `ThisIsMy_FAKE_Password6!`) `{FailCount}` times.
2. Run:

```powershell
{Shell} -File .\Export-LocalLinuxGroups.ps1 -ComputerFilter '{LinuxHost}'; $LASTEXITCODE
Import-Csv '{LinuxOutputDir}\LinuxLocalUsers.csv' | Select-Object UserName, BadPasswordAttempts | Format-Table
```

- **Pass when:** exit code is 0; `{FaillockUser}` shows `{FailCount}`, matching `sudo faillock --user {FaillockUser}` on the host; accounts with no failures show `0`, not blank. After `sudo faillock --user {FaillockUser} --reset` on the host, a re-run shows `0`.
- **Notes:** reaching `deny` locks `{FaillockUser}` for `unlock_time`; reset it with the same `--reset` command.

#### LT-LNX-03: BadPasswordAttempts blank without pam_faillock
Proves "not tracked" is reported as blank, not as 0.

```powershell
{Shell} -File .\Export-LocalLinuxGroups.ps1 -ComputerFilter '{LinuxNoFaillockHost}'; $LASTEXITCODE
Import-Csv '{LinuxOutputDir}\LinuxLocalUsers.csv' | Group-Object { [string]::IsNullOrEmpty($_.BadPasswordAttempts) } | Format-Table Name, Count
```

- **Pass when:** exit code is 0; every row's `BadPasswordAttempts` is blank (a single `True` group); the latest log has one `| Warning |` line saying pam_faillock tally data is unavailable for that host.

#### LT-LNX-04: Key auth with SudoCredentialSource elevation
Closes the open item "SudoCredentialSource override implemented but not verified live".

```powershell
{Shell} -File .\Export-LocalLinuxGroups.ps1 -ComputerFilter '{LinuxKeySudoHost}'; $LASTEXITCODE
```

- **Pass when:** exit code is 0; every `LinuxLocalUsers.csv` row has a non-blank `PasswordState`; the latest log has no `sudo elevation was not established` and no `failed to resolve SudoCredentialSource` warning.

#### LT-LNX-05: Non-PostgreSQL database signatures
Closes the open item "MySQL/MariaDB/MongoDB DatabaseSignatures are unverified".

```powershell
{Shell} -File .\Export-LocalLinuxGroups.ps1 -ComputerFilter '{LinuxDbHost}'; $LASTEXITCODE
Import-Csv '{LinuxOutputDir}\LinuxDatabases.csv' | Format-Table Engine, UnitName, Status, Listening
```

- **Pass when:** exit code is 0; a row with `Engine` = `{DbEngine}` appears, with the unit name `systemctl list-units --type=service` shows on the host; `Listening` matches `sudo ss -tlnp` on the host for the default port.
- **Notes:** if the row is missing, compare the host's real unit name with the `UnitPattern` in `Get-DefaultLinuxDatabaseSignatures`, and fix the default.

### Credential sources (via `..\aPeSecrets`)

#### LT-CRED-01: CCP credential source end to end
Closes half of the open item "CCP and Conjur remain unverified against a real deployment".

```powershell
{Shell} -File .\Export-LocalGroups.ps1 -ComputerFilter '{CcpWinHost}'; $LASTEXITCODE
```

- **Pass when:** exit code is 0 and `LocalUsers.csv` has rows for `{CcpWinHost}`. A failure in credential resolution (not connectivity) is an aPeSecrets bug: record the error text and fix it there.

#### LT-CRED-02: Conjur credential source end to end
The other half of the same open item.

```powershell
{Shell} -File .\Export-LocalGroups.ps1 -ComputerFilter '{ConjurWinHost}'; $LASTEXITCODE
```

- **Pass when:** same as LT-CRED-01, for `{ConjurWinHost}`.

### Installation (`Install-aPeDiscovery.ps1`)

#### LT-INST-01: Install on a clean host, then update
Proves the elevated install paths: PowerShell 7 MSI, Posh-SSH for all users, and RSAT. Needs a clean Windows host (a VM snapshot is ideal) and an elevated session. `{InstallRoot}` is the install folder, for example `C:\aPe`.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-aPeDiscovery.ps1 -InstallRoot '{InstallRoot}'; $LASTEXITCODE
& "$env:ProgramFiles\PowerShell\7\pwsh.exe" -NoProfile -Command '$PSVersionTable.PSVersion; Get-Module -ListAvailable Posh-SSH, ActiveDirectory | Select-Object Name, Version'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-aPeDiscovery.ps1 -InstallRoot '{InstallRoot}'; $LASTEXITCODE
```

- **Pass when:**
  - the first run exits 0, with PowerShell 7, the three repositories, Posh-SSH and the ActiveDirectory module all `Installed`;
  - `pwsh` reports 7.6 or later, and lists Posh-SSH and ActiveDirectory;
  - the second run exits 0 with every component `UpToDate`;
  - `{InstallRoot}\InstallLogs` has a transcript per run, plus the MSI log.
- **Notes:** repeat once with `-DownloadOnly -PackagePath` on a connected machine, then `-PackagePath` on an offline host. On Windows 10/11 without Windows Update, pass `-FeatureSource`.

## Adding a test
- Group tests under a heading, and give each one the next label in its group (`LT-<GROUP>-<NN>`, for example `LT-LOGON-01`). Never reuse or renumber a label: `Live-Testing.local.md` refers to it.
- Use placeholders for every environment-specific value. Put real values only in `Live-Testing.local.md`.
- Each test needs a runnable command and concrete "Pass when" items, so it can be repeated by anyone, or by Claude, without rediscovering the steps.
- A password placeholder, if one is ever needed in an example, is `ThisIsMy_FAKE_Password6!`.
