# Configuration reference

## ScanConfig.json (used by Export-ADGroups.ps1)

Top level:

| Property | Required | Description |
|---|---|---|
| `OutputDirectory` | Yes | Where `ADGroups.csv` / `ADGroupMembers.csv` / `ADComputers.csv` and the `Archive`/`Logs` subfolders are written. |
| `LogDirectory` | No | Defaults to `<OutputDirectory>\Logs`. |
| `ArchiveRetentionCount` | No | Timestamped CSV copies kept per file in `Archive`. Defaults to 30. |
| `Domains` | Yes | Array of domain entries, described below. |

Each entry in `Domains`:

| Property | Required | Description |
|---|---|---|
| `DomainName` | Yes | FQDN of the domain. Used as the `DomainName` column in the CSV output and for `-DomainFilter` matching. |
| `Server` | No | Explicit DC/GC to target. Defaults to `DomainName`. Set this explicitly for domains with no trust to the host running the script, since domain-name-based DC lookup can otherwise fail. |
| `Enabled` | No | Set to `false` to keep an entry in the file but skip it. Defaults to `true`. |
| `BaseOU` | No | Distinguished name to start scanning from. Defaults to the domain's root DN (the whole domain). |
| `OUDepth` | No | How many OU levels below `BaseOU` to descend into. `0` = only `BaseOU` itself, `1` = `BaseOU` + its immediate child OUs, etc. `-1` (default) = unlimited. |
| `ExcludeOUs` | No | Array of OU distinguished names to skip — a listed OU and everything under it is excluded, even if it falls within `BaseOU`/`OUDepth`. Useful for skipping a specific sub-tree (e.g. a "Disabled Accounts" OU) without having to lower `OUDepth` for the whole domain. |
| `IncludeGroupCategories` | No | Array restricting output to these `GroupCategory` values only: `Security`, `Distribution`. Omit (or leave empty) to include both. |
| `IncludeGroupScopes` | No | Array restricting output to these `GroupScope` values only: `DomainLocal`, `Global`, `Universal`. Omit (or leave empty) to include all three. |
| `ExcludeGroupNames` | No | Array of exact names or `-like` wildcard patterns (`*`, `?`) matched against each group's `SamAccountName`. Any match excludes the group from both `ADGroups.csv` and `ADGroupMembers.csv`. Useful for noisy built-ins (`Domain Users`, `Domain Computers`) or naming-convention test groups (`*-Test-*`). |
| `Computers` | No | Object enabling computer-object discovery for this domain — see below. Omit entirely to skip computer discovery for this domain (the default); an empty object (`{}`) enables it with defaults. |
| `CredentialSource` | Yes | One of `CurrentUser`, `PSCredential`, `CP`, `CCP`, `Conjur`. |
| `CredentialParams` | Depends on source | See "Credential sources" below. |

`IncludeGroupCategories`/`IncludeGroupScopes`/`ExcludeGroupNames` are all applied together (a group must pass every filter that's set to be included), evaluated in that order, per group, after it's read from AD — an invalid value in `IncludeGroupCategories` or `IncludeGroupScopes` (a typo, e.g. `"Securty"`) fails that domain's run immediately with a clear error rather than silently matching nothing.

### Computer object discovery (`Computers`)

Opt-in per domain (Section header above) — presence of the `Computers` property enables it, its
absence skips it entirely for that domain, so existing configs written before this feature keep
working unchanged. Output goes to `ADComputers.csv`, one row per computer object found.

| Property | Required | Description |
|---|---|---|
| `BaseOU` | No | Distinguished name to start scanning from — **independent of the domain entry's own `BaseOU`**, since computer objects are commonly organized under a different part of the tree than groups (e.g. `OU=Servers`/`OU=Workstations` vs. `OU=Groups`). Defaults to the domain's root DN. |
| `OUDepth` | No | Same semantics as the domain entry's `OUDepth`, applied to the computer scan's own `BaseOU`. `-1` (default) = unlimited. |
| `ExcludeOUs` | No | Same semantics as the domain entry's `ExcludeOUs`, applied to the computer scan's own OU tree. |
| `NameFilter` | No | Array of exact names or `-like` wildcard patterns, matched against the computer's name with its trailing `$` stripped (e.g. `SRV-APP01`, not `SRV-APP01$`). A computer is included only if it matches **at least one** pattern. Omit (or leave empty) to include all computers found. |
| `OSTypeFilter` | No | Array of exact values or `-like` wildcard patterns, matched against AD's `operatingSystem` attribute (e.g. `"Windows Server*"`, `"*Linux*"`). Same "match at least one" logic as `NameFilter`. **This attribute is self-reported by the computer at domain-join time and only refreshed periodically** — it can be blank (never populated) or stale (doesn't reflect an OS upgrade that didn't trigger a refresh), not a live, verified fact. |

`NameFilter` and `OSTypeFilter` are both applied (a computer must pass every filter that's set),
evaluated after the object is read from AD, the same "include only if it matches" logic as the
group filters above use for exclusion — just inverted, since these are inclusion filters rather than
exclusions.

## LocalScanConfig.json (used by Export-LocalGroups.ps1)

| Property | Required | Description |
|---|---|---|
| `OutputDirectory` | Yes | Where `LocalUsers.csv` / `LocalGroups.csv` / `LocalGroupMembers.csv` and the `Archive`/`Logs` subfolders are written. |
| `LogDirectory` | No | Defaults to `<OutputDirectory>\Logs`. |
| `ArchiveRetentionCount` | No | Defaults to 30. |
| `MaxConcurrency` | No | How many computers to scan at once, via a throttled runspace pool. Defaults to `1` (fully sequential — the original behavior). Must be `1` or greater. |
| `ConnectTimeoutMs` | No | Timeout for the TCP port-445 reachability check, in milliseconds. Defaults to `2000`. |
| `RetryCount` | No | Additional attempts for a computer that fails, before giving up on it. Defaults to `0` (no retry — the original behavior). Each retry re-runs the entire per-computer scan from the reachability check onward; any rows a partial earlier attempt collected are discarded first. |
| `RetryDelaySeconds` | No | Delay between retry attempts. Defaults to `5`. Ignored when `RetryCount` is `0`. |
| `ExcludeUserNames` | No | Array of exact names or `-like` wildcard patterns (`*`, `?`) matched against each local account's name. Any match excludes that account from `LocalUsers.csv`. Useful for built-ins that are rarely interesting (`DefaultAccount`, `WDAGUtilityAccount`, `Guest`). |
| `ExcludeGroupNames` | No | Array of exact names or wildcard patterns matched against each local group's name. Any match excludes that group from both `LocalGroups.csv` and `LocalGroupMembers.csv`. |
| `DatabaseSignatures` | No | Array of `{ Engine, ServicePattern, DefaultPort }` used to recognize a database engine from its Windows service name and, when `DefaultPort` isn't `null`, probe that port on the same computer. Omit to use the built-in list (`Modules\LocalComputerScanner.psm1`'s `Get-DefaultDatabaseSignatures` — the same list shown in `LocalScanConfig.example.json`); provide your own array to **replace** (not merge with) that built-in list — see "Adding a new signature" below. `ServicePattern` is matched with `-like` against the service's short name (e.g. `MSSQLSERVER`), not its display name. |
| `SoftwareSignatures` | No | Array of `{ Name, Category, ServicePattern, DefaultPort }`, same matching mechanism as `DatabaseSignatures`, for recognizing any other software by its Windows service name. Unlike `DatabaseSignatures`, there is **no built-in default** — omit it (or leave it empty) and nothing is checked. `DefaultPort` may be `null` for software with no fixed listening port. |

These apply globally, to every computer in `ComputersToScan.csv` — there is currently no per-computer override.

### Database and other-software detection

`Export-LocalGroups.ps1` reuses the same WinNT bind already open for users/groups to also read each
computer's Windows services (confirmed live: the WinNT provider's `Children` collection includes
`Service`-class objects alongside `user`/`group`, with no extra connectivity or credential needed),
and matches each service's short name against two independent signature lists:

- **`DatabaseSignatures`** → `LocalDatabases.csv`, one row per matched database engine service.
- **`SoftwareSignatures`** → `LocalSoftware.csv`, one row per matched other-software service. Empty
  by default (see above) — this is meant for whatever software categories matter to your own
  environment (web servers, remote-access tools, backup agents, monitoring/EDR agents, etc.), which
  is too environment-specific for this project to guess a sensible default list for.

A service can match both lists independently (checked separately, not either/or) if it happens to
fit a pattern in each. For either list, when the matched entry has a `DefaultPort` (not `null`),
that port is probed on the same computer via a direct TCP connect, so the output distinguishes
*installed* (the Windows service exists) from *actually listening on the network* — confirmed live
to matter in practice: a `Running` SQL Server instance still showed `Listening = False` on 1433
(TCP/IP protocol commonly ends up disabled).

#### Adding a new signature (database or software)

The same steps apply to both `DatabaseSignatures` and `SoftwareSignatures` — only the field names
differ (`Engine` vs. `Name`/`Category`).

1. **Find the service's exact short name** on a real host that has it installed — the short name
   (e.g. `MSSQLSERVER`), not the display name (e.g. "SQL Server (MSSQLSERVER)"), is what
   `ServicePattern` matches against. From an elevated PowerShell session on that host:
   ```powershell
   Get-Service | Where-Object { $_.DisplayName -like '*<something recognizable>*' } | Select-Object Name, DisplayName
   ```
   or, to see it exactly the way this tool sees it (via the WinNT provider rather than `Get-Service`):
   ```powershell
   $de = New-Object System.DirectoryServices.DirectoryEntry("WinNT://$env:COMPUTERNAME,computer")
   $de.Children | Where-Object { $_.SchemaClassName -eq 'Service' } | ForEach-Object { $_.Name.ToString() }
   ```
2. **Decide the `ServicePattern`.** Use the exact name for a single fixed service name (e.g.
   `MSSQLSERVER`), or a `-like` wildcard (`*`, `?`) if the real name varies by version/instance
   (e.g. `MySQL*` to catch `MySQL80`, `MySQL57`, etc.). Check it isn't so broad it would also match
   an unrelated service.
3. **Determine the default port**, if any — the vendor's documented default listening port for that
   service (e.g. 1433 for SQL Server, 5432 for PostgreSQL). Use `null` if there isn't a fixed
   default (e.g. a named/dynamic-port instance, or software with no network listener at all) —
   don't guess a port that might not apply, since a wrong `Listening` result is worse than a blank
   one.
4. **Pick a label** — `Engine` (`DatabaseSignatures`) or `Name` + `Category` (`SoftwareSignatures`;
   `Category` is a free-text grouping like `WebServer`/`RemoteAccess`/`Backup`, for the downstream
   tool to filter/report on).
5. **Add the entry to `LocalScanConfig.json`.** Two ways, depending on scope:
   - **Environment-specific, or you don't want it in every deployment**: add it directly to that
     file's `DatabaseSignatures`/`SoftwareSignatures` array. **Remember `DatabaseSignatures`
     replaces the built-in list rather than adding to it** — if you want the defaults *and* your
     addition, copy the full list from `Get-DefaultDatabaseSignatures` (or
     `LocalScanConfig.example.json`) into your config first, then add your new entry to that copy.
     `SoftwareSignatures` has no built-in list to worry about losing.
   - **You want it available everywhere by default** (database engines only): add it to
     `Get-DefaultDatabaseSignatures` in `Modules\LocalComputerScanner.psm1` directly, so every
     deployment gets it without needing its own config override.
6. **Test against a known host before a full run**:
   ```powershell
   .\Export-LocalGroups.ps1 -ComputerFilter '<a host known to have it installed>'
   ```
   then check `LocalDatabases.csv`/`LocalSoftware.csv` for the expected row, including whether
   `Listening` matches what you expect.

`LocalDatabasesListening.csv` is a convenience view — the subset of `LocalDatabases.csv` where
`Listening = True` — for a downstream tool that only cares about database engines actually reachable
on the network, not merely installed. It's derived, not a separate check: every row in it also still
appears in `LocalDatabases.csv`.

Two more verified examples, beyond the IIS/OpenSSH ones already in `LocalScanConfig.example.json`:
Remote Desktop (`{ "Name": "Remote Desktop", "Category": "RemoteAccess", "ServicePattern": "TermService", "DefaultPort": 3389 }`)
and Windows Firewall (`{ "Name": "Windows Firewall", "Category": "Security", "ServicePattern": "MpsSvc", "DefaultPort": null }`
— the firewall service doesn't listen on a port itself, so `DefaultPort` is `null` and `Listening`
is always blank for it; `Status` is the useful signal there). Confirmed live: on the test machine,
`TermService` was `Running` but `Listening = False` on 3389 — Remote Desktop can be disabled at the
OS-feature level even while its underlying service keeps running, another case where `Status` and
`Listening` genuinely disagree.

### Local account password fields

`LocalUsers.csv` includes `PasswordLastSet`, `PasswordExpired`, and `BadPasswordAttempts` for every
local account, read from the same WinNT bind (no configuration needed — always collected). `PasswordLastSet`
is computed as this host's current time minus the account's `PasswordAge` (seconds since last
change, as the *target* computer's clock measured it), so it's an approximate absolute date, subject
to ordinary clock skew between the scanning host and the target — not a precise timestamp read
directly off the target. See [CSV-Schemas.md](CSV-Schemas.md) for the full column reference.

### Retrying failed computers

`RetryCount`/`RetryDelaySeconds` (see the table above) retry a computer that fails before giving up
on it, absorbing a transient blip (a momentary network hiccup, a credential-provider timeout) in an
unattended nightly run rather than failing that computer outright on the first error. Every computer
still failing after retries gets a row in `LocalScanErrors.csv` (`ScanTimestamp`, `ComputerName`,
`ErrorMessage`) — a structured record a downstream tool can track over time, not just a line in the
log file.

### Service account discovery

Answers "what services run as this account" (a local user, domain user, or a suspected gMSA/MSA)
across the scanned estate — no configuration needed, always collected. Unlike `DatabaseSignatures`/
`SoftwareSignatures`, this isn't name-pattern matching: **every** service's `ServiceAccountName` is
read and classified, and anything that isn't a built-in identity, a per-service virtual account, or
blank ends up in `LocalServiceAccounts.csv`.

Classification rules (verified live against a real machine's full service list, and unit-tested
against synthetic domain-user/gMSA examples):

| `ServiceAccountName` looks like | Classified as | Kept in output? |
|---|---|---|
| `LocalSystem`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService` | `BuiltIn` | No |
| `NT SERVICE\<ServiceName>` (per-service virtual account — increasingly SQL Server's own default) | `Virtual` | No |
| *(blank)* — kernel drivers have no logon account concept | `Blank` | No |
| `DOMAIN\name$` or `.\name$` | `LikelyGmsaOrMsa` | **Yes**, flagged |
| Anything else (`.\name`, `DOMAIN\name`) | `User` | **Yes** |

**The gMSA/MSA classification is a naming-convention heuristic** — a trailing `$` is the standard,
unambiguous Microsoft convention for a group-managed or standalone managed service account, but it's
not an authoritative check against AD's `msDS-GroupManagedServiceAccount` object class, since this
script has no AD connectivity of its own (that's `Export-ADGroups.ps1`'s domain). `LikelyGmsaOrMsa`
rows are flagged, not silently dropped, precisely because of that uncertainty — filter them out
downstream if you only want real user accounts, or cross-reference the account name against your AD
export if you need certainty.

`LocalGmsaServiceAccounts.csv` is exactly that filtered subset, kept as its own file (in addition to
— not instead of — its rows still appearing in `LocalServiceAccounts.csv`) specifically so it can
feed a validation step: cross-reference each account name in this file against AD and flag any that
AD does **not** recognize as a real gMSA/standalone MSA. A row here that fails that check is a red
flag — an account deliberately or accidentally named to look like a managed service account without
actually being one.

## ComputersToScan.csv (input to Export-LocalGroups.ps1)

| Column | Required | Description |
|---|---|---|
| `ComputerName` | Yes | Hostname or FQDN to scan. |
| `Enabled` | No | `0`/`false` to skip a row without deleting it. |
| `CredentialSource` | Yes | One of `CurrentUser`, `PSCredential`, `CP`, `CCP`, `Conjur`. |
| `CredentialParamsJson` | Depends on source | A JSON object (as a quoted CSV field) with the same shape as `CredentialParams` below. |
| `Notes` | No | Free text, not used by the script. |

## LinuxComputersToScan.csv (input to Export-LocalLinuxGroups.ps1)

Entirely separate from `ComputersToScan.csv` — a deliberate decision to keep the two platforms'
input/output files apart rather than share one schema with platform-specific blanks.

| Column | Required | Description |
|---|---|---|
| `ComputerName` | Yes | Hostname or IP to scan (used directly as `New-SSHSession -ComputerName`). |
| `Enabled` | No | `0`/`false` to skip a row without deleting it. |
| `CredentialSource` | Yes | One of `CurrentUser`, `PSCredential`, `CP`, `CCP`, `Conjur`. |
| `CredentialParamsJson` | Depends on source | A JSON object (as a quoted CSV field) with the same shape as `CredentialParams` below — plus the Linux-specific `KeyFilePath` field for key-based auth (see "Credential sources"). |
| `Notes` | No | Free text, not used by the script. |

## LinuxScanConfig.json (used by Export-LocalLinuxGroups.ps1)

| Property | Required | Description |
|---|---|---|
| `OutputDirectory` | Yes | Where `LinuxLocalUsers.csv` / `LinuxLocalGroups.csv` / `LinuxLocalGroupMembers.csv` / `LinuxSudoRights.csv` / `LinuxScanErrors.csv` and the `Archive`/`Logs` subfolders are written. |
| `LogDirectory` | No | Defaults to `<OutputDirectory>\Logs`. |
| `ArchiveRetentionCount` | No | Defaults to 30. |
| `MaxConcurrency` | No | How many computers to scan at once, via the same kind of throttled runspace pool as `Export-LocalGroups.ps1`. Defaults to `1` (fully sequential). Must be `1` or greater. Verified live: 3 simultaneous scans of the same host completed within the same second with no cross-talk between their results. |
| `ConnectTimeoutMs` | No | Timeout for the TCP port-22 reachability check, in milliseconds. Defaults to `2000`. |
| `SshConnectTimeoutSeconds` | No | Passed to `New-SSHSession -ConnectionTimeout`. Defaults to `15`. |
| `CommandTimeoutSeconds` | No | Passed to `Invoke-SSHCommand -TimeOut` for the combined per-computer discovery command. Defaults to `60` — the command loops `sudo -n -l -U` over every discovered account, so a host with many local accounts needs more headroom than a single simple command would. |
| `AcceptNewHostKey` | No | `true` (default) passes `-AcceptKey` to `New-SSHSession`, auto-trusting a host the first time it's scanned (Posh-SSH persists accepted keys to the Run As account's `$HOME\.poshss\hosts.json`, so this only matters on first contact per host). Set `false` to require the host key already be trusted via some other means. |
| `RetryCount` | No | Additional attempts for a computer that fails, before giving up on it. Defaults to `0`. Each retry re-runs the entire per-computer scan (new SSH session, new combined command); any rows a partial earlier attempt collected are discarded first. |
| `RetryDelaySeconds` | No | Delay between retry attempts. Defaults to `5`. Ignored when `RetryCount` is `0`. |

These apply globally, to every computer in `LinuxComputersToScan.csv` — there is currently no per-computer override.

### Sudo-dependent fields

`LinuxLocalUsers.csv`'s `PasswordState`/`PasswordLastSet`/`PasswordNeverExpires` and every row of
`LinuxSudoRights.csv` beyond a bare "no access" all require the **connecting** account to have usable
`sudo` rights on the target — specifically **broad** (`ALL`) rights to get useful data out of
`LinuxSudoRights.csv` for accounts other than itself (confirmed live: an account with only a narrow
sudo grant of its own could not list another account's rights). When the connecting account has no
sudo access at all, `sudo -n ...` fails fast with no password prompt (confirmed live — it never
hangs), so these fields are simply left blank/`Unknown` rather than causing the scan to fail. There is
currently no configuration to *supply* a sudo password for a password-required rule — see
[Design-Local-Linux-Discovery.md](Design-Local-Linux-Discovery.md) Section 5a/10 for the proposed
(not yet built) `SudoCredentialSource`/`SudoCredentialParams` mechanism.

## Credential sources

`CredentialSource` / `CredentialParams` (or `CredentialParamsJson`) accept the same shape in all
three input files (`ComputersToScan.csv`, `LinuxComputersToScan.csv`, and `ScanConfig.json`'s
per-domain entries).

- **CurrentUser** — run as whatever account is already running the script. `CredentialParams` is ignored (pass `{}`).
- **PSCredential** — reads a credential exported ahead of time with `Get-Credential | Export-Clixml -Path ...`. Requires `CredentialFilePath`. Because `Export-Clixml` encrypts with DPAPI, the file can only be read back by the same Windows account, on the same machine, that created it — typically the scheduled task's Run As account. For `Export-LocalLinuxGroups.ps1` with key-based SSH auth, this file still supplies the SSH username (`New-SSHSession -Credential` is required in every parameter set, including key-based ones) — its password can be an empty `SecureString` when the key itself has no passphrase.
- **CP** — CyberArk's Application Access Manager Credential Provider, via `CLIPasswordSDK.exe`. Requires `AppID`; and either `Query`, or one or more of `Safe`/`Folder`/`Object`. Optional `ClipasswordsdkPath` if the SDK is installed somewhere other than the default path. Optional `UserName` fallback if the CP doesn't return `PassProps.UserName` for this account.
- **CCP** — CyberArk's Central Credential Provider REST web service. Requires `BaseUrl` and `AppID`; and either `Query`, or one or more of `Safe`/`Folder`/`Object`. Optional `Reason` and `ClientCertificateThumbprint` (for mutual-TLS AppIDs; the certificate must already be installed in `LocalMachine\My` or `CurrentUser\My`).
- **Conjur** — Requires `ApplianceUrl`, `Account`, `AuthnLogin` (the host identity), `Identifier` (the variable holding the password), and either `ApiKeyPath` (a file containing the host's API key) or `ApiKeyEnvVar` (an environment variable containing it). Also requires either `UserName` (literal) or `UsernameIdentifier` (a second Conjur variable holding the username).

`Export-LocalLinuxGroups.ps1` recognizes one additional `CredentialParams` field, read directly by
the script rather than by `CredentialResolver.psm1`:

- **`KeyFilePath`** — path to a private key file, passed straight through to `New-SSHSession -KeyFile`. When set, SSH authenticates with this key rather than the resolved credential's password; the resolved credential's username is still used as the SSH login name (and its password, if any, as the key's passphrase). Omit for plain password authentication.

> **Verify before production use.** The CP/CCP/Conjur helpers implement each product's publicly documented integration pattern, but exact details — CLI install path, the CCP web service's virtual directory name, supported query parameters, TLS/certificate requirements — vary by version and by how your environment is configured. Confirm every value against your own CyberArk deployment before relying on this for a production nightly run.

## Why per-domain and per-computer credentials are separate

Some target domains have no trust relationship with the domain the scheduled task's host belongs to, so a single set of credentials can't reach every domain. `ScanConfig.json` therefore carries its own `CredentialSource`/`CredentialParams` per domain, and `ComputersToScan.csv` carries its own per computer, rather than either script relying on one shared identity.
