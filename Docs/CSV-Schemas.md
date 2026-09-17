# CSV output schemas

All files are UTF-8, comma-delimited, with a header row (`Export-Csv -NoTypeInformation`). Every row carries a `ScanTimestamp` (the time the run started, not per-row) so a downstream import can identify which run a row came from.

## ADGroups.csv (Export-ADGroups.ps1)

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run that produced this row. |
| DomainName | From the config entry's `DomainName`. |
| GroupName | sAMAccountName. |
| DistinguishedName | Full DN of the group. |
| ObjectGUID | AD objectGUID. |
| SID | Group's SID. |
| GroupCategory | `Security` or `Distribution`. |
| GroupScope | `DomainLocal`, `Global`, or `Universal`. |
| Description | AD `description` attribute. |
| ManagedBy | DN of the `managedBy` attribute, if set. |
| WhenCreated / WhenChanged | AD timestamps. |
| ParentOU | DN of the OU the group was found directly under. |
| MemberCount | Count of the group's `member` attribute at scan time. **Note:** AD's default 1,500-value range limit on the `member` attribute means this count (and the raw-DN fallback path used for membership resolution) can be incomplete for groups with more than ~1,500 direct members; `Get-ADGroupMember`, the primary path used for the membership rows themselves, is not affected by this limit. |

## ADGroupMembers.csv (Export-ADGroups.ps1)

Direct members only — nested groups are **not** expanded. One row per (group, direct member) pair.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| DomainName | Domain the group belongs to. |
| GroupName | Group's sAMAccountName. |
| GroupDistinguishedName | Group's DN. |
| GroupSID | Group's SID. |
| MemberName | Member's sAMAccountName (falls back to `Name` if not present, e.g. some foreignSecurityPrincipal objects). |
| MemberDistinguishedName | Member's DN. |
| MemberSID | Member's SID. |
| MemberObjectClass | e.g. `user`, `group`, `computer`, `foreignSecurityPrincipal`. |

## LocalUsers.csv (Export-LocalGroups.ps1)

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| UserName | Local account name. |
| SID | Local account SID. |
| Description | WinNT `Description` property. |
| Disabled | `True`/`False`, from the `ADS_UF_ACCOUNTDISABLE` bit. |
| PasswordNeverExpires | `True`/`False`, from the `ADS_UF_DONT_EXPIRE_PASSWD` bit. |
| LastLogin | WinNT `LastLogin` property (may be blank if never logged on locally). |
| PasswordLastSet | Approximate absolute date the account's password was last changed — this host's clock at scan time, minus the target's own `PasswordAge` (seconds). Approximate due to ordinary clock skew between the scanning host and the target, not because the underlying value is unreliable. Blank if the property couldn't be read for this account. |
| PasswordExpired | `True`/`False` from the WinNT `PasswordExpired` property. Blank if unreadable. |
| BadPasswordAttempts | Count from the WinNT `BadPasswordAttempts` property. Blank if unreadable. |

## LocalGroups.csv (Export-LocalGroups.ps1)

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| GroupName | Local group name. |
| SID | Local group SID. |
| Description | WinNT `Description` property. |

## LocalGroupMembers.csv (Export-LocalGroups.ps1)

Direct members only. One row per (local group, member) pair.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| GroupName | Local group name. |
| GroupSID | Local group SID. |
| MemberName | Member's account name. |
| MemberOrigin | `Local` if the member is a local account on the same computer; otherwise the NetBIOS domain name the member came from. |
| MemberObjectClass | WinNT class of the member (e.g. `User`, `Group`). |

## LocalDatabases.csv (Export-LocalGroups.ps1)

One row per Windows service that matched a `DatabaseSignatures` entry (see
[Configuration.md](Configuration.md#database-and-other-software-detection)) — not one row per
computer, so a computer with no recognized database service produces no rows here at all.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| Engine | The matched signature's `Engine` label (e.g. `SQL Server`, `PostgreSQL`). |
| ServiceName | The Windows service's short name (e.g. `MSSQLSERVER`). |
| DisplayName | The service's display name (e.g. `SQL Server (MSSQLSERVER)`). |
| Path | The service's binary path, exactly as registered (includes command-line arguments; quoting is whatever the service itself was registered with). |
| StartType | Decoded from the Win32 `SERVICE_START_TYPE` value: `Boot`, `System`, `Automatic`, `Manual`, or `Disabled`. |
| Status | Decoded from the Win32 current-state value: `Stopped`, `Running`, `Paused`, or one of the transitional states (`StartPending`, etc.). |
| DefaultPort | The signature's configured default port, or blank when the signature deliberately has none (SQL Server named instances — see Configuration.md). |
| Listening | `True`/`False` result of probing `DefaultPort` on this computer, or blank when `DefaultPort` is blank. **A service can be `Running` with `Listening = False`** — e.g. SQL Server's TCP/IP protocol is commonly left disabled, or the engine only listens on named pipes; confirmed live during testing. `Status` and `Listening` answer two different questions (is the Windows service running vs. is the network port reachable) and should not be assumed to agree. |

## LocalDatabasesListening.csv (Export-LocalGroups.ps1)

The subset of `LocalDatabases.csv` where `Listening = True` — same columns, same meaning. A
convenience view, not a separate detection path: every row here also appears in
`LocalDatabases.csv`; nothing here is detected any differently. Empty when no detected database
engine is actually listening on its default port.

## LocalSoftware.csv (Export-LocalGroups.ps1)

Same mechanism as `LocalDatabases.csv`, for arbitrary software matched against `SoftwareSignatures`
(see [Configuration.md](Configuration.md#database-and-other-software-detection)) — empty by
default, so this file has no rows at all unless `SoftwareSignatures` is populated. One row per
matched service, not per computer.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| Name | The matched signature's `Name` label (e.g. `IIS`, `OpenSSH Server`). |
| Category | The matched signature's `Category` label (e.g. `WebServer`, `RemoteAccess`) — free text, for the downstream tool to group/filter on. |
| ServiceName | The Windows service's short name (e.g. `W3SVC`). |
| DisplayName | The service's display name (e.g. `World Wide Web Publishing Service`). |
| Path | The service's binary path, exactly as registered. |
| StartType | Same decoding as `LocalDatabases.csv`. |
| Status | Same decoding as `LocalDatabases.csv`. |
| DefaultPort | The signature's configured default port, or blank if the signature has none. |
| Listening | Same meaning as `LocalDatabases.csv` — `Status = Running` does not guarantee `Listening = True`, and vice versa. |

## LocalScanErrors.csv (Export-LocalGroups.ps1)

One row per computer that failed — after exhausting any `RetryCount` retries — during this run.
Empty when every enabled computer succeeded. Unlike the other `Local*.csv` files, this one has at
most one row per computer (the final failure), not one row per item found.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| ErrorMessage | The exception message from the final failed attempt (e.g. "Port 445 (SMB/RPC) is not reachable..."). Never includes credential secrets. |

## LocalServiceAccounts.csv (Export-LocalGroups.ps1)

One row per Windows service whose logon ("Run As") account is a real local/domain user or a
suspected gMSA/MSA — i.e. every service *except* ones running as a built-in identity
(`LocalSystem`, `NT AUTHORITY\LocalService`/`NetworkService`), a per-service virtual account
(`NT SERVICE\<name>`), or with no account at all (kernel drivers). Unlike `LocalDatabases.csv`/
`LocalSoftware.csv`, this isn't signature-matched — every service on the computer is considered, not
just ones matching a configured pattern, since "what runs as this account" needs to see everything.
See [Configuration.md](Configuration.md#service-account-discovery) for the classification rules and
their limits.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| ServiceName | The Windows service's short name. |
| DisplayName | The service's display name. |
| ServiceAccountName | The raw WinNT `ServiceAccountName` value (e.g. `CONTOSO\svc_backup`, `CONTOSO\svc_app$`). |
| AccountType | `User` or `LikelyGmsaOrMsa`. The latter is a **naming-convention heuristic** (a trailing `$`, the standard Microsoft convention for gMSA/standalone MSA), not an authoritative check against AD's `msDS-GroupManagedServiceAccount` object class — this tool has no AD connectivity of its own. `BuiltIn`/`Virtual`/`Blank` services are excluded entirely and never appear in this file. |
| StartType | Same decoding as `LocalDatabases.csv`. |
| Status | Same decoding as `LocalDatabases.csv`. |
| Path | The service's binary path, exactly as registered. |

## LocalGmsaServiceAccounts.csv (Export-LocalGroups.ps1)

The subset of `LocalServiceAccounts.csv` where `AccountType = LikelyGmsaOrMsa` — same columns, same
meaning. A convenience view, not a separate detection path: every row here also appears in
`LocalServiceAccounts.csv`. Intended to be handed to a separate AD cross-reference step (not part of
this tool) that checks each account here against AD and flags any that AD does **not** actually
recognize as a real `msDS-GroupManagedServiceAccount`/standalone MSA — since the trailing-`$`
classification that put a row here is a naming convention, not proof, this file is exactly the list
a downstream validation step needs to confirm or refute. Empty when no service on any scanned
computer runs as an account matching that convention.

## Design notes

- Both scripts write a stable, fixed-name set of CSVs into `OutputDirectory` (overwritten each run) so a downstream import tool always reads the same path, plus a timestamped copy in `Archive` for history/troubleshooting (count controlled by `ArchiveRetentionCount`).
- Membership is captured as **direct members only** in both scripts, matching AD's own model. A downstream tool that needs effective/recursive membership can walk the groups file itself using the membership file as edges.
