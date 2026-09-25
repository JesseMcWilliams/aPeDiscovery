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

## ADComputers.csv (Export-ADGroups.ps1)

One row per AD computer object found. Only produced for domains whose config entry has a
`Computers` block (see [Configuration.md](Configuration.md#computer-object-discovery-computers)) —
empty (no rows, but the file is still written) for domains without one, and the file itself is only
meaningful when at least one domain in the config opts in.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| DomainName | From the config entry's `DomainName`. |
| ComputerName | The computer's `sAMAccountName` with its trailing `$` stripped (e.g. `SRV-APP01`, not `SRV-APP01$`) — what `NameFilter` matches against, and a directly usable hostname. |
| SamAccountName | The raw `sAMAccountName`, `$` included, for exact AD identity fidelity. |
| DNSHostName | AD's `dNSHostName` attribute (the computer's FQDN, e.g. `srv-app01.contoso.com`) — typically the most useful value for actually connecting to it. Can be blank if never populated. |
| DistinguishedName | Full DN of the computer object. |
| ObjectGUID | AD objectGUID. |
| SID | Computer's SID. |
| Enabled | `True`/`False` — the AD account-enabled state of the computer object itself (not whether the machine is powered on). |
| OperatingSystem | AD's `operatingSystem` attribute — self-reported by the computer at domain-join time, refreshed only periodically. Can be blank or stale; not a live fact. What `OSTypeFilter` matches against. |
| OperatingSystemVersion | AD's `operatingSystemVersion` attribute — same caveats as `OperatingSystem`. |
| Description | AD `description` attribute. |
| LastLogonTimestamp | Converted from AD's replicated `lastLogonTimestamp` attribute to an actual date. This attribute is intentionally imprecise (AD only replicates it every few days, to limit replication traffic) — treat it as "roughly this recently," not exact, and useful mainly for spotting computer objects that look long-stale. Blank if never set. |
| WhenCreated / WhenChanged | AD timestamps. |
| ParentOU | DN of the OU the computer was found directly under. |

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

## LinuxLocalUsers.csv (Export-LocalLinuxGroups.ps1)

Entirely separate from `LocalUsers.csv` — no shared filename, no shared schema (UID/GID instead of
SID, no `Description`/`Disabled` boolean the same way Windows has them). Sourced from `/etc/passwd`
plus a `sudo`-derived `/etc/shadow` projection.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| UserName | `/etc/passwd` field 1. |
| UID | `/etc/passwd` field 3. |
| PrimaryGID | `/etc/passwd` field 4. |
| Description | `/etc/passwd` field 5 (the GECOS field). |
| HomeDirectory | `/etc/passwd` field 6. |
| Shell | `/etc/passwd` field 7. |
| PasswordState | One of `PasswordSet`, `PasswordSetButLocked`, `LockedNoHash`, `NeverSet`, `SystemNoLogin`, `SystemNoLoginLocked`, `Unknown` — classified from `/etc/shadow` field 2's shape (real hash, `!`-prefixed hash, bare `!`, `!!`, `*`, `!*`). Blank when the connecting account has no usable `sudo` access to read `/etc/shadow` at all (a warning is logged for that computer, not an error — the rest of the scan still succeeds). |
| PasswordLastSet | `/etc/shadow` field 3 (days since the Unix epoch), converted to a date locally. Blank under the same conditions as `PasswordState`, or when the field itself is empty. |
| PasswordNeverExpires | `True` when `/etc/shadow` field 4 (max password age) is empty or the standard shadow-utils "effectively never" sentinel (≥ 99999 days); `False` when it's a smaller real number; blank under the same conditions as `PasswordState`. |
| DirectoryJoined | `True` when this computer appears to be joined to a directory service (`sssd` actually active with a real `/etc/sssd/sssd.conf`, or `winbind` actually active) — **not** merely whether `/etc/nsswitch.conf` mentions `sss` (confirmed live: that alone is unreliable — a base image can reference it with `sssd` never actually configured/active). Informational only: users/groups are still collected normally either way; this just flags that some entries on a `True` computer may be directory-sourced rather than genuinely local. |
| SshPasswordLoginPossible | `True` when the account could actually log in over SSH with a password: effective `PasswordAuthentication` is `yes` (from `sudo -n sshd -T`, the fully-resolved config — not a `sshd_config` grep, which would miss anything left at a compiled-in default), the account has a real usable password (`PasswordState = PasswordSet`), its shell is in `/etc/shells`, and — for `root` specifically — `PermitRootLogin` isn't set to a password-blocking value. Blank/`Unknown` when the connecting account had no sudo access to read the effective sshd config or `PasswordState` itself. |
| SshKeyLoginPossible | `True` when the account could log in over SSH with a key: effective `PubkeyAuthentication` is `yes`, its `~/.ssh/authorized_keys` file exists and is non-empty (checked via `sudo -n test -s`, needed to read another account's `0700` home directory), and its shell is in `/etc/shells`. **Only the default `~/.ssh/authorized_keys` path is checked** — a customized `AuthorizedKeysFile` directive in `sshd_config` isn't accounted for (see [Open-Items.md](Open-Items.md)). Blank/`Unknown` when the connecting account had no sudo access to check. |

## LinuxLocalGroups.csv (Export-LocalLinuxGroups.ps1)

Sourced from `/etc/group`. There is no Linux equivalent of Windows' group `Description` — the field
simply doesn't exist in `/etc/group`, not a gap in what's collected.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| GroupName | `/etc/group` field 1. |
| GID | `/etc/group` field 3. |
| DirectoryJoined | Same meaning and detection as `LinuxLocalUsers.csv`'s `DirectoryJoined` column. |

## LinuxLocalGroupMembers.csv (Export-LocalLinuxGroups.ps1)

Direct, explicit members only — `/etc/group` field 4. A user whose *primary* GID matches a group but
who isn't also listed explicitly in that group's member list will not appear here, the same
documented parity limitation `LocalGroupMembers.csv` has on the Windows side.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| GroupName | `/etc/group` field 1. |
| GID | `/etc/group` field 3. |
| MemberName | One entry from `/etc/group` field 4's comma-separated member list. |

## LinuxSudoRights.csv (Export-LocalLinuxGroups.ps1)

One row per discovered account (from `LinuxLocalUsers.csv`) per computer — every account gets a row,
not just ones with sudo access, so absence of a row is never mistaken for "no access" (it means the
scan couldn't produce this file at all, e.g. the whole computer failed). Collected via one remote
`sudo -n -l -U <user>` call per account, looped in a single SSH command per computer rather than one
round trip per account. Requires the *connecting* account to have broad (`ALL`) sudo rights on the
target — an account with only a narrow sudo grant of its own will likely be unable to list *other*
accounts' rights at all, and every row on that computer will read `Unknown`.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| UserName | The account this row's sudo check was run for. |
| SudoAccess | `None` (no matching sudoers rule at all), `PasswordlessSomeOrAll` (at least one `NOPASSWD` rule), `PasswordRequired` (rule(s) exist, none are `NOPASSWD`), or `Unknown` (output didn't match a recognized pattern — e.g. the connecting account itself lacks the broad sudo rights this check needs). |
| RawSudoListOutput | The full text `sudo -n -l -U <user>` returned for this account, since (confirmed live) an account can hold multiple distinct rules at once — e.g. a broad password-required group rule *plus* a narrow account-specific grant — that a single flag would flatten away. |

## LinuxDatabases.csv (Export-LocalLinuxGroups.ps1)

One row per systemd service unit that matched a `DatabaseSignatures` entry (see
[Configuration.md](Configuration.md#linux-database-and-other-software-detection)) — not one row per
computer, so a computer with no recognized database service produces no rows here at all. A
templated unit can legitimately produce two rows for what's conceptually one engine — confirmed
live: Debian/Ubuntu's PostgreSQL package registers both `postgresql.service` (a thin wrapper) and
the actual instantiated `postgresql@18-main.service`, and both match the `postgresql*` pattern.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| Engine | The matched signature's `Engine` label (e.g. `PostgreSQL`). |
| UnitName | The systemd unit's name (e.g. `postgresql@18-main.service`). |
| Description | The unit's `systemctl show` `Description` property. |
| Status | `ActiveState/SubState` (e.g. `active/running`). |
| StartType | The unit's `UnitFileState` (e.g. `enabled`, `enabled-runtime`, `disabled`, `static`, `masked`) — confirmed live to have more than the four commonly-documented values (`enabled-runtime` seen on the instantiated PostgreSQL unit). |
| Path | The unit's raw `ExecStart` property text (includes the full wrapper command line where one exists, e.g. `pg_ctlcluster`) — not simplified, since simplifying it risks losing real detail (like which wrapper actually launched the engine). |
| DefaultPort | The signature's configured default port, or blank when the signature has none. |
| Listening | `True`/`False` result of checking `DefaultPort` against a single `ss -tlnp` capture for that computer, or blank when `DefaultPort` is blank **or** the connecting account had no usable sudo access to run `ss -tlnp` at all (a `WARN` is logged in that case — see [Configuration.md](Configuration.md#sudo-dependent-fields-and-elevation)). |

## LinuxSoftware.csv (Export-LocalLinuxGroups.ps1)

Same mechanism as `LinuxDatabases.csv`, for arbitrary software matched against `SoftwareSignatures`
(see [Configuration.md](Configuration.md#linux-database-and-other-software-detection)) — empty by
default, so this file has no rows at all unless `SoftwareSignatures` is populated. One row per
matched unit, not per computer.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| Name | The matched signature's `Name` label (e.g. `OpenSSH Server`, `Docker`). |
| Category | The matched signature's `Category` label — free text, for the downstream tool to group/filter on. |
| UnitName | The systemd unit's name. |
| Description | Same meaning as `LinuxDatabases.csv`. |
| Status | Same meaning as `LinuxDatabases.csv`. |
| StartType | Same meaning as `LinuxDatabases.csv`. |
| Path | Same meaning as `LinuxDatabases.csv`. |
| DefaultPort | The signature's configured default port, or blank if the signature has none (e.g. `docker.service` itself doesn't bind a port directly — the containers it manages do, via separate `docker-proxy` processes not tied to any one signature). |
| Listening | Same meaning as `LinuxDatabases.csv`. |

## LinuxServiceAccounts.csv (Export-LocalLinuxGroups.ps1)

One row per systemd service unit whose **actual running process** is owned by anything other than
`root` — every registered service unit is considered (via `systemctl list-unit-files` union
`systemctl list-units`, not just ones matching a signature), since "what runs as this account" needs
to see everything, mirroring `LocalServiceAccounts.csv`'s role on the Windows side.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| UnitName | The systemd unit's name. |
| Description | The unit's `Description` property. |
| ServiceAccountName | The **resolved** account — preferentially the live process owner of the unit's `MainPID` (cross-referenced against a `ps -eo pid,user` capture taken the same run), falling back to the unit's own `User=` property only when no live PID exists to check, and to `root` (excluded from this file) when neither resolves anything. **Confirmed live this matters**: `postgresql@18-main.service`'s `User=` property is blank, but its `MainPID` is the actual `postgres` process — the naive "blank `User=` means root" reading would have wrongly excluded a real, meaningful service account. |
| StartType | The unit's `UnitFileState`. |
| Status | `ActiveState/SubState`. |
| Path | The unit's raw `ExecStart` text. |

## LinuxUnrecognizedListeningPorts.csv (Export-LocalLinuxGroups.ps1)

One row per TCP port found actually listening (via the same single `ss -tlnp` capture used for
`Listening` above) that does **not** match any configured `DatabaseSignatures`/`SoftwareSignatures`
entry's `DefaultPort` — surfaces something running that no configured signature expected at all, a
capability the Windows tool's one-port-per-signature design structurally can't offer. Empty when the
connecting account had no usable sudo access to run `ss -tlnp` (same condition that leaves
`Listening` blank above), or when every listening port happens to match a configured signature.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| Port | The listening TCP port number. |
| ProcessName | The owning process's name, from `ss -tlnp`'s own process-attribution field (e.g. `docker-proxy`, `sshd`). Blank if `ss -tlnp` couldn't attribute a process (needs sudo; confirmed live this can still happen even with sudo for certain kernel-owned sockets). |
| PID | The owning process's PID, from the same `ss -tlnp` field. |
| ProcessOwner | The owning account, resolved by cross-referencing `PID` against the same `ps -eo pid,user` capture `LinuxServiceAccounts.csv` uses — not from `ss -tlnp` itself, which reports the process name/PID but not its owning account. |

## LinuxScanErrors.csv (Export-LocalLinuxGroups.ps1)

Same shape and purpose as `LocalScanErrors.csv` — one row per computer that failed (after exhausting
`RetryCount` retries) during this run, at most one row per computer, empty when every enabled
computer succeeded.

| Column | Description |
|---|---|
| ScanTimestamp | Start time of the run. |
| ComputerName | From the input CSV. |
| ErrorMessage | The exception message from the final failed attempt (e.g. "Port 22 (SSH) is not reachable..."). Never includes credential secrets. |

## Design notes

- All three scripts write a stable, fixed-name set of CSVs into `OutputDirectory` (overwritten each run) so a downstream import tool always reads the same path, plus a timestamped copy in `Archive` for history/troubleshooting (count controlled by `ArchiveRetentionCount`).
- Membership is captured as **direct members only** in all three scripts, matching AD's/`/etc/group`'s own model. A downstream tool that needs effective/recursive membership can walk the groups file itself using the membership file as edges.
- The Linux output files are entirely separate from the Windows ones — no shared filenames, no `Platform` column, no unified schema. The column sets were never identical anyway (UID/GID vs. SID; Linux groups have no `Description` at all), so this avoids a wider shared schema full of platform-specific blanks.
