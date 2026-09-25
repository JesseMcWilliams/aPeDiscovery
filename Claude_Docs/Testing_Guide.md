# Testing guide

Step-by-step procedures for validating every feature of the three scripts before relying on them for
a real nightly run. Each section assumes you've already done the matching **Quick start** step in
[README.md](../README.md) (copied the relevant `.example` files and edited them for your
environment).

General approach used throughout: prefer `-DomainFilter`/`-ComputerFilter` to test against **one**
target first, inspect the CSV output directly (`Import-Csv ... | Format-Table`/`Format-List`), then
scale up — this is the same approach used to build and verify these scripts in the first place, not
a separate/lighter-weight test method invented just for this guide.

---

## 1. Export-ADGroups.ps1

### 1.1 Basic connectivity and group export

```powershell
.\Export-ADGroups.ps1 -DomainFilter 'contoso.com' -Verbose
```
Check: exit code `0`, `ADGroups.csv`/`ADGroupMembers.csv` written with rows for that domain only, and
the log (`<OutputDirectory>\Logs`) has no `ERROR` lines. If it fails, check `CredentialSource`/
`CredentialParams` for that domain first (see [Reference_Configuration.md](Reference_Configuration.md#credential-sources)),
then `Server` (an explicit DC/GC may be required for an untrusted domain).

### 1.2 OU scoping (`BaseOU`/`OUDepth`/`ExcludeOUs`)

Set `BaseOU` to a specific OU you know the group count for, re-run, and confirm `ADGroups.csv` only
contains groups from that OU and its children (or fewer children, if `OUDepth` is also set). Add an
`ExcludeOUs` entry for a child OU and confirm its groups disappear from the next run while sibling
OUs' groups remain.

### 1.3 Group filters (`IncludeGroupCategories`/`IncludeGroupScopes`/`ExcludeGroupNames`)

```powershell
Import-Csv .\Output\ADGroups.csv | Group-Object GroupCategory, GroupScope | Format-Table Name, Count
```
Set `IncludeGroupCategories: ["Security"]`, re-run, and confirm the output above only ever shows
`Security` rows. Repeat for `IncludeGroupScopes`. For `ExcludeGroupNames`, pick a known noisy built-in
(e.g. `"Domain Users"`) or a wildcard test-group pattern, add it, re-run, and confirm it's gone from
both `ADGroups.csv` and `ADGroupMembers.csv`. Also deliberately misspell a category (e.g.
`"Securty"`) and confirm the run fails immediately with a clear error rather than silently matching
nothing.

### 1.4 Computer object discovery (`Computers`)

Add a `Computers` block to one domain entry (start with `{}` for defaults — every computer in the
domain), run with `-DomainFilter` for that domain, and confirm `ADComputers.csv` is written with one
row per computer object. Then narrow it down:

```powershell
Import-Csv .\Output\ADComputers.csv | Select-Object ComputerName, OperatingSystem | Format-Table
```
Set `NameFilter: ["SRV-*"]` and confirm only matching computer names remain. Set
`OSTypeFilter: ["Windows Server*"]` and confirm only matching `OperatingSystem` values remain — note
this attribute can be blank/stale (see [README.md](../README.md#known-limitations--things-to-verify-for-your-environment)),
so a computer you expect to match but don't see may simply have an unpopulated attribute, not a
filter bug. Remove the `Computers` block from a domain entry entirely and confirm `ADComputers.csv`
is still written but has zero rows for that domain (opt-in, not an error).

---

## 2. Export-LocalGroups.ps1

### 2.1 Basic connectivity and user/group export

```powershell
.\Export-LocalGroups.ps1 -ComputerFilter 'SRV-APP01' -Verbose
```
Check: exit code `0`, `LocalUsers.csv`/`LocalGroups.csv`/`LocalGroupMembers.csv` have rows for that
computer. If it fails on port 445 reachability, confirm from the scanning host:
`Test-NetConnection SRV-APP01 -Port 445`. If it fails on credentials, check that row's
`CredentialSource`/`CredentialParams` in `ComputersToScan.csv`.

### 2.2 Concurrency (`MaxConcurrency`)

```powershell
Measure-Command { .\Export-LocalGroups.ps1 }
```
With `MaxConcurrency: 1`, note the elapsed time against several computers; raise it (e.g. to `5`) and
confirm the run completes noticeably faster with the same computer count, and that `LocalUsers.csv`'s
row count is unchanged (same data, just collected in parallel). To specifically confirm no
cross-talk between concurrent scans, temporarily add duplicate rows in `ComputersToScan.csv` pointing
at the same computer (different `Notes`, same `ComputerName`) with `MaxConcurrency` ≥ the duplicate
count, and confirm the resulting row counts are an exact multiple of a single scan's — any
mismatch would indicate shared-state corruption between runspaces. Remove the duplicates afterward.

### 2.3 Retry (`RetryCount`/`RetryDelaySeconds`)

Point a row at a computer that's briefly unreachable (or temporarily block port 445 to it), set
`RetryCount: 2`, run, and confirm the log shows multiple `WARN` attempt lines for that computer
before it's finally recorded in `LocalScanErrors.csv` — not just one failure.

### 2.4 Exclude filters (`ExcludeUserNames`/`ExcludeGroupNames`)

```powershell
Import-Csv .\Output\LocalUsers.csv | Select-Object -ExpandProperty UserName
```
Add a known local account name (or wildcard) to `ExcludeUserNames`, re-run, and confirm it's gone
from `LocalUsers.csv`. Same pattern for `ExcludeGroupNames` against `LocalGroups.csv`/
`LocalGroupMembers.csv`.

### 2.5 Database/software detection (`DatabaseSignatures`/`SoftwareSignatures`)

Run against a computer with a known database engine installed (e.g. SQL Server or PostgreSQL) and
confirm a matching row appears in `LocalDatabases.csv` with the correct `Engine`/`ServiceName`. Check
`Listening` against what you actually expect (`Test-NetConnection <host> -Port <DefaultPort>` from
the scanning host as an independent check) — remember `Status = Running` does not guarantee
`Listening = True` (see [Reference_Configuration.md](Reference_Configuration.md#database-and-other-software-detection)).
Confirm `LocalDatabasesListening.csv` contains exactly the subset where `Listening = True`. Add a
`SoftwareSignatures` entry (e.g. the `RemoteDesktop`/`TermService` example from
`LocalScanConfig.example.json`) and confirm the equivalent behavior in `LocalSoftware.csv`. See
[Reference_Configuration.md](Reference_Configuration.md#adding-a-new-signature-database-or-software) for the full
"add a new signature" steps if testing one not already in the default list.

### 2.6 Service account discovery

```powershell
Import-Csv .\Output\LocalServiceAccounts.csv | Group-Object AccountType | Format-Table Name, Count
```
Confirm no `LocalSystem`/`NT AUTHORITY\...`/`NT SERVICE\...`/blank rows appear at all (they're
excluded by design). Find a service you know runs as a real domain user and confirm it's classified
`User`; if you have (or can name) an account following the gMSA/MSA `$`-suffix convention, confirm it
lands in `AccountType = LikelyGmsaOrMsa` and also appears in `LocalGmsaServiceAccounts.csv`.

### 2.7 Password fields and error handling

```powershell
Import-Csv .\Output\LocalUsers.csv | Select-Object UserName, PasswordLastSet, PasswordExpired, BadPasswordAttempts
```
Spot-check a couple of known accounts' values against what Computer Management's "Local Users and
Groups" snap-in shows for the same accounts on that machine. Point `-ComputerFilter` at a
nonexistent/unreachable hostname and confirm it produces exactly one row in `LocalScanErrors.csv`
with a clear `ErrorMessage`, while the exit code is `1` and the log has a corresponding `ERROR` line.

---

## 3. Export-LocalLinuxGroups.ps1

Requires `Install-Module Posh-SSH` on the scanning host and a Linux target reachable over SSH with a
working credential (password or key) already configured in `LinuxComputersToScan.csv`.

### 3.1 Basic connectivity and user/group export

```powershell
.\Export-LocalLinuxGroups.ps1 -ComputerFilter '<your test host>' -Verbose
```
Check: exit code `0`, `LinuxLocalUsers.csv`/`LinuxLocalGroups.csv`/`LinuxLocalGroupMembers.csv` have
rows. Cross-check the counts against the target directly if you have another way in:
`ssh <host> 'wc -l /etc/passwd /etc/group'` should roughly match `LinuxLocalUsers.csv`/
`LinuxLocalGroups.csv`'s row counts (off by the header row).

### 3.2 Key-based vs. password auth

Test one `LinuxComputersToScan.csv` row using a plain password credential (`CredentialSource:
PSCredential`, no `KeyFilePath`), and a second row using a key (`KeyFilePath` set in
`CredentialParamsJson`) against a host configured to accept that key. Confirm both succeed
independently — this exercises both branches of the `New-SSHSession` call in
`Modules\LocalLinuxComputerScanner.psm1`.

### 3.3 Concurrency (`MaxConcurrency`)

Same idea as Section 2.2: temporarily duplicate a row in `LinuxComputersToScan.csv` pointing at the
same host 2-3 times, set `MaxConcurrency` to at least that many, run, and confirm:
- The log shows multiple `Starting scan of computer '<host>'` lines at (or within a second of) the
  same timestamp — proof the scans actually ran in parallel, not queued one after another.
- `LinuxLocalUsers.csv`'s (and the other files') row counts are an exact multiple of what a single
  scan of that host produces — proof there's no cross-talk between concurrent runspaces' results.
Remove the duplicate rows afterward and re-run once against your real target list to leave the
output files in a clean, non-duplicated state.

### 3.4 Reachability and retry

Point `-ComputerFilter` at an address with nothing listening on port 22 and confirm it fails fast with
a "Port 22 (SSH) is not reachable" error rather than hanging until an SSH-level timeout. Set
`RetryCount: 1` against a target that intermittently fails (or temporarily firewall off port 22 to it)
and confirm the log shows a retry attempt before the final `LinuxScanErrors.csv` row.

### 3.5 Password-state fields (requires sudo on the target)

```powershell
Import-Csv .\Output\Linux\LinuxLocalUsers.csv | Group-Object PasswordState | Format-Table Name, Count
Import-Csv .\Output\Linux\LinuxLocalUsers.csv | Where-Object UserName -eq '<your scanning account>' | Format-List
```
If the connecting account has usable `sudo` rights on the target, confirm every account gets a
non-blank `PasswordState` (one of `PasswordSet`/`PasswordSetButLocked`/`LockedNoHash`/`NeverSet`/
`SystemNoLogin`/`SystemNoLoginLocked`) and that a locked/system account's `PasswordNeverExpires`
matches what you'd expect from `sudo cat /etc/shadow` directly on the target. If the connecting
account has **no** sudo rights, confirm these fields come back blank for every account (not an error)
and the log has a `WARN` line noting shadow data was unavailable for that computer.

### 3.6 Sudo rights discovery

```powershell
Import-Csv .\Output\Linux\LinuxSudoRights.csv | Group-Object SudoAccess | Format-Table Name, Count
Import-Csv .\Output\Linux\LinuxSudoRights.csv | Where-Object UserName -eq '<a known sudo-group account>' | Format-List
```
Confirm every account discovered in `LinuxLocalUsers.csv` has a matching row here (one row each, not
just accounts with access). For an account you know has no sudo rights at all, confirm `SudoAccess =
None`. For one with a `NOPASSWD` rule, confirm `SudoAccess = PasswordlessSomeOrAll` and that
`RawSudoListOutput` contains the literal rule text. For one with only password-required rules (no
`NOPASSWD` at all), confirm `SudoAccess = PasswordRequired`. If the connecting account itself lacks
broad (`ALL`) sudo rights, expect every row to read `Unknown` instead — this is a real constraint of
how `sudo -n -l -U` works, not a bug (see [Reference_Configuration.md](Reference_Configuration.md#sudo-dependent-fields)).

### 3.7 Directory-join detection (`DirectoryJoined`)

```powershell
Import-Csv .\Output\Linux\LinuxLocalUsers.csv | Group-Object DirectoryJoined | Format-Table Name, Count
```
Against a host that is **not** actually joined to SSSD/Winbind, confirm every row reads `False` —
including if `/etc/nsswitch.conf` happens to mention `sss` (confirmed live this can be present from a
base OS image with `sssd` never actually configured; don't rely on `nsswitch.conf` alone to judge this
by eye). If you have (or can join) a host actually connected to SSSD or Winbind, confirm every row for
that host reads `True`, and that `LinuxLocalUsers.csv`/`LinuxLocalGroups.csv` still contain the same
rows as before (this flag is informational only — it never filters anything out).

### 3.8 Sudo elevation for the password-required case

Configure a row whose `CredentialSource` resolves to an account with full (`ALL`) but
password-required (not `NOPASSWD`) sudo rights, and use it as the connecting account (not just a
target another account checks via `-U`). Confirm:
```powershell
Import-Csv .\Output\Linux\LinuxLocalUsers.csv | Where-Object UserName -eq '<that account>' | Format-List PasswordState, PasswordLastSet
```
`PasswordState` should be populated (e.g. `PasswordSet`), proving real elevation happened via the
account's own password rather than relying on `NOPASSWD`. No `WARN` about "sudo elevation was not
established" should appear in the log for this run. Then test the opposite: an account with **no**
sudo access at all as the connecting account, and confirm the fields come back blank with a `WARN`
logged, but the scan still succeeds (exit code `0`, other computers unaffected).

### 3.9 Database/software detection and service accounts (Phase 5)

Run against a computer with a known database engine or other signature-matched software installed
(the default `DatabaseSignatures` cover PostgreSQL/MySQL/MariaDB/MongoDB by unit name):
```powershell
Import-Csv .\Output\Linux\LinuxDatabases.csv | Format-Table Engine, UnitName, Status, Listening
```
Confirm a matching row appears with the correct `Engine`/`UnitName`, and that `Listening` matches
what you'd expect from an independent check (e.g. `ss -tlnp` run directly on the target, or a
`Test-NetConnection <host> -Port <DefaultPort>` from the scanning host). Add a `SoftwareSignatures`
entry (e.g. `{ "Name": "OpenSSH Server", "Category": "RemoteAccess", "UnitPattern": "ssh.service",
"DefaultPort": 22 }`) and confirm the equivalent behavior in `LinuxSoftware.csv`, including that
`LinuxUnrecognizedListeningPorts.csv`'s row count drops once that port becomes recognized. Then check
`LinuxServiceAccounts.csv`:
```powershell
Import-Csv .\Output\Linux\LinuxServiceAccounts.csv | Group-Object ServiceAccountName | Format-Table Name, Count
```
Confirm no row has `ServiceAccountName` blank or `root` (both excluded by design), and — if you have
a service that runs via a privilege-dropping wrapper (PostgreSQL's `pg_ctlcluster` is a good example
if installed) — confirm its row shows the *real* running account, not `root`, even though
`systemctl show <unit> --property=User` for that same unit may come back blank. If the connecting
account has no usable sudo access, confirm `Listening` is blank throughout and
`LinuxUnrecognizedListeningPorts.csv` is empty, with a `WARN` logged, rather than the scan failing.

### 3.10 Per-account SSH login eligibility

Requires the connecting account to have usable sudo access (same requirement as 3.5/3.6).
```powershell
Import-Csv .\Output\Linux\LinuxLocalUsers.csv | Select-Object UserName, PasswordState, Shell, SshPasswordLoginPossible, SshKeyLoginPossible | Format-Table
```
Cross-check a few accounts you already know the ground truth for:
- An account you know has a real, unlocked password and a real shell (e.g. `/bin/bash`) should show
  `SshPasswordLoginPossible = True`.
- An account whose SSH key you're actually using to connect right now should show
  `SshKeyLoginPossible = True` — this is directly, immediately verifiable, since you're using it.
- A system/service account with a `nologin` or `false` shell should show `False` for both, regardless
  of its password/key state.
- If you know a specific account's `authorized_keys` file is empty (or you can check with
  `sudo cat ~<user>/.ssh/authorized_keys` directly on the target), confirm `SshKeyLoginPossible =
  False` for it even if `PubkeyAuthentication` is otherwise enabled host-wide.
Then test with a connecting account that has **no** sudo access: confirm both fields come back blank
(`$null`, not `False`) for every account, with a `WARN` logged about the effective sshd configuration
being unavailable, and the scan still succeeding.

---

## 4. Things this guide deliberately does not cover

`BadPasswordAttempts` for Linux accounts is designed but not yet built, so there's no test procedure
for it here — see [Design_Local-Linux-Discovery.md](Design_Local-Linux-Discovery.md) Section 8. It's
the only remaining unbuilt item in the Linux design; add a section here once it's implemented,
following the same "one real target, inspect the CSV directly, then scale up" pattern used above.
