# Local Windows Discovery — Design

**Status:** Implemented
**Initiated:** 2026-09-16
**Origin:** User request to discover local users, local groups, and local group membership on
domain computers, driven by an input CSV where each computer can point at its own credential.

This document describes the design behind `Export-LocalGroups.ps1`. See
[Reference_Configuration.md](Reference_Configuration.md) for the full config/input schema and
[Reference_CSV-Schemas.md](Reference_CSV-Schemas.md) for exact output columns; this doc focuses on the *why* behind the
shape of the thing, not a field-by-field reference.

---

## 1. Why this is worth doing

AD-level discovery (`Export-ADGroups.ps1`) has no visibility into **local** accounts, local groups,
and local group membership on individual computers — e.g. a local Administrator account, a
locally-created service account, or a domain user someone added directly to a server's local
`Administrators` group outside of any AD group. That's exactly the kind of unmanaged privilege a
PAM-adjacent discovery effort needs visibility into, and AD-only scanning can't see it.

## 2. Context & constraints

- **Not every target can be assumed to have WinRM/PSRemoting enabled and trusted.** Requiring that
  as a prerequisite would exclude an unknown fraction of the computer estate. The ADSI WinNT
  provider was chosen specifically because it needs only RPC/SAM connectivity — the same access
  the classic "Local Users and Groups" MMC snap-in needs against a remote machine — not WinRM.
- **One credential does not cover the whole estate.** Different computers may need different
  credentials (different local admin accounts, different vaulted safes), so the credential source
  is specified **per computer**, in the input CSV, rather than once for the whole run.
- **This runs unattended, nightly, via Scheduled Task** — same operational constraints as the AD
  script: one unreachable/misconfigured computer must not abort the run, and the run must leave a
  clear audit trail.

## 3. Non-goals

- **Read-only.** Nothing in this tool modifies local accounts, groups, or membership.
- **No domain group membership resolution.** That's `Export-ADGroups.ps1`'s job; this tool only
  reports what a local WinNT bind can see (which does include domain-origin members added directly
  to a local group — see `MemberOrigin` in the output — but not the domain group's own further
  membership).
- **No general software/asset inventory, no OS patch level.** The deliberate exceptions (added
  2026-09-16, extended 2026-09-16 twice) are: (1) **known database engines and known other
  software**, each recognized only by an explicit signature the operator configured — a
  service that doesn't match a configured `DatabaseSignatures`/`SoftwareSignatures` entry produces
  no row in those files, however interesting it might be; and (2) **every service's logon account**,
  which — unlike (1) — genuinely is a blanket enumeration (see Section 5), because answering "what
  runs as this account" requires seeing every service, not just recognized ones. Built-in/virtual/
  blank accounts are filtered out as noise before anything is kept, so this still isn't a general
  "list every service" inventory in its output, even though every service is examined to produce it.

## 4. Requirements

**Functional**
- Input CSV of computers, each independently enabled/disabled, each with its own credential source.
- Local user inventory (with disabled/password-never-expires flags where available).
- Local group inventory.
- Local group direct-membership, with each member classified as local or naming the domain it came
  from.

**Non-functional**
- A single offline/unreachable computer must fail fast (reachability pre-check) and not stall the
  rest of the run.
- Continue past a failed computer; exit code reflects overall success/partial-failure.
- A failed computer can be retried a configurable number of times before being recorded as failed,
  to absorb a transient blip in an unattended nightly run.
- Every computer that still fails after retries is recorded as a structured row (`LocalScanErrors.csv`),
  not only a log line, so a downstream tool can track failing hosts the same way it tracks everything
  else.
- Secrets are never written to the log.

## 5. Architecture

```
ComputersToScan.csv
  └─ filter to enabled rows matching -ComputerFilter (if given)
  └─ RunspacePool sized by MaxConcurrency (default 1 = sequential), one PowerShell instance per
     computer, each running Invoke-LocalComputerScan (Modules\LocalComputerScanner.psm1):
       up to RetryCount+1 attempts (default 1 = no retry), clearing any rows from a prior
       partial attempt before each one, RetryDelaySeconds between attempts:
         Test-TcpPortOpen -Port 445 reachability check → throw fast if unreachable
         resolve credential (CredentialResolver.psm1, per-row CredentialParamsJson)
         bind System.DirectoryServices.DirectoryEntry("WinNT://<computer>,computer", user, pass)
         for each child object:
           SchemaClassName 'user'    → filter by ExcludeUserNames → user row (UserFlags bit-decoded,
                                        PasswordAge/PasswordExpired/BadPasswordAttempts read)
           SchemaClassName 'group'   → filter by ExcludeGroupNames → group row, then .Invoke('Members')
             └─ each member's AdsPath authority segment classifies it Local vs. <NetBIOS domain>
           SchemaClassName 'Service' → read ServiceAccountName (every service, unconditionally)
                                       → classify via Get-ServiceAccountType → BuiltIn/Virtual/Blank
                                         dropped; User/LikelyGmsaOrMsa → service-account row
                                     → match name against DatabaseSignatures → database row
                                     → match name against SoftwareSignatures → software row (independently - not either/or)
             └─ for either signature match, if it has a DefaultPort, Test-TcpPortOpen probes it on this computer
       returns one result object: { ComputerName, Success, ErrorMessage, UserRows, GroupRows, MemberRows, DatabaseRows, SoftwareRows, ServiceAccountRows }
  └─ main script EndInvoke()s each job as it completes, merges rows into the master lists;
     a still-failed result (or an EndInvoke that itself threw) becomes one LocalScanErrors.csv row
  └─ two convenience views are then derived in-memory from the merged lists, not re-detected:
       DatabaseRows | Where Listening -eq $true      → LocalDatabasesListening.csv
       ServiceAccountRows | Where AccountType -eq 'LikelyGmsaOrMsa' → LocalGmsaServiceAccounts.csv
Export-Csv → LocalUsers.csv / LocalGroups.csv / LocalGroupMembers.csv / LocalDatabases.csv / LocalSoftware.csv / LocalScanErrors.csv / LocalServiceAccounts.csv / LocalDatabasesListening.csv / LocalGmsaServiceAccounts.csv (+ timestamped Archive copy, retention-pruned)
```

**Why ADSI WinNT over PSRemoting or CIM/WMI** (the three options considered — see Alternatives):
`Invoke-Command`/PSRemoting needs WinRM enabled and a trust path for authentication on every
target, which can't be assumed; CIM/WMI's `Win32_GroupUser` association class is a known-slow,
awkward way to get group membership at scale. The WinNT provider needs neither WinRM nor a domain
trust — just RPC/SAM reachability and a valid local-or-domain credential the target recognizes.

**Why a TCP-445 reachability pre-check, not ICMP (changed 2026-09-16).** ADSI's `DirectoryEntry`
bind doesn't fail fast on its own against an unreachable host; `RefreshCache()` is used to force the
bind (and surface an auth failure) right away, but an offline host can still hang far longer than is
acceptable in a nightly run across many computers. The original pre-check used an ICMP ping
(`Test-Connection`), which was flagged as a known limitation: ICMP can be blocked by a firewall
between the scanning host and a target that is otherwise fully reachable on port 445, causing a
false skip. `Test-TcpPortOpen` (`Modules\NetworkHelpers.psm1`) replaces it with a direct,
short-timeout TCP connect to port 445 — the actual dependency this tool needs — confirmed live
against `doesnotexist.invalid` (correctly rejected) and a real reachable host (correctly passed)
during testing.

**Database engine detection (added 2026-09-16), and why it reuses the WinNT bind instead of a new
mechanism.** The user asked whether database presence could be identified during this scan.
Verified live before building anything: the same `DirectoryEntry.Children` collection already bound
for users/groups also returns `Service`-class objects (291 of them on the test machine) — no new
connectivity, credential, or dependency is needed. Each service's short name is matched against
`DatabaseSignatures` (`{Engine, ServicePattern, DefaultPort}`); a match produces a `LocalDatabases.csv`
row with the service's path, decoded `StartType`/`Status`, and — when the signature has a
`DefaultPort` — the result of a `Test-TcpPortOpen` probe against that port on the same computer,
answering "is it actually listening on the network", not just "is the Windows service installed".
Confirmed live: a real SQL Server install showed `Status = Running` but `Listening = False` (TCP/IP
protocol commonly ends up disabled, or the engine only listens on named pipes) — the two columns
answer genuinely different questions and can disagree.

Other options considered for this:
- **Local group names as the signal** (e.g. SQL Server's own `SQLServerMSASUser$...`,
  `SQLRUserGroup`) — already incidentally captured in `LocalGroups.csv` today with no extra code,
  but SQL-Server-specific, easy to miss, and not a general mechanism — kept as an incidental bonus,
  not the primary detection path.
- **Remote Registry uninstall-key scan** (`HKLM\SOFTWARE\...\Uninstall`) — would catch a database
  that's installed but has no persistent service, but depends on the Remote Registry service, which
  is commonly disabled as a hardening measure — not used, to avoid a fragile dependency.
- **`Win32_Product` (WMI)** — rejected outright: querying it is documented to trigger a
  consistency-check/repair pass against every installed MSI on the machine, which is slow and can
  have side effects. Consistent with CIM/WMI already being rejected for group membership (see
  below).

**Generalized to arbitrary other software via `SoftwareSignatures` (added 2026-09-16).** The user
asked for a way to check for other software beyond databases, "a list of some sort". Rather than
building a second, parallel mechanism, the exact same per-service matching logic runs a second,
independent check against a `SoftwareSignatures` list, producing `LocalSoftware.csv` with a
matching shape (`Name`/`Category` instead of `Engine`). The two lists are checked independently
(not either/or) since a service could plausibly matter to both. Deliberately **no built-in default**
for `SoftwareSignatures`, unlike `DatabaseSignatures`: the small set of well-known database engines
was confident enough to ship as a default, but "other software worth watching for" (web servers,
remote-access tools, backup/monitoring/EDR agents, etc.) varies too much by environment and vendor
to guess a defensible default list without risking asserting service names that aren't actually
correct for a given install. Two high-confidence examples (IIS/`W3SVC`, OpenSSH Server/`sshd`) are
shown in `LocalScanConfig.example.json` purely as a pattern to copy, not as a shipped default — both
were verified live on the test machine (IIS: `Listening = True` on port 80, matching a real
running site). Two further verified examples (Remote Desktop/`TermService`/3389, Windows
Firewall/`MpsSvc`/no port) are shown in `Claude_Docs\Reference_Configuration.md`; the Remote Desktop one turned up
the same `Running`-but-not-`Listening` divergence as SQL Server did, on this same test machine.

**Local account password fields, retry-on-failure, and structured error output (added 2026-09-16),
all from the same follow-up question ("what other features should be added?").** Verified live
before adding: the WinNT provider's `PasswordAge`, `PasswordExpired`, and `BadPasswordAttempts`
properties are real and readable across every local account tested (including disabled built-ins,
which returned `0`/`False` rather than throwing) — same bind, no new dependency, and directly
PAM-relevant in a way `LastLogin` alone isn't (a local account with a very old or already-expired
password is exactly the kind of thing this tool exists to surface). `PasswordAge` (seconds) is
converted to an approximate absolute `PasswordLastSet` date rather than exposed as a raw age, since
an absolute date is more directly useful to a downstream tool and doesn't go stale relative to when
the CSV is actually read — the tradeoff is that the conversion is only as accurate as the clock skew
between the scanning host and the target.

Retry and structured errors were added together since they address the same operational reality: a
nightly unattended run across many computers will occasionally hit a transient failure (a network
blip, a momentary auth hiccup) that has nothing to do with that computer's actual state.
`RetryCount`/`RetryDelaySeconds` re-run the *entire* per-computer scan (not just the failed step) up
to `RetryCount` additional times, clearing any partially-collected rows before each attempt so a
later success can't leave duplicates behind — simpler and more robust than trying to resume a scan
partway through. Every computer still failing after retries becomes a `LocalScanErrors.csv` row
(previously, a failure was only ever visible as a log line), matching how every other finding this
tool produces is a structured row, not just a log message. Verified live: a real host and a
deliberately-unreachable one run together with `RetryCount = 2` showed exactly the expected pattern —
attempts 1/3 and 2/3 logged as retryable `WARN`s with the configured delay between them, attempt 3/3
logged as the final `ERROR`, and exactly one row (not three) in `LocalScanErrors.csv`.

**Service account discovery (added 2026-09-16), answering "what services run as this account".**
The user asked whether every service using a specified local or domain user (excluding gMSA/MSA)
could be identified. Verified live before building anything: the WinNT provider exposes each
service's logon identity as `ServiceAccountName` (confirmed via trial and error — `StartName` and
`ServiceAccount`, the names a Win32/WMI background might suggest, do not exist on this object;
`ServiceAccountName` does). A full survey of the test machine's ~290 services showed exactly four
patterns: built-in identities (`LocalSystem`, `NT AUTHORITY\LocalService`/`NetworkService`),
per-service virtual accounts (`NT SERVICE\<name>` — confirmed as SQL Server's own default on this
machine, e.g. `NT Service\MSSQLSERVER`), blank (kernel drivers), and — not present on this
particular machine, so verified instead with synthetic examples via unit-style testing of the
classifier itself — real local/domain user accounts and gMSA/MSA accounts, which share identical
`DOMAIN\name` syntax except for the trailing `$` gMSA/MSA convention.

This is architecturally different from database/software detection: those match services *by name*
against a configured signature list, so a service outside the list produces no row anywhere. "What
runs as account X" instead needs every service's *account* examined, regardless of what the service
is — there's no name pattern to match against ahead of time. So `ServiceAccountName` is read and
classified for every service unconditionally, and only `BuiltIn`/`Virtual`/`Blank` results are
discarded as noise; `User` and `LikelyGmsaOrMsa` both survive into `LocalServiceAccounts.csv`, with
`AccountType` distinguishing them. `LikelyGmsaOrMsa` is flagged rather than dropped (a explicit
choice made with the user) because the trailing-`$` classification is a naming-convention heuristic,
not an authoritative check against AD's `msDS-GroupManagedServiceAccount` object class — this script
has no AD connectivity of its own, so it cannot positively confirm an account's actual object class
the way `Export-ADGroups.ps1` could if this were ever cross-referenced against it.

**Two derived, filtered views added in the same follow-up (added 2026-09-16): `LocalDatabasesListening.csv`
and `LocalGmsaServiceAccounts.csv`.** Both are pure in-memory filters of data already collected —
`DatabaseRows` where `Listening = True`, and `ServiceAccountRows` where `AccountType =
LikelyGmsaOrMsa` — computed once in the main script after all computers finish, not re-detected per
computer inside `Invoke-LocalComputerScan`. Neither changes what's captured; both are strictly
narrower views of `LocalDatabases.csv`/`LocalServiceAccounts.csv`, which keep every row exactly as
before. `LocalGmsaServiceAccounts.csv` exists specifically to be handed to a validation step the user
described: cross-reference each account name in it against AD and flag any that AD does not actually
recognize as a real gMSA/standalone MSA — i.e. an account that adopted the naming convention without
being a genuine managed service account, which this tool's own naming-convention heuristic cannot by
itself tell apart from the real thing. Verified live: filtering a real `LocalDatabases.csv` row set
correctly isolated exactly the listening entry; the gMSA filter was verified against synthetic rows
(no real gMSA-run service existed on the test machine) and confirmed to isolate exactly the
`LikelyGmsaOrMsa` entries.

**Why a runspace pool for concurrency, not `Start-Job` or `ForEach-Object -Parallel` (added
2026-09-16).** Three options were considered for `MaxConcurrency`:
- `ForEach-Object -Parallel` — rejected; it's PowerShell 7+ only, and this project explicitly
  supports Windows PowerShell 5.1.
- `Start-Job` (background jobs) — rejected; each job is a separate process, which is much heavier
  (process startup cost, and every module has to be re-imported per job) for what is fundamentally
  a lot of short-lived, I/O-bound work per computer.
- **A `RunspacePool`** (`System.Management.Automation.Runspaces`) — chosen; it's built into both
  Windows PowerShell 5.1 and PowerShell 7 with no extra module dependency, runspaces are threads
  within the same process (much lower overhead than a job per computer), and `MaxConcurrency`
  becomes a direct constructor argument (`CreateRunspacePool(1, $maxConcurrency, ...)`) — including
  the degenerate `MaxConcurrency = 1` case, which serializes naturally through the exact same code
  path rather than needing a separate sequential branch.

Each unit of work returns its own row collections rather than every runspace mutating shared
`$userRows`/`$groupRows`/`$memberRows` lists directly — `List[object].Add()` is not safe to call
concurrently from multiple threads, so aggregation happens back on the main thread instead, after
each job's `EndInvoke()` returns. The one genuinely shared side effect, the log file, **is** written
concurrently from multiple runspaces (each computer logs its own start/completion/error line as it
happens), so `Write-DiscoveryLog` (`Modules\Logging.psm1`) now guards its file write with a named
`Mutex` keyed on the log path — plain `Add-Content` has no coordination across concurrent writers to
the same file.

**A real bug hit and fixed while building this, worth remembering:**
`InitialSessionState.ImportPSModule(string[])`, called once with all four module paths in a single
array (`$iss.ImportPSModule(@($a, $b, $c, $d))`), silently resolved to a *different* overload that
joined the array into one space-separated string and then failed to import anything — with no
visible error until a runspace tried to call a command none of the modules had actually loaded
("`Invoke-LocalComputerScan` is not recognized..."). Confirmed live by testing directly against a
runspace pool. The fix is to call `ImportPSModule` once per module path, each in its own one-element
array (see the loop in `Export-LocalGroups.ps1`).

## 6. Security considerations

- Credentials are resolved per computer at the point of use; `GetNetworkCredential().Password` is
  only ever held in memory transiently to construct the `DirectoryEntry` bind, and is never logged.
- Only the credential *source* and outcome appear in the log, never the secret itself.

## 7. Known limitations

- **Primary-group membership is not captured — decided, will not be added.** Like Active Directory,
  Windows has a "primary group" concept for an account that isn't reflected in a group's explicit
  member list. Adding a resolved `PrimaryGroupName` column to `LocalUsers.csv` was considered and
  tested live against a real machine: every local account's `primaryGroupID` (read via the WinNT
  provider) came back `513` ("Domain Users" RID) — a value that matches **no local group at all**,
  since local SAM RIDs for built-ins start at 544 (`Administrators`) and up; `513` is only a
  meaningful group RID in a domain SAM/AD context. Local accounts don't really use a customizable
  primary group the way domain accounts do, so a resolved column would come back blank for nearly
  every account in practice. Given that low real-world yield, the user chose not to build it and to
  record this finding instead.
- **GPO-driven local admin rights (Restricted Groups / Group Policy Preferences) have no separate
  tracking — decided, no change planned.** This turned out to be less of a visibility gap than it
  first appears: Restricted Groups/GPP work by writing their result into the target's actual local
  group membership, which this tool already reads. The remaining gap is **provenance**, not
  visibility — this tool can tell you who is currently in `Administrators`, but not whether GPO put
  them there or a person did. The user confirmed that isn't currently needed; a genuinely
  provenance-aware view would mean either reading the target's local RSoP/GPO cache (needing
  WinRM/PSRemoting on every target, reintroducing the dependency this design specifically avoids) or
  a separate, unverified AD-side GPO scan — left as a possible future addition, not this tool's job.
- Launching one PowerShell instance per computer up front (rather than trickling them in as slots
  free up) means memory/handle usage scales with the total computer count, not just
  `MaxConcurrency` — fine for the list sizes this has been tested with, but worth revisiting if a
  single run ever needs to cover tens of thousands of computers (see Section 9).
- **Database and software detection only recognize the specific service(s) a signature's
  `ServicePattern` matches.** For databases, that's deliberately the primary engine/listener service
  only — auxiliary components (SQL Server Agent, Browser, Polybase, telemetry, etc.) are not
  matched, so `LocalDatabases.csv` reports one row for "the database", not every related service.
  Anything outside the configured `DatabaseSignatures`/`SoftwareSignatures` lists — a different
  engine, unusual service naming, or software nobody thought to add a signature for — is invisible
  to this feature; it is a recognized-signature allowlist, not a general
  database/software-discovery mechanism.
- **`SoftwareSignatures` ships empty by default.** Unlike `DatabaseSignatures`, nothing is checked
  until an operator populates it — there is no attempt at a universal "interesting software" default
  list, since what counts as interesting is inherently environment-specific (see Section 5).
- **`Listening = False` does not mean "not installed"**, and `Listening = True` does not guarantee
  the port is actually this engine (a firewalled/NAT'd or repurposed port could give a false
  positive on either side) — `Listening` is a best-effort network-level corroboration of the
  service-based detection, not an independent proof.
- **`PasswordLastSet` is an approximate date, not an exact one.** It's derived from the target's own
  `PasswordAge` (seconds) applied against the scanning host's clock, so ordinary clock skew between
  the two machines shows up as error in the computed date. Fine for spotting a password that's
  months or years stale; not precise enough to trust down to the minute.
- **Retry re-runs the whole per-computer scan, not just the step that failed.** A computer that
  fails partway through (e.g. after enumerating users, mid-group-loop) restarts from the
  reachability check on the next attempt — simpler and more robust than resuming mid-scan, but means
  a retry costs roughly the same as a fresh attempt, not just the remaining work.
- **`LocalScanErrors.csv` records only the final outcome**, not a row per retry attempt — the
  per-attempt `WARN`/`ERROR` detail lives in the log file, not the CSV.
- **`LocalServiceAccounts.csv`'s `AccountType = LikelyGmsaOrMsa` is a naming-convention heuristic**
  (a trailing `$`), not an authoritative check against AD — nothing stops a real user account from
  also being named with a trailing `$` (rare in practice, but possible), and this tool has no AD
  connectivity to positively confirm an account's actual object class.
- **Service account discovery only sees what the WinNT provider reports as `ServiceAccountName`.**
  A service whose logon account was changed outside the normal SCM registration path, or one running
  under an unusual mechanism this hasn't been tested against, could report something this tool's
  classifier doesn't recognize — it would fall through to `User` (the default case), which is a safe
  default (better to show a possibly-mundane account than hide a possibly-interesting one) but worth
  knowing about if an unexpected value shows up in practice.

## 8. Alternatives considered

- **PowerShell Remoting (`Invoke-Command`)** — rejected; requires WinRM enabled and trusted on
  every target, which can't be assumed across an unknown estate.
- **CIM/WMI (`Get-CimInstance Win32_UserAccount`/`Win32_Group`/`Win32_GroupUser`)** — rejected;
  broadly compatible, but group-membership queries via `Win32_GroupUser` are notoriously slow and
  awkward compared to the WinNT provider's direct `Members()` call.
- **`Start-Job` / `ForEach-Object -Parallel` for concurrency** — rejected in favor of a
  `RunspacePool`; see Section 5.
- **Remote Registry uninstall-key scan** and **`Win32_Product` (WMI)**, for database detection —
  both rejected; see Section 5.

## 9. Open decisions

Primary-group membership and GPO-driven local admin rights were both discussed and decided (see
Section 7 for the outcome and, for primary-group, the live finding that settled it) — neither is an
open item any more.

**Remaining open items:**
- Should job creation itself be throttled (e.g. launch only `MaxConcurrency` jobs at a time and
  start the next as one finishes) rather than creating a `PowerShell` instance for every computer
  up front, to bound memory for very large computer lists?
- Should `ExcludeUserNames`/`ExcludeGroupNames` support a per-computer override in
  `ComputersToScan.csv`, the way credential source already does, rather than only a global setting
  in `LocalScanConfig.json`?
- Should the Remote Registry uninstall-key scan (rejected above as a *default*) be offered as an
  opt-in extra signal for environments known to have it enabled, to catch a database that's
  installed but has no running/recognized service?
- Should `DatabaseSignatures` grow to cover more engines (e.g. Sybase/SAP ASE, DB2, Redis,
  Elasticsearch) by default, or stay minimal and rely on per-deployment overrides in
  `LocalScanConfig.json`?
- Should `DatabaseSignatures`/`SoftwareSignatures` in config **merge** with the built-in list
  instead of **replacing** it, so adding one engine doesn't require copying the whole default list?
  Documented clearly as replace-semantics for now (see Reference_Configuration.md), but a merge would be more
  convenient for the common case of "just add one more".
- Should this project maintain a small, curated example `SoftwareSignatures` list beyond the two
  starter entries (IIS, OpenSSH Server) for other commonly-relevant categories (backup agents,
  EDR/AV, remote-support tools) — or is that better left entirely to each deployment, given how much
  service naming varies by vendor and version?
- Should retry use a fixed delay (current behavior) or exponential backoff? Should a failed attempt
  ever resume from where it left off instead of restarting the whole per-computer scan?
- Should `LocalServiceAccounts.csv` ever be cross-referenced against `Export-ADGroups.ps1`'s output
  to positively confirm a `LikelyGmsaOrMsa` account's real AD object class, turning the current
  naming heuristic into an authoritative check? Would require correlating the two scripts' output
  (a domain lookup, not something this script can do on its own).
- Should there be a way to narrow `LocalServiceAccounts.csv` to specific account name(s) of interest
  (e.g. only report services running as a particular vaulted account), rather than always returning
  every non-built-in/non-virtual service account across the estate?

## 10. Revision log

| Date | Change |
|---|---|
| 2026-09-16 | Initial version, documenting the as-built `Export-LocalGroups.ps1`. |
| 2026-09-16 | Replaced the ICMP reachability check with a TCP-445 probe; added `MaxConcurrency`-throttled runspace-pool execution (`Modules\LocalComputerScanner.psm1`, `Modules\NetworkHelpers.psm1`); made `Write-DiscoveryLog` safe for concurrent writers; added `ExcludeUserNames`/`ExcludeGroupNames` filters. |
| 2026-09-16 | Decided, with the user: primary-group membership will **not** be added, based on a live test showing local accounts' `primaryGroupID` universally resolves to nothing on the local machine (see Section 7); GPO-driven local admin rights get **no change**, since the tool already captures the effective result. |
| 2026-09-16 | Added database engine detection (`LocalDatabases.csv`, `DatabaseSignatures`), reusing the WinNT bind's `Service`-class children plus a `Test-TcpPortOpen` probe of each engine's default port. Verified live against a real SQL Server install, including a `Running`-but-not-`Listening` case. |
| 2026-09-16 | Generalized database detection to arbitrary other software (`LocalSoftware.csv`, `SoftwareSignatures`, no built-in default list); added the step-by-step "adding a new signature" guide to `Claude_Docs\Reference_Configuration.md`. Verified live (IIS/`W3SVC`, `Listening = True` on port 80) alongside the existing SQL Server detection in the same run. |
| 2026-09-16 | Added `PasswordLastSet`/`PasswordExpired`/`BadPasswordAttempts` to `LocalUsers.csv`; added `RetryCount`/`RetryDelaySeconds` (whole-scan retry) and `LocalScanErrors.csv` (structured per-computer failure records); added Remote Desktop/Windows Firewall as further verified `SoftwareSignatures` examples. All four verified live in one combined run (real password fields, a retried-then-failed unreachable host producing exactly one error row, and RDP showing the same `Running`-but-not-`Listening` divergence already seen with SQL Server). |
| 2026-09-16 | Added service account discovery (`LocalServiceAccounts.csv`, `Get-ServiceAccountType`) — answers "what services run as this account" for any local/domain user or suspected gMSA/MSA, across every service unconditionally rather than by name-pattern matching. Verified live: `ServiceAccountName` confirmed as the correct WinNT property via trial and error; classification rules confirmed against a real machine's ~290 services (BuiltIn/Virtual/Blank cases) and, since no real user/gMSA-run service existed on that machine to test against, against synthetic domain-user and gMSA examples; a full run confirmed zero false positives with all other output unaffected. Decided with the user: broad discovery (not a targeted account-name filter) with gMSA/MSA flagged, not hard-filtered, given the heuristic isn't authoritative. |
| 2026-09-16 | Added two derived, filtered views: `LocalDatabasesListening.csv` (`LocalDatabases.csv` rows where `Listening = True`) and `LocalGmsaServiceAccounts.csv` (`LocalServiceAccounts.csv` rows where `AccountType = LikelyGmsaOrMsa`), the latter explicitly intended to feed a later AD cross-reference step that flags accounts using the gMSA naming convention without actually being a real gMSA/MSA. Both source files are unchanged and keep every row. Verified live/synthetically that each filter isolates exactly the intended subset. |
