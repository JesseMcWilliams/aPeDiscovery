# Open items

A single, project-wide backlog of everything still outstanding across `Export-ADObjects.ps1`,
`Export-LocalGroups.ps1`, and `Export-LocalLinuxGroups.ps1` — decisions still needing an answer,
features designed but not built, and things that need your environment (a specific test account, a
live domain controller) to finish verifying. Each design doc still carries its own "Open decisions"
section for narrative/history; this document exists so the full remaining picture doesn't have to be
assembled by reading all three. Update it as items get resolved or new ones surface, the same way
each design doc's own Section 10/Revision log is kept current.

Last updated: 2026-10-09 (Linux `BadPasswordAttempts` built; `Export-ADGroups.ps1` renamed to
`Export-ADObjects.ps1`; logging moved to the sibling LogaPe module; every verification gap below now
has a labelled live test in [Testing_Live-Test-Definitions.md](Testing_Live-Test-Definitions.md)).

## Linux discovery (`Export-LocalLinuxGroups.ps1`)

See [Design_Local-Linux-Discovery.md](Design_Local-Linux-Discovery.md) for full detail on all of
these.

**Built, not yet verified live:**
- **`BadPasswordAttempts`** (pam_faillock), added 2026-10-09. The parser and the pam.d detection were
  checked offline against sample output; it needs a real host with pam_faillock enabled (LT-LNX-02)
  and one without it (LT-LNX-03).
- **`pam_tally2` isn't read.** Older distros that use pam_tally2 instead of pam_faillock get a blank
  `BadPasswordAttempts`. Add a fallback only if a real target environment needs it.

**Known, accepted simplification (not blocking, documented in the design doc and CSV schema):**
- **`SshKeyLoginPossible` only checks the default `~/.ssh/authorized_keys` path** — it does not read
  `sshd -T`'s effective `AuthorizedKeysFile` value, so an environment that customizes that directive
  (e.g. a centralized keys directory, or `%h`/`%u` tokens beyond the default) would get an incorrect
  result. Deliberately not generalized in the first implementation since this test VM doesn't exercise
  that case — revisit if it becomes relevant to a real target environment.

**Recently resolved:**
- ~~Per-account SSH-login eligibility~~ — **implemented and verified live (Round 14)**:
  `SshPasswordLoginPossible`/`SshKeyLoginPossible` on every `LinuxLocalUsers.csv` row, confirmed
  against real, previously-known ground truth (`the NOPASSWD sudo test account`'s and `the lab admin account`'s results both matched
  facts already established earlier in this project) - the first clean implementation with no bugs
  found.
- ~~Phase 5~~ — **implemented and verified live (Round 13)**: `LinuxDatabases.csv`,
  `LinuxSoftware.csv`, `LinuxServiceAccounts.csv`, `LinuxUnrecognizedListeningPorts.csv` all built and
  confirmed against real PostgreSQL/Docker/CUPS/OpenSSH units on the test VM. Two real bugs found and
  fixed along the way (a `systemctl show` multi-unit batch call aborting on one unqueryable unit, and
  a UTF-8 status bullet corrupting `awk`-based unit-name extraction from `systemctl list-units`).
- ~~Sudo-elevated command execution for the password-required case~~ — **resolved (Round 12)**:
  `echo | sudo -S` is now wired into `Modules\LocalLinuxComputerScanner.psm1` (a single ticket-refresh
  call per computer, not per account) and verified end-to-end across all three sudo states. The
  `SudoCredentialSource` override path for key-based auth is implemented but not separately verified
  live, for lack of a matching test scenario (LT-LNX-04).

**Needs your environment to finish verifying:**
- ~~A test account with genuinely password-required sudo rights~~ — **resolved (Round 10)**: the
  user configured `the password-required sudo test account` via CyberArk CP; `LinuxSudoRights.csv`'s `PasswordRequired`
  classification is confirmed correct against it. Only the actual password-supply mechanism itself
  (above) remains unbuilt/unexercised.
- **MySQL/MariaDB/MongoDB `DatabaseSignatures` are unverified** — only PostgreSQL is installed on the
  current test VM. Needs one of those engines available to confirm the `UnitPattern`/`DefaultPort`
  starter values now that Phase 5 is built and working (LT-LNX-05).

**Housekeeping (low priority):**
- `Secrets\aped-linux-test-key`'s public half is still installed on the test VM. Fine to leave while
  it's still being used for testing; remove it from the VM's `authorized_keys` (and this project's
  `Secrets\` folder) once you're done with it.

## Windows local discovery (`Export-LocalGroups.ps1`)

See [Design_Local-Windows-Discovery.md](Design_Local-Windows-Discovery.md) Section 9 for full detail.

- Should job creation be throttled to launch only `MaxConcurrency` jobs at a time (rather than one
  `PowerShell` instance per computer up front), to bound memory on a very large computer list? Not a
  problem at the scale tested so far.
- Should `ExcludeUserNames`/`ExcludeGroupNames` support a per-computer override in
  `ComputersToScan.csv` (like `CredentialSource` already does), not just a global setting?
- Should the Remote Registry uninstall-key scan (rejected as a *default*) be offered as an opt-in
  extra signal, to catch a database installed but with no running/recognized service?
- Should `DatabaseSignatures` grow to cover more engines by default (Sybase/SAP ASE, DB2, Redis,
  Elasticsearch), or stay minimal and rely on per-deployment overrides?
- Should `DatabaseSignatures`/`SoftwareSignatures` in config **merge** with the built-in list instead
  of **replacing** it? Currently documented as replace-semantics; a merge would be more convenient
  for "just add one more engine."
- Should this project maintain a broader curated `SoftwareSignatures` example list (backup agents,
  EDR/AV, remote-support tools) beyond the two starter entries (IIS, OpenSSH Server)?
- Should retry use exponential backoff instead of a fixed delay? Should a failed attempt resume from
  where it left off rather than restarting the whole per-computer scan?
- Should `LocalServiceAccounts.csv`'s `LikelyGmsaOrMsa` naming-convention heuristic be upgraded to an
  authoritative check by cross-referencing `Export-ADObjects.ps1`'s output? Would need to correlate
  the two scripts' output, since neither has the other's connectivity on its own.
- Should there be a way to narrow `LocalServiceAccounts.csv` to specific account name(s) of interest,
  rather than always returning every non-built-in/non-virtual account across the estate?

## AD discovery (`Export-ADObjects.ps1`)

See [Design_AD-Discovery.md](Design_AD-Discovery.md) Section 9 for full detail.

- **Redesign in progress:** per-type Users/Computers/Groups blocks with every filter built into the LDAP query.
  See [Planning_AD-Object-Filters.md](Planning_AD-Object-Filters.md). It supersedes several questions below
  (exclude-style computer filters, `BaseOU` defaults) and fixes a gap: objects in the default
  `CN=Users`/`CN=Computers`/`CN=Builtin` containers are never exported today.

- Should Azure AD / Entra ID group export be added as a second data source feeding the same output
  shape? Currently on-prem AD only.
- Is the 1,500-member range limit on `MemberCount` worth fixing with ranged attribute retrieval, or
  acceptable given `Get-ADGroupMember` (the primary membership path) isn't affected?
- Should `ExcludeGroupNames` also (or instead) support matching on `DistinguishedName`/OU-relative
  path, for when the same name recurs under different OUs but only one instance should be excluded?
- Should `NameFilter`/`OSTypeFilter` (computer discovery) support an exclude-style variant, mirroring
  `ExcludeGroupNames`, for "scan everything except..." rather than only "scan only matching..."?
- Is defaulting the `Computers` block's `BaseOU` to the domain root the right default, given the
  whole reason for scoping it independently is that computers usually live elsewhere in the tree?
- **Computer object discovery (`ADComputers.csv`) has never been tested against a live domain
  controller** — only verified via a mocked-object pipeline, since no AD/RSAT environment was
  available while building it. Needs `-DomainFilter` validation against a real domain before
  production use (LT-AD-02).

## Cross-cutting / project-wide

- **Security findings F1–F3** ([Reference_Security-Team-Brief.md](Reference_Security-Team-Brief.md#7-known-risks-and-open-findings)):
  - **F1:** the Linux sudo password is embedded (base64) in the remote command line, so it's visible in the target's process list and in command auditing. Fix: send it over the SSH session's input stream.
  - **F2:** `/etc/shadow` hashes are sent back to the scanning host for classification. Fix: classify on the target.
  - **F3:** `AcceptNewHostKey` defaults to true, so host keys are trusted on first use.

  All three are in `Modules\LocalLinuxComputerScanner.psm1`, `Export-LocalLinuxGroups.ps1` and its config.
- **`Install-aPeDiscovery.ps1`'s elevated paths are untested.** The repository install/update and the offline bundle were tested; installing PowerShell 7, Posh-SSH and RSAT has only run as `-WhatIf` (LT-INST-01).

- **`CredentialResolver.psm1`'s `Conjur` source is unverified against a real deployment.** `CP` was
  verified end-to-end here on 2026-09-17 (see
  [Archive_Design_Local-Linux-Discovery-Revision-Log.md](Archive_Design_Local-Linux-Discovery-Revision-Log.md),
  Round 10), and that testing found and fixed a real output-parsing bug. `CCP` was verified live in
  aPeSecrets on 2026-09-21 (its `Reference_Configuration.md`), but not yet through an aPeDiscovery
  scan (LT-CRED-01). Treat `Conjur` with the same suspicion until it's tested (LT-CRED-02).
- **FIPS-mode hosts need LogaPe's FIPS fix (merged to LogaPe `main` 2026-10-09, after 0.5.0).**
  LogaPe 0.5.0 and the `Logging.psm1` it replaced both named the log mutex with an MD5 hash, which
  throws on Windows PowerShell 5.1 under FIPS policy and would stop every script at its first log
  write. The LogaPe fix switches to `SHA256CryptoServiceProvider`. It still needs a run on a
  FIPS-enforced host to confirm.
- **LogaPe is now a sibling dependency**, like aPeSecrets: all three scripts import
  `..\LogaPe\LogaPe\LogaPe.psd1`, so `LogaPe` must be checked out next to this repo. Every logger
  has LogaPe's default masking on (`-EnableDefaultMasking`), so `password=...`/`token: ...`-style
  text reaching a log line, including text inside exception messages, is written as `***`. The
  output CSVs (for example `*ScanErrors.csv`'s `ErrorMessage`) are not masked.
- **Linux and Windows local discovery still have separate, duplicated `RunspacePool`/retry/error-CSV
  implementations** (`Modules\LocalComputerScanner.psm1` vs. `Modules\LocalLinuxComputerScanner.psm1`)
  rather than a shared orchestration layer — a deliberate choice so far (the two scripts' actual
  connection/data-collection logic is different enough that a shared abstraction didn't seem worth
  it), but worth revisiting if a third platform (e.g. macOS) is ever added.
- No automated test suite (Pester or otherwise) exists for any of the three scripts — all
  verification to date has been manual, live testing against real targets (see
  [Testing_Guide.md](Testing_Guide.md)) plus one isolated mock-object test for AD computer discovery.
  Pure parsers like `ConvertFrom-LinuxFaillockOutput`, `ConvertTo-LinuxPasswordState` and
  `ConvertTo-LinuxSudoAccess` are the cheapest place to start a Pester suite.
