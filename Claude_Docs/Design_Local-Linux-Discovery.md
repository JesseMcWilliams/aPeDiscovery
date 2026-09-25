# Local Linux Discovery — Design

**2026-09-21 update:** `Modules\CredentialResolver.psm1` (`Get-DiscoveryCredential`) referenced
throughout this document was extracted into the sibling **aPeSecrets** project and renamed
`Get-ResolvedCredential` — the CP live-verification and bugfix history below is preserved as-is
(it happened here, in this project, before the move), but the module itself, and any future
CP/CCP/Conjur/WindowsCredentialManager work, now lives at `..\aPeSecrets\Modules\CredentialResolver.psm1`.

**Status:** Phases 1-5 plus per-account SSH-login eligibility are all implemented and verified live —
`Export-LocalLinuxGroups.ps1` and `Modules\LocalLinuxComputerScanner.psm1` now exist, covering
connectivity (password + key auth, retry, `RunspacePool`-based concurrency mirroring
`Export-LocalGroups.ps1` exactly), users/groups/membership, password-state fields, sudo rights for
every discovered account (`LinuxSudoRights.csv`), `DirectoryJoined` (SSSD/Winbind detection), full
sudo elevation via `echo | sudo -S` (a single ticket-refresh call per computer, not per account),
database/software/service-account detection (`LinuxDatabases.csv`/`LinuxSoftware.csv`/
`LinuxServiceAccounts.csv`/`LinuxUnrecognizedListeningPorts.csv`), and now `SshPasswordLoginPossible`/
`SshKeyLoginPossible` on every user row — all confirmed against the real Ubuntu test VM, including a
dedicated concurrency test, end-to-end verification across all three sudo states (`NOPASSWD`,
password-required using `the password-required sudo test account` as the actual connecting account, and zero access with clean
graceful degradation), real PostgreSQL/Docker/CUPS/OpenSSH detections with correctly-resolved service
accounts, and SSH-login-eligibility results directly corroborated by this session's own live usage
(`the NOPASSWD sudo test account`'s `SshKeyLoginPossible = True` and `the lab admin account`'s `SshKeyLoginPossible = False` both matched
already-known ground truth). Several real bugs were found and fixed along the way: a
misleadingly-worded PowerShell parameter-binding error for a `Mandatory [string[]]` containing a
blank element, `sudo -n -v` not honoring `NOPASSWD` the way an actual exempted command does, a UTF-8
status-bullet character corrupting unit-name extraction from `systemctl list-units`' default output,
and a single `systemctl show <all units>` batch call aborting after only a couple of units when one
of them wasn't individually queryable (fixed by reverting to a per-unit loop, matching the
already-proven `SUDOUSER` pattern). CyberArk CP itself is verified live end-to-end too, having caught
and fixed a real `CLIPasswordSDK.exe` output-parsing bug in `Modules\CredentialResolver.psm1`. The
only remaining unbuilt item in the whole Linux design is `BadPasswordAttempts` (`faillock`). Linux
output/input files are entirely separate from the Windows tool's, as decided. See
`Claude_Docs\Planning_Open-Items.md` for the full outstanding-work backlog across this whole project, not just Linux.
**Initiated:** 2026-09-16
**Origin:** User request to extend local-account discovery (already built for Windows, via
`Export-LocalGroups.ps1`) to Linux targets, keeping output formats similar across both. The user
later directed that connectivity use the `Posh-SSH` PowerShell module rather than the `plink.exe`
approach this document originally proposed.

This document is a plan, not an implementation — nothing described here has been built yet. Its
purpose is to surface the design decisions that need an answer (Section 10) before a
`Export-LocalLinuxGroups.ps1` gets written, using the same shape of doc as
[Design_Local-Windows-Discovery.md](Design_Local-Windows-Discovery.md) and
[Design_AD-Discovery.md](Design_AD-Discovery.md).

**A note on verification:** `Posh-SSH`'s cmdlets, parameters, and output shapes below were confirmed
live — the module was installed (`Install-Module Posh-SSH -Scope CurrentUser`) and its real command
signatures and help/examples inspected — not written from memory.

**Update 2026-09-17 — first verified against Windows (own OpenSSH Server), then against a real Linux
VM.** With the user's approval, Windows' OpenSSH Server feature was enabled on the development
machine to first close the "never tested against anything" gap: `New-SSHSession`/`Invoke-SSHCommand`/
`Remove-SSHSession` connected via key-based auth and ran `whoami && hostname` successfully. The user
then set up a real Ubuntu test VM and provided its address/username, closing the remaining gap for
real: the actual proposed `/etc/passwd`+`/etc/group` collection command ran successfully against it
(56 users, 87 groups, correct multi-member group parsing) — **and that test caught a real bug in this
document's original design**: `Invoke-SSHCommand`'s `.Output` is a `String[]` (array of lines), not a
single string as originally assumed, which silently breaks a naive `-split` on it. See Sections 4-5
for the corrected design and Section 9 for the full test record.

---

## 1. Why this is worth doing

Local-account discovery exists today for Windows but not Linux, leaving the same class of blind
spot on the Linux estate that motivated the Windows tool: local accounts, local groups, and local
group membership that AD-only discovery can't see and that a downstream PAM-adjacent tool needs
visibility into.

## 2. Context & constraints

- **The control host is Windows** — the same host already running `Export-ADGroups.ps1` and
  `Export-LocalGroups.ps1`. Nothing here assumes PowerShell/`pwsh` is installed on the Linux
  targets themselves; like the Windows script's "no WinRM required" constraint, this should stay
  agentless — reachable over SSH with nothing pre-installed beyond a standard `sh`/`bash` and
  `getent`/`coreutils`, which any Linux target should already have.
- **Connectivity is `Posh-SSH`, per explicit user direction** — not the `plink.exe`-based approach
  originally proposed here after finding a proven pattern for it in the sibling `aPePAS` repository
  (`APIModules\Custom\Invoke-CustomTestConnectivity.ps1`). `Posh-SSH` is a PowerShell Gallery module
  (`Install-Module Posh-SSH`), not something built into Windows PowerShell/`pwsh`, so it becomes a
  new prerequisite on the control host that neither `Export-ADGroups.ps1` nor
  `Export-LocalGroups.ps1` needed. See Section 4 for what was verified about it.
- **CyberArk remains the credential system of record**, per the existing `CredentialResolver.psm1`.
  Unlike the `plink`-based approach originally considered, `Posh-SSH` turns out **not** to need a new
  credential shape for key-based auth (see Section 4) — the existing `PSCredential`-returning
  `Get-DiscoveryCredential` covers both password and key-based auth with only a small addition to
  `CredentialParams`, not a new resolver method.
- **This would run unattended, nightly, via Scheduled Task**, same operational bar as the other two
  scripts: one unreachable/misconfigured host must not abort the run, and the run must leave a
  clear audit trail.

## 3. Non-goals (proposed)

- **Sudo rights discovery and sudo-elevated command execution are now in scope** (added
  2026-09-17, per user direction) — see Section 5a. This reverses what this document originally
  proposed (excluding sudoers enumeration from v1); it's no longer deferred.
- **No SELinux/AppArmor policy discovery, no software/package inventory, no OS patch level.**
  Strictly local users, groups, and group membership, mirroring the Windows tool's scope.
- **No resolution of directory-integrated accounts (SSSD/Winbind/LDAP) — decided with the user
  (2026-09-17): still read `/etc/passwd`/`/etc/group` directly (the `files` NSS source only, not
  `getent`) and collect them exactly as before, but flag the computer.** A Linux host joined to AD
  via SSSD or Winbind can present domain accounts through `getent passwd`/`getent group` alongside
  genuinely local ones; rather than excluding such hosts or trying to positively distinguish
  local-vs-directory-sourced *entries* (a harder problem, deferred), every user/group row from a
  directory-joined computer now carries `DirectoryJoined = True` (see Section 6), telling a
  downstream consumer "some entries here may not be genuinely local" without attempting to sort out
  which ones. **Implemented and verified live** — see Section 9, Round 9. Detection deliberately does
  **not** trust `/etc/nsswitch.conf` mentioning `sss` on its own: confirmed live that this project's
  own test VM has `sss` in `nsswitch.conf`'s `passwd`/`group` lines from its base Ubuntu image with
  `sssd` never actually active or configured (no `/etc/sssd/sssd.conf` at all) — a real false-positive
  trap. The actual check is `sssd` active AND a real `sssd.conf` present, or `winbind` active.
- **Read-only.** Nothing here would modify accounts, groups, or membership on any target.

## 4. Connectivity & credential model — decided (Posh-SSH)

**Verified live** (module installed, real cmdlets/parameters/examples inspected — not written from
memory):

- **`New-SSHSession`** opens a session: `New-SSHSession -ComputerName <host> -Credential <PSCredential> [-Port 22] [-ConnectionTimeout <seconds, default 10>] [-KeyFile <path> | -KeyString <string[]>] [-AcceptKey] [-Force] [-ErrorOnUntrusted] [-KnownHost <IStore>]`. `-Credential` is **required in every parameter set**, including the key-based ones — when a key is supplied, `-Credential`'s password field is used as the key's passphrase (blank/dummy if the key has none) and its username field is the SSH login name. This is the important finding: `Get-DiscoveryCredential`'s existing `PSCredential`-returning shape already covers **both** password auth and key auth — key-based auth only additionally needs a key file path, which can simply be a new field in `CredentialParams` (e.g. `KeyFilePath`) read directly by the Linux script, not a new resolver method or return shape. This resolves what the original (`plink`-based) version of this document flagged as an open gap in `CredentialResolver.psm1` — there isn't one.
- **Host key trust is handled natively**, unlike the manual fingerprint-parsing retry the `plink`-based approach would have needed: `-AcceptKey` auto-trusts a new host (trust-on-first-use), `-Force` skips host-key validation entirely (not recommended as a default), and by default `New-SSHSession` persists accepted host keys to `$HOME\.poshss\hosts.json` — so a host only needs `-AcceptKey` the *first* time it's ever scanned from a given Run As identity; subsequent runs trust it automatically from that file. Worth remembering operationally: `$HOME` here means the Scheduled Task's Run As account's profile, so that JSON file's location and persistence follow that account, the same way the `PSCredential` source's DPAPI-encrypted file does.
- **`Invoke-SSHCommand`** runs a command over an existing session: `Invoke-SSHCommand -SSHSession <session> -Command '<command>' [-TimeOut <seconds, default 60>]`. It returns an object with `Host`, `Output`, and `ExitStatus` (int) properties. **Correction (2026-09-17, found by live testing against a real Linux VM — the cmdlet's own documented example doesn't make this clear): `.Output` is a `System.String[]` — one element per line — not a single string.** This document originally assumed a single string and proposed `-split`ting it on a separator; run for real, `-split` against an array operates *per element* instead of on the whole, and silently produced garbage (each array slot just reported its own single unsplit line, with the actual separator line the only one that split into two empties) — a real, confirmed pitfall, not a hypothetical one. The correct approach, verified working against a real 56-user/87-group `/etc/passwd`+`/etc/group` dump: find the separator line's index with `[array]::IndexOf($lines, '<separator>')` and slice the array on either side of it, rather than joining/splitting a string.
- **`Remove-SSHSession`** closes a session — call this in a `finally`, mirroring how the Windows tool always disposes its `PowerShell` instances.
- Posh-SSH also exposes `Invoke-SSHCommand -SessionId <int[]> ... -ThrottleLimit <int, default 32>`, which can run one command across *many already-open* sessions in parallel using Posh-SSH's own throttling. This is a real, usable alternative to a `RunspacePool` for the command-execution step specifically — considered and not chosen as the primary design; see Section 5 and Alternatives.

**Security note (an improvement over the `plink` approach this document originally proposed):**
`plink -pw` passes the password as a plain command-line argument, briefly visible to anything else
on the host that can enumerate process command lines. `Posh-SSH`'s `-Credential` is an in-process
`PSCredential` object passed directly to a .NET SSH library call, not a spawned external process
with a command-line argument — it does not have this exposure. This was a real security tradeoff the
`plink`-based design would have inherited from `aPePAS`; switching to `Posh-SSH` avoids it rather
than accepting it.

## 5. Proposed architecture

```
LinuxComputersToScan.csv (a separate file from the Windows tool's ComputersToScan.csv — decided 2026-09-17)
  └─ RunspacePool sized by MaxConcurrency (mirrors Export-LocalGroups.ps1's architecture exactly),
     one PowerShell instance per computer, each running Invoke-LocalLinuxComputerScan:
       up to RetryCount+1 attempts, clearing any rows from a prior partial attempt first:
         Test-TcpPortOpen -Port 22 reachability check → throw fast if unreachable
         resolve credential (CredentialResolver.psm1, per-row CredentialParamsJson)
         New-SSHSession -ComputerName <host> -Credential <cred> [-KeyFile <path if configured>]
                        -ConnectionTimeout <seconds> -AcceptKey -ErrorAction Stop
         Invoke-SSHCommand -SSHSession <session> -Command '<remote read-only command>' -TimeOut <seconds>
           └─ parse .Output (a single string) locally into rows
         Remove-SSHSession <session>  (always, in a finally)
       returns one result object, same shape as the Windows tool's: { ComputerName, Success,
       ErrorMessage, UserRows, GroupRows, MemberRows }
  └─ main script EndInvoke()s each job, merges rows; a still-failed result becomes a LocalScanErrors.csv row
Export-Csv → LinuxLocalUsers.csv / LinuxLocalGroups.csv / LinuxLocalGroupMembers.csv / LocalScanErrors.csv
  (+ timestamped Archive copy, retention-pruned — same pattern as the other two scripts)
```

This deliberately mirrors `Export-LocalGroups.ps1`'s architecture (RunspacePool, per-computer retry
loop, structured error CSV) rather than inventing a new shape for Linux — the two scripts' internal
structure should look like siblings, differing mainly in the connection/data-collection step
(`Posh-SSH` + shell commands vs. ADSI/WinNT), not in concurrency, retry, or error handling.

**Why TCP-22 instead of ICMP for the reachability check, and why keep it at all given
`New-SSHSession` has its own `-ConnectionTimeout`.** ICMP can be blocked while the actual dependency
(port 22) is not — the same reasoning that led `Export-LocalGroups.ps1` to replace its own ICMP
check with TCP-445. A cheap TCP-22 probe before resolving a credential also avoids spending a
CyberArk CP/CCP/Conjur round-trip (each has its own latency and, depending on the source, rate
limits) on a host that's obviously down — `New-SSHSession`'s own timeout would eventually reach the
same conclusion, but only after the credential was already resolved.

**Remote command shape — verified live against a real Linux VM (2026-09-17):** a single
non-interactive command that prints `/etc/passwd` and `/etc/group` with a distinguishing separator
line between them (`cat /etc/passwd; echo '---APEDISC-SEP---'; cat /etc/group`), run exactly as
proposed and confirmed working end-to-end against a real Ubuntu VM (56 users, 87 groups, correctly
including a multi-member group: `sudo:x:27:the lab admin account,a lab service account with layered sudo rights,another lab service account with layered sudo rights`). Parsing keeps all
logic in PowerShell rather than pushing a script to the target, the same philosophy as the Windows
tool — but **must operate on `.Output` as an array of lines** (find the separator line's index via
`[array]::IndexOf`, slice on either side of it), not as a single string to `-split` — see Section 4
for why the naive string-split approach silently breaks.

## 5b. Sudo rights discovery, elevation & data model (split out)

This doc was split for length. The full sudo-discovery/elevation design (formerly Section 5a) and the full data model / parity / Phase 5 design (formerly Sections 6, 6a, 6b) now live in their own files:

- [Design_Local-Linux-Discovery-Sudo-Elevation.md](Design_Local-Linux-Discovery-Sudo-Elevation.md)
- [Design_Local-Linux-Discovery-Data-Model.md](Design_Local-Linux-Discovery-Data-Model.md)

## 7. Security considerations

- Same credential-handling posture as the other two scripts: resolved per host at the point of use,
  never logged; only the source and outcome appear in the log.
- **`Posh-SSH`'s `-Credential` avoids the command-line exposure `plink -pw` would have had** (see
  Section 4) — the password/passphrase is passed as an in-process object to a .NET SSH library, not
  as a visible external-process argument. This is a genuine improvement over the design this
  document originally proposed, not a tradeoff carried forward.
- `Install-Module Posh-SSH` pulls a third-party module from the PowerShell Gallery onto the control
  host — the same supply-chain trust consideration as any external dependency. Pin an exact version
  once this is actually built, the same way `CredentialResolver.psm1` already urges verifying
  CP/CCP/Conjur specifics against the real deployment rather than assuming.
- If a later phase adds `/etc/shadow`-derived fields, only the specific derived flags needed
  (disabled/never-expires) should ever be parsed out and logged — never the shadow file's raw
  content, which includes password hashes.
- **A sudo password supplied via `echo '<password>' | sudo -S` is briefly visible on the *target*
  host's own process list** (`ps aux`/`/proc/<pid>/cmdline`) while the command runs — see Section 5a
  for the full discussion and the `SUDO_ASKPASS` alternative that would avoid it.

## 8. Phased rollout (proposed)

1. **Phase 1 — implemented.** Password auth via `Posh-SSH` (no `CredentialResolver.psm1` changes
   needed); `/etc/passwd` + `/etc/group`; no primary-group resolution; `RunspacePool`-based
   concurrency mirroring `Export-LocalGroups.ps1`. All verified live, including a dedicated
   concurrency test.
2. **Phase 2 — implemented.** Key-based auth: an optional `KeyFilePath` field in `CredentialParams`,
   passed straight through to `New-SSHSession -KeyFile`. Turned out much smaller than originally
   scoped — see Section 4 — since `Get-DiscoveryCredential`'s existing return shape already covers
   the username/passphrase half. Verified live (this is how the test VM itself is scanned).
3. **Phase 3 — implemented and fully verified.** Sudo rights discovery (`LinuxSudoRights.csv`, see
   Section 5a): every discovered account classified as `None` / `PasswordlessSomeOrAll` /
   `PasswordRequired`, via one remote `sudo -n -l -U <user>` loop per computer. All three categories
   now confirmed against real accounts (Round 10 closed the last gap: a genuinely password-required
   test account, `the password-required sudo test account`, correctly classifies as `PasswordRequired`).
4. **Phase 4 — implemented and verified; one item still missing.** `/etc/shadow`-derived fields
   (`PasswordState`, `PasswordLastSet`, `PasswordNeverExpires`), full sudo elevation (`echo | sudo -S`,
   one ticket-refresh call per computer per Round 11/12), and per-account SSH-login eligibility
   (`SshPasswordLoginPossible`/`SshKeyLoginPossible`, Round 14) are all implemented in
   `Modules\LocalLinuxComputerScanner.psm1` and verified live across all three sudo states, including
   graceful degradation to blank/`Unknown` fields when no sudo credential is available at all. **Not
   yet implemented**: `BadPasswordAttempts` (`faillock`) — the only remaining item in the whole Linux
   design (Section 6).
5. **Phase 5 — implemented and verified live (Round 13).** `LinuxDatabases.csv`/`LinuxSoftware.csv`
   (systemd-unit-name signature matching, enriched via `systemctl show`, listening confirmed via one
   `ss -tlnp` capture per computer rather than a probe per signature), `LinuxServiceAccounts.csv`
   (every non-`root` service account, resolved via the unit's live `MainPID` rather than `systemctl
   show`'s own `User=`), and `LinuxUnrecognizedListeningPorts.csv` (any listening port matching no
   configured signature). Verified against real PostgreSQL, Docker, CUPS, and OpenSSH units on the
   test VM. `MySQL`/`MariaDB`/`MongoDB` starter signatures remain unverified — no such engine has been
   available to test against.

## 10. Open decisions (need an answer before Phase 1 starts)

- ~~Shared or separate input file/script?~~ / ~~Shared or separate output schema?~~ — **decided with
  the user (2026-09-17): separate.** No `Platform` column, no shared filenames with the Windows tool,
  for input or output. See Section 6/6b.
- ~~Default host-key trust policy~~ — **decided (2026-09-17, Round 9): keep `-AcceptKey` by default**,
  as already implemented. No change made.
- ~~`RunspacePool` (mirroring the Windows tool) vs. `Posh-SSH`'s own `Invoke-SSHCommand -SessionId
  <array> -ThrottleLimit`** for concurrency~~ — **decided and verified live (2026-09-17, Round 8):
  `RunspacePool`.** Built exactly per Section 5's diagram, `MaxConcurrency`-throttled, one
  `Invoke-LocalLinuxComputerScan` call per computer. Verified with 3 simultaneous scans of the same
  test VM (all 3 `New-SSHSession`s opened and completed within the same second, each runspace's rows
  correctly isolated — no cross-talk between concurrent attempts' user/group/sudo data). Posh-SSH's
  own `-SessionId`/`-ThrottleLimit` alternative was not built — the `RunspacePool` approach already
  works and keeps the two scripts' concurrency model identical, which was the original reason to
  prefer it.
- ~~Phase 5's remaining open question~~ — **decided and implemented (2026-09-17, Rounds 9/13): yes,
  the port table also drives detection on its own**, into `LinuxUnrecognizedListeningPorts.csv` — see
  Section 6b. `MySQL`/`MariaDB`/`MongoDB` starter signatures remain unverified (see
  `Claude_Docs\Planning_Open-Items.md`).
- ~~SSSD/Winbind-joined hosts~~ — **decided and implemented (2026-09-17, Round 9): still collect
  normally, flag the computer via `DirectoryJoined`** — see Section 3/6/9.
- ~~Sudo password source~~ — **decided and implemented (2026-09-17, Round 9/12)**: reuse the login
  password when SSH auth is password-based; require a separate `SudoCredentialSource`/
  `SudoCredentialParams` when it's key-based (or when explicitly overridden regardless of auth type).
  See Section 5a. The `SudoCredentialSource` override path itself is implemented but not separately
  verified live against a real mismatched-credential setup — see `Claude_Docs\Planning_Open-Items.md`.
- ~~Should `SshPasswordLoginPossible`/`SshKeyLoginPossible` be a new Phase, or folded into Phase 4~~ —
  **resolved by implementation (2026-09-17, Round 14): folded into the main scan**, not a separate
  phase — both fields are populated in the same combined remote command as everything else, gated on
  the same sudo elevation. A scan account without sudo correctly reports both as `$null`/`Unknown`
  (not a guess) rather than falling back to a `sshd_config` grep. `AuthorizedKeysFile` is **not** read
  from `sshd -T`'s effective output as originally proposed — only the default
  `~/.ssh/authorized_keys` path is checked, a documented simplification tracked in
  `Claude_Docs\Planning_Open-Items.md` for any environment with a customized directive.
- ~~Needed before Phase 3/4 can finish being verified: a test account with password-required sudo
  rights~~ — **resolved (2026-09-17, Round 10)**: the user configured `the password-required sudo test account` (full `ALL` sudo,
  password-required) via CyberArk CP. `LinuxSudoRights.csv`'s `PasswordRequired` classification is
  now confirmed correct against real data. Only the actual `echo | sudo -S` elevation mechanism
  itself (next item) remains unexercised.
- ~~`echo '<password>' | sudo -S` vs. a `SUDO_ASKPASS` helper script~~ — **decided and implemented
  (2026-09-17): `echo | sudo -S`.** `SUDO_ASKPASS` needs a helper file pre-staged on every target
  (not guaranteed to exist), so it isn't universal the way `echo | sudo -S` is — see Section 5a for
  the full side-by-side, the live verification across all three sudo states, and Round 12 for the
  actual implementation (a single ticket-refresh call per computer, not per account) and its two
  real bugs found and fixed.
- ~~Validate against a real target before committing to this design as final~~ — **fully done**
  (2026-09-17, see Section 9): verified first against Windows OpenSSH (proving the mechanism), then
  against a real Ubuntu VM running the actual proposed `/etc/passwd`+`/etc/group` command, which
  caught and fixed a real bug (`.Output` is a `String[]`, not a string).

## 11. History

The session-by-session progress tracker and revision log (formerly Sections 9 and 11) are preserved word-for-word in [Archive_Design_Local-Linux-Discovery-Revision-Log.md](Archive_Design_Local-Linux-Discovery-Revision-Log.md). Ongoing history is tracked in git from this point on.
