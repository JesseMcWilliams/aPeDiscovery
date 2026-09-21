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
password-required using `CAscanner2` as the actual connecting account, and zero access with clean
graceful degradation), real PostgreSQL/Docker/CUPS/OpenSSH detections with correctly-resolved service
accounts, and SSH-login-eligibility results directly corroborated by this session's own live usage
(`CAscanner`'s `SshKeyLoginPossible = True` and `ladmin`'s `SshKeyLoginPossible = False` both matched
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
`Docs\Open-Items.md` for the full outstanding-work backlog across this whole project, not just Linux.
**Initiated:** 2026-09-16
**Origin:** User request to extend local-account discovery (already built for Windows, via
`Export-LocalGroups.ps1`) to Linux targets, keeping output formats similar across both. The user
later directed that connectivity use the `Posh-SSH` PowerShell module rather than the `plink.exe`
approach this document originally proposed.

This document is a plan, not an implementation — nothing described here has been built yet. Its
purpose is to surface the design decisions that need an answer (Section 10) before a
`Export-LocalLinuxGroups.ps1` gets written, using the same shape of doc as
[Design-Local-Windows-Discovery.md](Design-Local-Windows-Discovery.md) and
[Design-AD-Discovery.md](Design-AD-Discovery.md).

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
including a multi-member group: `sudo:x:27:ladmin,CyberArkPCRec,CyberArkSHRec`). Parsing keeps all
logic in PowerShell rather than pushing a script to the target, the same philosophy as the Windows
tool — but **must operate on `.Output` as an array of lines** (find the separator line's index via
`[array]::IndexOf`, slice on either side of it), not as a single string to `-split` — see Section 4
for why the naive string-split approach silently breaks.

## 5a. Sudo rights discovery and elevation (added 2026-09-17, per user direction)

Two related but distinct needs: (1) **document** each scanned account's sudo rights as a data point
in its own right (mirrors the Windows tool's service-account discovery — "what elevated access does
this account actually have"), and (2) **use** sudo when a later phase needs an elevated read (e.g.
`/etc/shadow` for password-aging fields), including supplying a password non-interactively when the
account's sudo rule requires one.

**Verified live against the real test VM, "no access" case (`CAscanner`, before it had any sudo
rights):**
- `sudo -n -l` (non-interactively, list rights) exits `1` with `stderr`: `sudo: Sorry, user CAscanner
  may not run sudo on ladmin-Virtual-Machine.` — **no password prompt at all** when there's no
  matching sudoers rule; sudo fails fast instead of asking. This message is a clean, reliable pattern
  to detect the "no sudo access whatsoever" case (`ExitStatus = 1` and this specific text on
  `.Error`).
- Confirmed `Invoke-SSHCommand`'s result object also has an `.Error` property (stderr), alongside the
  already-known `.Output`/`.ExitStatus` — useful here since sudo's rights-check messages land on
  stderr, not stdout.

**Verified live, passwordless (`NOPASSWD`) case (2026-09-17, after the user granted `CAscanner`
`NOPASSWD` sudo rights):**
- `sudo -n -l` now exits `0` and prints the granted rule(s) as plain text:
  ```
  User CAscanner may run the following commands on ladmin-Virtual-Machine:
      (ALL : ALL) ALL
      (ALL : ALL) NOPASSWD: ALL
  ```
  (This test VM's sudoers config grants both a regular `ALL` rule and a `NOPASSWD: ALL` rule for the
  account — real, observed data, not something this design assumed.) `ExitStatus = 0` plus non-empty
  `.Output` (vs. the "no access" case's `ExitStatus = 1` and specific `.Error` text) is enough to
  distinguish "has some access" from "none" cleanly; a simple check for the literal substring
  `NOPASSWD` in that output distinguishes passwordless from password-required rules.
- `sudo -n whoami` (an actual elevated command, not just the rights *listing*) executed immediately
  with zero password prompt and returned `root` — confirms real command elevation works end-to-end
  for a `NOPASSWD` account, not just that `-l` reports it should.
- **The Phase 4 use case itself confirmed working**: `sudo -n cat /etc/shadow` succeeded (57 lines).
  Rather than ever transmitting or displaying raw shadow content (which includes password hashes),
  the test ran `awk` *on the remote host* to derive only the specific non-sensitive fields a
  disabled/password-aging check needs (locked-vs-set, last-change day, max-age) — e.g.
  `root:LOCKED:20691:99999` — proving both the elevation mechanism and the "only derive specific
  fields remotely, never pull raw shadow content back" security posture from Section 7 together, in
  one real test.

**Password-required case — verified live (2026-09-17, Round 10).** The user configured a real
CyberArk CP test account (`CAscanner2`, Safe `McWilliams Jesse`) with full (`ALL`) sudo rights but no
`NOPASSWD` grant. Two things confirmed:
- **Self-check, `sudo -n -l` run as `CAscanner2` itself** (via a real SSH session authenticated with
  the CP-retrieved password): `whoami` → `CAscanner2`; `sudo -n -l` → `ExitStatus = 1`, output
  `sudo: interactive authentication is required` — a **third**, distinct message pattern, different
  from both the self-check "no access" case (`Sorry, user X may not run sudo`) and the `-U`-check "no
  access" case (`is not allowed to run sudo`).
- **The actual mechanism this tool uses, `sudo -n -l -U CAscanner2` run by the already-broad-sudo
  scanning account (`CAscanner`)**: `ExitStatus = 0`, output `User CAscanner2 may run the following
  commands on ladmin-Virtual-Machine:\n    (ALL : ALL) ALL` — a rule with **no** `NOPASSWD` keyword,
  which `ConvertTo-LinuxSudoAccess` (`Modules\LocalLinuxComputerScanner.psm1`) correctly classifies as
  `PasswordRequired` (confirmed by re-running `Export-LocalLinuxGroups.ps1` for real: `CAscanner2`'s
  row in `LinuxSudoRights.csv` reads exactly `SudoAccess = PasswordRequired`). This is the mechanism
  that actually matters, since the tool never logs into an account as itself — it always checks every
  discovered account's rights via `-U` from the one already-connected scanning account.
- **The actual `echo '<password>' | sudo -S <command>` password-supply mechanism is still not
  exercised** — this test only confirmed the *classification* is correct, not the elevation itself
  (which is still blocked on the `echo | sudo -S` vs. `SUDO_ASKPASS` decision — see Section 10).

**Security tradeoff to document prominently once this is tested and built:** embedding the password
in `echo '<password>' | sudo -S ...` means it appears, briefly, as a process argument on the *target*
Linux host while that command runs — visible to anything else on that host that can read `ps
aux`/`/proc/<pid>/cmdline` (unless the host restricts that via a `hidepid` mount option or similar).
This is the same class of exposure `aPePAS`'s `plink -pw` accepted on the Windows control-host side
(Section 4's Security note) — except here it would be exposed on the *scanned target*, not the
control host.

**`SUDO_ASKPASS` alternative — investigated live against the real test VM (2026-09-17), using
`CAscanner2`'s real CyberArk-retrieved password, never displayed or logged:**
- **No askpass helper exists on this VM by default** — `which ssh-askpass x11-ssh-askpass
  ssh-askpass-fullscreen` and `dpkg -l | grep -i askpass` both came back empty. Unlike `echo | sudo
  -S`, which needs nothing pre-staged, this mechanism requires **writing an executable helper script
  to the target's filesystem before every elevated call**, and reliably removing it afterward — a
  real file, with execute permission, that `echo | sudo -S` never creates at all.
- **`SUDO_ASKPASS` alone does nothing — `-A`/`--askpass` must be passed explicitly on every call.**
  Confirmed live: with the env var set but no `-A` flag, `sudo whoami` just says `A terminal is
  required to authenticate` and fails, ignoring the env var entirely.
- **It does work correctly in this tool's actual execution context** — a single non-interactive
  `Invoke-SSHCommand` call with no allocated terminal. Confirmed: `sudo -A whoami` returned `root`
  successfully once a minimal echo-based helper script was wired up via `SUDO_ASKPASS`.
- **A missing/misconfigured helper fails cleanly and fast** — confirmed: pointing `SUDO_ASKPASS` at a
  nonexistent path produces `Failed to run askpass program ... No such file or directory`, exit `1`,
  no hang. Good, but it's one more failure mode `echo | sudo -S` doesn't have.
- **A wrong password triggers sudo's normal retry loop — the helper gets invoked up to 3 times**
  (`passwd_tries` default) before failing, not once. Confirmed live: `sudo: Authentication failed,
  try again.` twice, then `sudo: maximum 3 incorrect authentication attempts`.
- **It relocates the exposure, it doesn't eliminate it** (not separately re-verified live, but
  standard sudo/Linux behavior): the password still has to reach the helper somehow — an environment
  variable the helper echoes is readable via `/proc/<pid>/environ` by root or the same user. Narrower
  than `ps aux` (readable by anyone), but not zero, and subject to the same `hidepid` mount-option
  caveat already noted for `echo | sudo -S`.
- **Askpass was designed for GUI callers** (an X11/Wayland password dialog for graphical `sudo`), not
  headless scripted use — there's less real-world precedent for a plain echo-based helper than for
  its intended use case.

**Net assessment**: `SUDO_ASKPASS`'s advantage (avoiding `ps aux` exposure) is real but narrower than
it sounds once the `/proc/<pid>/environ` exposure and the same `hidepid` caveat are accounted for,
while it adds concrete new costs `echo | sudo -S` doesn't have for this project's "one brief remote
command per SSH call" use case: deploying and cleaning up a helper file per target, an extra `-A`
requirement on every call, and an extra failure mode.

**Decided with the user (2026-09-17): `echo '<password>' | sudo -S`.** The user's own framing after
reviewing this section: `SUDO_ASKPASS` needs a helper file to already exist (or be deployed) on every
target, which isn't guaranteed — `echo | sudo -S` needs nothing pre-staged and works regardless of
target state, making it the only genuinely **universal** option of the two. Verified live across all
three sudo states before locking this in, using real accounts and never displaying any password:
- **Password-required (`CAscanner2`)**: `echo "$REALPW" | sudo -S -p '' whoami` → `root`, exit `0`.
  A wrong password → one clean `sudo: Authentication failed, try again.` then `Authentication
  required but not attempted`, exit `1` — and notably **only one retry attempt**, not
  `SUDO_ASKPASS`'s three, since piped stdin has only one line to offer before EOF; `echo | sudo -S`
  fails faster on a wrong password than the askpass alternative did.
- **`NOPASSWD` (`CAscanner`)**: piping a completely irrelevant/garbage value via `-S` still succeeds
  immediately (`root`, exit `0`) — sudo simply never reads stdin when `NOPASSWD` already applies.
  This means the *same* `echo | sudo -S` invocation is safe to use unconditionally, without first
  detecting whether an account actually needs a password.
- **Zero sudo access (`CyberArkSHUser01`, connected to and running the command as itself)**: `echo
  'garbage' | sudo -S -p '' whoami` failed in ~0.2 seconds (confirmed no hang) — but with a **fourth**
  distinct "no access" message pattern never seen before: `sudo: I'm sorry CyberArkSHUser01. I'm
  afraid I can't do that`. This is `sudo`'s `insults` plugin (`Defaults insults` in `/etc/sudoers`) —
  **a real, environment-specific quirk of this particular test VM's sudoers config, not a universal
  sudo behavior** — most systems don't have it enabled, so don't assume this exact wording elsewhere.
  It doesn't need separate handling regardless, since error detection here only needs "did the
  command succeed," not pattern-matching the specific failure text.
This confirms the mechanism is safe to build: no hang risk in any of the three states, and no
pre-staging requirement on the target. **Not yet wired into `Modules\LocalLinuxComputerScanner.psm1`**
— this was mechanism verification, not implementation; see `Docs\Open-Items.md`.

**Where does the sudo password come from? — decided with the user (2026-09-17):**
- **When the primary SSH credential is password-based** (no `KeyFilePath` in `CredentialParams`),
  reuse that same resolved credential's password for sudo — no separate lookup, since sudo's default
  `PAM` configuration wants the account's own login password and that's exactly what was already
  resolved to authenticate the SSH session.
- **When the primary SSH credential is key-based** (`KeyFilePath` set), there is no password to
  reuse, so an explicit `SudoCredentialSource`/`SudoCredentialParams` pair in `CredentialParams` is
  required, resolved via the same `Get-DiscoveryCredential` mechanism as everything else. A
  key-based row with a `PasswordRequired` sudo account and no `SudoCredentialSource` configured
  should fail clearly for that one elevation step (not the whole scan) rather than silently attempt
  elevation with no password.

**Not yet implemented in code** — this is a resolved design rule, but wiring it into
`Modules\LocalLinuxComputerScanner.psm1` depends on first settling *how* the password gets supplied
to `sudo` (`echo | sudo -S` vs. a `SUDO_ASKPASS` helper — still open, see Section 10/`Docs\Open-Items.md`)
and having a real password-required test account to verify against (also still needed).

**Checking every discovered account's sudo rights, not just the scan account's own — verified live
(2026-09-17).** The original tests above only ever checked `CAscanner`'s *own* rights (plain
`sudo -n -l`, no target specified). Per the user's follow-up request, this needs to cover every
account this tool discovers via `/etc/passwd`, which is a different sudo feature:

- **`sudo -n -l -U <username>`** lists *another* account's effective rights. Verified against three
  real accounts on the test VM:
  - `sudo -n -l -U ladmin` → `User ladmin may run the following commands on ladmin-Virtual-Machine:
    (ALL : ALL) ALL` (`ladmin` is a member of the `sudo` group — see the earlier `/etc/group` dump —
    so this rule comes from the group-based `%sudo ALL=(ALL:ALL) ALL` line in `/etc/sudoers`, not a
    per-user rule; `sudo -l -U` correctly resolves that for you rather than requiring this design to
    separately cross-reference group membership itself).
  - `sudo -n -l -U daemon` → `User daemon is not allowed to run sudo on ladmin-Virtual-Machine.` —
    **the "no access" message is worded differently here than the self-check case** (`is not
    allowed to run sudo` vs. the self-check's `Sorry, user X may not run sudo`) — both patterns need
    recognizing as "no access", not just one.
  - `sudo -n -l -U CyberArkPCRec` → **two rules at once**: `(ALL : ALL) ALL` (via `sudo` group
    membership, password-required — the base `/etc/sudoers` grants no `NOPASSWD` for that group) and
    `(ALL : ALL) /usr/bin/passwd` (a narrow, account-specific grant from its own
    `/etc/sudoers.d/CyberArkPCRec` file: `CyberArkPCRec ALL=(ALL:ALL)/usr/bin/passwd`). Confirmed the
    identical pattern for `CyberArkSHRec`. **This is genuinely PAM-relevant, real data**: these two
    accounts are individually, explicitly granted the ability to run `/usr/bin/passwd` as any user —
    i.e. reset any local account's password — which is exactly the kind of specific elevated
    capability a security team needs visibility into, and exactly why preserving the *full* rule
    text per account (not collapsing to one yes/no flag) matters.
- **A real constraint this uncovers**: listing *another* user's sudo rights this way requires the
  *scanning* account to itself have broad (`ALL`) sudo rights — `daemon`'s and `CyberArkPCRec`'s
  rights were only visible because `CAscanner` already has `NOPASSWD: ALL`. An account with only a
  narrow sudo grant (like `CyberArkPCRec` itself) likely could not run `sudo -l -U` for other
  accounts at all. This is a stronger requirement than "the scan account needs *some* sudo" (Section
  5a's earlier framing) — it needs broad rights specifically, to be useful for this particular check.
- **A complementary, secondary source: `/etc/sudoers` and `/etc/sudoers.d/*` directly.** Both are
  readable with `sudo` (confirmed: `/etc/sudoers` is `-r--r-----`, per-file entries in
  `/etc/sudoers.d/` are `-rw-r-----`, all `root`-owned — a plain user can't read them, `sudo cat`
  can). This shows the *raw configured* rule text and which file it came from (e.g. `CAscanner`'s own
  grant is visible verbatim: `CAscanner ALL=(ALL:ALL) NOPASSWD: ALL`, in its own
  `/etc/sudoers.d/CAscanner` file) — useful for audit/provenance ("where did this rule come from"),
  but doesn't resolve group-based grants the way `sudo -l -U` already does. Proposed as a secondary,
  optional source, not the primary mechanism.

**Output** (implemented as `LinuxSudoRights.csv`): `ScanTimestamp`, `ComputerName`, `UserName`,
`SudoAccess` (`None` / `PasswordlessSomeOrAll` / `PasswordRequired` — classify by checking the
`-U` output for the literal substring `NOPASSWD`; all three category boundaries now confirmed against
real accounts, including a genuinely password-required one — see Round 10), `RawSudoListOutput` (the full rule
text for that account, since — as `CyberArkPCRec` shows — an account can have multiple distinct
rules at once that a single flag would flatten away). Collected via one remote command that loops
over every discovered `/etc/passwd` account and runs `sudo -n -l -U "$user"` for each, rather than
one round-trip per account.

## 6. Data model & interfaces (proposed — not final)

Proposed columns, mirroring the Windows output shape. Every field below marked **verified** was
confirmed live against the real test VM (2026-09-17); everything else is still a proposal.

**LinuxLocalUsers.csv:** `ScanTimestamp`, `ComputerName`, `UserName`, `UID`, `PrimaryGID`,
`Description` (the GECOS field), `HomeDirectory`, `Shell` — all **verified** via `/etc/passwd`.
Plus, now that the scan account has `sudo` (see Section 5a):
`PasswordLastSet` — **verified**, `/etc/shadow` field 3 (days since epoch) converted with `date -d
"1970-01-01 +N days"` (confirmed: `20691` → `2026-08-26`);
`PasswordNeverExpires` — **concept verified, classification not yet coded**: real accounts on the
test VM showed a max-age of `99999` days (~273 years), the standard shadow-utils "effectively never
expires" sentinel, but the actual "is this the sentinel" check hasn't been written;
`BadPasswordAttempts` — **verified**, via `faillock --user <name>` (querying your *own* account
needs no elevation; querying another account will very likely need `sudo`, per normal Linux
file-permission behavior on `/var/run/faillock/*`, though that specific case wasn't tested).
**No longer gated on a later phase** — all of this is available now that sudo rights exist.

**Password state — refined from a simple `Disabled` boolean to a real classification (verified
2026-09-17, needs `sudo` to read `/etc/shadow`).** `/etc/shadow` field 2 turned out to have more
shapes on the real VM than a single `Disabled` flag captures:

| Field 2 looks like | Meaning | Observed on |
|---|---|---|
| `$6$...` (a real hash, no leading `!`) | Password set and usable | `ladmin`, the `CyberArk*` accounts |
| `!$6$...` (a real hash, leading `!`) | Had a password, then explicitly locked (`passwd -l`) | not observed on this VM, but a real, distinct sudo/passwd state |
| bare `!` | Locked, no hash ever set | `CAscanner` (see below) |
| `!!` | Password never set (fresh-account convention) | not observed on this VM |
| bare `*` | No password login intended (older/base-package convention) | `root`, `daemon`, `bin`, and other pre-installed base accounts |
| `!*` | No password login intended (systemd-sysusers convention) | `systemd-network`, `dhcpcd`, `messagebus`, and other systemd-created service accounts |

Two distinct "no password login" conventions (`*` vs. `!*`) coexist on the *same* system depending on
which tool created the account — both need recognizing, not just one.

**`CAscanner` itself is a live, already-proven example of the key point this whole area is about**:
its own password state is bare `!` (locked, no hash) — it has **no usable password at all** — yet
every command in this design has been executed *as* `CAscanner` all session, via SSH key auth. SSH
key eligibility and SSH password eligibility are independent per-account questions, not two views of
the same fact, and this is direct, lived proof of that, not just a theoretical claim.

**SSH login-method eligibility per account — implemented and verified live (2026-09-17, Round 14).
Columns `SshPasswordLoginPossible`/`SshKeyLoginPossible` on every `LinuxLocalUsers.csv` row:**
- **The authoritative source is `sshd -T`** (dumps sshd's *fully resolved* effective config,
  applying compiled-in defaults for anything not explicitly set in `sshd_config`) — **not** grepping
  `sshd_config` directly, which only shows explicit overrides and would silently miss anything
  running on a default. Confirmed live: `sshd -T` **requires `sudo`** — run as `CAscanner` without
  elevation it fails outright (`sshd: no hostkeys available -- exiting.`, since resolving the config
  needs read access to the private host key files). With `sudo -n sshd -T`, the real effective
  settings on this VM were: `passwordauthentication yes`, `pubkeyauthentication yes`,
  `permitemptypasswords no`, `kbdinteractiveauthentication no`, `usepam yes`, and — a real, specific
  finding worth calling out — **`permitrootlogin prohibit-password`**, meaning `root` can SSH in with
  a key but never a password, an exception to the global `passwordauthentication yes` that only
  applies to `root`. No `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups`/`Match` blocks exist on
  this VM, so no additional per-user/group restriction beyond these global settings and each
  account's own state.
- **`SshPasswordLoginPossible`** = effective `PasswordAuthentication` is `yes` for that host, AND the
  account's shadow state (above) is a real, unlocked, non-empty password, AND (for `root`
  specifically) `PermitRootLogin` doesn't specifically block password auth, AND the account's shell
  is a real, interactive one (see below).
- **`SshKeyLoginPossible`** = effective `PubkeyAuthentication` is `yes`, AND that account has at least
  one entry in its `authorized_keys` file. **Confirmed this needs `sudo` to check for any account
  other than the scanning account itself** — a `.ssh` directory is `0700` (owner-only), so reading
  another user's `authorized_keys` without elevation fails with `Permission denied` (confirmed live);
  with `sudo`, it's readable (confirmed: `ladmin`'s exists but is **empty** — 0 lines — meaning
  `ladmin` has no key-based login configured at all, consistent with `ladmin` being a
  password-authenticating account instead).
  **Implementation-time simplification (2026-09-17, Round 14)**: rather than reading the
  `AuthorizedKeysFile` directive from `sshd -T`'s effective output (this design's original proposal,
  to correctly handle a site that customizes it), the actual code only checks the default
  `~/.ssh/authorized_keys` path (`sudo -n test -s "$home/.ssh/authorized_keys"`, one call per
  discovered account in the same marker-delimited loop pattern as `SUDOUSER`). This is a real,
  documented gap for any environment with a customized `AuthorizedKeysFile` directive — tracked in
  `Docs\Open-Items.md` rather than solved now, since generalizing it (multiple space-separated paths,
  `%h`/`%u` token substitution) adds real complexity for a case this test VM doesn't exercise.
- **Whether the account's shell can even run our discovery commands matters here too, not just
  whether it can get an *interactive* login.** `/etc/shells` lists the shells a distro considers valid
  logins (confirmed on this VM: `/bin/sh`, `/bin/bash`, `/bin/rbash`, `/usr/bin/dash`,
  `/usr/bin/screen`, and their `/usr/bin/` equivalents — notably **not** `/usr/sbin/nologin` or
  `/bin/false`). sshd execs a requested command through the account's configured shell even for a
  non-interactive `ssh user@host command` — a `nologin`/`false` shell refuses to run *any* command,
  including this project's own discovery commands, so a scan against such an account would fail
  regardless of what password/key auth allows. On the test VM, the human/service accounts of interest
  (`root`, `ladmin`, all `CyberArk*` accounts, `CAscanner`) all have a real shell (`/bin/bash` or
  `/bin/sh`); the ~45 other system accounts (`daemon`, `www-data`, `systemd-*`, etc.) do not.
- **All of this needs `sudo`, and most of it needs the fully-resolved `sshd -T` output specifically**
  — a scan account without sudo rights could only see explicit `sshd_config` overrides (which, on
  this VM, would have missed `passwordauthentication`, `pubkeyauthentication`, and
  `permitrootlogin` entirely, since none of them are explicitly set there) and could not read any
  other account's `authorized_keys` at all. Worth stating plainly in whatever documentation this
  becomes: **this whole attribute area is gated on the scan account having sudo.**

**`DirectoryJoined`** (added 2026-09-17, on both `LinuxLocalUsers.csv` and `LinuxLocalGroups.csv`) —
**implemented and verified live.** `True` when the computer is actually joined to a directory
(`sssd` active with a real `sssd.conf`, or `winbind` active), else `False`. See the Non-goals section
above for why `/etc/nsswitch.conf` alone isn't trusted for this.

**LinuxLocalGroups.csv:** `ScanTimestamp`, `ComputerName`, `GroupName`, `GID` — **verified** via
`/etc/group`. There is no Linux equivalent of Windows' group `Description` at all — `/etc/group`
simply has no such field. Not a gap to close; it doesn't exist.

**LinuxLocalGroupMembers.csv:** `ScanTimestamp`, `ComputerName`, `GroupName`, `GID`, `MemberName` —
**verified**, including a real multi-member group (`sudo:x:27:ladmin,CyberArkPCRec,CyberArkSHRec`).
Only `/etc/group`'s explicit member list — a user whose *primary* GID matches a group but who isn't
also listed as an explicit member would not appear here, the same documented parity limitation as
the Windows tool's primary-group gap.

**Decided with the user (2026-09-17): these stay separate `Linux*.csv` files** — not the same
filenames the Windows tool produces, no `Platform` column, no unified schema. The column sets were
never identical anyway (UID/GID vs. SID; Linux groups have no `Description` at all), so this avoids a
wider shared schema with platform-specific blanks. This also settles `ComputersToScan.csv` vs. a
separate `LinuxComputersToScan.csv` (Section 2) the same way — separate, not shared.

## 6a. Verified parity comparison against the Windows tool (2026-09-17)

Tested methodically against the real Linux VM, category by category, to answer directly: can this
match what `Export-LocalGroups.ps1` collects on Windows?

**Full or near-full parity, verified:** users, groups, membership, and the password-aging fields
(`Disabled`, `PasswordLastSet`, `PasswordNeverExpires`-concept, `BadPasswordAttempts`) — all
confirmed above in Section 6.

**Real structural differences — not gaps to close, just how Linux works:**
- **Groups have no `Description` field at all** (see Section 6) — nothing to collect, not a testing
  gap.
- **A systemd service's `User=` property is blank far more often than Windows' `ServiceAccountName`
  — but blank has a determinate meaning, not an unclear one.** `systemctl show <unit>
  --property=User` only returns a value when the unit file explicitly sets one; unset means systemd's
  own documented default, **`root`** — confirmed live on `ssh.service`/`cups.service` (blank, and both
  processes do in fact run as root). This isn't the ambiguous gap it first looked like — see Section
  6b, where it becomes the exact same noise-filtering rule Windows already uses (exclude the mundane
  default identity, keep only services running as something else).
- **`lastlog`/`last` are not installed on this VM at all** (`command not found`, exit `127`).
  Windows' `LastLogin` has no guaranteed Linux equivalent — a real design would need a `command -v
  lastlog` presence check with graceful "unavailable" handling, not an assumption it's always there.

**A place Linux can exceed Windows, not just match it:** `ss -tlnp` (the process-owner column needs
`sudo`) returns **every actually-listening TCP port and its owning process/PID in one call** —
verified: `443` → `docker-proxy`, `631` → `cupsd`, `22` → `sshd`. The Windows database/software
detection has to probe one specific default port per signature from the control host (`Test-TcpPortOpen`
per `DatabaseSignatures`/`SoftwareSignatures` entry); a Linux design could instead pull the *entire*
listening-port table locally in one command and cross-reference signatures against it — catching a
database running on a non-default port, which the Windows design structurally can't do. Combined
with `systemctl show`'s `ActiveState`/`SubState` (~`Status`), `UnitFileState` (~`StartType`, though
coarser — enabled/disabled rather than Windows' Boot/System/Automatic/Manual/Disabled scale), and
`ExecStart` (~`Path`), the building blocks for a Linux `DatabaseSignatures`/`SoftwareSignatures`
equivalent are confirmed to exist — see Section 6b for the actual design, now worked out.

**Sudo rights discovery itself (Section 5a) has no Windows-side equivalent at all** — it's a
Linux-specific addition to this project's data model, not something being matched.

## 6b. Phase 5 design: database/software/service-account detection (added 2026-09-17)

**Decided with the user: Linux output files stay entirely separate from the Windows tool's** — no
shared filenames, no `Platform` column, no unified schema. This resolves two of Section 10's earlier
open decisions. Every file below is a new, Linux-only file.

### `LinuxDatabases.csv` and `LinuxSoftware.csv`

Same two-list design as the Windows tool (`DatabaseSignatures`/`SoftwareSignatures`), adapted to
systemd: match a **systemd unit name** (analogous to a Windows service short name) against a
configured pattern, then enrich the match via `systemctl show`, then cross-reference the configured
port against a single `ss -tlnp` capture (not a probe per signature).

**Proposed signature shape**: `LinuxDatabaseSignatures` = `[{ Engine, UnitPattern, DefaultPort }]`,
`LinuxSoftwareSignatures` = `[{ Name, Category, UnitPattern, DefaultPort }]` — deliberately parallel
to the Windows `DatabaseSignatures`/`SoftwareSignatures` shape, just `ServicePattern` renamed to
`UnitPattern` since it matches a systemd unit name, not a Win32 service short name.

**`PostgreSQL` verified for real (2026-09-17)** — the user had PostgreSQL installed on the test VM,
confirming this end-to-end against a real engine rather than only a starter guess:
- `{ Engine: "PostgreSQL", UnitPattern: "postgresql*", DefaultPort: 5432 }` — **confirmed correct**.
  Debian/Ubuntu's PostgreSQL package does use a *templated* unit exactly as anticipated:
  `postgresql@18-main.service` (version `18`, cluster `main`), plus a thin `postgresql.service`
  wrapper. The `postgresql*` pattern matches the real instantiated unit name.
- **A real enumeration gap this uncovered**: `systemctl list-unit-files` — the enumeration scope this
  design chose specifically to catch every *registered* service — only shows the **template**
  (`postgresql@.service`), never the instantiated `postgresql@18-main.service` that's actually
  running. Matching `UnitPattern` against `list-unit-files`' output alone would find the template
  name (still matches `postgresql*`) but would never surface *which* version/cluster is actually
  instantiated, or its real runtime state. **Enumeration needs to also check `systemctl list-units`
  (or a targeted `systemctl list-units 'postgresql@*'`) for already-running template instances** —
  `list-unit-files` alone is not sufficient for template-instantiated services.
- `{ Engine: "MySQL/MariaDB", UnitPattern: "mysql.service", DefaultPort: 3306 }` and
  `{ Engine: "MySQL/MariaDB", UnitPattern: "mariadb.service", DefaultPort: 3306 }` — still unverified,
  neither engine is installed on this VM.
- `{ Engine: "MongoDB", UnitPattern: "mongod.service", DefaultPort: 27017 }` — still unverified, same
  reason.

**Enrichment, per matched unit** (verified live, now against a real database too):
`systemctl show <unit> --property=Description,ActiveState,SubState,UnitFileState,ExecStart,User,
Group,FragmentPath` — `Description` (confirmed populated for every service, e.g. `ssh.service` →
`OpenBSD Secure Shell server`, `postgresql@18-main.service` → `PostgreSQL Cluster 18-main`; the
`DisplayName` equivalent), `ActiveState`/`SubState` (~`Status`, confirmed `active`/`running` for the
live cluster), `ExecStart` (~`Path`, confirmed real: `/usr/bin/pg_ctlcluster --skip-systemctl-redirect
18-main start` — Debian/Ubuntu's PostgreSQL packaging launches through a `pg_ctlcluster` wrapper, not
the server binary directly). `UnitFileState` turned out to have a **fifth value** beyond the
`enabled`/`disabled`/`static`/`masked` set confirmed earlier: **`enabled-runtime`** — seen on
`postgresql@18-main.service`, meaning it's enabled only for the current boot via a runtime symlink
(created by the `pg_createcluster`/`pg_ctlcluster` tooling), not persistently the normal way
`systemctl enable` would. Worth treating `UnitFileState` as a small open enum to capture verbatim
rather than a fixed four-value set.

**A real correction to the `ServiceAccountName`/`LinuxServiceAccounts.csv` design, found by this
test**: `systemctl show postgresql@18-main.service --property=User` came back **blank** — by the
"blank means root" rule below, that would have been excluded as noise. But `sudo ss -tlnp` showed the
truth: `LISTEN 127.0.0.1:5432 ... users:(("postgres",pid=1544127,fd=6))` — **the actual server
process runs as `postgres`, not `root`.** `pg_ctlcluster` (the systemd-tracked process, which *does*
start as root) drops privileges internally before running the real database server, the same pattern
already seen with `sshd`. So the "blank `User=` → root, exclude" rule is **only correct for services
that genuinely run as root throughout** — for anything using a wrapper that drops privileges
internally, `systemctl show` alone under-reports and would wrongly hide a real, meaningful service
account. **Fix**: for any matched unit, also resolve the actual running process's owner — via
`ss -tlnp`'s process-owner field when the service listens on a network port (already being captured
for the `Listening` check anyway, so no extra remote call needed for `LinuxDatabases.csv`/
`LinuxSoftware.csv`), or via `ps -o user= -p <MainPID>` (from `systemctl show`'s `MainPID` property)
for services that don't listen on a port at all. Use the process-owner result when it differs from
`User=`, not just `User=` alone.

**Listening confirmation — the one place this can exceed the Windows design, not just match it**:
capture `sudo ss -tlnp` **once per computer** (already confirmed to return every listening port and
its owning process/PID in one call), then check whether the signature's `DefaultPort` appears in
that table — rather than the Windows tool's one-`Test-TcpPortOpen`-call-per-signature approach. One
remote round trip covers every signature's listening check for that computer, and — as a stretch
possibility, not required for a first version — the same captured table could flag something
listening on a port *no* configured signature expected, which the Windows design has no way to
surface at all.

**Enumeration scope, corrected by the PostgreSQL test**: `systemctl list-unit-files --type=service`
(confirmed: 324 unit files on the test VM) catches every statically-registered service — but **not**
an instantiated template unit like `postgresql@18-main.service` (only the template
`postgresql@.service` appears there). Full coverage needs **both**: `list-unit-files` for the
complete registered-service list (matching the Windows tool's scope), **and** `systemctl list-units`
(or a per-signature `systemctl list-units '<pattern>'`) to catch already-running instances of
template units that `list-unit-files` alone would miss entirely.

### `LinuxServiceAccounts.csv`

Mirrors the Windows tool's `LocalServiceAccounts.csv` — examines *every* registered service's
account, not just signature-matched ones, answering "what runs as this account" across the estate.

**The noise-filtering rule, refined by the PostgreSQL test above**: the account of interest is the
*actual running process's* owner, not simply `systemctl show`'s `User=` property — resolved via
`ss -tlnp`'s process-owner field (for listening services) or `ps -o user= -p <MainPID>` (otherwise),
falling back to `User=` (or the systemd default, `root`, when even that's unset) only when neither of
those resolves anything. **Exclude every service whose *resolved* account is `root`** — the same
exclusion Windows already applies to its own default identities (`LocalSystem`, etc.) — keep every
service running as anything else, including `postgres` (confirmed: correctly resolved as non-root and
worth keeping, once the process-owner cross-check replaces a bare `User=` read). Unlike Windows,
Linux doesn't need a `Virtual`/`gMSA` category — there's no per-service virtual-account or
managed-service-account convention in this model, just "root" (noise) vs. "a specific named account"
(kept) — the wrinkle is entirely in *how* the account gets resolved, not in the category system.

**Proposed columns**: `ScanTimestamp`, `ComputerName`, `UnitName`, `Description`, `ServiceAccountName`
(the *resolved* account, per the process-owner cross-check above — not a bare `User=` read; `root`
rows excluded), `StartType` (`UnitFileState`), `Status` (`ActiveState`/`SubState`), `Path`
(`ExecStart`).

**Implementation-time simplification, confirmed correct against real data (2026-09-17, Round 13):**
the actual code does **not** use `ss -tlnp`'s process-owner field for `ServiceAccountName` resolution
at all — only `MainPID` cross-referenced against a single `ps -eo pid,user` capture. Verified live
that `postgresql@18-main.service`'s `MainPID` **is already** the real `postgres` process's PID (not
`pg_ctlcluster`'s own launcher PID — systemd's tracking settles on the actual worker process for this
unit), so a `ps`-based lookup on `MainPID` alone resolves it correctly, and does so for **both**
listening and non-listening services alike, which `ss -tlnp` structurally cannot (it only covers
processes with an open port). `ss -tlnp` is kept exclusively for what it's uniquely good at -
`Listening` confirmation and `LinuxUnrecognizedListeningPorts.csv` - not for service-account
resolution, which turned out not to need it.

### `LinuxUnrecognizedListeningPorts.csv` — decided with the user (2026-09-17)

The port table **does** also drive detection on its own, not just corroborate signature matches:
every port in the single per-computer `ss -tlnp` capture that does **not** correspond to any matched
`LinuxDatabaseSignatures`/`LinuxSoftwareSignatures` entry's `DefaultPort` gets a row in a new file,
`LinuxUnrecognizedListeningPorts.csv` — `ScanTimestamp`, `ComputerName`, `Port`, `Protocol`,
`ProcessName`, `PID`, `ProcessOwner` (all straight from that one `ss -tlnp` capture already being
collected for the signature-listening check, so this needs no extra remote call). This surfaces
something listening that no configured signature expected at all — the exact capability Section 6a
originally flagged as a place Linux could exceed the Windows tool's one-port-per-signature design,
now turned into a concrete output. **Implemented and verified live (Round 13)** — the actual column
set is `ScanTimestamp`, `ComputerName`, `Port`, `ProcessName`, `PID`, `ProcessOwner` (no separate
`Protocol` column — `ss -tlnp`'s own `-t` flag already scopes the whole capture to TCP, so a
per-row protocol value would be redundant).

`MySQL`/`MariaDB`/`MongoDB` starter signatures remain unverified (no such engine on the test VM).

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
   test account, `CAscanner2`, correctly classifies as `PasswordRequired`).
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

## 9. Progress tracker

`Export-LocalLinuxGroups.ps1` and `Modules\LocalLinuxComputerScanner.psm1` now exist and are verified
live against the real test VM (Round 8) — connectivity, concurrency, users/groups/membership,
password-state fields, and sudo rights for every account are all implemented and working.

**Round 1 — Windows OpenSSH Server (proved the mechanism works at all):**
- Windows' OpenSSH Server feature was enabled on the development machine (with the user's approval)
  since no SSH target existed yet.
- A passphrase-less ed25519 test keypair was generated and its public half installed into
  `C:\ProgramData\ssh\administrators_authorized_keys` (the file Windows OpenSSH requires for an
  account in `BUILTIN\Administrators`) — required an elevated session the assistant didn't have, so
  the user ran the write + `icacls` lockdown themselves.
- `New-SSHSession -KeyFile <path> -AcceptKey` connected; `Invoke-SSHCommand -Command 'whoami &&
  hostname'` returned `ExitStatus = 0` and the correct output; `Remove-SSHSession` cleaned up.
- Cleaned up afterward: the user removed the `administrators_authorized_keys` entry, and the local
  test key files were deleted from the assistant's scratchpad.

**Round 2 — a real Ubuntu test VM (the user set one up specifically for this) — proved the actual
design, and caught a real bug in it:**
- A new, separate ed25519 keypair was generated into `Secrets\aped-linux-test-key` (this project's
  git-ignored secrets folder, not the scratchpad, since this key was meant to persist for ongoing
  testing rather than be a one-off). The user installed the public key on the VM themselves and
  supplied its address and username.
- `New-SSHSession` connected successfully to a real `Linux ... Ubuntu ... x86_64 GNU/Linux` host.
- The actual proposed command (`cat /etc/passwd; echo '---APEDISC-SEP---'; cat /etc/group`) was run
  for real. The first parsing attempt — written the way Section 4 originally described `.Output`
  (as one string, `-split` on the separator) — produced silently wrong results (each array element
  reporting itself as an unsplit single line). Investigating the raw output revealed the actual bug:
  `.Output` is a `System.String[]`, not a string. Fixed by locating the separator line's array index
  and slicing on either side of it; re-run and confirmed correct: 56 users, 87 groups, including a
  real multi-member group (`sudo:x:27:ladmin,CyberArkPCRec,CyberArkSHRec`) parsed correctly.
- **Follow-up worth doing**: `Secrets\aped-linux-test-key`'s public half is still installed on the
  test VM, and it's passphrase-less. Fine to leave in place while this VM continues to be used for
  Linux discovery testing; worth removing (from the VM's `~/.ssh/authorized_keys` and this project's
  `Secrets\` folder) once that testing is done.

**Round 3 — sudo rights discovery, mostly verified (2026-09-17):**
- `CAscanner` (initially no sudo group membership) confirmed the "no sudo access at all" case:
  `sudo -n -l` exits `1` with `stderr` = `sudo: Sorry, user CAscanner may not run sudo on
  ladmin-Virtual-Machine.`, with **no password prompt** — sudo fails fast when no rule matches at
  all. Also confirmed `Invoke-SSHCommand`'s result object exposes `.Error` (stderr), not just
  `.Output`/`.ExitStatus`.
- The user then granted `CAscanner` `NOPASSWD` sudo rights on the same VM, confirming the passwordless
  case for real: `sudo -n -l` now exits `0` and lists the granted rules (`(ALL : ALL) ALL` and
  `(ALL : ALL) NOPASSWD: ALL`); `sudo -n whoami` elevates immediately with no prompt (`root`); and
  `sudo -n cat /etc/shadow` (57 lines) confirmed elevated reads work, with a remote `awk` deriving
  only non-sensitive fields (locked/hasset, last-change day, max-age) rather than ever transmitting
  raw shadow content — full details in Section 5a.
- **Still not tested**: an account whose sudo rights require an actual password (as opposed to
  `NOPASSWD`), and the `echo '<password>' | sudo -S` non-interactive password-supply mechanism this
  design proposes for that case — `NOPASSWD` deliberately never reaches that code path. Needs the
  user to configure a password-required (not `NOPASSWD`) sudo rule on a test account.

**Round 4 — full Windows-parity comparison, verified category by category (2026-09-17):**
- Confirmed `/etc/shadow`-derived user fields (`Disabled`, `PasswordLastSet`, `PasswordNeverExpires`
  concept) and `faillock`-derived `BadPasswordAttempts` all work now that sudo rights exist — see
  Section 6, now updated to remove the earlier "gated on a later phase" framing.
- Confirmed `systemctl show <unit> --property=...` works for service/database detection — including
  the real, structural finding that `User=` is only populated for units that explicitly declare it
  (`systemd-resolved.service` does; `ssh.service` and `cups.service` don't).
- Confirmed `ss -tlnp` (needs `sudo` for the owning-process column) returns every listening port and
  its owning process in one call — identified as a real opportunity to exceed the Windows tool's
  per-signature-port-probe design, not just match it.
- Confirmed `lastlog`/`last` are simply not installed on this VM — no Linux `LastLogin` equivalent
  can be assumed present.
- Full comparison written up in the new Section 6a.

**Round 5 — password state, shell validity, and SSH login-method eligibility, verified (2026-09-17):**
- Refined `Disabled` into a real classification of `/etc/shadow` field 2's possible shapes (real
  hash / locked-with-hash / locked-no-hash / never-set / two distinct "system, no password" markers)
  — see Section 6, all confirmed against real accounts on the VM, including two different "no
  password login" conventions coexisting on the same system (`*` vs. `!*`).
- Confirmed `sudo -n sshd -T` is the authoritative source for effective SSH auth settings (not
  grepping `sshd_config`, which would have missed several settings entirely on this VM since they
  aren't explicitly set there) — and confirmed it **requires `sudo`** (fails outright as a plain
  user: `sshd: no hostkeys available -- exiting.`).
- Found a real, specific setting worth designing around: `permitrootlogin prohibit-password` — `root`
  can SSH in with a key but never a password, an exception to the otherwise-global
  `passwordauthentication yes`.
- Confirmed checking `SshKeyLoginPossible` for an arbitrary account needs `sudo` too (another
  account's `.ssh` is `0700`, unreadable otherwise — confirmed both the failure without sudo and
  success with it, finding `ladmin`'s `authorized_keys` exists but is empty).
- `CAscanner` itself — locked/no-password, yet used for every SSH-key-authenticated command all
  session — is live, already-established proof that SSH key and password login eligibility are
  independent per-account facts, not two views of one fact.
- **This whole attribute area depends on the scan account having sudo** — without it, none of this
  (accurate password state, effective sshd settings, other accounts' `authorized_keys`) is available.

**Round 6 — sudo rights for every discovered account, not just the scan account's own, verified
(2026-09-17):**
- `sudo -n -l -U <username>` confirmed working for checking a *different* account's rights: `ladmin`
  → full `ALL` rights (via `sudo` group membership, correctly resolved without this design needing to
  separately cross-reference group membership itself); `daemon` → no access, with a **differently
  worded** message than the self-check case (`is not allowed to run sudo` vs. `Sorry, user X may not
  run sudo`) — both patterns need recognizing.
- Found a genuinely PAM-relevant real result: `CyberArkPCRec`/`CyberArkSHRec` each have **two**
  layered rules — a group-inherited `(ALL:ALL) ALL` (password-required) plus their own
  account-specific, password-required `(ALL:ALL) /usr/bin/passwd` grant (from their own
  `/etc/sudoers.d/<name>` file) — i.e. each can reset any local account's password specifically.
  Confirms preserving the *full* rule text per account matters; a single flag would have flattened
  this away.
- Confirmed `/etc/sudoers`/`/etc/sudoers.d/*` are directly readable with `sudo` (root-owned,
  `0440`/`0640`) as a secondary, raw-rule/provenance source — `CAscanner`'s own grant was visible
  verbatim in its own sudoers.d file.
- Identified a real, stronger constraint than previously assumed: checking *other* accounts' rights
  this way needs the *scanning* account to have **broad** (`ALL`) sudo rights itself, not just *some*
  sudo access.

**Round 7 — PostgreSQL investigated, and Phase 5 verified against a real database engine
(2026-09-17):**
- The user reported PostgreSQL on the test VM "keeps stopping" and asked for it to be investigated.
  Found no actual problem: `NRestarts=0`, `Result=success`, only one stop/start cycle in the entire
  journal, a clean "received fast shutdown request" with zero errors/OOM kills, and
  `/var/log/apt/history.log` confirming the one restart was a routine `apt upgrade` of the
  `postgresql-18` package — not a crash loop. Nothing needed fixing.
- With a real engine now available, tested the `LinuxDatabaseSignatures` design (Section 6b) against
  it for the first time: the `postgresql*` unit-pattern match, `systemctl show` enrichment, and
  `ss -tlnp` listening confirmation all worked correctly against `postgresql@18-main.service` (port
  5432, owning process `postgres`).
- **Caught a real bug in the design's own service-account resolution**: `systemctl show`'s `User=`
  for that unit was blank — which the existing rule would have classified as `root` and excluded —
  but the actual running process is owned by `postgres` (`pg_ctlcluster` starts as root and drops
  privileges internally, the same pattern already seen with `sshd`). Corrected Section 6b:
  `ServiceAccountName` must be resolved from the actual process owner, not read directly from
  `User=`.
- Also found `systemctl list-unit-files` alone misses instantiated template units (shows only the
  `postgresql@.service` template, never the running `postgresql@18-main.service`) — enumeration needs
  `list-units` too — and a fifth `UnitFileState` value, `enabled-runtime`, beyond the four confirmed
  earlier.

**Round 8 — implementation: `Export-LocalLinuxGroups.ps1` + `Modules\LocalLinuxComputerScanner.psm1`
built and verified live (2026-09-17):**
- Per user request ("update the linux scanner to allow multiple processes at once like the windows
  scanner"), the first real script was written rather than continuing as design-only — there was no
  script to "update" a concurrency feature onto, so this built the whole Phase 1-3 slice at once,
  following this document's already-settled design exactly (Section 5's architecture diagram, the
  `ImportPSModule`-per-path fix, the marker-line/array-slicing parse approach).
- One combined remote command per computer (not one call per data type) collects `/etc/passwd`,
  `/etc/group`, a `sudo`-derived `/etc/shadow` projection, and every discovered account's
  `sudo -n -l -U <user>` output, using `===MARKER===` lines to delimit sections — parsed by finding
  each marker's array index and slicing `Invoke-SSHCommand`'s `.Output` between them (per the bug
  fixed in Round 2), rather than one SSH round trip per data type or per account.
- Ran against the real test VM (192.222.222.152): 57 users, 88 groups, 15 membership rows, 57
  sudo-rights rows, on the first successful run — no bugs found in the connect/parse/export path
  itself. Spot-checked correctness against known real data from earlier rounds: `CAscanner`'s
  `PasswordState` = `LockedNoHash` (matches Round 5's finding for this account), its
  `SudoAccess` = `PasswordlessSomeOrAll` with the exact `ALL` + `NOPASSWD: ALL` rule text (matches
  Round 3's grant), and `CyberArkPCRec`/`CyberArkSHRec` both = `PasswordRequired` with the exact
  layered `ALL` + `/usr/bin/passwd` rule text (matches Round 6's finding) — the implementation
  reproduces every previously-verified finding correctly, not just new output.
- **Concurrency specifically verified**, since that was the explicit ask: ran 3 simultaneous scans
  against the same VM (`MaxConcurrency=3`, 3 rows in the input CSV all pointing at the same host).
  All 3 `New-SSHSession`s started within the same logged second and all 3 completed within
  well under a second total, with results correctly isolated per runspace (171 total user rows =
  exactly 57 × 3, 264 group rows = exactly 88 × 3) — confirms both genuine parallel execution (not
  serialized despite looking that way from one host) and no shared-state corruption between
  concurrent attempts, the main risk a `RunspacePool` design has to rule out.
- Scoped out of this pass, left as Section 8/10 open items: `BadPasswordAttempts` (`faillock`),
  per-account SSH-login eligibility, Phase 5 (databases/software/service accounts), and the
  password-required sudo case's actual password-supply mechanism — none of these were part of the
  concurrency ask and Phase 5 in particular still has an open design question (Section 10).

**Round 9 — four open decisions resolved with the user, one implemented and verified live
(2026-09-17):**
- **Host-key trust default: confirmed as-is.** The user confirmed the already-implemented
  `-AcceptKey`-by-default behavior is fine — no change needed.
- **Sudo credential source: decided.** Password-based primary auth reuses that same credential's
  password for sudo; key-based primary auth requires an explicit `SudoCredentialSource`/
  `SudoCredentialParams`. See Section 5a for the full rule. Not yet coded — still blocked on the
  `echo | sudo -S` vs. `SUDO_ASKPASS` mechanism choice (tracked in `Docs\Open-Items.md`) — the
  password-required test account this also needed was supplied and verified in Round 10, below.
- **SSSD/Winbind-joined hosts: decided and implemented.** Still collect local users/groups/membership
  normally, but flag the computer via a new `DirectoryJoined` column (see Section 6). Built into
  `Modules\LocalLinuxComputerScanner.psm1`'s combined remote command (a `===DIRJOIN===` section) and
  verified live against the real test VM: **caught a real false-positive trap in the process** — the
  test VM's `/etc/nsswitch.conf` already lists `sss` in its `passwd`/`group` lines (an artifact of the
  base Ubuntu image), which would have wrongly flagged this non-joined VM as directory-joined had that
  been the signal used. Checking whether `sssd` is actually **active** (`systemctl is-active sssd`)
  and has a real `/etc/sssd/sssd.conf` (this VM has neither — `inactive`, no `sssd.conf` file despite
  the package being `enabled`) correctly returns `DirectoryJoined = False` for all 57 users and 88
  groups. Re-ran the full scan afterward to confirm no regression to any previously-verified field.
- **Phase 5 port-table detection: decided.** The `ss -tlnp` port table now also drives detection on
  its own, not just corroborates signature matches — a new `LinuxUnrecognizedListeningPorts.csv` (see
  Section 6b) will hold one row per listening port that matches no configured signature. Design-only;
  Phase 5 has no code yet.

**Round 10 — CyberArk CP verified live end-to-end, and a real, significant bug found and fixed
(2026-09-17):**
- After a reboot to finish installing the real CyberArk Credential Provider, the user configured two
  real CP test accounts and asked for CP retrieval to be tested: `CAscanner2` (Safe `McWilliams
  Jesse`) — full `ALL` sudo rights, password-required, not `NOPASSWD` — and `CyberArkSHUser01` (Safe
  `McWilliams Jesse`, under an `Operating System-...` object name) — no sudo access at all.
- **Found the real install path**: `C:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe`
  (64-bit `Program Files`), not `Program Files (x86)` as `Get-CredentialFromCP`
  (`Modules\CredentialResolver.psm1`) previously defaulted to.
- **Found and fixed a real, significant bug**: `CLIPasswordSDK.exe GetPassword /o Password,PassProps.UserName`
  returns a plain comma-separated list of **values** in the requested order (e.g.
  `ThisIsMyPassword!,CAscanner2`), never `Key=Value` pairs — confirmed by probing with non-secret
  fields only (`/o PassProps.UserName` alone returned bare `CAscanner2`; a field that doesn't apply
  returns the literal string `<na>`). `Get-CredentialFromCP`'s original parsing logic expected
  `Key=Value` tokens and would have thrown "did not return a Password value" on **every** real CP
  call — this had never actually been exercised against a real Credential Provider before this.
  Fixed by requesting `Password` and `PassProps.UserName` as two separate single-field calls (avoids
  any risk of a comma embedded in the password itself being mistaken for a field separator — there's
  no confirmed guarantee CLIPasswordSDK escapes that case) rather than parsing a combined
  multi-field line.
- **Verified the fix live for both accounts**, confirming a real password and the correct username
  came back for each without ever displaying the actual secret value in this session's output.
- **Closed the last remaining Phase 3 gap**: used `CAscanner2` to finally observe the
  password-required `sudo -n -l` self-check pattern for real (`sudo: interactive authentication is
  required`, a third distinct message pattern) via a genuine SSH connection authenticated with the
  CP-retrieved password — and, more importantly, confirmed the actual mechanism this tool uses
  (`sudo -n -l -U CAscanner2`, run by the already-broad-sudo scanning account) correctly returns a
  no-`NOPASSWD` `(ALL : ALL) ALL` rule, which `ConvertTo-LinuxSudoAccess` correctly classifies as
  `PasswordRequired` — confirmed by re-running `Export-LocalLinuxGroups.ps1` for real and finding
  exactly that in `LinuxSudoRights.csv`. `CyberArkSHUser01` independently re-confirmed `SudoAccess =
  None`. This closes the "needed before Phase 3/4 can finish being verified" item from Section 10.
- **Not yet done**: actually supplying `CAscanner2`'s password to elevate a real command (the `echo
  password | sudo -S` vs. `SUDO_ASKPASS` mechanism is still undecided, so this test only confirmed
  the classification, not the elevation itself).

**Round 11 — the sudo elevation mechanism decided and verified safe across all three sudo states
(2026-09-17):**
- After reviewing Section 5a's `echo | sudo -S` vs. `SUDO_ASKPASS` comparison, the user made the
  call: `echo | sudo -S`, on the grounds that `SUDO_ASKPASS` needs a helper file pre-staged on every
  target (not guaranteed to exist — confirmed in Round 10's research this VM has none), so it isn't
  "universal" the way `echo | sudo -S` is.
- Verified live, using `CAscanner2`'s real CP-retrieved password (never displayed) and never
  hard-coding any account's actual sudo state ahead of time:
  - **Password-required**: correct password → success (`root`, exit `0`); wrong password → one
    clean failure and stop (`Authentication failed, try again.` then `Authentication required but
    not attempted`), exit `1` — notably only **one** retry, not `SUDO_ASKPASS`'s three, since piped
    stdin has just one line before EOF.
  - **`NOPASSWD`**: piping a completely irrelevant value via `-S` still succeeds immediately — sudo
    never reads stdin once `NOPASSWD` already applies. Confirms the *same* invocation is safe to use
    unconditionally, without first detecting whether an account needs a password at all.
  - **Zero sudo access**: failed in ~0.2 seconds — confirmed no hang — but surfaced a **fourth**,
    previously-unseen "no access" message: `sudo: I'm sorry CyberArkSHUser01. I'm afraid I can't do
    that`, from sudo's `insults` plugin (`Defaults insults`) — flagged explicitly as a quirk of this
    one test VM's sudoers config, not a general sudo behavior, and not one that needs separate
    handling since error detection only needs success/failure, not the specific message text.
- This closes out the mechanism-choice research entirely: no hang risk in any state, no pre-staging
  requirement. **Not yet wired into `Modules\LocalLinuxComputerScanner.psm1`** — this round was
  mechanism verification, not implementation.

**Round 12 — sudo elevation wired into code and verified across all three sudo states, plus two real
bugs found and fixed (2026-09-17):**
- **Design refinement before implementing**: rather than piping the sudo password before every
  individual `sudo -n` call (of which there can be dozens per computer - one per discovered
  account), verified live that a single `sudo -S -p '' -v` "refresh the credential ticket" call at
  the very top of the combined remote command lets every subsequent `sudo -n` call in that same
  script succeed for the rest of its run, without needing the password again. This cuts the
  password's exposure window on the target's process list from one-per-account to once-per-computer.
- **Implemented**: `Invoke-LocalLinuxComputerScan` now resolves a sudo password per the decided rule
  (Section 5a) - reusing the primary credential's password when it's password-based, or resolving
  `SudoCredentialSource`/`SudoCredentialParams` when the primary is key-based or an explicit override
  is configured - base64-encodes it (to avoid any shell metacharacter in the password breaking the
  remote script, not as a security measure), and substitutes it into a `__SUDO_REFRESH__` placeholder
  in the remote command template. When no sudo credential is available, the placeholder becomes `true`
  (a no-op), falling straight through to the pre-existing `-n`-only behavior.
- **Bug #1, found immediately on first real test**: a `[Parameter(Mandatory)] [string[]]` parameter
  (`Get-LinuxSectionLines`'s `-Lines`) throws a misleadingly-worded `Cannot bind argument ... because
  it is an empty string` for the **entire array** if even one element is `$null` or an empty string -
  confirmed via a minimal repro. This had never surfaced before because every prior command in the
  combined remote script always produced non-empty output on success; the new sudo ticket refresh is
  the first command whose *success* case produces zero output, making this the first time a genuinely
  blank line ever appeared in the captured output. Fixed by adding `[AllowEmptyString()]`/
  `[AllowNull()]` to the parameter.
- **Bug #2, found once the first bug was fixed and real elevation could be observed**: the diagnostic
  check used to confirm elevation succeeded, `sudo -n -v`, does **not** honor a working `NOPASSWD: ALL`
  rule the way running an actual exempted command does - confirmed live: `sudo -n -v` failed with
  `sudo: interactive authentication is required` for `CAscanner` even though `sudo -n -l`/`sudo -n
  whoami`/`sudo -n awk ...` all succeeded correctly for that same account in the same session. This
  would have logged a false "elevation not established" warning on every `NOPASSWD`-only computer
  despite every real command succeeding. Fixed by checking with `sudo -n true` (a trivial no-op
  command) instead of `-v`.
- **Verified end-to-end across all three sudo states after both fixes**, using real accounts, no
  password ever displayed or logged:
  - **`NOPASSWD` (`CAscanner`)**: full data, no elevation warning (correctly not needed).
  - **Password-required (`CAscanner2`), used as the actual connecting/SSH account for the first
    time** (previously only ever checked *as a `-U` target* by a different, already-NOPASSWD scanning
    account): `PasswordState = PasswordSet` for its own row, populated entirely via the newly-wired
    elevation - proof the mechanism works for an account with **zero** `NOPASSWD` rights of its own,
    not just ones that already had another path to elevation.
  - **Zero sudo access (`CyberArkSHUser01`)**: clean graceful degradation - both the "elevation not
    established" and "shadow data unavailable" warnings logged correctly and honestly (elevation
    genuinely failed here), every password-state field left blank, no scan failure.
- **Not separately verified live**: the `SudoCredentialSource`/`SudoCredentialParams` override path
  for a key-based primary connection (no test scenario exists where a key-based account's *separate*
  vaulted sudo password is known to be correct - the override code was reviewed for correctness but
  not exercised against a real mismatched-credential-source setup).

**Round 13 — Phase 5 implemented, and two more real bugs found and fixed (2026-09-17):**
- Per user request ("do Phase 5"), implemented `LinuxDatabases.csv`/`LinuxSoftware.csv`/
  `LinuxServiceAccounts.csv`/`LinuxUnrecognizedListeningPorts.csv` in
  `Modules\LocalLinuxComputerScanner.psm1` and `Export-LocalLinuxGroups.ps1`, following Section 6b's
  design (with the `ServiceAccountName`-resolution simplification noted there).
- **Investigated live whether `systemctl show` could take every discovered unit name in one call**
  (avoiding one remote round trip per unit) — confirmed it preserves argument order exactly and
  separates each unit's properties with a blank line for a handful of units, but **found a real,
  serious bug at real scale**: passing all ~330 real unit names in one call produced only ~16 lines of
  output and exit status `1`, instead of the ~2,300 expected. Root-caused to `systemctl show` silently
  giving up after encountering a unit it can't individually query (a bare template like
  `alsa-card-wait@.service`, listed in `list-unit-files` but not directly showable) - it doesn't skip
  the bad name and continue, it aborts the whole batch. Fixed by reverting to a per-unit loop with
  `===UNIT:<name>===` markers, mirroring the already-proven `SUDOUSER` pattern - confirmed live this
  costs almost nothing (353 real units in ~1.7 seconds) while being fully resilient to any single
  unqueryable unit.
- **Found a second real bug in the same investigation**: `systemctl list-units`' default tabular
  output prefixes a failed/problem unit's row with a colored UTF-8 status bullet ("●"), which
  `awk '{print $1}'` was picking up as if it were the unit name itself, corrupting that entry and
  triggering `systemctl show`'s "Invalid unit name" error - part of what caused the batch-abort above.
  Fixed by adding `--plain` to `list-units`, which suppresses the bullet and restores a clean,
  awk-parseable unit-name-first column.
- **Verified end-to-end against real, already-installed software on the test VM**: PostgreSQL (both
  `postgresql.service` and `postgresql@18-main.service` matched `postgresql*`, `ServiceAccountName`
  correctly resolved to `postgres` via `MainPID` rather than the unit's blank `User=`), Docker, CUPS,
  and OpenSSH (added as `SoftwareSignatures` test entries) - all enriched correctly, `Listening`
  correct against a real `ss -tlnp` capture, and `LinuxUnrecognizedListeningPorts.csv` correctly
  shrank from 10 to 6 rows once those three signatures were added, with the remaining rows (DNS,
  Docker's own published-port proxies) correctly still unrecognized since no signature claims those
  specific ports. A full scan (users/groups/sudo-rights/Phase 5 all together) completes in ~2.3
  seconds against the real VM, no regressions to any previously-verified field.

**Round 14 — per-account SSH login eligibility implemented and verified live, no new bugs found
(2026-09-17):**
- Per user request ("do... Per-account SSH"), implemented `SshPasswordLoginPossible`/
  `SshKeyLoginPossible` in `Modules\LocalLinuxComputerScanner.psm1`, resolving Section 10's
  phase-placement question by folding it into the main scan rather than a separate phase, and
  simplifying `AuthorizedKeysFile` handling to just the default path (see Section 6) rather than
  reading `sshd -T`'s effective value, tracked as a documented gap in `Docs\Open-Items.md`.
- Added `===SSHDT===` (`sudo -n sshd -T`), `===SHELLS===` (`/etc/shells`), and `===AUTHKEYS===` (a
  per-account `sudo -n test -s "$home/.ssh/authorized_keys"` loop, marker-delimited exactly like
  `SUDOUSER`/`UNIT`) to the combined remote command - all reusing the same sudo ticket Phase 3/4/5
  already establish, no new elevation mechanism needed.
- **Verified end-to-end with no new bugs** - the first clean implementation this session without a
  fix-it round. Confirmed against real, previously-known ground truth rather than just internally
  consistent output: `CAscanner` (`PasswordState = LockedNoHash`, no usable password) correctly shows
  `SshPasswordLoginPossible = False` and `SshKeyLoginPossible = True` - directly corroborated by this
  entire session's own use of `CAscanner`'s SSH key throughout. `ladmin` (`PasswordState = PasswordSet`,
  real password) correctly shows `SshPasswordLoginPossible = True` and `SshKeyLoginPossible = False` -
  matching Round 5's finding that `ladmin`'s `authorized_keys` exists but is empty. `root`
  (`PasswordState = SystemNoLogin`) and `daemon` (`nologin` shell) both correctly show `False` for
  both fields. Full scan (all phases together) still completes in ~2.8 seconds, no regressions.
- Both fields are populated as `$null` (not `False`) when the underlying data is unavailable (no
  sudo), confirmed live via the earlier zero-access-account test scenario, distinguishing "confirmed
  not possible" from "unknown" for a downstream consumer.
- This closes every item in the Linux design except `BadPasswordAttempts` (`faillock`).

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
  `Docs\Open-Items.md`).
- ~~SSSD/Winbind-joined hosts~~ — **decided and implemented (2026-09-17, Round 9): still collect
  normally, flag the computer via `DirectoryJoined`** — see Section 3/6/9.
- ~~Sudo password source~~ — **decided and implemented (2026-09-17, Round 9/12)**: reuse the login
  password when SSH auth is password-based; require a separate `SudoCredentialSource`/
  `SudoCredentialParams` when it's key-based (or when explicitly overridden regardless of auth type).
  See Section 5a. The `SudoCredentialSource` override path itself is implemented but not separately
  verified live against a real mismatched-credential setup — see `Docs\Open-Items.md`.
- ~~Should `SshPasswordLoginPossible`/`SshKeyLoginPossible` be a new Phase, or folded into Phase 4~~ —
  **resolved by implementation (2026-09-17, Round 14): folded into the main scan**, not a separate
  phase — both fields are populated in the same combined remote command as everything else, gated on
  the same sudo elevation. A scan account without sudo correctly reports both as `$null`/`Unknown`
  (not a guess) rather than falling back to a `sshd_config` grep. `AuthorizedKeysFile` is **not** read
  from `sshd -T`'s effective output as originally proposed — only the default
  `~/.ssh/authorized_keys` path is checked, a documented simplification tracked in
  `Docs\Open-Items.md` for any environment with a customized directive.
- ~~Needed before Phase 3/4 can finish being verified: a test account with password-required sudo
  rights~~ — **resolved (2026-09-17, Round 10)**: the user configured `CAscanner2` (full `ALL` sudo,
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

## 11. Revision log

| Date | Change |
|---|---|
| 2026-09-16 | Initial draft — proposed design, nothing implemented yet. |
| 2026-09-16 | Replaced the `plink.exe`-based connectivity design with `Posh-SSH`, per explicit user direction. Installed the real module and verified its cmdlets/parameters/examples live (`New-SSHSession`, `Invoke-SSHCommand`, `Remove-SSHSession`, `New-SSHTrustedHost`) rather than relying on memory. Key finding: key-based auth needs far less new design than originally scoped — `Get-DiscoveryCredential`'s existing `PSCredential` shape already covers it, needing only an added `KeyFilePath` field, not a new resolver method. Also resolved: host-key trust is handled natively by `Posh-SSH` (`-AcceptKey` plus a persistent `$HOME\.poshss\hosts.json` store), eliminating the manual fingerprint-parsing retry logic the `plink` approach would have needed. Architecture updated to mirror `Export-LocalGroups.ps1`'s `RunspacePool`/retry/structured-error pattern directly. Not verified: actual command execution against a real SSH target — no SSH server was available in this environment, and enabling one for testing was treated as a decision to ask about rather than make unilaterally. |
| 2026-09-17 | With the user's approval, enabled Windows' OpenSSH Server on the development machine and ran a real end-to-end Posh-SSH test: key-based `New-SSHSession` connected, `Invoke-SSHCommand` executed a command and returned the expected `ExitStatus`/`Output`, `Remove-SSHSession` cleaned up. This closes the "not verified against a real target" gap for the Posh-SSH mechanism itself (the remote command's Linux-specific shell content is still unverified — see Section 10). Flagged a cleanup follow-up: a passphrase-less test key remains installed in `administrators_authorized_keys` on the dev machine. |
| 2026-09-17 | Cleaned up the Windows test key (user removed the `administrators_authorized_keys` entry; local key files deleted). Generated a new, persistent test keypair (`Secrets\aped-linux-test-key`) for a real Ubuntu VM the user set up specifically for this; the user supplied its address/username after installing the public key themselves. Ran the actual proposed `/etc/passwd`+`/etc/group` command against it for real — this caught a genuine bug in this document's design: `Invoke-SSHCommand`'s `.Output` is a `String[]` (one element per line), not a single string, which silently breaks a naive `-split`. Corrected Sections 4-5 to the array-index-slicing approach and confirmed it against real data (56 users, 87 groups, correct multi-member group parsing). This closes every remaining "not verified against a real target" item. |
| 2026-09-17 | Added sudo rights discovery and sudo-elevated command support to scope (Section 5a), per user direction — reversing this document's original "no sudoers enumeration in v1" non-goal. New phases (3 and 4) cover documenting sudo access (`LinuxSudoRights.csv`) and then using it. Verified live: an account with zero sudo rights (`CAscanner`) gets a clean, fast, no-password-prompt failure from `sudo -n -l` with a specific, parseable message; also confirmed `Invoke-SSHCommand`'s result exposes `.Error` (stderr). Not yet verified: passwordless (`NOPASSWD`) sudo, password-required sudo, and the proposed `echo password \| sudo -S` non-interactive password supply — none can be tested without the user granting a test account some form of sudo rights on the VM. Flagged the security tradeoff of that mechanism (password briefly visible on the target's own process list) as something to weigh against a `SUDO_ASKPASS` alternative before committing to it. |
| 2026-09-17 | User granted `CAscanner` `NOPASSWD` sudo rights on the test VM. Verified live: `sudo -n -l` now returns the granted rules (`ExitStatus = 0`, listing both `ALL` and `NOPASSWD: ALL`); `sudo -n whoami` elevates immediately with zero password prompt; `sudo -n cat /etc/shadow` succeeds, and a remote `awk` filter confirmed the "derive only specific non-sensitive fields, never pull raw shadow content back" approach end-to-end. This fully closes Phase 3/4's passwordless path. Only the password-required sudo case (and the `echo password \| sudo -S` supply mechanism it needs) remains unverified — requires the user to configure a password-required, not `NOPASSWD`, sudo rule on a test account. |
| 2026-09-17 | Ran a full, methodical Windows-parity comparison against the real VM (new Section 6a) to directly answer "can Linux match what the Windows tool collects?". Confirmed at or near parity: users/groups/membership plus, now that sudo rights exist, `Disabled`/`PasswordLastSet`/`PasswordNeverExpires`-concept/`BadPasswordAttempts` — moved these out of Section 6's earlier "gated on a later phase" framing since they're verified now. Confirmed real, permanent (not just unverified) differences: Linux groups have no `Description` field at all, `systemctl show`'s `User=` property is only populated for units that declare it (verified both ways: `systemd-resolved.service` populated, `ssh.service`/`cups.service` blank), and `lastlog`/`last` aren't installed on this VM at all. Identified a place Linux can exceed Windows: `ss -tlnp` returns every listening port and its owning process in one call, vs. Windows' one-port-at-a-time signature probe. Added Phase 5 (database/software/service-account detection) to the rollout and a corresponding open decision on its design shape — building blocks confirmed to exist, actual signature-matching design not yet worked out. |
| 2026-09-17 | Per user request, verified shell/password-state/SSH-login-eligibility/home-directory data. Refined `Disabled` into a full `/etc/shadow` field-2 classification (real hash / locked-with-hash / locked-no-hash / never-set / two distinct "system, no password" conventions), confirmed against real accounts including two conventions coexisting on one system. Confirmed `sudo -n sshd -T` (not grepping `sshd_config`) is the only reliable way to get effective `PasswordAuthentication`/`PubkeyAuthentication`/`PermitRootLogin`/etc. — several of these weren't explicitly set in this VM's config file at all, and `sshd -T` itself requires `sudo` (fails outright without it). Found a real, specific setting worth designing around: `permitrootlogin prohibit-password` (root: key only, never password). Confirmed checking another account's `authorized_keys` for `SshKeyLoginPossible` also needs `sudo` (a `.ssh` dir is `0700`); found `ladmin`'s exists but is empty. Used `CAscanner`'s own locked/no-password state, alongside its already-proven SSH-key access all session, as live proof that key-login and password-login eligibility are independent per-account facts. Documented that this entire attribute area depends on the scan account having `sudo` — without it, none of it is available. |
| 2026-09-17 | Per user request, extended sudo rights discovery (Section 5a) to cover every discovered account, not just the scan account's own. Verified `sudo -n -l -U <username>` works for checking another account's rights, correctly resolving group-based grants (`ladmin`, via the `sudo` group) without this design needing to separately cross-reference group membership. Found the "no access" message is worded differently for a `-U` check (`is not allowed to run sudo`) than a self-check (`Sorry, user X may not run sudo`) — both need recognizing. Found a genuinely PAM-relevant real result: `CyberArkPCRec`/`CyberArkSHRec` each hold a group-inherited `ALL` rule plus their own account-specific grant to run `/usr/bin/passwd` as anyone — i.e. reset any local account's password — confirming why the design preserves full rule text per account rather than a single flag. Also confirmed `/etc/sudoers`/`/etc/sudoers.d/*` are directly readable with `sudo` as a secondary, raw-rule/provenance source. Identified a stronger constraint than previously stated: checking other accounts' rights this way needs the scanning account to have *broad* sudo rights, not just some. |
| 2026-09-17 | Per user direction, decided Linux output (and input) files stay entirely separate from the Windows tool's — no shared filenames, no `Platform` column, resolving two long-standing open decisions. Designed Phase 5 in full (new Section 6b): `LinuxDatabases.csv`/`LinuxSoftware.csv` (systemd-unit-name signature matching, parallel to Windows' `DatabaseSignatures`/`SoftwareSignatures` shape, enriched via `systemctl show`, listening confirmed via one `ss -tlnp` capture per computer rather than a probe per signature) and `LinuxServiceAccounts.csv` (every non-`root` service account). Verified live before finalizing: `Description=` is a real, populated property for every service (confirmed `DisplayName` equivalent exists); `systemctl list-unit-files` (324 unit files) is the correct enumeration scope to match Windows' "every registered service" coverage, not `list-units` (222 — only ever-loaded units). Corrected the earlier "blank `User=` is an unclear gap" framing to what it actually is: a determinate default (`root`), handled with the same noise-filtering rule Windows already applies to its own built-in identities. The starter `LinuxDatabaseSignatures` examples (PostgreSQL/MySQL/MariaDB/MongoDB unit names) are explicitly flagged as unverified, since the test VM has no database engine installed to check them against. |
| 2026-09-17 | The user reported PostgreSQL on the test VM "keeps stopping" and asked for it to be investigated. Found no actual problem: `NRestarts=0`, `Result=success`, only one stop/start cycle in the entire journal, a clean "received fast shutdown request" with zero errors/OOM kills, and `/var/log/apt/history.log` confirming the one restart was triggered by a routine `apt upgrade` that updated the `postgresql-18` package — not a crash loop. With a real engine now available, closed Phase 5's last open item by testing the actual `LinuxDatabaseSignatures` design against it: the `postgresql*` unit-pattern match, `systemctl show` enrichment, and `ss -tlnp` listening confirmation all worked (`postgresql@18-main.service`, port 5432, owning process `postgres`). This also **caught a real bug in the design's own service-account resolution**: `systemctl show`'s `User=` for `postgresql@18-main.service` was blank (which the existing rule would have classified as `root` and excluded), but the actual running process is owned by `postgres` — `pg_ctlcluster` starts as root and drops privileges internally, the same pattern already seen with `sshd`. Corrected Section 6b: `ServiceAccountName` must be resolved from the actual process owner (via `ss -tlnp`'s process-owner field, or `ps -o user= -p <MainPID>`), not read directly from `systemctl show`'s `User=` property. Also found `systemctl list-unit-files` alone misses instantiated template units (it shows only the `postgresql@.service` template, never `postgresql@18-main.service`) — enumeration needs `list-units` too. Found a fifth `UnitFileState` value, `enabled-runtime`, beyond the four confirmed earlier. |
| 2026-09-17 | Per user request to add concurrency "like the windows scanner," built the first real implementation: `Export-LocalLinuxGroups.ps1` and `Modules\LocalLinuxComputerScanner.psm1` (Phases 1-3, plus the `/etc/shadow`-derived half of Phase 4), following this document's already-settled design exactly — `RunspacePool` sized by `MaxConcurrency` (resolving Section 10's `RunspacePool`-vs-`Posh-SSH`-native-throttling question in favor of `RunspacePool`), one combined marker-delimited remote command per computer, retry-with-backoff, `LinuxScanErrors.csv`. Verified live against the real test VM: correct output reproducing every previously-recorded finding (`CAscanner`'s `LockedNoHash`/`PasswordlessSomeOrAll` state, `CyberArkPCRec`/`CyberArkSHRec`'s layered `PasswordRequired` rules), and a dedicated concurrency test (3 simultaneous scans of the same host, all completing within the same second with correctly isolated per-runspace results, no cross-talk) confirming the `RunspacePool` design is both genuinely parallel and safe. Not yet implemented: `BadPasswordAttempts`, per-account SSH-login eligibility, Phase 5, and the password-required sudo password-supply mechanism — see Section 8. |
| 2026-09-17 | User resolved four outstanding open decisions in one pass (Round 9). Host-key trust default confirmed as-is (no change). Sudo credential source decided: reuse the login password when SSH auth is password-based, require an explicit `SudoCredentialSource`/`SudoCredentialParams` when it's key-based (Section 5a) — not yet coded, still blocked on the `echo \| sudo -S` vs. `SUDO_ASKPASS` choice and a password-required test account. Phase 5's port-table question decided: `ss -tlnp` now also drives detection on its own via a new `LinuxUnrecognizedListeningPorts.csv` (Section 6b) — design-only, Phase 5 has no code yet. SSSD/Winbind-joined hosts decided **and implemented**: still collect local users/groups/membership normally, but flag the computer via a new `DirectoryJoined` column on `LinuxLocalUsers.csv`/`LinuxLocalGroups.csv` (Section 3/6). Verified live against the real test VM — this caught a genuine false-positive trap: the VM's `/etc/nsswitch.conf` already lists `sss` in its `passwd`/`group` lines purely as a base-Ubuntu-image artifact, with `sssd` never actually active and no `sssd.conf` present at all; trusting `nsswitch.conf` alone would have wrongly flagged this non-joined VM as directory-joined. The actual check (`sssd` active AND a real `sssd.conf` present, or `winbind` active) correctly returned `DirectoryJoined = False` for all 57 users/88 groups; a full re-run confirmed no regression to any previously-verified field. Created `Docs\Open-Items.md` to track this project's full remaining backlog (across AD, Windows, and Linux) in one place, per user request, rather than leaving it scattered across each design doc's own Section 10. |
| 2026-09-17 | After rebooting to finish installing the real CyberArk Credential Provider, the user configured two real CP test accounts and asked for CP retrieval to be tested (Round 10): `CAscanner2` (full `ALL` sudo, password-required) and `CyberArkSHUser01` (no sudo access), both under Safe `McWilliams Jesse`, AppID `APP_AIHost`. **Found and fixed a real, significant bug in `Modules\CredentialResolver.psm1`**: `CLIPasswordSDK.exe`'s `/o` output is a plain comma-separated list of values in the requested field order (e.g. `ThisIsMyPassword!,CAscanner2`), never `Key=Value` pairs as `Get-CredentialFromCP` had assumed — that assumption had never been exercised against a real Credential Provider before and would have thrown "did not return a Password value" on every real call. Fixed by requesting `Password` and `PassProps.UserName` via two separate single-field calls, avoiding any risk of a comma inside the password itself being misread as a field separator. Also corrected the default `ClipasswordsdkPath` to the real confirmed install location (`C:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe`, 64-bit `Program Files`, not `Program Files (x86)`). Verified the fix live for both accounts (password + username retrieved correctly, secret never displayed), then verified a real SSH connection using the CP-retrieved password. Used `CAscanner2` to close Phase 3's last gap: observed the password-required `sudo -n -l` self-check message for the first time (`sudo: interactive authentication is required`, a third distinct pattern), and — more importantly — confirmed the tool's actual mechanism (`sudo -n -l -U CAscanner2`, run by the broad-sudo scanning account) correctly returns a no-`NOPASSWD` rule that `ConvertTo-LinuxSudoAccess` classifies as `PasswordRequired`, reproduced in a real `Export-LocalLinuxGroups.ps1` run. `CyberArkSHUser01` independently re-confirmed `SudoAccess = None`. Still not done: the actual `echo password \| sudo -S` elevation mechanism itself, pending the still-open askpass-vs-echo decision. |
| 2026-09-17 | User asked what `SUDO_ASKPASS`'s limitations are. Rather than answer from general knowledge alone, investigated it live against the real test VM using `CAscanner2`'s real CyberArk-retrieved password (never displayed or logged). Found: no askpass helper exists on the VM by default (would need to deploy one to every target); `SUDO_ASKPASS` does nothing without an explicit `-A` flag on every call (confirmed: `A terminal is required to authenticate` without it); it does work correctly in this tool's actual no-tty single-command execution context once wired up; a missing helper fails cleanly and fast; a wrong password triggers sudo's normal 3-attempt retry loop, re-invoking the helper each time; and the mechanism only *relocates* the exposure (`/proc/<pid>/environ` vs. `ps aux`) rather than eliminating it, subject to the same `hidepid` caveat already noted for `echo \| sudo -S`. Recorded a net assessment in Section 5a leaning toward `echo \| sudo -S` as the lower-complexity choice, while leaving the final decision itself to the user. |
| 2026-09-17 | User reviewed Section 5a and decided: `echo \| sudo -S`, calling it "the only universal one" — `SUDO_ASKPASS` needs a helper file pre-staged on every target, which isn't guaranteed, so it fails the "works everywhere" bar `echo \| sudo -S` meets. Verified this live (Round 11) across all three sudo states using real accounts, never displaying any password: password-required (`CAscanner2`) succeeds with the correct password and fails cleanly with the wrong one, in a single attempt (fewer than `SUDO_ASKPASS`'s three); `NOPASSWD` (`CAscanner`) succeeds even when fed a completely irrelevant piped value, confirming the same invocation is safe to use unconditionally; zero sudo access (`CyberArkSHUser01`) fails in ~0.2 seconds with no hang, surfacing a fourth, previously-unseen "no access" message from sudo's `insults` plugin — flagged as a quirk specific to this test VM's config, not general sudo behavior. This closes the mechanism-choice decision and its safety verification; wiring `echo \| sudo -S` into `Modules\LocalLinuxComputerScanner.psm1` itself remains the next implementation step. |
| 2026-09-17 | Per user request ("Wire" the elevation mechanism), implemented `echo \| sudo -S` in `Modules\LocalLinuxComputerScanner.psm1` (Round 12). Refined the design first: a single `sudo -S -p '' -v` ticket refresh at the top of the combined remote command (verified live to let every subsequent `sudo -n` call succeed for the rest of that script's run) replaces piping the password before every individual `sudo -n` call, cutting the exposure window from once-per-account to once-per-computer. Found and fixed two real bugs while testing: (1) a `Mandatory [string[]]` parameter throws a misleadingly-worded "empty string" error for the whole array if any element is blank/null - never surfaced before since this is the first command whose success case produces zero output; fixed with `AllowEmptyString`/`AllowNull`. (2) `sudo -n -v` does not honor `NOPASSWD` the way an actual exempted command does, which would have logged a false "elevation not established" warning on every `NOPASSWD`-only computer; fixed by checking with `sudo -n true` instead. Verified end-to-end across all three sudo states with real accounts: `NOPASSWD` (`CAscanner`) unaffected, password-required (`CAscanner2`, used as the connecting account for the first time rather than only a `-U` target) now returns fully populated data via real elevation, and zero access (`CyberArkSHUser01`) degrades gracefully with correct warnings and blank fields. The `SudoCredentialSource` override path for key-based auth is implemented but not separately verified live (no matching test scenario exists yet). |
| 2026-09-17 | Per user request ("do Phase 5"), implemented `LinuxDatabases.csv`/`LinuxSoftware.csv`/`LinuxServiceAccounts.csv`/`LinuxUnrecognizedListeningPorts.csv` (Round 13). Investigated whether a single `systemctl show <all units>` call could replace one call per unit, and found a real, serious bug at real scale: it silently aborts after only a couple of units when one of them (a bare template like `alsa-card-wait@.service`) isn't individually queryable, producing ~16 lines instead of ~2,300. Also found the root cause was compounded by a second bug: `systemctl list-units`' default output prefixes a failed unit's row with a UTF-8 status bullet that `awk '{print $1}'` misreads as the unit name. Fixed both by reverting to a per-unit loop with `===UNIT:<name>===` markers (mirroring the already-proven `SUDOUSER` pattern - confirmed resilient and fast: 353 real units in ~1.7 seconds) and adding `--plain` to `list-units`. Simplified the service-account-resolution design from the originally-proposed `ss -tlnp`-process-owner-or-`ps`-by-MainPID dual path down to `ps`-by-MainPID alone, confirmed live to already resolve `postgresql@18-main.service` correctly to `postgres` (MainPID **is** the real worker process, not `pg_ctlcluster`'s launcher) and to work uniformly for listening and non-listening services alike. Verified end-to-end against real PostgreSQL, Docker, CUPS, and OpenSSH on the test VM - correct signature matches, correct service-account resolution, correct `Listening` values, and `LinuxUnrecognizedListeningPorts.csv` correctly shrinking as more signatures were added. A full scan (all phases together) completes in ~2.3 seconds against the real VM. This closes every item in the Linux design except `BadPasswordAttempts` and per-account SSH-login eligibility. |
| 2026-09-17 | Per user request ("do... Per-account SSH"), implemented `SshPasswordLoginPossible`/`SshKeyLoginPossible` on every `LinuxLocalUsers.csv` row (Round 14) - the first clean implementation this session with no bugs found. Resolved Section 10's open question by folding it into the main scan (not a separate phase) and simplifying `AuthorizedKeysFile` handling to only the default `~/.ssh/authorized_keys` path rather than reading `sshd -T`'s effective value, tracked as a documented gap. Reused the existing sudo elevation for `sudo -n sshd -T` (effective config) and a per-account `sudo -n test -s` loop. Verified against real, previously-known ground truth: `CAscanner`'s `SshKeyLoginPossible = True` (directly corroborated by this session's own SSH key usage all along) and `ladmin`'s `SshKeyLoginPossible = False` (matching Round 5's finding that its `authorized_keys` exists but is empty) both came back correct on the first try, along with `root`/`daemon` correctly showing `False` for both fields. This closes every item in the Linux design except `BadPasswordAttempts`. |
