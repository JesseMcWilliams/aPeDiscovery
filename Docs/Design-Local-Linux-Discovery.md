# Local Linux Discovery — Design

**Status:** Proposed — connectivity mechanism decided and verified end-to-end against a real Linux VM; sudo rights discovery/elevation in scope for every discovered account (not just the scan account), with no-access and passwordless (`NOPASSWD`) cases verified live (password-required case still open); users/groups/membership/password-aging/password-state/SSH-login-eligibility all verified at or near Windows parity (Sections 6/6a); database/software/service-account detection (Phase 5) designed and verified against a real PostgreSQL install (Section 6b), including a real correction to service-account resolution it caught; Linux output/input files decided to stay entirely separate from the Windows tool's; no script code written yet
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
- **No resolution of directory-integrated accounts (SSSD/Winbind/LDAP).** A Linux host joined to AD
  via SSSD or Winbind can present domain accounts through `getent passwd`/`getent group` alongside
  genuinely local ones. Proposed v1 scope reads `/etc/passwd` and `/etc/group` directly (the
  `files` NSS source only) rather than `getent`, mirroring the Windows tool's "local SAM only, not
  resolved domain group membership" scope — see Open Decisions for the membership-classification
  wrinkle this creates.
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

**Still not verified — no suitable test account exists for this case yet:**
- **An account whose sudo rights require an actual password** (as opposed to `NOPASSWD`). `NOPASSWD`
  was what got tested here, which — deliberately, since sudo checks it first — never exercises the
  password-prompt path at all. `sudo -n -l` for a password-required account is expected to fail
  differently than "no access" (commonly with a message indicating a password is needed, e.g. `sudo:
  a password is required`), and the actual `echo '<password>' | sudo -S -p '' <command>`
  non-interactive password-supply mechanism (Section 7's security tradeoff) has still never been
  exercised. Needs the user to configure a test account with a password-required (not `NOPASSWD`)
  sudo rule.

**Security tradeoff to document prominently once this is tested and built:** embedding the password
in `echo '<password>' | sudo -S ...` means it appears, briefly, as a process argument on the *target*
Linux host while that command runs — visible to anything else on that host that can read `ps
aux`/`/proc/<pid>/cmdline` (unless the host restricts that via a `hidepid` mount option or similar).
This is the same class of exposure `aPePAS`'s `plink -pw` accepted on the Windows control-host side
(Section 4's Security note) — except here it would be exposed on the *scanned target*, not the
control host. Worth weighing against the alternative (a `SUDO_ASKPASS` helper script, more setup,
avoids the command-line exposure) before committing to the simpler `echo | sudo -S` approach for real.

**Where does the sudo password come from?** Not necessarily the same secret used for SSH login —
SSH auth here is commonly key-based (see Section 4), but sudo always wants a *password* (the
account's own, by sudo's default `PAM` configuration) unless `NOPASSWD` applies. Proposed: an
optional `SudoCredentialSource`/`SudoCredentialParams` pair in `CredentialParams`, resolved via the
same `Get-DiscoveryCredential` mechanism as everything else, defaulting to reusing the primary
credential's password only when the primary source is itself password-based (not key-based, where
there is no password to reuse).

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

**Proposed output**: `LinuxSudoRights.csv` — `ScanTimestamp`, `ComputerName`, `UserName`,
`SudoAccess` (`None` / `PasswordlessSomeOrAll` / `PasswordRequired` — classify by checking the
`-U` output for the literal substring `NOPASSWD`; exact category boundaries to be finalized once a
genuinely password-required account is observed — see below), `RawSudoListOutput` (the full rule
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

**SSH login-method eligibility per account (verified 2026-09-17) — proposed new columns
`SshPasswordLoginPossible`/`SshKeyLoginPossible`:**
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
  password-authenticating account instead). The file path itself should be read from `sshd_config`'s
  `AuthorizedKeysFile` directive (default, and what this VM uses: `.ssh/authorized_keys`, relative to
  each account's home) rather than hardcoded, since a site can point it somewhere else (e.g. a
  centralized keys directory).
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

### Still open (see Section 10)

Whether `LinuxDatabaseSignatures`/`LinuxSoftwareSignatures` should key primarily off unit-name
patterns (as designed above, now verified against a real PostgreSQL install) or primarily off the
`ss -tlnp` port table, or genuinely cross-reference both, is still open for the *default listening
port* case generally — but the process-owner correction above is settled, not still open.
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

1. **Phase 1** — password auth via `Posh-SSH` (no `CredentialResolver.psm1` changes needed);
   `/etc/passwd` + `/etc/group`; no primary-group resolution. All verified live.
2. **Phase 2** — key-based auth: add an optional `KeyFilePath` field to `CredentialParams`, passed
   straight through to `New-SSHSession -KeyFile`. Turned out much smaller than originally scoped —
   see Section 4 — since `Get-DiscoveryCredential`'s existing return shape already covers the
   username/passphrase half. Verified live.
3. **Phase 3** — sudo rights discovery (`LinuxSudoRights.csv`, see Section 5a): classify each scanned
   account as no-access / passwordless / password-required, based on `sudo -n -l`. The no-access and
   passwordless cases are both verified live now; only password-required is still unconfirmed.
4. **Phase 4** — sudo-elevated command execution, unlocking `/etc/shadow`-derived fields
   (`Disabled`/`PasswordLastSet`/`PasswordNeverExpires`, folded into `LinuxLocalUsers.csv` per
   Section 6 rather than treated as a separate later addition) and `BadPasswordAttempts` via
   `faillock`. The passwordless path (`sudo -n <command>`) is verified live end-to-end, including the
   "derive only specific non-sensitive fields remotely, never pull raw shadow content back" approach.
   Only the password-required path (resolving and supplying a sudo password) remains unverified.
5. **Phase 5** *(added 2026-09-17, designed 2026-09-17)* — `LinuxDatabases.csv`/`LinuxSoftware.csv`
   (systemd-unit-name signature matching, enriched via `systemctl show`, listening confirmed via one
   `ss -tlnp` capture per computer rather than a probe per signature) and `LinuxServiceAccounts.csv`
   (every non-`root` service account). Design is worked out in full — see Section 6b — but unverified
   against a real installed database engine, since the test VM has none.

## 9. Progress tracker

No script code exists for this yet (`Export-LocalLinuxGroups.ps1` is not written). Connectivity
(`Posh-SSH`) is decided, and its full connect/execute/parse/disconnect flow is now verified against
both a Windows and a real Linux target.

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

## 10. Open decisions (need an answer before Phase 1 starts)

- ~~Shared or separate input file/script?~~ / ~~Shared or separate output schema?~~ — **decided with
  the user (2026-09-17): separate.** No `Platform` column, no shared filenames with the Windows tool,
  for input or output. See Section 6/6b.
- **Default host-key trust policy**: always pass `-AcceptKey` (fully automatic trust-on-first-use,
  simplest for an unattended nightly run) or require a pre-seeded known-hosts store per environment
  (safer against a first-contact MITM, more operational setup)? `-Force` (skip validation entirely)
  should not be a default either way.
- **`RunspacePool` (mirroring the Windows tool) vs. `Posh-SSH`'s own `Invoke-SSHCommand -SessionId
  <array> -ThrottleLimit`** for concurrency — Section 5 proposes the former for architectural
  consistency with `Export-LocalGroups.ps1`, but the latter is a real, simpler alternative Posh-SSH
  offers natively once sessions are already open. Worth a second look once this is actually built.
- **Phase 5's remaining open question, narrowed by the real PostgreSQL test**: unit-name matching
  (enriched via `systemctl show`) as primary and the `ss -tlnp` port table as corroboration is
  confirmed to work for a real engine now — still open is whether the port table should *also* drive
  detection on its own (catching something listening that no configured signature expected at all),
  which wasn't tested. The process-owner-resolution correction (Section 6b) is settled, not open.
- **Should `SshPasswordLoginPossible`/`SshKeyLoginPossible` be a new Phase, or folded into Phase 4**
  (both need `sudo`, same as the shadow/`faillock` fields)? Also: should `AuthorizedKeysFile` be read
  from `sshd -T`'s effective output per host (correct, handles a customized path) rather than assumed
  to be the default `.ssh/authorized_keys`, and should a scan account *without* sudo report these
  fields as `Unknown` rather than guessing from a possibly-incomplete `sshd_config` grep?
- **Needed before Phase 3/4 can finish being verified: a test account with *password-required* sudo
  rights** (not `NOPASSWD` — that case is now verified, see Section 9, Round 3). The user would need
  to configure a sudoers rule for `CAscanner` (or another test account) that requires a password, so
  the exact `sudo -n -l` output for that case and the `echo '<password>' | sudo -S` supply mechanism
  can actually be exercised, the same way the no-access and passwordless cases already were.
- **Does the sudo password default to the same secret as the SSH login password, or does it need its
  own vaulted lookup** (`SudoCredentialSource`/`SudoCredentialParams`)? Only matters when SSH auth is
  key-based (no password exists to reuse) or when an environment's sudo password genuinely differs
  from the account's login password — see Section 5a.
- **`echo '<password>' | sudo -S` vs. a `SUDO_ASKPASS` helper script** for supplying the password —
  the former is simpler but exposes the password briefly on the target's own process list; is that
  tradeoff acceptable, or is the extra setup of an askpass helper worth it? See Section 5a/7.
- **How should SSSD/Winbind-joined hosts be handled** — excluded from scope entirely (relying on
  `Export-ADGroups.ps1` for their directory-sourced accounts), or does this tool need to positively
  distinguish local vs. directory-sourced entries when both can appear in `getent`'s merged view?
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
