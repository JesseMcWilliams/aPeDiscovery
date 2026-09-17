# Local Linux Discovery — Design

**Status:** Proposed — connectivity mechanism decided, no code written yet
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

**Update 2026-09-17 — the full connect/execute/parse/disconnect flow is now verified end-to-end.**
With the user's approval, Windows' OpenSSH Server feature was enabled on the development machine
specifically to close this gap. `New-SSHSession`/`Invoke-SSHCommand`/`Remove-SSHSession` were run for
real, not just inspected: a session was established via key-based auth (`SessionId=0, Connected=True`),
a command was executed (`whoami && hostname`) and returned exactly the expected `ExitStatus = 0` and
`Output` string, and the session was cleanly removed. The target was Windows (this project's only
available SSH server), not Linux, so the *shell dialect* of the actual `/etc/passwd`+`/etc/group`
command in Section 5 is still unverified against a real Linux target — but the mechanism this whole
design depends on (Posh-SSH itself, end to end) no longer is. See Section 9 for how this was set up
and a follow-up worth doing.

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

- **No sudoers/privilege-escalation enumeration in v1.** Discovering *who has sudo and to run
  what* is a natural and valuable follow-on, but is a distinct data model from "local users, groups,
  and group membership" as originally scoped for the Windows tool, and is proposed as later work
  rather than v1 scope.
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
- **`Invoke-SSHCommand`** runs a command over an existing session: `Invoke-SSHCommand -SSHSession <session> -Command '<command>' [-TimeOut <seconds, default 60>]`. Confirmed via the cmdlet's own documented example: it returns an object with `Host`, `Output` (the command's raw stdout as a single string), and `ExitStatus` (int) properties — exactly the shape needed to run the `/etc/passwd`+`/etc/group` dump and parse `.Output` locally, the same "nothing runs on the target beyond a shell built-in" philosophy as the Windows tool.
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
ComputersToScan.csv (Linux rows — see Open Decisions on whether this is a shared or separate file)
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

**Remote command shape (proposed, unchanged from the original plan):** a single non-interactive
command that prints `/etc/passwd` and `/etc/group` with a distinguishing separator line between them
(e.g. `cat /etc/passwd; echo '---APEDISC-SEP---'; cat /etc/group`), parsed from `Invoke-SSHCommand`'s
`.Output` string locally on the control host — keeping all parsing logic in PowerShell rather than
pushing a parsing script to the target, the same "nothing installed on the target" philosophy as the
Windows tool.

## 6. Data model & interfaces (proposed — not final)

Proposed columns, mirroring the Windows output shape:

**LinuxLocalUsers.csv:** `ScanTimestamp`, `ComputerName`, `UserName`, `UID`, `PrimaryGID`,
`Description` (the GECOS field), `HomeDirectory`, `Shell`. `Disabled` and `PasswordNeverExpires`
equivalents would require reading `/etc/shadow`, which needs root or passwordless sudo for the scan
account — proposed as a Phase 2 addition gated on that being available (see Section 8), not part of
the v1 column set.

**LinuxLocalGroups.csv:** `ScanTimestamp`, `ComputerName`, `GroupName`, `GID`.

**LinuxLocalGroupMembers.csv:** `ScanTimestamp`, `ComputerName`, `GroupName`, `GID`, `MemberName`.
Only `/etc/group`'s explicit member list — a user whose *primary* GID matches a group but who isn't
also listed as an explicit member would not appear here, the same documented parity limitation as
the Windows tool's primary-group gap.

Whether these should be separate `Linux*.csv` files (as sketched above) or the *same* filenames the
Windows tool already produces (`LocalUsers.csv` etc.) with an added `Platform` column distinguishing
`Windows`/`Linux` rows, for one unified downstream import, is an open decision (Section 10) — the
column sets aren't identical (UID/GID vs. SID, no direct `Disabled`/`PasswordNeverExpires` in v1),
so unifying the files would mean either a wider shared schema with platform-specific blanks, or
keeping the two per-platform member files distinct with a shared *groups* file. Not resolved here.

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

## 8. Phased rollout (proposed)

1. **Phase 1** — password auth via `Posh-SSH` (no `CredentialResolver.psm1` changes needed); `/etc/passwd`
   + `/etc/group` only (no `Disabled`/`PasswordNeverExpires`); no primary-group resolution; no
   sudoers data.
2. **Phase 2** — key-based auth: add an optional `KeyFilePath` field to `CredentialParams`, passed
   straight through to `New-SSHSession -KeyFile`. Turned out much smaller than originally scoped —
   see Section 4 — since `Get-DiscoveryCredential`'s existing return shape already covers the
   username/passphrase half.
3. **Phase 3** — `/etc/shadow`-derived fields, gated on the scan account having root or passwordless
   sudo for a narrow, specific read command.

## 9. Progress tracker

No script code exists for this yet (`Export-LocalLinuxGroups.ps1` is not written). Connectivity
mechanism (`Posh-SSH`) is decided, and — as of 2026-09-17 — its actual connect/execute/parse/
disconnect flow is verified end-to-end against a real SSH server:

- Windows' OpenSSH Server feature was enabled on the development machine (with the user's approval)
  specifically to create a test target, since none existed before.
- A passphrase-less ed25519 test keypair was generated and its public half installed into
  `C:\ProgramData\ssh\administrators_authorized_keys` (the file Windows OpenSSH requires for an
  account in `BUILTIN\Administrators`, rather than the per-user `~/.ssh/authorized_keys`) — this
  required an elevated session the assistant didn't have, so the user ran the write + `icacls`
  lockdown themselves.
- `New-SSHSession -KeyFile <path> -AcceptKey` connected successfully; `Invoke-SSHCommand -Command
  'whoami && hostname'` returned `ExitStatus = 0` and the correct `Output` string; `Remove-SSHSession`
  cleaned up.
- **Follow-up worth doing**: the test key is still installed in `administrators_authorized_keys` on
  the development machine. It's passphrase-less, so anyone who obtains the private key file (in the
  assistant's scratchpad) could use it. Recommend removing that entry (and the local key files) once
  this design work is done with it, unless it's being kept deliberately for further testing.
- The target was Windows, not Linux — this confirms Posh-SSH itself works end-to-end, but the actual
  remote command in Section 5 (`cat /etc/passwd; echo ...; cat /etc/group`) has not been run against
  a real Linux shell.

## 10. Open decisions (need an answer before Phase 1 starts)

- **Shared or separate input file/script?** Now more attractive than when this was `plink`-based:
  since the Linux and Windows scripts' architecture (RunspacePool, retry, structured errors) is now
  essentially identical and differs only in the connection/collection step, add a `Platform` column
  to the existing `ComputersToScan.csv` so one file drives both, or keep a separate
  `LinuxComputersToScan.csv` and `Export-LocalLinuxGroups.ps1`?
- **Shared or separate output schema?** Per-platform files (as sketched in Section 6) or a single
  unified schema with a `Platform` column and platform-specific columns left blank where not
  applicable?
- **Default host-key trust policy**: always pass `-AcceptKey` (fully automatic trust-on-first-use,
  simplest for an unattended nightly run) or require a pre-seeded known-hosts store per environment
  (safer against a first-contact MITM, more operational setup)? `-Force` (skip validation entirely)
  should not be a default either way.
- **`RunspacePool` (mirroring the Windows tool) vs. `Posh-SSH`'s own `Invoke-SSHCommand -SessionId
  <array> -ThrottleLimit`** for concurrency — Section 5 proposes the former for architectural
  consistency with `Export-LocalGroups.ps1`, but the latter is a real, simpler alternative Posh-SSH
  offers natively once sessions are already open. Worth a second look once this is actually built.
- **Is passwordless sudo available/acceptable** for the scan account, to unlock Phase 3's
  `/etc/shadow`-derived fields? If not, Phase 3 may need to be dropped rather than deferred.
- **How should SSSD/Winbind-joined hosts be handled** — excluded from scope entirely (relying on
  `Export-ADGroups.ps1` for their directory-sourced accounts), or does this tool need to positively
  distinguish local vs. directory-sourced entries when both can appear in `getent`'s merged view?
- ~~Validate against a real target before committing to this design as final~~ — **done for the
  Posh-SSH mechanism itself** (2026-09-17, see Section 9): connect/execute/parse/disconnect verified
  end-to-end against a real OpenSSH server. **Still open**: the actual `/etc/passwd`+`/etc/group`
  command has only been designed against Linux's shell semantics, never run against a real Linux
  target (the only server available to test against here was Windows).

## 11. Revision log

| Date | Change |
|---|---|
| 2026-09-16 | Initial draft — proposed design, nothing implemented yet. |
| 2026-09-16 | Replaced the `plink.exe`-based connectivity design with `Posh-SSH`, per explicit user direction. Installed the real module and verified its cmdlets/parameters/examples live (`New-SSHSession`, `Invoke-SSHCommand`, `Remove-SSHSession`, `New-SSHTrustedHost`) rather than relying on memory. Key finding: key-based auth needs far less new design than originally scoped — `Get-DiscoveryCredential`'s existing `PSCredential` shape already covers it, needing only an added `KeyFilePath` field, not a new resolver method. Also resolved: host-key trust is handled natively by `Posh-SSH` (`-AcceptKey` plus a persistent `$HOME\.poshss\hosts.json` store), eliminating the manual fingerprint-parsing retry logic the `plink` approach would have needed. Architecture updated to mirror `Export-LocalGroups.ps1`'s `RunspacePool`/retry/structured-error pattern directly. Not verified: actual command execution against a real SSH target — no SSH server was available in this environment, and enabling one for testing was treated as a decision to ask about rather than make unilaterally. |
| 2026-09-17 | With the user's approval, enabled Windows' OpenSSH Server on the development machine and ran a real end-to-end Posh-SSH test: key-based `New-SSHSession` connected, `Invoke-SSHCommand` executed a command and returned the expected `ExitStatus`/`Output`, `Remove-SSHSession` cleaned up. This closes the "not verified against a real target" gap for the Posh-SSH mechanism itself (the remote command's Linux-specific shell content is still unverified — see Section 10). Flagged a cleanup follow-up: a passphrase-less test key remains installed in `administrators_authorized_keys` on the dev machine. |
