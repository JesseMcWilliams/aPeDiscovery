# Local Linux Discovery — Design

**Status:** Proposed — not started
**Initiated:** 2026-09-16
**Origin:** User request to extend local-account discovery (already built for Windows, via
`Export-LocalGroups.ps1`) to Linux targets, keeping output formats similar across both.

This document is a plan, not an implementation — nothing described here has been built yet. Its
purpose is to surface the design decisions that need an answer (Section 10) before a
`Export-LocalLinuxGroups.ps1` gets written, using the same shape of doc as
[Design-Local-Windows-Discovery.md](Design-Local-Windows-Discovery.md) and
[Design-AD-Discovery.md](Design-AD-Discovery.md).

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
- **A directly relevant, already-proven pattern exists in the sibling `aPePAS` repository.**
  `APIModules\Custom\Invoke-CustomTestConnectivity.ps1` already drives non-interactive SSH
  authentication against Linux targets from Windows PowerShell 5.1, using `plink.exe` (PuTTY's
  CLI, vendored at the `aPePAS` repo root) with `-batch -pw <password>`. Its code comments record
  two things confirmed live by that project's user, both directly relevant here:
  - Native OpenSSH (and therefore PowerShell 7's `-SSHTransport`) **does not support non-interactive
    password authentication** — only key-based auth works reliably without a TTY. `plink -pw`
    is the only one of the two that reliably authenticates with a password non-interactively.
  - An unrecognized host key does not need to hang the connection: `plink -batch` fails fast with a
    parseable fingerprint in its error text, which that code retries once against via `-hostkey`
    (trust-on-first-use).
  That module only ever runs `exit` as the remote command (it's an auth *test*, not a data
  collector), but `plink` supports passing a real remote command in the same call, streaming its
  stdout back — so the same connection mechanism extends naturally to actually collecting data,
  not just testing login. `aPeDiscovery` is a separate git repository from `aPePAS`, so reusing this
  means either duplicating the relevant helper functions or factoring them into a module both
  repos can pull from (see Open Decisions).
- **CyberArk remains the credential system of record**, per the existing `CredentialResolver.psm1`
  — but see Section 4: Linux/SSH commonly authenticates with a private key rather than a password,
  which that module doesn't currently produce.
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

## 4. Connectivity & credential model — the core open design area

**Proposed primary path: `plink.exe`, reusing the `aPePAS` pattern.** Locate `plink.exe` (PATH,
project root, standard PuTTY install paths — same search order as `Find-PlinkExecutable` in
`aPePAS`), invoke it as `plink -ssh -batch -pw <password> <user>@<host> "<remote command>"`, with
the same trust-on-first-use host-key handling for a never-before-seen host, and capture stdout for
parsing.

**Proposed fallback path for key-based auth:** native `ssh.exe` (built into modern Windows) or
PowerShell 7's `-SSHTransport`, for credentials that are a private key rather than a password —
`plink` also supports key-based auth (`-i <keyfile>`), so this may not need a separate code path at
all, only a separate argument set depending on what `CredentialResolver` returns for a given host.

**The gap this exposes in `CredentialResolver.psm1`:** every source today (`CurrentUser`,
`PSCredential`, `CP`, `CCP`, `Conjur`) resolves to a username + password `PSCredential`. SSH
key-based auth needs a private key (and possibly a passphrase) instead, and CyberArk can vault SSH
keys as their own account/secret type in CP/CCP/Conjur just as it does passwords. Whether
`CredentialResolver` needs a second resolution shape (e.g. a `Get-DiscoverySshKey` alongside
`Get-DiscoveryCredential`) — or whether Linux discovery stays password-only for v1 and defers
key-based auth — is an open decision (Section 10), not assumed here.

**Security note carried over from `aPePAS`:** `plink -pw` passes the password as a plain
command-line argument, briefly visible to anything else on the host that can enumerate process
command lines while `plink` is running. This is inherent to `plink`'s own `-pw` flag, not something
a wrapper around it can avoid while still using that flag — the same tradeoff `aPePAS` already
accepted for its connectivity test, and one this design would inherit rather than solve.

## 5. Proposed architecture

```
ComputersToScan.csv (Linux rows — see Open Decisions on whether this is a shared or separate file)
  └─ for each enabled row:
       TCP-22 reachability check → skip fast if unreachable
       resolve credential (CredentialResolver.psm1, per-row CredentialParamsJson)
       plink -ssh -batch -pw <password> <user>@<host> "<remote read-only command>"
         └─ trust-on-first-use retry with -hostkey <fingerprint> on first-time hosts (per aPePAS pattern)
       parse stdout (getent-free /etc/passwd + /etc/group content) into rows
Export-Csv → LinuxLocalUsers.csv / LinuxLocalGroups.csv / LinuxLocalGroupMembers.csv
  (+ timestamped Archive copy, retention-pruned — same pattern as the other two scripts)
```

**Why TCP-22 instead of ICMP for the reachability check.** The Windows script's ICMP pre-check was
flagged as an open limitation there for exactly this reason — ICMP can be blocked while the actual
dependency (here, port 22) is not. Since this is a fresh design, proposing the TCP-probe pattern
already used elsewhere in this project (`Test-TcpPortOpen`-style connect-with-timeout, as seen in
`aPePAS`'s own connectivity module) directly, rather than inheriting the same limitation.

**Remote command shape (proposed):** a single non-interactive command that prints `/etc/passwd`
and `/etc/group` with a distinguishing separator line between them (e.g.
`cat /etc/passwd; echo '---APEDISC-SEP---'; cat /etc/group`), parsed locally on the control host —
keeping all the parsing logic in PowerShell rather than pushing a parsing script to the target, in
the same spirit as the Windows script needing nothing installed on its targets.

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
- `plink -pw`'s command-line exposure (Section 4) is inherited, not solved, by this design — using
  key-based auth where available avoids it entirely, which is one more reason key-based auth support
  is worth prioritizing over staying password-only.
- If Phase 2 adds `/etc/shadow`-derived fields, only the specific derived flags needed
  (disabled/never-expires) should ever be parsed out and logged — never the shadow file's raw
  content, which includes password hashes.

## 8. Phased rollout (proposed)

1. **Phase 1** — password-only auth via `plink`; `/etc/passwd` + `/etc/group` only (no
   `Disabled`/`PasswordNeverExpires`); no primary-group resolution; no sudoers data.
2. **Phase 2** — key-based auth support (extends `CredentialResolver.psm1`).
3. **Phase 3** — `/etc/shadow`-derived fields, gated on the scan account having root or passwordless
   sudo for a narrow, specific read command.

## 9. Progress tracker

Not started — no code exists for this yet.

## 10. Open decisions (need an answer before Phase 1 starts)

- **Shared or separate input file?** Add a `Platform` column to the existing
  `ComputersToScan.csv`/`Export-LocalGroups.ps1` input so one file drives both Windows and Linux
  scans, or keep a separate `LinuxComputersToScan.csv` and a separate
  `Export-LocalLinuxGroups.ps1` script?
- **Shared or separate output schema?** Per-platform files (as sketched in Section 6) or a single
  unified schema with a `Platform` column and platform-specific columns left blank where not
  applicable?
- **Does `CredentialResolver.psm1` need to support SSH private keys**, not just username+password,
  for Linux targets — and if so, which of CP/CCP/Conjur will actually be used to vault Linux SSH
  keys/passwords in this environment?
- **Should the `plink`-invocation logic be factored into something both `aPeDiscovery` and
  `aPePAS` can share**, since it would otherwise be duplicated between two separate git
  repositories?
- **Is passwordless sudo available/acceptable** for the scan account, to unlock Phase 3's
  `/etc/shadow`-derived fields? If not, Phase 3 may need to be dropped rather than deferred.
- **How should SSSD/Winbind-joined hosts be handled** — excluded from scope entirely (relying on
  `Export-ADGroups.ps1` for their directory-sourced accounts), or does this tool need to positively
  distinguish local vs. directory-sourced entries when both can appear in `getent`'s merged view?

## 11. Revision log

| Date | Change |
|---|---|
| 2026-09-16 | Initial draft — proposed design, nothing implemented yet. |
