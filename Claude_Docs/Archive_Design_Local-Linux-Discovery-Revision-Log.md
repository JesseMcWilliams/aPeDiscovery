# Archive: Local Linux Discovery — Progress Tracker & Revision Log

> Moved word-for-word out of `Design_Local-Linux-Discovery.md` (formerly Sections 9 and 11) to keep that doc under the ~500-line budget. This is historical session-by-session narrative; git history is the source of truth going forward. **Don't read this unless the task needs that history.**

---

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
  real multi-member group (`sudo:x:27:the lab admin account,a lab service account with layered sudo rights,another lab service account with layered sudo rights`) parsed correctly.
- **Follow-up worth doing**: `Secrets\aped-linux-test-key`'s public half is still installed on the
  test VM, and it's passphrase-less. Fine to leave in place while this VM continues to be used for
  Linux discovery testing; worth removing (from the VM's `~/.ssh/authorized_keys` and this project's
  `Secrets\` folder) once that testing is done.

**Round 3 — sudo rights discovery, mostly verified (2026-09-17):**
- `the NOPASSWD sudo test account` (initially no sudo group membership) confirmed the "no sudo access at all" case:
  `sudo -n -l` exits `1` with `stderr` = `sudo: Sorry, user the NOPASSWD sudo test account may not run sudo on
  the lab test VM.`, with **no password prompt** — sudo fails fast when no rule matches at
  all. Also confirmed `Invoke-SSHCommand`'s result object exposes `.Error` (stderr), not just
  `.Output`/`.ExitStatus`.
- The user then granted `the NOPASSWD sudo test account` `NOPASSWD` sudo rights on the same VM, confirming the passwordless
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
  success with it, finding `the lab admin account`'s `authorized_keys` exists but is empty).
- `the NOPASSWD sudo test account` itself — locked/no-password, yet used for every SSH-key-authenticated command all
  session — is live, already-established proof that SSH key and password login eligibility are
  independent per-account facts, not two views of one fact.
- **This whole attribute area depends on the scan account having sudo** — without it, none of this
  (accurate password state, effective sshd settings, other accounts' `authorized_keys`) is available.

**Round 6 — sudo rights for every discovered account, not just the scan account's own, verified
(2026-09-17):**
- `sudo -n -l -U <username>` confirmed working for checking a *different* account's rights: `the lab admin account`
  → full `ALL` rights (via `sudo` group membership, correctly resolved without this design needing to
  separately cross-reference group membership itself); `daemon` → no access, with a **differently
  worded** message than the self-check case (`is not allowed to run sudo` vs. `Sorry, user X may not
  run sudo`) — both patterns need recognizing.
- Found a genuinely PAM-relevant real result: `a lab service account with layered sudo rights`/`another lab service account with layered sudo rights` each have **two**
  layered rules — a group-inherited `(ALL:ALL) ALL` (password-required) plus their own
  account-specific, password-required `(ALL:ALL) /usr/bin/passwd` grant (from their own
  `/etc/sudoers.d/<name>` file) — i.e. each can reset any local account's password specifically.
  Confirms preserving the *full* rule text per account matters; a single flag would have flattened
  this away.
- Confirmed `/etc/sudoers`/`/etc/sudoers.d/*` are directly readable with `sudo` (root-owned,
  `0440`/`0640`) as a secondary, raw-rule/provenance source — `the NOPASSWD sudo test account`'s own grant was visible
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
- Ran against the real test VM (the lab test VM): 57 users, 88 groups, 15 membership rows, 57
  sudo-rights rows, on the first successful run — no bugs found in the connect/parse/export path
  itself. Spot-checked correctness against known real data from earlier rounds: `the NOPASSWD sudo test account`'s
  `PasswordState` = `LockedNoHash` (matches Round 5's finding for this account), its
  `SudoAccess` = `PasswordlessSomeOrAll` with the exact `ALL` + `NOPASSWD: ALL` rule text (matches
  Round 3's grant), and `a lab service account with layered sudo rights`/`another lab service account with layered sudo rights` both = `PasswordRequired` with the exact
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
  `echo | sudo -S` vs. `SUDO_ASKPASS` mechanism choice (tracked in `Claude_Docs\Planning_Open-Items.md`) — the
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
  real CP test accounts and asked for CP retrieval to be tested: `the password-required sudo test account` (Safe `McWilliams
  Jesse`) — full `ALL` sudo rights, password-required, not `NOPASSWD` — and `the no-sudo-access test account` (Safe
  `the test CyberArk safe`, under an `Operating System-...` object name) — no sudo access at all.
- **Found the real install path**: `C:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe`
  (64-bit `Program Files`), not `Program Files (x86)` as `Get-CredentialFromCP`
  (`Modules\CredentialResolver.psm1`) previously defaulted to.
- **Found and fixed a real, significant bug**: `CLIPasswordSDK.exe GetPassword /o Password,PassProps.UserName`
  returns a plain comma-separated list of **values** in the requested order (e.g.
  `ThisIsMy_FAKE_Password6!,the password-required sudo test account`), never `Key=Value` pairs — confirmed by probing with non-secret
  fields only (`/o PassProps.UserName` alone returned bare `the password-required sudo test account`; a field that doesn't apply
  returns the literal string `<na>`). `Get-CredentialFromCP`'s original parsing logic expected
  `Key=Value` tokens and would have thrown "did not return a Password value" on **every** real CP
  call — this had never actually been exercised against a real Credential Provider before this.
  Fixed by requesting `Password` and `PassProps.UserName` as two separate single-field calls (avoids
  any risk of a comma embedded in the password itself being mistaken for a field separator — there's
  no confirmed guarantee CLIPasswordSDK escapes that case) rather than parsing a combined
  multi-field line.
- **Verified the fix live for both accounts**, confirming a real password and the correct username
  came back for each without ever displaying the actual secret value in this session's output.
- **Closed the last remaining Phase 3 gap**: used `the password-required sudo test account` to finally observe the
  password-required `sudo -n -l` self-check pattern for real (`sudo: interactive authentication is
  required`, a third distinct message pattern) via a genuine SSH connection authenticated with the
  CP-retrieved password — and, more importantly, confirmed the actual mechanism this tool uses
  (`sudo -n -l -U the password-required sudo test account`, run by the already-broad-sudo scanning account) correctly returns a
  no-`NOPASSWD` `(ALL : ALL) ALL` rule, which `ConvertTo-LinuxSudoAccess` correctly classifies as
  `PasswordRequired` — confirmed by re-running `Export-LocalLinuxGroups.ps1` for real and finding
  exactly that in `LinuxSudoRights.csv`. `the no-sudo-access test account` independently re-confirmed `SudoAccess =
  None`. This closes the "needed before Phase 3/4 can finish being verified" item from Section 10.
- **Not yet done**: actually supplying `the password-required sudo test account`'s password to elevate a real command (the `echo
  password | sudo -S` vs. `SUDO_ASKPASS` mechanism is still undecided, so this test only confirmed
  the classification, not the elevation itself).

**Round 11 — the sudo elevation mechanism decided and verified safe across all three sudo states
(2026-09-17):**
- After reviewing Section 5a's `echo | sudo -S` vs. `SUDO_ASKPASS` comparison, the user made the
  call: `echo | sudo -S`, on the grounds that `SUDO_ASKPASS` needs a helper file pre-staged on every
  target (not guaranteed to exist — confirmed in Round 10's research this VM has none), so it isn't
  "universal" the way `echo | sudo -S` is.
- Verified live, using `the password-required sudo test account`'s real CP-retrieved password (never displayed) and never
  hard-coding any account's actual sudo state ahead of time:
  - **Password-required**: correct password → success (`root`, exit `0`); wrong password → one
    clean failure and stop (`Authentication failed, try again.` then `Authentication required but
    not attempted`), exit `1` — notably only **one** retry, not `SUDO_ASKPASS`'s three, since piped
    stdin has just one line before EOF.
  - **`NOPASSWD`**: piping a completely irrelevant value via `-S` still succeeds immediately — sudo
    never reads stdin once `NOPASSWD` already applies. Confirms the *same* invocation is safe to use
    unconditionally, without first detecting whether an account needs a password at all.
  - **Zero sudo access**: failed in ~0.2 seconds — confirmed no hang — but surfaced a **fourth**,
    previously-unseen "no access" message: `sudo: I'm sorry the no-sudo-access test account. I'm afraid I can't do
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
  `sudo: interactive authentication is required` for `the NOPASSWD sudo test account` even though `sudo -n -l`/`sudo -n
  whoami`/`sudo -n awk ...` all succeeded correctly for that same account in the same session. This
  would have logged a false "elevation not established" warning on every `NOPASSWD`-only computer
  despite every real command succeeding. Fixed by checking with `sudo -n true` (a trivial no-op
  command) instead of `-v`.
- **Verified end-to-end across all three sudo states after both fixes**, using real accounts, no
  password ever displayed or logged:
  - **`NOPASSWD` (`the NOPASSWD sudo test account`)**: full data, no elevation warning (correctly not needed).
  - **Password-required (`the password-required sudo test account`), used as the actual connecting/SSH account for the first
    time** (previously only ever checked *as a `-U` target* by a different, already-NOPASSWD scanning
    account): `PasswordState = PasswordSet` for its own row, populated entirely via the newly-wired
    elevation - proof the mechanism works for an account with **zero** `NOPASSWD` rights of its own,
    not just ones that already had another path to elevation.
  - **Zero sudo access (`the no-sudo-access test account`)**: clean graceful degradation - both the "elevation not
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
  reading `sshd -T`'s effective value, tracked as a documented gap in `Claude_Docs\Planning_Open-Items.md`.
- Added `===SSHDT===` (`sudo -n sshd -T`), `===SHELLS===` (`/etc/shells`), and `===AUTHKEYS===` (a
  per-account `sudo -n test -s "$home/.ssh/authorized_keys"` loop, marker-delimited exactly like
  `SUDOUSER`/`UNIT`) to the combined remote command - all reusing the same sudo ticket Phase 3/4/5
  already establish, no new elevation mechanism needed.
- **Verified end-to-end with no new bugs** - the first clean implementation this session without a
  fix-it round. Confirmed against real, previously-known ground truth rather than just internally
  consistent output: `the NOPASSWD sudo test account` (`PasswordState = LockedNoHash`, no usable password) correctly shows
  `SshPasswordLoginPossible = False` and `SshKeyLoginPossible = True` - directly corroborated by this
  entire session's own use of `the NOPASSWD sudo test account`'s SSH key throughout. `the lab admin account` (`PasswordState = PasswordSet`,
  real password) correctly shows `SshPasswordLoginPossible = True` and `SshKeyLoginPossible = False` -
  matching Round 5's finding that `the lab admin account`'s `authorized_keys` exists but is empty. `root`
  (`PasswordState = SystemNoLogin`) and `daemon` (`nologin` shell) both correctly show `False` for
  both fields. Full scan (all phases together) still completes in ~2.8 seconds, no regressions.
- Both fields are populated as `$null` (not `False`) when the underlying data is unavailable (no
  sudo), confirmed live via the earlier zero-access-account test scenario, distinguishing "confirmed
  not possible" from "unknown" for a downstream consumer.
- This closes every item in the Linux design except `BadPasswordAttempts` (`faillock`).


## 11. Revision log

| Date | Change |
|---|---|
| 2026-09-16 | Initial draft — proposed design, nothing implemented yet. |
| 2026-09-16 | Replaced the `plink.exe`-based connectivity design with `Posh-SSH`, per explicit user direction. Installed the real module and verified its cmdlets/parameters/examples live (`New-SSHSession`, `Invoke-SSHCommand`, `Remove-SSHSession`, `New-SSHTrustedHost`) rather than relying on memory. Key finding: key-based auth needs far less new design than originally scoped — `Get-DiscoveryCredential`'s existing `PSCredential` shape already covers it, needing only an added `KeyFilePath` field, not a new resolver method. Also resolved: host-key trust is handled natively by `Posh-SSH` (`-AcceptKey` plus a persistent `$HOME\.poshss\hosts.json` store), eliminating the manual fingerprint-parsing retry logic the `plink` approach would have needed. Architecture updated to mirror `Export-LocalGroups.ps1`'s `RunspacePool`/retry/structured-error pattern directly. Not verified: actual command execution against a real SSH target — no SSH server was available in this environment, and enabling one for testing was treated as a decision to ask about rather than make unilaterally. |
| 2026-09-17 | With the user's approval, enabled Windows' OpenSSH Server on the development machine and ran a real end-to-end Posh-SSH test: key-based `New-SSHSession` connected, `Invoke-SSHCommand` executed a command and returned the expected `ExitStatus`/`Output`, `Remove-SSHSession` cleaned up. This closes the "not verified against a real target" gap for the Posh-SSH mechanism itself (the remote command's Linux-specific shell content is still unverified — see Section 10). Flagged a cleanup follow-up: a passphrase-less test key remains installed in `administrators_authorized_keys` on the dev machine. |
| 2026-09-17 | Cleaned up the Windows test key (user removed the `administrators_authorized_keys` entry; local key files deleted). Generated a new, persistent test keypair (`Secrets\aped-linux-test-key`) for a real Ubuntu VM the user set up specifically for this; the user supplied its address/username after installing the public key themselves. Ran the actual proposed `/etc/passwd`+`/etc/group` command against it for real — this caught a genuine bug in this document's design: `Invoke-SSHCommand`'s `.Output` is a `String[]` (one element per line), not a single string, which silently breaks a naive `-split`. Corrected Sections 4-5 to the array-index-slicing approach and confirmed it against real data (56 users, 87 groups, correct multi-member group parsing). This closes every remaining "not verified against a real target" item. |
| 2026-09-17 | Added sudo rights discovery and sudo-elevated command support to scope (Section 5a), per user direction — reversing this document's original "no sudoers enumeration in v1" non-goal. New phases (3 and 4) cover documenting sudo access (`LinuxSudoRights.csv`) and then using it. Verified live: an account with zero sudo rights (`the NOPASSWD sudo test account`) gets a clean, fast, no-password-prompt failure from `sudo -n -l` with a specific, parseable message; also confirmed `Invoke-SSHCommand`'s result exposes `.Error` (stderr). Not yet verified: passwordless (`NOPASSWD`) sudo, password-required sudo, and the proposed `echo password \| sudo -S` non-interactive password supply — none can be tested without the user granting a test account some form of sudo rights on the VM. Flagged the security tradeoff of that mechanism (password briefly visible on the target's own process list) as something to weigh against a `SUDO_ASKPASS` alternative before committing to it. |
| 2026-09-17 | User granted `the NOPASSWD sudo test account` `NOPASSWD` sudo rights on the test VM. Verified live: `sudo -n -l` now returns the granted rules (`ExitStatus = 0`, listing both `ALL` and `NOPASSWD: ALL`); `sudo -n whoami` elevates immediately with zero password prompt; `sudo -n cat /etc/shadow` succeeds, and a remote `awk` filter confirmed the "derive only specific non-sensitive fields, never pull raw shadow content back" approach end-to-end. This fully closes Phase 3/4's passwordless path. Only the password-required sudo case (and the `echo password \| sudo -S` supply mechanism it needs) remains unverified — requires the user to configure a password-required, not `NOPASSWD`, sudo rule on a test account. |
| 2026-09-17 | Ran a full, methodical Windows-parity comparison against the real VM (new Section 6a) to directly answer "can Linux match what the Windows tool collects?". Confirmed at or near parity: users/groups/membership plus, now that sudo rights exist, `Disabled`/`PasswordLastSet`/`PasswordNeverExpires`-concept/`BadPasswordAttempts` — moved these out of Section 6's earlier "gated on a later phase" framing since they're verified now. Confirmed real, permanent (not just unverified) differences: Linux groups have no `Description` field at all, `systemctl show`'s `User=` property is only populated for units that declare it (verified both ways: `systemd-resolved.service` populated, `ssh.service`/`cups.service` blank), and `lastlog`/`last` aren't installed on this VM at all. Identified a place Linux can exceed Windows: `ss -tlnp` returns every listening port and its owning process in one call, vs. Windows' one-port-at-a-time signature probe. Added Phase 5 (database/software/service-account detection) to the rollout and a corresponding open decision on its design shape — building blocks confirmed to exist, actual signature-matching design not yet worked out. |
| 2026-09-17 | Per user request, verified shell/password-state/SSH-login-eligibility/home-directory data. Refined `Disabled` into a full `/etc/shadow` field-2 classification (real hash / locked-with-hash / locked-no-hash / never-set / two distinct "system, no password" conventions), confirmed against real accounts including two conventions coexisting on one system. Confirmed `sudo -n sshd -T` (not grepping `sshd_config`) is the only reliable way to get effective `PasswordAuthentication`/`PubkeyAuthentication`/`PermitRootLogin`/etc. — several of these weren't explicitly set in this VM's config file at all, and `sshd -T` itself requires `sudo` (fails outright without it). Found a real, specific setting worth designing around: `permitrootlogin prohibit-password` (root: key only, never password). Confirmed checking another account's `authorized_keys` for `SshKeyLoginPossible` also needs `sudo` (a `.ssh` dir is `0700`); found `the lab admin account`'s exists but is empty. Used `the NOPASSWD sudo test account`'s own locked/no-password state, alongside its already-proven SSH-key access all session, as live proof that key-login and password-login eligibility are independent per-account facts. Documented that this entire attribute area depends on the scan account having `sudo` — without it, none of it is available. |
| 2026-09-17 | Per user request, extended sudo rights discovery (Section 5a) to cover every discovered account, not just the scan account's own. Verified `sudo -n -l -U <username>` works for checking another account's rights, correctly resolving group-based grants (`the lab admin account`, via the `sudo` group) without this design needing to separately cross-reference group membership. Found the "no access" message is worded differently for a `-U` check (`is not allowed to run sudo`) than a self-check (`Sorry, user X may not run sudo`) — both need recognizing. Found a genuinely PAM-relevant real result: `a lab service account with layered sudo rights`/`another lab service account with layered sudo rights` each hold a group-inherited `ALL` rule plus their own account-specific grant to run `/usr/bin/passwd` as anyone — i.e. reset any local account's password — confirming why the design preserves full rule text per account rather than a single flag. Also confirmed `/etc/sudoers`/`/etc/sudoers.d/*` are directly readable with `sudo` as a secondary, raw-rule/provenance source. Identified a stronger constraint than previously stated: checking other accounts' rights this way needs the scanning account to have *broad* sudo rights, not just some. |
| 2026-09-17 | Per user direction, decided Linux output (and input) files stay entirely separate from the Windows tool's — no shared filenames, no `Platform` column, resolving two long-standing open decisions. Designed Phase 5 in full (new Section 6b): `LinuxDatabases.csv`/`LinuxSoftware.csv` (systemd-unit-name signature matching, parallel to Windows' `DatabaseSignatures`/`SoftwareSignatures` shape, enriched via `systemctl show`, listening confirmed via one `ss -tlnp` capture per computer rather than a probe per signature) and `LinuxServiceAccounts.csv` (every non-`root` service account). Verified live before finalizing: `Description=` is a real, populated property for every service (confirmed `DisplayName` equivalent exists); `systemctl list-unit-files` (324 unit files) is the correct enumeration scope to match Windows' "every registered service" coverage, not `list-units` (222 — only ever-loaded units). Corrected the earlier "blank `User=` is an unclear gap" framing to what it actually is: a determinate default (`root`), handled with the same noise-filtering rule Windows already applies to its own built-in identities. The starter `LinuxDatabaseSignatures` examples (PostgreSQL/MySQL/MariaDB/MongoDB unit names) are explicitly flagged as unverified, since the test VM has no database engine installed to check them against. |
| 2026-09-17 | The user reported PostgreSQL on the test VM "keeps stopping" and asked for it to be investigated. Found no actual problem: `NRestarts=0`, `Result=success`, only one stop/start cycle in the entire journal, a clean "received fast shutdown request" with zero errors/OOM kills, and `/var/log/apt/history.log` confirming the one restart was triggered by a routine `apt upgrade` that updated the `postgresql-18` package — not a crash loop. With a real engine now available, closed Phase 5's last open item by testing the actual `LinuxDatabaseSignatures` design against it: the `postgresql*` unit-pattern match, `systemctl show` enrichment, and `ss -tlnp` listening confirmation all worked (`postgresql@18-main.service`, port 5432, owning process `postgres`). This also **caught a real bug in the design's own service-account resolution**: `systemctl show`'s `User=` for `postgresql@18-main.service` was blank (which the existing rule would have classified as `root` and excluded), but the actual running process is owned by `postgres` — `pg_ctlcluster` starts as root and drops privileges internally, the same pattern already seen with `sshd`. Corrected Section 6b: `ServiceAccountName` must be resolved from the actual process owner (via `ss -tlnp`'s process-owner field, or `ps -o user= -p <MainPID>`), not read directly from `systemctl show`'s `User=` property. Also found `systemctl list-unit-files` alone misses instantiated template units (it shows only the `postgresql@.service` template, never `postgresql@18-main.service`) — enumeration needs `list-units` too. Found a fifth `UnitFileState` value, `enabled-runtime`, beyond the four confirmed earlier. |
| 2026-09-17 | Per user request to add concurrency "like the windows scanner," built the first real implementation: `Export-LocalLinuxGroups.ps1` and `Modules\LocalLinuxComputerScanner.psm1` (Phases 1-3, plus the `/etc/shadow`-derived half of Phase 4), following this document's already-settled design exactly — `RunspacePool` sized by `MaxConcurrency` (resolving Section 10's `RunspacePool`-vs-`Posh-SSH`-native-throttling question in favor of `RunspacePool`), one combined marker-delimited remote command per computer, retry-with-backoff, `LinuxScanErrors.csv`. Verified live against the real test VM: correct output reproducing every previously-recorded finding (`the NOPASSWD sudo test account`'s `LockedNoHash`/`PasswordlessSomeOrAll` state, `a lab service account with layered sudo rights`/`another lab service account with layered sudo rights`'s layered `PasswordRequired` rules), and a dedicated concurrency test (3 simultaneous scans of the same host, all completing within the same second with correctly isolated per-runspace results, no cross-talk) confirming the `RunspacePool` design is both genuinely parallel and safe. Not yet implemented: `BadPasswordAttempts`, per-account SSH-login eligibility, Phase 5, and the password-required sudo password-supply mechanism — see Section 8. |
| 2026-09-17 | User resolved four outstanding open decisions in one pass (Round 9). Host-key trust default confirmed as-is (no change). Sudo credential source decided: reuse the login password when SSH auth is password-based, require an explicit `SudoCredentialSource`/`SudoCredentialParams` when it's key-based (Section 5a) — not yet coded, still blocked on the `echo \| sudo -S` vs. `SUDO_ASKPASS` choice and a password-required test account. Phase 5's port-table question decided: `ss -tlnp` now also drives detection on its own via a new `LinuxUnrecognizedListeningPorts.csv` (Section 6b) — design-only, Phase 5 has no code yet. SSSD/Winbind-joined hosts decided **and implemented**: still collect local users/groups/membership normally, but flag the computer via a new `DirectoryJoined` column on `LinuxLocalUsers.csv`/`LinuxLocalGroups.csv` (Section 3/6). Verified live against the real test VM — this caught a genuine false-positive trap: the VM's `/etc/nsswitch.conf` already lists `sss` in its `passwd`/`group` lines purely as a base-Ubuntu-image artifact, with `sssd` never actually active and no `sssd.conf` present at all; trusting `nsswitch.conf` alone would have wrongly flagged this non-joined VM as directory-joined. The actual check (`sssd` active AND a real `sssd.conf` present, or `winbind` active) correctly returned `DirectoryJoined = False` for all 57 users/88 groups; a full re-run confirmed no regression to any previously-verified field. Created `Claude_Docs\Planning_Open-Items.md` to track this project's full remaining backlog (across AD, Windows, and Linux) in one place, per user request, rather than leaving it scattered across each design doc's own Section 10. |
| 2026-09-17 | After rebooting to finish installing the real CyberArk Credential Provider, the user configured two real CP test accounts and asked for CP retrieval to be tested (Round 10): `the password-required sudo test account` (full `ALL` sudo, password-required) and `the no-sudo-access test account` (no sudo access), both under Safe `the test CyberArk safe`, AppID `the test AppID`. **Found and fixed a real, significant bug in `Modules\CredentialResolver.psm1`**: `CLIPasswordSDK.exe`'s `/o` output is a plain comma-separated list of values in the requested field order (e.g. `ThisIsMy_FAKE_Password6!,the password-required sudo test account`), never `Key=Value` pairs as `Get-CredentialFromCP` had assumed — that assumption had never been exercised against a real Credential Provider before and would have thrown "did not return a Password value" on every real call. Fixed by requesting `Password` and `PassProps.UserName` via two separate single-field calls, avoiding any risk of a comma inside the password itself being misread as a field separator. Also corrected the default `ClipasswordsdkPath` to the real confirmed install location (`C:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe`, 64-bit `Program Files`, not `Program Files (x86)`). Verified the fix live for both accounts (password + username retrieved correctly, secret never displayed), then verified a real SSH connection using the CP-retrieved password. Used `the password-required sudo test account` to close Phase 3's last gap: observed the password-required `sudo -n -l` self-check message for the first time (`sudo: interactive authentication is required`, a third distinct pattern), and — more importantly — confirmed the tool's actual mechanism (`sudo -n -l -U the password-required sudo test account`, run by the broad-sudo scanning account) correctly returns a no-`NOPASSWD` rule that `ConvertTo-LinuxSudoAccess` classifies as `PasswordRequired`, reproduced in a real `Export-LocalLinuxGroups.ps1` run. `the no-sudo-access test account` independently re-confirmed `SudoAccess = None`. Still not done: the actual `echo password \| sudo -S` elevation mechanism itself, pending the still-open askpass-vs-echo decision. |
| 2026-09-17 | User asked what `SUDO_ASKPASS`'s limitations are. Rather than answer from general knowledge alone, investigated it live against the real test VM using `the password-required sudo test account`'s real CyberArk-retrieved password (never displayed or logged). Found: no askpass helper exists on the VM by default (would need to deploy one to every target); `SUDO_ASKPASS` does nothing without an explicit `-A` flag on every call (confirmed: `A terminal is required to authenticate` without it); it does work correctly in this tool's actual no-tty single-command execution context once wired up; a missing helper fails cleanly and fast; a wrong password triggers sudo's normal 3-attempt retry loop, re-invoking the helper each time; and the mechanism only *relocates* the exposure (`/proc/<pid>/environ` vs. `ps aux`) rather than eliminating it, subject to the same `hidepid` caveat already noted for `echo \| sudo -S`. Recorded a net assessment in Section 5a leaning toward `echo \| sudo -S` as the lower-complexity choice, while leaving the final decision itself to the user. |
| 2026-09-17 | User reviewed Section 5a and decided: `echo \| sudo -S`, calling it "the only universal one" — `SUDO_ASKPASS` needs a helper file pre-staged on every target, which isn't guaranteed, so it fails the "works everywhere" bar `echo \| sudo -S` meets. Verified this live (Round 11) across all three sudo states using real accounts, never displaying any password: password-required (`the password-required sudo test account`) succeeds with the correct password and fails cleanly with the wrong one, in a single attempt (fewer than `SUDO_ASKPASS`'s three); `NOPASSWD` (`the NOPASSWD sudo test account`) succeeds even when fed a completely irrelevant piped value, confirming the same invocation is safe to use unconditionally; zero sudo access (`the no-sudo-access test account`) fails in ~0.2 seconds with no hang, surfacing a fourth, previously-unseen "no access" message from sudo's `insults` plugin — flagged as a quirk specific to this test VM's config, not general sudo behavior. This closes the mechanism-choice decision and its safety verification; wiring `echo \| sudo -S` into `Modules\LocalLinuxComputerScanner.psm1` itself remains the next implementation step. |
| 2026-09-17 | Per user request ("Wire" the elevation mechanism), implemented `echo \| sudo -S` in `Modules\LocalLinuxComputerScanner.psm1` (Round 12). Refined the design first: a single `sudo -S -p '' -v` ticket refresh at the top of the combined remote command (verified live to let every subsequent `sudo -n` call succeed for the rest of that script's run) replaces piping the password before every individual `sudo -n` call, cutting the exposure window from once-per-account to once-per-computer. Found and fixed two real bugs while testing: (1) a `Mandatory [string[]]` parameter throws a misleadingly-worded "empty string" error for the whole array if any element is blank/null - never surfaced before since this is the first command whose success case produces zero output; fixed with `AllowEmptyString`/`AllowNull`. (2) `sudo -n -v` does not honor `NOPASSWD` the way an actual exempted command does, which would have logged a false "elevation not established" warning on every `NOPASSWD`-only computer; fixed by checking with `sudo -n true` instead. Verified end-to-end across all three sudo states with real accounts: `NOPASSWD` (`the NOPASSWD sudo test account`) unaffected, password-required (`the password-required sudo test account`, used as the connecting account for the first time rather than only a `-U` target) now returns fully populated data via real elevation, and zero access (`the no-sudo-access test account`) degrades gracefully with correct warnings and blank fields. The `SudoCredentialSource` override path for key-based auth is implemented but not separately verified live (no matching test scenario exists yet). |
| 2026-09-17 | Per user request ("do Phase 5"), implemented `LinuxDatabases.csv`/`LinuxSoftware.csv`/`LinuxServiceAccounts.csv`/`LinuxUnrecognizedListeningPorts.csv` (Round 13). Investigated whether a single `systemctl show <all units>` call could replace one call per unit, and found a real, serious bug at real scale: it silently aborts after only a couple of units when one of them (a bare template like `alsa-card-wait@.service`) isn't individually queryable, producing ~16 lines instead of ~2,300. Also found the root cause was compounded by a second bug: `systemctl list-units`' default output prefixes a failed unit's row with a UTF-8 status bullet that `awk '{print $1}'` misreads as the unit name. Fixed both by reverting to a per-unit loop with `===UNIT:<name>===` markers (mirroring the already-proven `SUDOUSER` pattern - confirmed resilient and fast: 353 real units in ~1.7 seconds) and adding `--plain` to `list-units`. Simplified the service-account-resolution design from the originally-proposed `ss -tlnp`-process-owner-or-`ps`-by-MainPID dual path down to `ps`-by-MainPID alone, confirmed live to already resolve `postgresql@18-main.service` correctly to `postgres` (MainPID **is** the real worker process, not `pg_ctlcluster`'s launcher) and to work uniformly for listening and non-listening services alike. Verified end-to-end against real PostgreSQL, Docker, CUPS, and OpenSSH on the test VM - correct signature matches, correct service-account resolution, correct `Listening` values, and `LinuxUnrecognizedListeningPorts.csv` correctly shrinking as more signatures were added. A full scan (all phases together) completes in ~2.3 seconds against the real VM. This closes every item in the Linux design except `BadPasswordAttempts` and per-account SSH-login eligibility. |
| 2026-09-17 | Per user request ("do... Per-account SSH"), implemented `SshPasswordLoginPossible`/`SshKeyLoginPossible` on every `LinuxLocalUsers.csv` row (Round 14) - the first clean implementation this session with no bugs found. Resolved Section 10's open question by folding it into the main scan (not a separate phase) and simplifying `AuthorizedKeysFile` handling to only the default `~/.ssh/authorized_keys` path rather than reading `sshd -T`'s effective value, tracked as a documented gap. Reused the existing sudo elevation for `sudo -n sshd -T` (effective config) and a per-account `sudo -n test -s` loop. Verified against real, previously-known ground truth: `the NOPASSWD sudo test account`'s `SshKeyLoginPossible = True` (directly corroborated by this session's own SSH key usage all along) and `the lab admin account`'s `SshKeyLoginPossible = False` (matching Round 5's finding that its `authorized_keys` exists but is empty) both came back correct on the first try, along with `root`/`daemon` correctly showing `False` for both fields. This closes every item in the Linux design except `BadPasswordAttempts`. |
