# Local Linux Discovery — Sudo Rights Discovery & Elevation

> Split out of `Design_Local-Linux-Discovery.md` (formerly Section 5a) because that doc was over 1,000 lines. See that doc for overall status/context.

---

## 5a. Sudo rights discovery and elevation (added 2026-09-17, per user direction)

Two related but distinct needs: (1) **document** each scanned account's sudo rights as a data point
in its own right (mirrors the Windows tool's service-account discovery — "what elevated access does
this account actually have"), and (2) **use** sudo when a later phase needs an elevated read (e.g.
`/etc/shadow` for password-aging fields), including supplying a password non-interactively when the
account's sudo rule requires one.

**Verified live against the real test VM, "no access" case (`the NOPASSWD sudo test account`, before it had any sudo
rights):**
- `sudo -n -l` (non-interactively, list rights) exits `1` with `stderr`: `sudo: Sorry, user the NOPASSWD sudo test account
  may not run sudo on the lab test VM.` — **no password prompt at all** when there's no
  matching sudoers rule; sudo fails fast instead of asking. This message is a clean, reliable pattern
  to detect the "no sudo access whatsoever" case (`ExitStatus = 1` and this specific text on
  `.Error`).
- Confirmed `Invoke-SSHCommand`'s result object also has an `.Error` property (stderr), alongside the
  already-known `.Output`/`.ExitStatus` — useful here since sudo's rights-check messages land on
  stderr, not stdout.

**Verified live, passwordless (`NOPASSWD`) case (2026-09-17, after the user granted `the NOPASSWD sudo test account`
`NOPASSWD` sudo rights):**
- `sudo -n -l` now exits `0` and prints the granted rule(s) as plain text:
  ```
  User the NOPASSWD sudo test account may run the following commands on the lab test VM:
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
CyberArk CP test account (`the password-required sudo test account`, Safe `the test CyberArk safe`) with full (`ALL`) sudo rights but no
`NOPASSWD` grant. Two things confirmed:
- **Self-check, `sudo -n -l` run as `the password-required sudo test account` itself** (via a real SSH session authenticated with
  the CP-retrieved password): `whoami` → `the password-required sudo test account`; `sudo -n -l` → `ExitStatus = 1`, output
  `sudo: interactive authentication is required` — a **third**, distinct message pattern, different
  from both the self-check "no access" case (`Sorry, user X may not run sudo`) and the `-U`-check "no
  access" case (`is not allowed to run sudo`).
- **The actual mechanism this tool uses, `sudo -n -l -U the password-required sudo test account` run by the already-broad-sudo
  scanning account (`the NOPASSWD sudo test account`)**: `ExitStatus = 0`, output `User the password-required sudo test account may run the following
  commands on the lab test VM:\n    (ALL : ALL) ALL` — a rule with **no** `NOPASSWD` keyword,
  which `ConvertTo-LinuxSudoAccess` (`Modules\LocalLinuxComputerScanner.psm1`) correctly classifies as
  `PasswordRequired` (confirmed by re-running `Export-LocalLinuxGroups.ps1` for real: `the password-required sudo test account`'s
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
`the password-required sudo test account`'s real CyberArk-retrieved password, never displayed or logged:**
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
- **Password-required (`the password-required sudo test account`)**: `echo "$REALPW" | sudo -S -p '' whoami` → `root`, exit `0`.
  A wrong password → one clean `sudo: Authentication failed, try again.` then `Authentication
  required but not attempted`, exit `1` — and notably **only one retry attempt**, not
  `SUDO_ASKPASS`'s three, since piped stdin has only one line to offer before EOF; `echo | sudo -S`
  fails faster on a wrong password than the askpass alternative did.
- **`NOPASSWD` (`the NOPASSWD sudo test account`)**: piping a completely irrelevant/garbage value via `-S` still succeeds
  immediately (`root`, exit `0`) — sudo simply never reads stdin when `NOPASSWD` already applies.
  This means the *same* `echo | sudo -S` invocation is safe to use unconditionally, without first
  detecting whether an account actually needs a password.
- **Zero sudo access (`the no-sudo-access test account`, connected to and running the command as itself)**: `echo
  'garbage' | sudo -S -p '' whoami` failed in ~0.2 seconds (confirmed no hang) — but with a **fourth**
  distinct "no access" message pattern never seen before: `sudo: I'm sorry the no-sudo-access test account. I'm
  afraid I can't do that`. This is `sudo`'s `insults` plugin (`Defaults insults` in `/etc/sudoers`) —
  **a real, environment-specific quirk of this particular test VM's sudoers config, not a universal
  sudo behavior** — most systems don't have it enabled, so don't assume this exact wording elsewhere.
  It doesn't need separate handling regardless, since error detection here only needs "did the
  command succeed," not pattern-matching the specific failure text.
This confirms the mechanism is safe to build: no hang risk in any of the three states, and no
pre-staging requirement on the target. **Not yet wired into `Modules\LocalLinuxComputerScanner.psm1`**
— this was mechanism verification, not implementation; see `Claude_Docs\Planning_Open-Items.md`.

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
to `sudo` (`echo | sudo -S` vs. a `SUDO_ASKPASS` helper — still open, see Section 10/`Claude_Docs\Planning_Open-Items.md`)
and having a real password-required test account to verify against (also still needed).

**Checking every discovered account's sudo rights, not just the scan account's own — verified live
(2026-09-17).** The original tests above only ever checked `the NOPASSWD sudo test account`'s *own* rights (plain
`sudo -n -l`, no target specified). Per the user's follow-up request, this needs to cover every
account this tool discovers via `/etc/passwd`, which is a different sudo feature:

- **`sudo -n -l -U <username>`** lists *another* account's effective rights. Verified against three
  real accounts on the test VM:
  - `sudo -n -l -U the lab admin account` → `User the lab admin account may run the following commands on the lab test VM:
    (ALL : ALL) ALL` (`the lab admin account` is a member of the `sudo` group — see the earlier `/etc/group` dump —
    so this rule comes from the group-based `%sudo ALL=(ALL:ALL) ALL` line in `/etc/sudoers`, not a
    per-user rule; `sudo -l -U` correctly resolves that for you rather than requiring this design to
    separately cross-reference group membership itself).
  - `sudo -n -l -U daemon` → `User daemon is not allowed to run sudo on the lab test VM.` —
    **the "no access" message is worded differently here than the self-check case** (`is not
    allowed to run sudo` vs. the self-check's `Sorry, user X may not run sudo`) — both patterns need
    recognizing as "no access", not just one.
  - `sudo -n -l -U a lab service account with layered sudo rights` → **two rules at once**: `(ALL : ALL) ALL` (via `sudo` group
    membership, password-required — the base `/etc/sudoers` grants no `NOPASSWD` for that group) and
    `(ALL : ALL) /usr/bin/passwd` (a narrow, account-specific grant from its own
    `/etc/sudoers.d/a lab service account with layered sudo rights` file: `a lab service account with layered sudo rights ALL=(ALL:ALL)/usr/bin/passwd`). Confirmed the
    identical pattern for `another lab service account with layered sudo rights`. **This is genuinely PAM-relevant, real data**: these two
    accounts are individually, explicitly granted the ability to run `/usr/bin/passwd` as any user —
    i.e. reset any local account's password — which is exactly the kind of specific elevated
    capability a security team needs visibility into, and exactly why preserving the *full* rule
    text per account (not collapsing to one yes/no flag) matters.
- **A real constraint this uncovers**: listing *another* user's sudo rights this way requires the
  *scanning* account to itself have broad (`ALL`) sudo rights — `daemon`'s and `a lab service account with layered sudo rights`'s
  rights were only visible because `the NOPASSWD sudo test account` already has `NOPASSWD: ALL`. An account with only a
  narrow sudo grant (like `a lab service account with layered sudo rights` itself) likely could not run `sudo -l -U` for other
  accounts at all. This is a stronger requirement than "the scan account needs *some* sudo" (Section
  5a's earlier framing) — it needs broad rights specifically, to be useful for this particular check.
- **A complementary, secondary source: `/etc/sudoers` and `/etc/sudoers.d/*` directly.** Both are
  readable with `sudo` (confirmed: `/etc/sudoers` is `-r--r-----`, per-file entries in
  `/etc/sudoers.d/` are `-rw-r-----`, all `root`-owned — a plain user can't read them, `sudo cat`
  can). This shows the *raw configured* rule text and which file it came from (e.g. `the NOPASSWD sudo test account`'s own
  grant is visible verbatim: `the NOPASSWD sudo test account ALL=(ALL:ALL) NOPASSWD: ALL`, in its own
  `/etc/sudoers.d/the NOPASSWD sudo test account` file) — useful for audit/provenance ("where did this rule come from"),
  but doesn't resolve group-based grants the way `sudo -l -U` already does. Proposed as a secondary,
  optional source, not the primary mechanism.

**Output** (implemented as `LinuxSudoRights.csv`): `ScanTimestamp`, `ComputerName`, `UserName`,
`SudoAccess` (`None` / `PasswordlessSomeOrAll` / `PasswordRequired` — classify by checking the
`-U` output for the literal substring `NOPASSWD`; all three category boundaries now confirmed against
real accounts, including a genuinely password-required one — see Round 10), `RawSudoListOutput` (the full rule
text for that account, since — as `a lab service account with layered sudo rights` shows — an account can have multiple distinct
rules at once that a single flag would flatten away). Collected via one remote command that loops
over every discovered `/etc/passwd` account and runs `sudo -n -l -U "$user"` for each, rather than
one round-trip per account.

