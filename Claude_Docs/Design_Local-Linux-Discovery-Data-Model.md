# Local Linux Discovery — Data Model, Parity & Phase 5 Design

> Split out of `Design_Local-Linux-Discovery.md` (formerly Sections 6, 6a, 6b) because that doc was over 1,000 lines. See that doc for overall status/context.

---

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
| `$6$...` (a real hash, no leading `!`) | Password set and usable | `the lab admin account`, the `CyberArk*` accounts |
| `!$6$...` (a real hash, leading `!`) | Had a password, then explicitly locked (`passwd -l`) | not observed on this VM, but a real, distinct sudo/passwd state |
| bare `!` | Locked, no hash ever set | `the NOPASSWD sudo test account` (see below) |
| `!!` | Password never set (fresh-account convention) | not observed on this VM |
| bare `*` | No password login intended (older/base-package convention) | `root`, `daemon`, `bin`, and other pre-installed base accounts |
| `!*` | No password login intended (systemd-sysusers convention) | `systemd-network`, `dhcpcd`, `messagebus`, and other systemd-created service accounts |

Two distinct "no password login" conventions (`*` vs. `!*`) coexist on the *same* system depending on
which tool created the account — both need recognizing, not just one.

**`the NOPASSWD sudo test account` itself is a live, already-proven example of the key point this whole area is about**:
its own password state is bare `!` (locked, no hash) — it has **no usable password at all** — yet
every command in this design has been executed *as* `the NOPASSWD sudo test account` all session, via SSH key auth. SSH
key eligibility and SSH password eligibility are independent per-account questions, not two views of
the same fact, and this is direct, lived proof of that, not just a theoretical claim.

**SSH login-method eligibility per account — implemented and verified live (2026-09-17, Round 14).
Columns `SshPasswordLoginPossible`/`SshKeyLoginPossible` on every `LinuxLocalUsers.csv` row:**
- **The authoritative source is `sshd -T`** (dumps sshd's *fully resolved* effective config,
  applying compiled-in defaults for anything not explicitly set in `sshd_config`) — **not** grepping
  `sshd_config` directly, which only shows explicit overrides and would silently miss anything
  running on a default. Confirmed live: `sshd -T` **requires `sudo`** — run as `the NOPASSWD sudo test account` without
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
  with `sudo`, it's readable (confirmed: `the lab admin account`'s exists but is **empty** — 0 lines — meaning
  `the lab admin account` has no key-based login configured at all, consistent with `the lab admin account` being a
  password-authenticating account instead).
  **Implementation-time simplification (2026-09-17, Round 14)**: rather than reading the
  `AuthorizedKeysFile` directive from `sshd -T`'s effective output (this design's original proposal,
  to correctly handle a site that customizes it), the actual code only checks the default
  `~/.ssh/authorized_keys` path (`sudo -n test -s "$home/.ssh/authorized_keys"`, one call per
  discovered account in the same marker-delimited loop pattern as `SUDOUSER`). This is a real,
  documented gap for any environment with a customized `AuthorizedKeysFile` directive — tracked in
  `Claude_Docs\Planning_Open-Items.md` rather than solved now, since generalizing it (multiple space-separated paths,
  `%h`/`%u` token substitution) adds real complexity for a case this test VM doesn't exercise.
- **Whether the account's shell can even run our discovery commands matters here too, not just
  whether it can get an *interactive* login.** `/etc/shells` lists the shells a distro considers valid
  logins (confirmed on this VM: `/bin/sh`, `/bin/bash`, `/bin/rbash`, `/usr/bin/dash`,
  `/usr/bin/screen`, and their `/usr/bin/` equivalents — notably **not** `/usr/sbin/nologin` or
  `/bin/false`). sshd execs a requested command through the account's configured shell even for a
  non-interactive `ssh user@host command` — a `nologin`/`false` shell refuses to run *any* command,
  including this project's own discovery commands, so a scan against such an account would fail
  regardless of what password/key auth allows. On the test VM, the human/service accounts of interest
  (`root`, `the lab admin account`, all `CyberArk*` accounts, `the NOPASSWD sudo test account`) all have a real shell (`/bin/bash` or
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
**verified**, including a real multi-member group (`sudo:x:27:the lab admin account,a lab service account with layered sudo rights,another lab service account with layered sudo rights`).
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

