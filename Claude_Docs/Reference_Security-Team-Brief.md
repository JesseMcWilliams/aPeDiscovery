# aPeDiscovery: security team brief

> **Stage: Reference.** For the security team: what aPeDiscovery does, which accounts and privileges it uses, how it handles credentials and data, what its activity looks like to monitoring tools, and its known risks. Keep it current: any change to accounts, data collected, credential handling or target-side activity updates this file in the same change. Network detail is in [Reference_Network-Firewall-Requirements.md](Reference_Network-Firewall-Requirements.md); host setup is in [Reference_Scanning-Host-Requirements.md](Reference_Scanning-Host-Requirements.md).

**Last updated:** 2026-10-09

## 1. What it is

PowerShell scripts, run as scheduled tasks on one Windows **scanning host**, that inventory accounts for CyberArk privileged access onboarding:

- **Active Directory:** users (including service accounts and gMSAs), groups and memberships, and computers, across one or more domains, including domains with no trust to the scanning host's domain.
- **Windows computers:** local users, local groups and members, services and the accounts they run as, and known database software.
- **Linux computers:** local users and groups, sudo rights, password state, SSH login eligibility, failed-login counts, services and listening ports.

Results go to CSV files today. A local SQLite database is planned (Phase 1), feeding CSV exports and, later, a database import and a web interface.

**It's read-only.** It doesn't create, change or delete anything on targets, in AD or in CyberArk. The two side effects on targets are in [Section 5](#5-what-it-leaves-on-targets).

## 2. Accounts and privileges

| Account | Used for | Privilege needed | Notes |
|---|---|---|---|
| **Task account** (for example `svc-apediscovery`) | Runs the scheduled tasks on the scanning host | Local logon as a batch job on that host only; read/write on its own folders | Needs no rights on targets when every target uses a CyberArk or file credential. |
| **AD scan identity**, one per domain | Querying AD | Ordinary domain user (read) | Some planned attributes are often restricted and may need delegated **read**: LAPS expiration dates (never the passwords), `msDS-User-Account-Control-Computed`, `msDS-GroupMSAMembership`. |
| **Windows scan identity**, per target | Reading local users, groups and services over SMB | **Local Administrator** on each target | Windows only lets administrators list local accounts remotely (Windows 10 1607 / Server 2016 and later). A domain account in the local Administrators group is preferred; local accounts face extra remote restrictions. |
| **Linux scan identity**, per target | SSH login and reading account data | SSH login, plus **sudo** to read `/etc/shadow` and to run `sudo -l -U`, `ss -tlnp`, `sshd -T` and `faillock` | Works without sudo, with those fields left blank. A `NOPASSWD` rule limited to those commands is the least-privilege option, and avoids the password exposure in [Section 7](#7-known-risks-and-open-findings) (F1). |

Recommendation: keep each scan identity in CyberArk, used only by aPeDiscovery, and restricted to logging on from the scanning host where the platform supports it.

## 3. Credential handling

- **Credentials are fetched at run time from CyberArk** (Credential Provider, CCP or Conjur) through the aPeSecrets module, or from a file encrypted for one account on one machine (Windows DPAPI), or from Windows Credential Manager.
- **Configs hold only pointers** (AppID, Safe, Object, file path), never passwords.
- **Credentials stay in memory,** for the duration of one domain's or computer's scan.
- **Logs mask secrets.** The logging module (LogaPe) writes text like `password=...`, `token: ...` or `apikey=...` as `***` in log files and on the console. Code review rule: never log a credential.
- **Never collected,** enforced in code: LAPS passwords (`ms-Mcs-AdmPwd`, `msLAPS-Password`, `msLAPS-EncryptedPassword`), gMSA passwords (`msDS-ManagedPassword`), `unicodePwd`.
- **Exceptions:** Linux password hashes and the Linux sudo password; see F1 and F2 in [Section 7](#7-known-risks-and-open-findings).

## 4. Activity that may trigger alerts

Most of this looks like attacker reconnaissance, because inventory and reconnaissance collect the same facts. Expect EDR, IDS and SIEM detections, and agree exceptions **scoped to the scanning host, the scan identities and the scheduled run windows**.

| Activity | Looks like | Where seen |
|---|---|---|
| LDAP queries (through AD Web Services) for `adminCount=1`, `servicePrincipalName=*`, delegation flags, nested group membership | AD reconnaissance tools (BloodHound/SharpHound), Kerberoasting target discovery. **No Kerberos service tickets are requested;** only the attributes are read. | DC logs, identity threat detection (for example Defender for Identity) |
| Remote listing of local users, groups and services over SMB, on many computers in a short time | Lateral-movement reconnaissance (`net user`/`net localgroup` style, SAM-R enumeration) | Target security logs, EDR, network IDS |
| SSH logins to many Linux hosts, each running one long command: `cat /etc/passwd /etc/group`, `sudo -l -U <every user>`, sudo reads of `/etc/shadow`, `ss -tlnp`, `sshd -T`, `faillock`, `systemctl show` | Linux privilege-escalation reconnaissance | auditd, EDR, `/var/log/secure` or `auth.log` |
| Connect tests to database ports (1433, 3306, 5432, 1521, 27017) | Port scanning | Network IDS, host firewalls |
| Many credential retrievals from CyberArk in a short window | Unusual vault access | CyberArk audit |

## 5. What it leaves on targets

| Target | Trace |
|---|---|
| AD | Logon and query events for the scan identity. |
| Windows | Logon events (network logon) for the scan identity. |
| Linux | SSH login and sudo entries in auth logs; a sudo authentication timestamp (when password-based sudo is used); the full remote command in any command auditing (see F1). |
| Scanning host | A Linux target's SSH host key is **recorded on first contact** when `AcceptNewHostKey` is true, the current default. See F3. |

## 6. Data collected and where it's kept

**Sensitivity:** the output is effectively a map of privileged access: privileged and service accounts, who can elevate where, unconstrained-delegation computers, accounts allowed weak encryption, and stale admin accounts. **Treat it as confidential.**

| Data | Location on the scanning host | Retention |
|---|---|---|
| CSV output | `OutputDirectory` from each config | Latest set, plus `ArchiveRetentionCount` timestamped copies (default 30) |
| Logs | `LogDirectory` | Per run; LogaPe rotation and retention as configured |
| SQLite store (Phase 1) | `Store.Path` in the general config | Current state, plus 90 runs of history by default (`KeepRuns`) |
| Configs | `Config\` | Pointers only, no secrets |

Required controls:
- NTFS permissions limiting all of the above to the task account and administrators (HR-DIR-03);
- the store's backups protected to the same level (HR-DIR-04);
- outputs handed to other systems over protected channels.

## 7. Known risks and open findings

| ID | Finding | Risk | Status / proposed fix |
|---|---|---|---|
| F1 | **The Linux sudo password is placed in the remote command line.** When a target needs password-based sudo, the password is embedded (base64, which is reversible) in the command sent over SSH. On the target, it's visible in the process list to other users for the few seconds the command runs, and it's captured verbatim by any command auditing (auditd execve rules, EDR command-line telemetry), so it can land in the SIEM. | High where password sudo is used | **Fixed, awaiting live verification** (merged to `main` 2026-10-10; LT-LNX-06 pending): the password now goes over the SSH command's stdin and is read by the shell, never placed in a command line. Scoped `NOPASSWD` rules remain the least-privilege option. |
| F2 | **Linux password hashes reach the scanning host.** To classify password state, the scanner reads `/etc/shadow` field 2 (the hash) through sudo, and classifies it on the scanning host. Hashes are never logged or written to disk, but they travel (inside SSH) and sit in memory. | Medium | **Fixed, awaiting live verification** (same branch, LT-LNX-06): `awk` on the target classifies field 2 and returns only the state name. |
| F3 | **SSH host keys are trusted on first use** (`AcceptNewHostKey` defaults to true), so a spoofed host on first contact would receive the scan credential. | Medium | **Fixed, awaiting live verification** (same branch, LT-LNX-07): `AcceptNewHostKey` defaults to false and unknown keys are refused; hosts are enrolled with `New-SSHTrustedHost` after a fingerprint check. |
| F4 | **The Windows scan needs local Administrator** on every target. | Inherent to remote local-account listing | Accepted. Use a dedicated, vaulted, rotated account. |
| F5 | **The Conjur credential source has never been tested** against a real Conjur. | Low | Live test LT-CRED-02 before production use. |
| F6 | **FIPS mode** is supported since the 2026-10-09 logging fix, but hasn't been run on a FIPS-enforced host. | Low | Test on a FIPS host. |
| F7 | **The CyberArk Credential Provider and PowerShell 7:** if an AppID authenticates the calling program by path or hash, moving from `powershell.exe` to `pwsh.exe` may need re-authorization. | Low (availability, not exposure) | Check during the PowerShell 7 rollout. |

## 8. Software supply chain

| Component | Source | Verification |
|---|---|---|
| aPeDiscovery, aPeSecrets, LogaPe (scripts) | Public GitHub repos (`JesseMcWilliams/*`), downloaded at a specific commit | The install script records the exact commit installed. Review changes before updating production. |
| PowerShell 7.6 | Microsoft's GitHub releases | The install script checks the SHA-256 that GitHub publishes, and Microsoft's Authenticode signature, before installing. |
| SQLite libraries (Phase 1) | nuget.org packages (Microsoft.Data.Sqlite 10.0.12, SQLitePCLRaw 2.1.12), stored in the repo | MIT and Apache-2.0 licenses; versions pinned in the repo. |
| Posh-SSH (Linux scans) | PowerShell Gallery, a community open-source module | Installed by name from the official gallery; pin the version for production. |
| ActiveDirectory module | Microsoft (RSAT Windows feature) | Installed through Windows. |

The install script also **removes the "downloaded from the internet" mark** (`Unblock-File`) from the repository files, so PowerShell will run them. That's expected; it's also why the source and commit checks above matter.

## 9. Checklist for the security team

- [ ] Approve the accounts and privileges in Section 2. For Linux, decide between scoped `NOPASSWD` and password sudo, given F1.
- [ ] Create EDR, IDS and SIEM exceptions for the activity in Section 4, scoped to host, accounts and schedule.
- [ ] Confirm data classification and the controls in Section 6.
- [ ] Decide whether F1–F3 must be fixed before production.
- [ ] Approve the software sources in Section 8.
