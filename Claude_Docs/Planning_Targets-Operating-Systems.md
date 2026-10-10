# Target research: enterprise operating systems

> **Stage: Planning.** Research on discovering local and privileged accounts on enterprise operating systems. Each section covers what to collect, how, with what least-privilege access, and the security practices to follow. Windows and Linux are built today; the rest are research only. Coverage status: [Planning_Target-Coverage.md](Planning_Target-Coverage.md). Questions referenced as (Qnn) are in [Planning_Questions.md](Planning_Questions.md).

**Researched:** 2026-10-09

## Common approach

- **Collector model:** for Unix-like systems, a POSIX `sh` collector sent over SSH stdin and run in memory (see [Planning_Collector-Architecture.md](Planning_Collector-Architecture.md)). Windows uses WinRM/JEA where allowed, with today's SMB/ADSI scan as the fallback. Mainframe and IBM i use their own native mechanisms (Sections 5–6).
- **What to collect everywhere:**
  - local accounts and their state (enabled, locked, password age, never expires);
  - local groups and members;
  - **who can act as administrator**: sudo/RBAC rules, admin group members, special authorities;
  - service and run-as accounts;
  - which accounts can log on remotely (SSH, RDP).
- **Elevation:** read-only, and limited to a published list of commands. On Unix, sudoers `NOPASSWD` limited to exactly the collector's commands is the least-privilege option. It also avoids sending a password at all (security brief F1).
- **Never return:** password hashes, private keys, or file contents beyond what's needed. Classify on the target and send back state names.

## 1. Windows (built)

| Item | Detail |
|---|---|
| Collect | Local users, groups and members (Administrators, Remote Desktop Users, Remote Management Users, Backup Operators, Hyper-V Administrators); services and their run-as accounts; LAPS status; scheduled-task run-as accounts (not collected today). |
| Today | ADSI WinNT over SMB 445 (remote SAM). Needs local Administrator on targets (security brief F4). |
| Option | A collector over **WinRM HTTPS (5986) into a JEA endpoint**, whose role capability allows only `Get-LocalUser`, `Get-LocalGroupMember`, `Get-CimInstance Win32_Service`, `Get-ScheduledTask`. It runs as a virtual account on the target, so the scan identity doesn't need to be a local administrator, and JEA transcripts audit every session (Q72). |
| Security practices | A domain scan account (local accounts are filtered by UAC remote restrictions); Kerberos; HTTPS-only WinRM; the JEA endpoint limited to the scan group. |
| Pitfalls | Since Windows 10 1607 / Server 2016, remote SAM enumeration is limited to Administrators by default. WinRM needs enabling and firewall rules on every target. Domain-group members of local groups need resolving against AD (join with the AD export). |

## 2. Linux (built: RHEL and clones, Ubuntu/Debian, SUSE, Amazon Linux, Oracle Linux)

| Item | Detail |
|---|---|
| Collect | Built today: `/etc/passwd`, `/etc/group`, password state (classified on the target), sudo rights per account, SSH login eligibility, faillock counts, services and run-as accounts, listening ports. Add: `/etc/sudoers.d` raw rules, SSSD/IdM-sourced sudo (via the directories doc), `authorized_keys` key counts and `from=` restrictions, and `AllowUsers`/`AllowGroups` in sshd. |
| Method | SSH; a POSIX `sh` collector over stdin (Section "Common approach"). |
| Distribution differences | PAM lockout: `pam_faillock` (RHEL 8+, newer Ubuntu/SUSE) vs `pam_tally2` (older). The admin group is `wheel` (RHEL/SUSE) vs `sudo` (Debian/Ubuntu). systemd everywhere current. SELinux (RHEL) or AppArmor (Ubuntu) can block some reads under confined sudo. |
| Least privilege | sudoers `NOPASSWD` limited to the collector's read commands (`cat /etc/shadow` isn't needed; `awk` over shadow is, along with `sudo -l -U`, `ss`, `sshd -T`, `faillock`). |
| Pitfalls | Directory-joined hosts (SSSD, Winbind) mix local and directory accounts; flagged today by `DirectoryJoined`. Containers and minimal images may lack tools such as `ss` or `sudo`. |

## 3. Unix

### 3.1 IBM AIX

| Item | Detail |
|---|---|
| Collect | Users (`lsuser -a id pgrp groups admin login rlogin account_locked ALL`); groups (`lsgroup ALL`); **RBAC roles** (`lsrole ALL`, and each user's `roles`); sudo if installed. |
| Specifics | AIX keeps user attributes in `/etc/security/user` and passwords in `/etc/security/passwd` (not `/etc/shadow`). `admin=true` users can only be changed by root. Enhanced RBAC roles (for example `isso`, `so`, `sa`) grant admin rights without sudo. |
| Least privilege | `lsuser` shows full attributes only to roles with `aix.security.user.audit`. An RBAC role with that authorization is cleaner than sudo. |
| Collector | POSIX `sh`, with AIX-specific commands; ksh is the default shell. |

### 3.2 Oracle Solaris 11

| Item | Detail |
|---|---|
| Collect | Users and groups; **RBAC**: `/etc/user_attr` (roles, rights profiles, authorizations), `prof_attr`, `exec_attr`, `policy.conf`; `root` is a **role** by default in Solaris 11, so record who can assume it (`roles` per user). |
| Commands | `getent user_attr`, `profiles <user>`, `roles <user>`. |
| Least privilege | A rights profile containing only the needed read commands, assigned to the scan account. |

### 3.3 HP-UX (legacy)

| Item | Detail |
|---|---|
| Collect | Users and groups; in **trusted mode**, password and lock state in `/tcb/files/auth/<letter>/<user>` instead of `/etc/shadow`; sudo if installed. |
| Notes | End of life; low priority unless present (Q82). Check trusted mode first (`/tcb` exists). |

## 4. macOS

| Item | Detail |
|---|---|
| Collect | Local users (`dscl . -list /Users UniqueID`, excluding IDs under 500), **admin group** members (`dscl . -read /Groups/admin GroupMembership`, GID 80), account policy and lock state (`pwpolicy`, `accountPolicyData`), SSH (Remote Login) and Screen Sharing access groups. |
| Method | SSH collector, if Remote Login is enabled, **or** the MDM's API (Jamf Pro, Intune), which already inventories local admins without opening SSH (Q83). |
| Pitfalls | Remote Login is off by default; a mobile fleet is often offline. MDM data is usually the more practical source. |

## 5. Mainframe (IBM z/OS)

| Item | Detail |
|---|---|
| Security managers | **RACF** (IBM), **CA ACF2** and **CA Top Secret** (Broadcom). Which one is installed decides everything (Q78). |
| Collect (RACF) | Users with **SPECIAL**, **OPERATIONS** or **AUDITOR** (system-wide or group-level); users with UID 0 in OMVS segments; `FACILITY`/`SURROGAT` profiles granting identity switching; revoked state and password intervals. |
| Method options | (a) The **IRRDBU00** unload utility, run as a scheduled batch job, produces a flat file of every profile; a filtered extract (privileged users only) is sent to the scanner, CMS-encrypted to its certificate (collector architecture layer 3). (b) **z/OS LDAP SDBM** read-only queries of RACF users and groups. (c) A REXX/TSO collector over SSH (z/OS UNIX). |
| Recommended | (a): it's what mainframe security teams already use for audits, and it needs no interactive access. |
| Least privilege | The unload runs under a batch ID with read access to the RACF database (or a copy of it); the scanner only receives the extract. |
| ACF2 / Top Secret | Equivalents: ACF2 `LIST LIKE(-)` reports and logonid privileges (`SECURITY`, `NON-CNCL`, `ACCOUNT`); Top Secret `TSS LIST(ACIDS)`, with `CONSOLE`, `ADMIN` and `MASTER` ACIDs. Same batch-extract model. |

## 6. IBM i (AS/400)

| Item | Detail |
|---|---|
| Collect | User profiles with special authorities, especially `*ALLOBJ` and `*SECADM` (and `*AUDIT`, `*IOSYSCFG`, `*SERVICE`, `*SPLCTL`), including those inherited from group profiles; status; password expiration; default-password profiles. |
| Method | SQL over DRDA/ODBC: `SELECT AUTHORIZATION_NAME, SPECIAL_AUTHORITIES, STATUS FROM QSYS2.USER_INFO`. Or `PRTUSRPRF TYPE(*AUTINFO)`. |
| Least privilege | Reading `QSYS2.USER_INFO` needs `*SECADM`, or function usage `QIBM_DB_SECADM` granted to the scan profile. That's narrower than giving it `*SECADM`. |
| Pitfalls | `USER_DEFAULT_PASSWORD` is visible only with `*ALLOBJ` plus `*SECADM`, so leave it out rather than over-privilege the scan profile. |

## Sources

- [IBM: lsuser command](https://www.ibm.com/docs/ssw_aix_72/l_commands/lsuser.html)
- [IBM Community: AIX advanced RBAC](https://community.ibm.com/community/user/blogs/christian-sonnemans1/2024/08/03/aix-advanced-rbac-part-2)
- [Oracle: Solaris 11 RBAC reference](https://docs.oracle.com/cd/E23824_01/html/821-1456/rbacref-6.html)
- [HPE community: HP-UX trusted mode TCB files](https://community.hpe.com/t5/operating-system-hp-ux/update-of-tcb-auth-files/m-p/4322071)
- [Level: macOS get local admins](https://level.io/library/scripts/script-macos-get-local-admins)
- [IBM: RACF utilities for auditors](https://public.dhe.ibm.com/s390/zos/racf/pdf/r16_RACF_Utilities_for_Auditors.pdf)
- [MC Press: IBM i user profile management](https://mcpressonline.com/security/ibm-i-os400-i5os/modernize-your-ibm-i-user-profile-management)
- [Microsoft Learn: Just Enough Administration](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview)
- [jdhitsolutions: local administrators with WMI/CIM](https://jdhitsolutions.com/blog/scripting/1532/get-local-administrators-with-wmi-and-powershell/)
