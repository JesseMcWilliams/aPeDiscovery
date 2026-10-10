# Target research: enterprise directories (LDAP)

> **Stage: Planning.** Research on discovering privileged identities in enterprise directories. Each section covers what to collect, how, with what least-privilege access, and the security practices to follow. Nothing here is built except Active Directory. Coverage status: [Planning_Target-Coverage.md](Planning_Target-Coverage.md). Questions referenced as (Qnn) are in [Planning_Questions.md](Planning_Questions.md).

**Researched:** 2026-10-09

## Common approach

- **Transport:** LDAP over TLS (LDAPS on 636, or StartTLS on 389) for every LDAP directory except AD, which uses AD Web Services (9389) through the ActiveDirectory module. Microsoft Graph over HTTPS for Entra ID. Simple binds over cleartext 389 must never be used: they send the bind password unencrypted.
- **Scan identity:** a dedicated, read-only bind account (service DN or app registration), stored in CyberArk. No write access, and no access to password attributes (`userPassword`, `unicodePwd`, LAPS secrets).
- **What counts as privileged:** membership in administrative groups and roles, plus the directory's own super-user identities (the root DN in OpenLDAP, Directory Manager in 389 DS) and any identities named in access-control rules that grant write access.
- **Collector type:** query on the scanning host (LDAP transport); nothing runs on the directory servers.

## 1. Microsoft Active Directory (built)

| Item | Detail |
|---|---|
| Collect | Users, groups and memberships (including nested), computers, and privileged markers (`adminCount`, built-in admin groups, SPNs, delegation, gMSA readers). Full design in [Planning_AD-Object-Filters.md](Planning_AD-Object-Filters.md). |
| Method | `Get-ADObject` with LDAP filters through ADWS (TCP 9389). |
| Least privilege | An ordinary domain user. Delegated read only for restricted attributes (LAPS expiration, gMSA membership). |
| Security practices | Kerberos rather than NTLM; scan account limited to logging on from the scanning host (authentication policy silo, or logon-workstations). Identity threat detection (for example Defender for Identity) will flag reconnaissance-style queries; agree exceptions (security brief §4). |
| Pitfalls | Default containers missed today (fixed in the redesign); primary-group membership isn't in `memberOf`; `adminCount` stays set after removal. |

## 2. Microsoft Entra ID (cloud directory)

| Item | Detail |
|---|---|
| Collect | Users, groups, **directory role assignments** (active), **PIM eligible assignments**, service principals and app registrations with privileged roles or API permissions, and group-assignable roles. |
| Method | Microsoft Graph REST over HTTPS: `roleManagement/directory/roleAssignments`, `roleEligibilitySchedules`/`roleEligibilityScheduleInstances`, `servicePrincipals`, `groups`. Authenticate as an app registration using a **certificate** credential, not a client secret. |
| Least privilege | **Application** permissions, read-only: `Directory.Read.All`, `RoleManagement.Read.Directory`, `RoleEligibilitySchedule.Read.Directory`, `Application.Read.All`. No `*.ReadWrite.*`. |
| Security practices | The app's certificate private key stays non-exportable on the scanning host (or in CyberArk). Admin consent is recorded. Conditional Access for workload identities limits the app to the scanning host's IP, where licensed. |
| Pitfalls | **Eligible** assignments aren't visible as active role members; without reading PIM, privileged users who activate on demand are missed. Paging and throttling (HTTP 429) must be handled. |
| Network | HTTPS to `login.microsoftonline.com` and `graph.microsoft.com` (new HR-NET entry when built). |

## 3. OpenLDAP

| Item | Detail |
|---|---|
| Collect | People and groups under the data suffix (`posixAccount`, `posixGroup`, `groupOfNames`/`groupOfUniqueNames`); **who can write**: the `olcRootDN` of each database, plus identities and groups granted `write` or `manage` in `olcAccess` rules; sudo rules if the `sudoRole` schema is used (`ou=SUDOers`). |
| Method | LDAP search over TLS. The `cn=config` ACLs (`olcAccess`, `olcRootDN`) can only be read by an identity allowed into `cn=config`; by default that's only local root over `ldapi:///` with SASL EXTERNAL. |
| Least privilege | A read-only bind DN for the data tree. For the ACL and root-DN data, either a read-only ACL on `cn=config` granted to the scan DN, **or** a small collector run over SSH on the LDAP server that queries `cn=config` locally and returns only the parsed results (Q81). |
| Security practices | Require TLS and authenticated binds (`olcRequire: authc`, no anonymous reads of user entries); never return `userPassword`. |
| Pitfalls | The root DN has full rights and doesn't appear in any ACL, so it has to be read from `olcRootDN` separately. ACL semantics (first match wins) make "who can write" an interpretation; report the raw rules alongside the parsed result. |

## 4. 389 Directory Server / Red Hat Directory Server

| Item | Detail |
|---|---|
| Collect | Users and groups; **Directory Manager** (`nsslapd-rootdn` in `cn=config`); ACIs (`aci` attributes) granting write; password-policy administrators. |
| Method | LDAP over TLS; read `cn=config` and the `aci` attributes. |
| Least privilege | A read-only bind DN with an ACI allowing read of `aci` and `cn=config`. |
| Pitfalls | ACIs are spread across the tree, so a subtree search for `(aci=*)` is required. |

## 5. FreeIPA / Red Hat Identity Management (IdM)

| Item | Detail |
|---|---|
| Collect | Users and groups (`admins` group); **sudo rules** (who, on which hosts, which commands, run-as); **HBAC rules** (who can log on where); RBAC roles, privileges and permissions; host groups. This is central privileged access for every enrolled Linux host. |
| Method | The IdM JSON-RPC API over HTTPS (`ipa sudorule_find`, `hbacrule_find`, `role_find`), or LDAP under `cn=sudorules,cn=sudo` and `cn=hbac`. |
| Least privilege | A dedicated IdM user with a read-only role (IdM's RBAC can grant read on sudo, HBAC and roles). |
| Security practices | Kerberos and TLS; no write privileges; the IdM `admin` account isn't used for scanning. |
| Pitfalls | Rules with category `all` (all hosts, all commands) need explicit flagging. Per-host local sudoers can still exist alongside IdM rules, so the OS scan remains necessary. |

## 6. Other directories

| Directory | Notes |
|---|---|
| **Oracle Unified Directory / Oracle Internet Directory** | Standard LDAP; super-user `cn=Directory Manager`; ACIs similar to 389 DS. Often the store for Oracle database enterprise users. |
| **Ping Directory / ForgeRock DS** | Standard LDAP with root DNs defined under `cn=Root DNs,cn=config`; privileges are attributes (`ds-privilege-name`). |
| **Novell/NetIQ eDirectory** | LDAP view of NDS; administrative rights come from trustee assignments, which are hard to read over LDAP. Lower priority unless present (Q70). |
| **RACF through LDAP (z/OS SDBM)** | z/OS LDAP can expose RACF users and groups read-only. One option for mainframe coverage without a batch job; see the operating systems doc. |

## Sources

- [Ubuntu Server: OpenLDAP access control](https://ubuntu.com/server/docs/ldap-access-control)
- [OpenLDAP list: finding identities with write access](https://lists.openldap.org/hyperkitty/list/openldap-technical@openldap.org/thread/5ESP2B6WLO4O7LJ6HD7DBPQT43GRRQWQ/)
- [Microsoft Graph: PIM for Entra roles APIs](https://learn.microsoft.com/graph/api/resources/privilegedidentitymanagementv3-overview)
- [Microsoft Learn: assign Entra roles in PIM with Graph PowerShell](https://learn.microsoft.com/powershell/microsoftgraph/tutorial-pim)
- [FreeIPA HBAC least privilege](https://computingforgeeks.com/freeipa-hbac-least-privilege-hbactest/)
- [SpecterOps: Attacking FreeIPA, enumeration](https://specterops.io/blog/2019/12/04/attacking-freeipa-part-ii-enumeration/)
