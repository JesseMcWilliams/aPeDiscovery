# AD object export: search types, filters and attributes

> **Stage: Planning.** A proposed redesign of `Export-ADObjects.ps1`: what it searches, how it filters, and what it collects. Nothing here is built yet. Where the results go (the SQLite store, the config files, exports) is in [Planning_Discovery-Data-Store.md](Planning_Discovery-Data-Store.md). Once built, the content moves into `Design_AD-Discovery.md` and `Reference_Configuration.md`, and this file is renamed `Archive_Planning_AD-Object-Filters.md`.

**Status:** decisions 25–59 agreed 2026-10-09. Target runtime is PowerShell 7.

## 1. Goals

- **One search type per run:** `Users`, `Groups`, `Computers` or `Servers`, described by a search config file (Section 3).
- **The same base options for every type:** target OU, excluded OUs, OU depth, name include/exclude, and group-membership include/exclude. Each type adds its own filters.
- **Filters inside the LDAP query:** every attribute filter is built into the query, so AD returns only matching objects. The current script fetches everything in each OU and filters afterwards.
- **A clean break:** the current `ScanConfig.json` layout is replaced. No deployed configs depend on it.

## 2. Gaps in the current script

| Gap | Effect |
|---|---|
| Only `organizationalUnit` objects are searched | Objects in the default containers (`CN=Users`, `CN=Computers`, `CN=Builtin`, `CN=Managed Service Accounts`) are never exported. This includes the built-in `Administrators` group and every account left in `CN=Users`. |
| No user export | There is no user output at all. |
| Filters run after the fetch | Every object in scope is downloaded, then most are thrown away. This is slow on large domains. |
| Inconsistent filters | Groups support exclude-by-name only; computers support include-by-name only. |
| `MemberCount` is capped | AD returns at most 1,500 values of `member` in one read, so larger groups are under-counted. |

## 3. Search config

Each run takes one search config file:

```powershell
.\Export-ADObjects.ps1 -SearchConfig .\Config\Searches\Tier0-Users.json
```

The domains themselves (server, credentials) live in the general config and are referenced by name; see [Planning_Discovery-Data-Store.md](Planning_Discovery-Data-Store.md#3-configuration-files). A search config holds only what to search for:

```json
{
  "Name": "Tier0-Users",
  "Type": "Users",
  "Domains": ["contoso.com", "fabrikam.local"],
  "BaseOU": "OU=Accounts,DC=contoso,DC=com",
  "OUDepth": -1,
  "ExcludeOUs": ["OU=Disabled,OU=Accounts,DC=contoso,DC=com"],
  "IncludeNames": ["adm-*", "svc-*"],
  "ExcludeNames": ["svc-test-*"],
  "MemberOf": { "Include": ["Tier0-Admins"], "Exclude": [], "Nested": true },
  "EnabledState": "Enabled",
  "LastLogon": { "OlderThanDays": null, "NewerThanDays": null, "IncludeNeverLoggedOn": true },
  "ChangedWithinDays": null,
  "Privileged": "Any",
  "AccountKinds": ["User", "Service", "gMSA", "MSA"],
  "PasswordNeverExpires": "Any",
  "PasswordNotRequired": "Any",
  "SmartcardRequired": "Any",
  "PasswordOlderThanDays": null,
  "Expired": "Exclude",
  "LockedOut": "Any",
  "AdditionalAttributes": ["extensionAttribute1"],
  "LDAPFilter": ""
}
```

- **`Name`** is the search's stable ID. The store records which search found each object, and the future web interface will list searches by it. It must be unique across `Config\Searches\`.
- **`Domains`** lists domain names from the general config. Omitting it means every enabled domain there. `BaseOU`/`ExcludeOUs` are DNs, so a search covering several domains usually leaves `BaseOU` empty (each domain's root).
- **The type-specific settings** (Section 5) are only valid for their own type. Anything else fails validation.
- **`Servers`** is `Computers` with `Roles` limited to `DomainController`, `ReadOnlyDomainController` and `Server` (the default is all three). It exists so server and workstation searches can be scheduled and scoped separately.

Conventions:

- **Tri-state settings** (`Privileged`, `Expired`, `LockedOut`, `Laps`, `Empty`, `ManagedBy`, the password flags) take `Any` (the default, no filter), `Only` or `Exclude`.
- **`EnabledState`** takes `Enabled`, `Disabled` or `Any` (the default).
- **List settings** (`Roles`, `Categories`, `Scopes`, `AccountKinds`, `OperatingSystems`) mean "include only these". Empty or omitted means no filter.
- **Name patterns** support `*` only. LDAP has no single-character wildcard, so a `?` fails validation instead of silently matching nothing.
- **Any invalid value** fails the run before anything is queried: an unknown setting, a bad enum, a malformed DN, an unknown domain name, or a `MemberOf` group that doesn't exist. Each config is checked against a JSON schema file (see the data-store doc).

## 4. Search scope: target OU, excluded OUs, depth

These select **where** to search; they can't be expressed as LDAP filters.

1. Start from `BaseOU` (default: the domain root).
2. Enumerate every **container** below it: `organizationalUnit`, `container` and `builtinDomain` objects. Including the last two fixes the gap in Section 2.
3. Keep containers within `OUDepth` levels of `BaseOU` (`0` = `BaseOU` only, `-1` = unlimited).
4. Drop any container that is, or sits under, an entry in `ExcludeOUs`. Matching uses whole DN components, so `OU=Disabled` doesn't also exclude `OU=Disabled-Archive`.
5. Run one `OneLevel` LDAP query per remaining container, with the full filter from Section 5.

When `OUDepth` is `-1` and `ExcludeOUs` is empty, a single `Subtree` query from `BaseOU` is used instead.

## 5. Filters and their LDAP form

Every row below is combined with `&` into one filter. `<ft>` is a Windows FILETIME integer computed from "now minus N days". The bit-test rule `1.2.840.113556.1.4.803` is written as `:803:`. All values are LDAP-escaped (`(`, `)`, `\`, NUL, and `*` outside name patterns), including DNs.

### 5.1 Base filter per type

| Type | Base LDAP filter |
|---|---|
| Users | `(\|(&(objectCategory=person)(objectClass=user))(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))` |
| Computers, Servers | `(objectCategory=computer)` (gMSAs and MSAs have their own `objectCategory`, so they aren't matched) |
| Groups | `(objectCategory=group)` |

### 5.2 Filters for every type (unless noted)

| # | Setting | LDAP |
|---|---|---|
| 26 | `IncludeNames` | `(\|(sAMAccountName=p1)(sAMAccountName=p2))`. Computers and Servers match the `name` attribute instead, which has no trailing `$`. |
| 26 | `ExcludeNames` | `(!(\|(sAMAccountName=p1)...))` |
| 31/44 | `MemberOf.Include` | Direct: `(memberOf=<groupDN>)`. Nested: `(memberOf:1.2.840.113556.1.4.1941:=<groupDN>)`. Several groups are OR-ed. |
| 31/44 | `MemberOf.Exclude` | `(!( ...same... ))` |
| 25 | `EnabledState` (not Groups) | Enabled: `(!(userAccountControl:803:=2))`. Disabled: `(userAccountControl:803:=2)` |
| 27 | `LastLogon.OlderThanDays` (not Groups) | `(lastLogonTimestamp<=<ft>)`, OR-ed with `(!(lastLogonTimestamp=*))` when `IncludeNeverLoggedOn` is true |
| 27 | `LastLogon.NewerThanDays` (not Groups) | `(lastLogonTimestamp>=<ft>)` |
| 28 | `ChangedWithinDays` | `(whenChanged>=<yyyyMMddHHmmss.0Z>)` |
| 30 | `Privileged` | Only: `(adminCount=1)`. Exclude: `(!(adminCount=1))` |
| 29 | `LDAPFilter` | Wrapped in parentheses if needed and AND-ed as-is |

Notes:

- **Group names in `MemberOf`** can be a DN or a `sAMAccountName`. Names are resolved to DNs once per domain, before the query is built.
- **Primary group membership isn't in `memberOf`.** A user's primary group (usually `Domain Users`; for computers `Domain Computers`) never appears there. When an `Include`/`Exclude` group can be a primary group, the builder also ORs in `(primaryGroupID=<RID>)`, taking the RID from the group's SID. This covers direct membership only; nested membership through a primary group is rare and is documented, not handled.
- **`lastLogonTimestamp` lags** by 9–14 days, so thresholds under about 14 days aren't meaningful.
- **`adminCount` is sticky:** it stays `1` after an account leaves a protected group. `Privileged: Only` therefore means "is or was privileged", which is the right set for CyberArk review.

### 5.3 Users

| # | Setting | LDAP |
|---|---|---|
| 32 | `AccountKinds` | `User`: person, no SPN. `Service`: person with `(servicePrincipalName=*)`. `gMSA`: `(objectClass=msDS-GroupManagedServiceAccount)`. `MSA`: `(objectClass=msDS-ManagedServiceAccount)`. The selected kinds are OR-ed. |
| 33 | `PasswordNeverExpires` | `(userAccountControl:803:=65536)` |
| 33 | `PasswordNotRequired` | `(userAccountControl:803:=32)` |
| 33 | `SmartcardRequired` | `(userAccountControl:803:=262144)` |
| 34 | `PasswordOlderThanDays` | `(pwdLastSet<=<ft>)`. Also matches `pwdLastSet=0` ("must change at next logon"), stored as a blank `PasswordLastSet`. |
| 35 | `Expired` | Only: `(&(accountExpires>=1)(accountExpires<=<now>))`. `0` and `9223372036854775807` both mean "never". |
| 35/50 | `LockedOut` | **Client-side** (agreed exception) |

`LockedOut`: AD computes lockout state on the fly (`msDS-User-Account-Control-Computed`), so it can't be searched, and `lockoutTime>0` stays set after a lockout expires. When this setting isn't `Any`, that attribute is read for each returned user and filtered after the query. At `Any`, nothing extra is read.

### 5.4 Computers and Servers

| # | Setting | LDAP |
|---|---|---|
| 36/49 | `Roles` | `DomainController`: `(userAccountControl:803:=8192)`. `ReadOnlyDomainController`: `(userAccountControl:803:=67108864)`. `Server`: not a DC, and `(operatingSystem=*Server*)`. `Workstation`: not a DC, `operatingSystem` set, and not `*Server*`. `Unknown`: not a DC, and `(!(operatingSystem=*))`. The selected roles are OR-ed. |
| — | `OperatingSystems` | `(\|(operatingSystem=p1)...)` |
| 38 | `RequireDnsHostName` | `(dNSHostName=*)` when `true`. **Off by default**, because the attribute isn't accurate in every environment. |
| 39 | `Laps` | Only: `(\|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))`. Each attribute is included only if it exists in that domain's schema (checked once per domain). |
| 37 | Cluster virtual names | **Not a filter.** Always collected and flagged `IsClusterVirtualName` (an SPN starting `MSClusterVirtualServer/`). Scan-target exports exclude them. |

`Server`/`Workstation` rely on `operatingSystem`, which each computer reports itself and refreshes only periodically. A blank value lands in `Unknown` rather than being guessed (agreed, 49).

### 5.5 Groups

| # | Setting | LDAP |
|---|---|---|
| — | `Categories` | Security: `(groupType:803:=2147483648)`. Distribution: `(!(groupType:803:=2147483648))` |
| — | `Scopes` | Global `(groupType:803:=2)`, DomainLocal `(groupType:803:=4)`, Universal `(groupType:803:=8)`, OR-ed |
| 40/48 | `ExcludeDefaultGroups` | `(!(&(isCriticalSystemObject=TRUE)(!(adminCount=1))))`. This drops AD's default groups (`Domain Users`, `Print Operators`, ...) but always keeps privileged ones (`Domain Admins`, `Administrators`, ...). |
| 41 | `Empty` | Only: `(!(member=*))`. Exclude: `(member=*)` |
| 43 | `ManagedBy` | Only: `(managedBy=*)`. Exclude: `(!(managedBy=*))` |
| 42 | `MemberExpansion` | `Direct` (default) or `Expanded`. Not a filter; see Section 6.4. |

`Empty` caveat: a group whose members all have it as their **primary** group (for example `Domain Users`) has an empty `member` attribute, so it counts as empty.

## 6. Attributes collected

Three rules:

1. **Raw values are kept** (for example `userAccountControl`, `groupType`) alongside the decoded columns, so later exports can use flags that aren't decoded today.
2. **`AdditionalAttributes`** in a search config adds more attributes for that search (for example `extensionAttribute1–15`). They're stored as name/value rows, so no schema change is needed.
3. **Secrets are never collected,** enforced in code even if they're listed in `AdditionalAttributes`: `ms-Mcs-AdmPwd`, `msLAPS-Password`, `msLAPS-EncryptedPassword`, `msDS-ManagedPassword`, `unicodePwd`.

### 6.1 Every type

`objectGUID`, `objectSid`, `distinguishedName`, `sAMAccountName`, `name`, `objectClass`, `description`, `managedBy`, `adminCount`, `isCriticalSystemObject`, `whenCreated`, `whenChanged`, `uSNChanged`.

`uSNChanged` is per domain controller, so it's only useful for incremental runs when the domain's `Server` is pinned in the general config.

### 6.2 Users (including service accounts, gMSAs, MSAs)

| Attributes | Why |
|---|---|
| `userPrincipalName`, `displayName`, `mail`, `givenName`, `sn` | The CyberArk account and owner details |
| `employeeID`, `employeeType`, `department`, `title`, `manager` | HR matching; `manager` is the usual owner of a service account |
| `userAccountControl`, `pwdLastSet`, `accountExpires`, `lastLogonTimestamp`, `primaryGroupID` | State, password age, staleness |
| `servicePrincipalName` | Service accounts; also a Kerberoasting risk flag on user accounts |
| `msDS-SupportedEncryptionTypes` | Whether weak (RC4-only) encryption is still allowed |
| `msDS-User-Account-Control-Computed` | Lockout and password-expired state; read only when the `LockedOut` filter is used |
| gMSA only: `msDS-GroupMSAMembership` (decoded to principal names), `msDS-ManagedPasswordInterval` | Which accounts can read the gMSA's password |

### 6.3 Computers and Servers

| Attributes | Why |
|---|---|
| `dNSHostName`, `operatingSystem`, `operatingSystemVersion` | Scan target, and Windows vs Linux routing |
| `userAccountControl`, `primaryGroupID` | Role and enabled state |
| `lastLogonTimestamp`, `pwdLastSet` | Staleness. Computers change their account password about every 30 days, so a password older than ~60 days usually means the machine is gone. |
| `servicePrincipalName` | Cluster names (37); `MSSQLSvc/` entries reveal SQL Server instances without scanning |
| `ms-Mcs-AdmPwdExpirationTime`, `msLAPS-PasswordExpirationTime` | LAPS status, from expiration dates only |
| `msDS-AllowedToDelegateTo`, plus the delegation bits in `userAccountControl` | Delegation risk |
| `location` | Site |

### 6.4 Groups and membership

| Attributes | Why |
|---|---|
| `groupType` | Category and scope, decoded |
| `member` | Direct members. It's read in chunks (ranged retrieval), which fixes the 1,500-value limit. |
| `mail`, `info` | Contact and notes |

`MemberExpansion: Expanded` adds one query per exported group, `(memberOf:1.2.840.113556.1.4.1941:=<groupDN>)` from the domain root. Members found directly are stored as `Direct`; the rest as `Nested`. Members in other domains or forests (foreign security principals) aren't expanded.

## 7. Implementation outline

1. **`Modules\ADHelpers.psm1`:**
   - `Get-ScopedSearchBase`: replaces `Get-ScopedOrganizationalUnits`. It covers all container types, plus depth and `ExcludeOUs`.
   - `ConvertTo-LdapFilterValue`: escaping.
   - `New-ADObjectLdapFilter`: takes the type and search config and returns one filter string. Pure, so it can be unit-tested offline.
   - `Resolve-MemberOfGroup`: name/DN to DN and RID.
2. **`Export-ADObjects.ps1`:** loads the general config and one search config; validates both; for each domain, runs `Get-ADObject -LDAPFilter ... -SearchBase <container> -SearchScope OneLevel` (or `Subtree`) and writes the results to the store.
3. **Tests:** this repo's first Pester suite, `Tests\ADHelpers.Tests.ps1`, covering the filter builder, escaping and search-base selection. All of it runs offline.
4. **Docs:** `Reference_Configuration.md`, `Reference_CSV-Schemas.md`, `Design_AD-Discovery.md`, `Testing_Live-Test-Definitions.md` (update LT-AD-01/02 and add tests for users, nested membership, default containers and LAPS), plus example search configs in `Config\Searches\`.

## 8. Live verification needed

These become new `LT-AD-*` tests:

- objects in `CN=Users`/`CN=Builtin` are now found;
- nested `MemberOf` and `MemberExpansion: Expanded` match `Get-ADGroupMember -Recursive`;
- `ExcludeDefaultGroups` keeps `Domain Admins`/`Administrators` and drops `Domain Users`;
- LAPS detection against a domain with legacy LAPS, Windows LAPS, or neither;
- whether the scan account can read `msDS-User-Account-Control-Computed`, the LAPS expiration attributes and `msDS-GroupMSAMembership` (all are commonly restricted);
- the `primaryGroupID` handling for `Domain Users`;
- the ActiveDirectory module on PowerShell 7.
