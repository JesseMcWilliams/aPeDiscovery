# AD Group Discovery — Design

**Status:** Implemented
**Initiated:** 2026-09-16
**Origin:** User request to build a nightly export of Active Directory group and group-membership
data, across one or more domains — including domains with no trust relationship to the host running
the scan — for import into a separate downstream tool.

This document describes the design behind `Export-ADGroups.ps1`. See
[Configuration.md](Configuration.md) for the full config schema and
[CSV-Schemas.md](CSV-Schemas.md) for exact output columns; this doc focuses on the *why* behind the
shape of the thing, not a field-by-field reference.

---

## 1. Why this is worth doing

A downstream tool needs a current, machine-readable picture of AD groups and their direct members
across every domain the organization cares about — including domains that don't trust the host
running the scan (e.g. an acquired company's domain, or a partner domain reachable only over a
dedicated link). Without this, that picture is either stale, manually assembled, or simply
unavailable for the untrusted domains.

## 2. Context & constraints

- **No trust required.** Every AD query uses `-Server` plus an explicit credential rather than
  relying on the calling identity's own domain trust, so a domain with zero trust relationship to
  the scanning host is scanned the same way as a fully-trusted one — the only requirement is
  network line-of-sight to a DC and a working credential.
- **CyberArk is the existing credential system of record.** Rather than inventing a new secrets
  store, credentials are resolved at runtime from whatever CyberArk already manages (CP, CCP, or
  Conjur) or from a pre-exported `PSCredential` file — see the sibling aPeSecrets project's
  `Modules\CredentialResolver.psm1` (extracted from this project 2026-09-21).
- **RSAT's `ActiveDirectory` module is the standard, already-available tool** for AD queries on an
  admin workstation, so this reuses it rather than reimplementing LDAP calls over
  `System.DirectoryServices`.
- **This runs unattended, nightly, via Scheduled Task** — so a single domain being unreachable or
  misconfigured must not abort the whole run, and the run must leave a clear audit trail.

## 3. Non-goals

- **No recursive/effective membership expansion.** The membership file records *direct* members
  only, matching AD's own model. A downstream tool that needs effective membership can walk nested
  groups itself using the groups file as the edge list — this keeps the export fast and keeps the
  group-nesting structure visible rather than flattening it away.
- **No AD user inventory.** Only groups/direct members and (opt-in, added 2026-09-17) computer
  objects are exported; a full user object export was not requested and is out of scope.
- **Read-only.** Nothing in this tool ever writes to AD.
- **On-prem AD only.** Azure AD / Entra ID is not covered (see Open Decisions).

## 4. Requirements

**Functional**
- Config-driven list of domains, each independently enabled/disabled.
- Per-domain scoping to a base OU and a maximum OU depth below it.
- Per-domain credential source (`CurrentUser`, `PSCredential` file, `CP`, `CCP`, or `Conjur`).
- CSV output of groups and of direct group→member pairs.
- Opt-in per-domain computer object discovery, independently scoped from the group scan, filterable
  by name and reported OS type (added 2026-09-17).

**Non-functional**
- Continue past a failed domain (log it, move on) rather than aborting the whole run.
- Exit code reflects overall success/partial-failure for Scheduled Task monitoring.
- Secrets are never written to the log.

## 5. Architecture

```
Config (JSON)
  └─ for each enabled domain:
       resolve credential (CredentialResolver.psm1)
       compute search bases (ADHelpers.psm1: base OU + OUDepth)
       remove any OU covered by ExcludeOUs (self or descendant)
       for each remaining search base:
         Get-ADGroup -SearchScope OneLevel  → filter by IncludeGroupCategories /
           IncludeGroupScopes / ExcludeGroupNames → group rows
         Get-ADGroupMember (direct members) → member rows
           └─ falls back to raw 'member' DN resolution if Get-ADGroupMember errors
       if domain config has a 'Computers' block:
         compute independent search bases (own BaseOU/OUDepth/ExcludeOUs)
         Get-ADComputer -SearchScope OneLevel → filter by NameFilter / OSTypeFilter (inclusion) → computer rows
Export-Csv → ADGroups.csv / ADGroupMembers.csv / ADComputers.csv (+ timestamped Archive copy, retention-pruned)
```

**Filtering (added 2026-09-16).** `ExcludeOUs` is applied once per domain, against the already
depth-scoped list of search bases, by string-suffix match (`$ou -eq $excluded -or $ou -like "*,$excluded"`)
— an OU is excluded if it *is* one of the listed DNs or is a descendant of one, so listing a parent
OU excludes its whole sub-tree without needing every child DN spelled out. `IncludeGroupCategories`/
`IncludeGroupScopes`/`ExcludeGroupNames` are applied per group, client-side, after `Get-ADGroup`
returns each OU's groups — not as an LDAP `-Filter` expression. Filtering client-side avoids relying
on exactly how the `ActiveDirectory` module's `-Filter` syntax translates a computed property like
`GroupCategory` (derived from the raw `groupType` bitmask, not a plain LDAP attribute) into an LDAP
filter, in favor of a mechanism whose behavior is simple and directly verifiable. An invalid
`IncludeGroupCategories`/`IncludeGroupScopes` value (e.g. a typo) fails that domain's run immediately
with a clear error, rather than silently filtering out every group.

**Why a manual OU-depth walk, not a single query.** AD's own `-SearchScope` only supports
`Base`/`OneLevel`/`Subtree` — there is no built-in "N levels deep" scope. `Get-ScopedOrganizationalUnits`
(in `ADHelpers.psm1`) enumerates every OU under the base via `Subtree`, then keeps only the ones
whose OU-component depth relative to the base is within the configured `OUDepth`, and queries each
kept OU with `OneLevel` for its direct groups. `OUDepth = -1` short-circuits this to a single
`Subtree` query for the common "scan everything under this OU" case.

**Why `Get-ADGroupMember` with a DN-resolution fallback, not just the `member` attribute.**
`Get-ADGroupMember` gives clean `SamAccountName`/`ObjectClass`/`SID` resolution for direct members
in one call, but is known to error on some `foreignSecurityPrincipal` members (cross-domain members
from a trusted domain). When it does, the script falls back to resolving the group's raw `member`
DN list one object at a time via `Get-ADObject`, with a per-run cache so a member appearing in
multiple groups (e.g. a commonly-nested admin group) is only resolved once.

**Computer object discovery (added 2026-09-17).** Opt-in per domain — only runs when that domain's
config entry has a `Computers` property, so an existing config written before this feature keeps
behaving exactly as before. Deliberately **independently scoped** from the domain's own group scan
(its own `BaseOU`/`OUDepth`/`ExcludeOUs`, reusing the same `Get-ScopedOrganizationalUnits` helper and
`ExcludeOUs` suffix-match logic groups already use) rather than reusing the group scan's `BaseOU`,
since computer objects are commonly organized under a different part of the tree than groups (e.g.
`OU=Servers` vs. `OU=Groups`) — silently reusing the group scan's OU would likely miss most
computers in a typical deployment. `NameFilter`/`OSTypeFilter` are **inclusion** filters (a computer
must match at least one pattern in each that's set) — the opposite direction from `ExcludeGroupNames`
— since "find computers matching X" is a search, not a noise-exclusion, the same way
`Export-LocalGroups.ps1`'s `-ComputerFilter` parameter works. `ComputerName` strips the trailing `$`
AD puts on every computer account's `SamAccountName` (kept verbatim in a separate `SamAccountName`
column), since a downstream tool consuming this to seed something like `Export-LocalGroups.ps1`'s own
`ComputersToScan.csv` wants a plain hostname, not a SAM account name. `LastLogonTimestamp` is
converted from AD's raw replicated attribute to an actual date, but that attribute is intentionally
imprecise (AD limits how often it replicates specifically to reduce replication traffic) — "roughly
this stale," not exact.

**Not tested against a live domain controller.** No RSAT `ActiveDirectory` module (or any AD
environment) was available in the environment this was built in — the same situation the rest of
this script was originally built under. The `Get-ADComputer` call, its properties
(`DNSHostName`/`OperatingSystem`/`OperatingSystemVersion`/`LastLogonTimestamp`/`Enabled`), and
`SamAccountName`'s trailing-`$` convention are all standard, long-documented AD schema/cmdlet
behavior, not something obscure — but the surrounding logic (filter application, date conversion,
name stripping) was only verified in isolation, not against a real domain. Verify with
`-DomainFilter` against one domain before relying on this in production.

## 6. Security considerations

- Credentials are resolved per domain at the point of use and never logged; only the *source*
  (`CP`/`CCP`/`Conjur`/etc.) and outcome (success/failure) appear in the log, never the secret
  itself.
- The account behind each domain's credential only needs standard AD read access — group and
  member enumeration doesn't require elevated rights, though this assumes the target domain hasn't
  restricted read access below AD's normal defaults (unconfirmed for any specific target domain;
  verify per domain).
- A `PSCredential` source's exported file is DPAPI-encrypted and only decryptable by the same
  Windows account, on the same machine, that created it.

## 7. Known limitations

- AD's default 1,500-value range limit on the `member` attribute can make `MemberCount`, and the
  rare DN-resolution fallback path, incomplete for groups with very large direct membership.
  `Get-ADGroupMember` (the primary membership path) is not affected.
- The OU-depth DN-component count treats a comma preceded by `\` as an escaped literal rather than a
  separator — this covers the common case of a comma inside an OU/CN name, but is not a full LDAP
  DN parser.
- No parallelism across domains — each is scanned sequentially.
- **`OperatingSystem`/`OperatingSystemVersion` are self-reported and only periodically refreshed** —
  a computer object can show a blank or stale OS value if the machine hasn't rejoined/refreshed
  recently; `OSTypeFilter` matches against whatever is currently in AD, not the machine's real,
  current state.
- **`LastLogonTimestamp` is deliberately imprecise** — AD limits how often it replicates this
  attribute to reduce replication traffic, so it's only accurate to within a few days, not a precise
  last-logon time.
- **Computer discovery has not been tested against a live domain controller** — no AD environment
  was available while building it. The logic pieces (trailing-`$` stripping, date conversion, filter
  matching) were verified in isolation; the actual `Get-ADComputer` call and its properties were not
  exercised against a real domain.

## 8. Alternatives considered

- **Raw LDAP via `System.DirectoryServices` instead of the `ActiveDirectory` module** — rejected;
  the RSAT module already provides reliable, well-tested group/member enumeration and is the
  standard tool for this job, so reimplementing it would add risk with no real benefit.
- **Recursive/effective membership in the members file** — rejected per the direct-members-only
  decision (see Non-goals); the downstream tool is expected to recurse using the groups file itself
  if it needs effective membership.

## 9. Open decisions

- Should Azure AD / Entra ID group export be added as a second data source feeding the same output
  shape?
- Is the 1,500-member range limit on `MemberCount` worth fixing with ranged attribute retrieval, or
  is it acceptable given `Get-ADGroupMember` isn't affected for the membership file itself?
- `ExcludeGroupNames` matches on `SamAccountName` only — should it also (or instead) support
  matching on `DistinguishedName`/OU-relative path, for cases where the same name could recur
  under different OUs but only one instance should be excluded?
- Should `NameFilter`/`OSTypeFilter` also support an exclude-style variant (mirroring
  `ExcludeGroupNames`), for "scan everything except..." rather than only "scan only matching..."?
- Is defaulting the `Computers` block's `BaseOU` to the domain root (rather than, say, to the
  domain entry's own `BaseOU`) the right default, given the whole reason for scoping it
  independently is that computers usually live somewhere else in the tree?
- Should computer discovery be validated against a live domain controller before being considered
  production-ready, given it hasn't been tested against one yet (see Section 7)?

## 10. Revision log

| Date | Change |
|---|---|
| 2026-09-16 | Initial version, documenting the as-built `Export-ADGroups.ps1`. |
| 2026-09-16 | Added per-domain `ExcludeOUs`, `IncludeGroupCategories`, `IncludeGroupScopes`, and `ExcludeGroupNames` filters (Section 5, Section 9). |
| 2026-09-17 | Added opt-in per-domain computer object discovery (`ADComputers.csv`), independently scoped from the group scan's own OU settings, with inclusion-style `NameFilter`/`OSTypeFilter`. Verified the pure logic pieces (trailing-`$` stripping, `LastLogonTimestamp` date conversion, filter matching) in isolation; the `Get-ADComputer` call itself was not tested against a live domain controller, since none was available. |
