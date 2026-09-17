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
  Conjur) or from a pre-exported `PSCredential` file — see `Modules\CredentialResolver.psm1`.
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
- **No AD user inventory.** Only groups and their direct members are exported; a full user object
  export was not requested and is out of scope.
- **Read-only.** Nothing in this tool ever writes to AD.
- **On-prem AD only.** Azure AD / Entra ID is not covered (see Open Decisions).

## 4. Requirements

**Functional**
- Config-driven list of domains, each independently enabled/disabled.
- Per-domain scoping to a base OU and a maximum OU depth below it.
- Per-domain credential source (`CurrentUser`, `PSCredential` file, `CP`, `CCP`, or `Conjur`).
- CSV output of groups and of direct group→member pairs.

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
Export-Csv → ADGroups.csv / ADGroupMembers.csv (+ timestamped Archive copy, retention-pruned)
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

## 10. Revision log

| Date | Change |
|---|---|
| 2026-09-16 | Initial version, documenting the as-built `Export-ADGroups.ps1`. |
| 2026-09-16 | Added per-domain `ExcludeOUs`, `IncludeGroupCategories`, `IncludeGroupScopes`, and `ExcludeGroupNames` filters (Section 5, Section 9). |
