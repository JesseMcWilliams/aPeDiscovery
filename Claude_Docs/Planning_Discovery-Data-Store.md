# Discovery data store, configuration and exports

> **Stage: Planning.** How discovery results are stored, configured and exported, starting with the AD export redesign in [Planning_AD-Object-Filters.md](Planning_AD-Object-Filters.md). Nothing here is built yet. Once built, the content moves into a `Design_` doc and `Reference_Configuration.md`.

**Status:** decisions 51–59 agreed 2026-10-09. The SQLite library was prototyped successfully (Section 4.1). PowerShell 7 verification results are in Section 8.

## 1. Phases

| Phase | Scope |
|---|---|
| 1 (this design) | Redesigned AD export, writing to a local SQLite store. Exports to CSV, driven by export configs. PowerShell 7. |
| 2 | Windows and Linux local scanners also write to the store, so AD and local data can be joined (for example, generating scan targets from AD). |
| 3 | Direct import into MSSQL, as a new export format. |
| 4 | Web interface for configs, runs and results. Section 7 lists what Phase 1 does now so this is easy later. |

## 2. Runtime: PowerShell 7

New code targets PowerShell 7 only. LogaPe, aPeSecrets and the existing scripts are verified on 7 and fixed where needed (Section 8). Benefits for this project:

- UTF-8 by default, which avoids the Windows PowerShell 5.1 ANSI misreads of CSV, JSON and Markdown.
- `Test-Json -Schema`, which validates the config files against JSON schema files (Section 3.4).
- `ForEach-Object -Parallel` and thread jobs, available for the later scanner work.
- Faster JSON and CSV handling, and active development (5.1 only gets fixes).

Verification used 7.6.6 (Section 8). The minimum supported 7.x version is open question 62.

## 3. Configuration files

All configs are JSON under `Config\`. The real files are gitignored, and each has a tracked `.example` copy. Each config has a `Name` that serves as its stable ID: runs, store rows and the future web interface refer to configs by name, never by file path.

### 3.1 General config: `Config\aPeDiscovery.json`

Shared by every run.

```json
{
  "Store": {
    "Path": "C:\\aPeDiscovery\\Data\\discovery.db",
    "HistoryMode": "CurrentState",
    "KeepRuns": 90
  },
  "Logging": { "Directory": "C:\\aPeDiscovery\\Logs", "Format": "Text", "RetentionDays": 30 },
  "Domains": [
    {
      "Name": "contoso.com",
      "Server": "dc01.contoso.com",
      "Enabled": true,
      "CredentialSource": "CP",
      "CredentialParams": { "AppID": "aPeDiscovery", "Safe": "AD-Scan", "Object": "contoso-scan" }
    }
  ]
}
```

| Setting | Meaning |
|---|---|
| `Store.HistoryMode` | `CurrentState` (default): one row per object, with first-seen, last-seen and removed-on runs. `FullSnapshots`: the same, plus a copy of every object's row per run, in history tables. |
| `Store.KeepRuns` | How many runs of history and run records to keep (both modes). |
| `Logging.Format` | `Text` or `Json` (LogaPe's JSON lines, which a web interface can read). |
| `Domains` | Connection details, referenced by `Name` from search configs. Credentials are pointers to an aPeSecrets source, never secrets. |

### 3.2 Search configs: `Config\Searches\*.json`

One per search: `Name`, `Type` (`Users`, `Groups`, `Computers`, `Servers`), `Domains` (names from the general config) and the type's filters. The full shape is in [Planning_AD-Object-Filters.md](Planning_AD-Object-Filters.md#3-search-config).

```powershell
.\Export-ADObjects.ps1 -SearchConfig .\Config\Searches\Tier0-Users.json
```

### 3.3 Export configs: `Config\Exports\*.json`

One per output. An export reads one view from the store (Section 5) and writes it in a format, to a location.

```json
{
  "Name": "Windows-Servers-To-Scan",
  "View": "v_scan_targets_windows",
  "Format": "Csv",
  "Csv": { "Delimiter": ",", "Encoding": "utf8", "IncludeHeader": true, "QuoteAll": true },
  "Destination": { "Directory": "C:\\aPeDiscovery\\Output", "FileName": "WindowsServersToScan.csv", "ArchiveCount": 30 },
  "Where": { "DomainName": ["contoso.com"] }
}
```

```powershell
.\Export-DiscoveryData.ps1 -ExportConfig .\Config\Exports\Windows-Servers-To-Scan.json
```

- **`Format`** is `Csv` in Phase 1. `Mssql` (direct bulk import) arrives in Phase 3, with its own `Mssql` block (server, database, table, credential source).
- **`Where`** is optional: simple column-equals-any-of filters, applied as SQL parameters, never as raw SQL text.
- **Table-creation scripts** for each view are shipped for MSSQL (`Sql\mssql\`), so CSV output can be bulk-loaded (`BULK INSERT`/`bcp`) into matching tables. MySQL and PostgreSQL scripts can be added the same way when needed.

### 3.4 Validation

Each config type has a JSON schema in `Config\Schemas\` (`general.schema.json`, `search.schema.json`, `export.schema.json`). Every script validates its configs with `Test-Json -Schema` before doing anything, then runs the checks a schema can't express: domain names exist, DNs parse, `MemberOf` groups resolve. The future web interface can build its forms and validation from the same schema files.

## 4. Store

### 4.1 Library

The SQLite .NET library is copied into the repo (`Lib\`) and loaded by one module, `Modules\DiscoveryStore.psm1`; no PowerShell Gallery dependency (decision 57). The library is **Microsoft.Data.Sqlite**, Microsoft's maintained library for modern .NET.

**Files** (about 2.5 MB, from nuget.org, with their license texts kept alongside):

| File | Package | License |
|---|---|---|
| `Microsoft.Data.Sqlite.dll` | Microsoft.Data.Sqlite.Core 10.0.12 (`lib\net8.0`) | MIT |
| `SQLitePCLRaw.core.dll`, `SQLitePCLRaw.batteries_v2.dll`, `SQLitePCLRaw.provider.e_sqlite3.dll` | SQLitePCLRaw 2.1.12 | Apache-2.0 |
| `e_sqlite3.dll` (native, win-x64) | SQLitePCLRaw.lib.e_sqlite3 2.1.12 | Apache-2.0; SQLite itself is public domain |

Microsoft.Data.Sqlite 10.0.12 is built against SQLitePCLRaw **2.1.x**, not the newer 3.x packages, so the versions must stay matched when upgrading.

**Loading:** .NET looks for the native `e_sqlite3.dll` next to `pwsh.exe`, not next to the managed DLLs. The module therefore loads it first by full path with `[System.Runtime.InteropServices.NativeLibrary]::Load()`, then loads the managed DLLs with `Add-Type -Path`, then calls `[SQLitePCL.Batteries_V2]::Init()`.

**Prototype results** (PowerShell 7.6.6 on .NET 10, 2026-10-09):

- loads from a plain folder, with no installer;
- SQLite 3.53.3, WAL mode on;
- 10,000 upserts in one transaction took 243 ms;
- two writer processes (3,000 rows each, one transaction per 100 rows) and one reader process (about 51,000 reads) ran at the same time with no errors, using `busy_timeout = 30000`;
- all 16,000 rows were present afterwards, and `PRAGMA integrity_check` returned `ok`.

All SQL lives in `DiscoveryStore.psm1`.

No other script talks to SQLite directly, so a later backend change (for example MSSQL for the web interface) touches one module.

### 4.2 Schema

| Table | Contents |
|---|---|
| `schema_version` | Current version. Numbered migration scripts upgrade older stores on open. |
| `runs` | One row per run: run ID, kind (search or export), config name, config hash, domain, start/end time (UTC), status, object counts, log file path, error text. |
| `ad_users`, `ad_computers`, `ad_groups` | One row per object, keyed by `(domain, object_guid)`: decoded columns, raw values, `first_seen_run`, `last_seen_run`, `removed_run`. |
| `ad_group_members` | Group to member, with `membership_type` (`Direct`, `Nested`) and the same seen/removed columns. |
| `ad_object_values` | Multi-valued and additional attributes (SPNs, `AdditionalAttributes`) as `(domain, object_guid, attribute, value)` rows. |
| `ad_object_searches` | Which search last saw each object, and in which run. Used for removal (Section 4.3). |
| `*_history` | `FullSnapshots` mode only: a copy of each object's row per run, pruned by `KeepRuns`. |

Portability rules, so exports map cleanly to MSSQL, MySQL and PostgreSQL:
- text, integer and real types only;
- dates in UTC as ISO 8601 text;
- GUIDs and SIDs as their string forms;
- booleans as `0`/`1`.

### 4.3 When an object counts as removed

A filtered search only sees part of a domain, so "not found" doesn't always mean "deleted". The rule:

- After a **complete** run of a search, every object that this search saw in its previous complete run but not this time is no longer seen by this search.
- An object is marked removed (`removed_run` set) only when **no search that has ever seen it** sees it any more.
- A run is complete when it finished without errors for that domain and didn't use `ChangedWithinDays`. Incremental runs only add and update.
- If an object reappears later, `removed_run` is cleared.

### 4.4 Concurrency

WAL mode, plus a busy timeout of 30 seconds (configurable). Each run writes in one transaction per domain, so a failed domain leaves nothing half-written. Separate runs of different searches can therefore overlap safely.

## 5. Views (what exports read)

Views are defined in `DiscoveryStore.psm1` and created or updated by the migrations. Initial set:

| View | Rows |
|---|---|
| `v_users` | Current (not removed) users with decoded columns |
| `v_privileged_accounts` | Users with `adminCount=1`, or direct/nested members of a privileged group |
| `v_service_accounts` | Users whose account kind is Service, gMSA or MSA, with their SPNs and owner (`manager`/`managedBy`) |
| `v_computers`, `v_servers` | Current computers; servers and domain controllers only |
| `v_scan_targets_windows` | Enabled, not stale, not cluster names, Windows OS, with a DNS name |
| `v_scan_targets_linux` | The same, for non-Windows OS values |
| `v_groups`, `v_group_members` | Current groups; membership with `Direct`/`Nested` |

The two scan-target views produce the same columns as `ComputersToScan.csv`/`LinuxComputersToScan.csv`, except the credential columns. Those come from a separate mapping (a Phase 2 decision).

## 6. Run flow

1. Load and validate the general config and the search config.
2. Open the store (create it or migrate it if needed) and insert a `runs` row.
3. For each domain: resolve the credential (aPeSecrets), build the search bases and filter, query AD, then upsert into the store in one transaction.
4. Apply the removal rule (Section 4.3), prune history to `KeepRuns`, and finish the `runs` row.
5. Exit `0` if every domain succeeded, `1` otherwise (as today). Print a one-line JSON summary (run ID, counts, status) as the last line of output, for schedulers and the web interface.

## 7. Web interface readiness (Phase 4)

Phase 1 doesn't build any of the web interface, but makes these choices so it fits later:

- **Configs are JSON with schemas** (Section 3.4). The interface can generate forms and validate input with the same rules as the scripts.
- **Everything is referenced by `Name`:** domains, searches and exports. The interface can list and link them.
- **Every run is recorded** in `runs`, with status, counts and the log path. Combined with `Json` logging, that's enough for a run history and log viewer.
- **Scripts are non-interactive,** with exit codes and a JSON summary line, so the interface can start runs and read the results.
- **There are no secrets in configs, the store or logs.** Credentials stay pointers to aPeSecrets sources, and LogaPe masking stays on.
- **All storage access is in one module.** A multi-user web application will probably want MSSQL rather than SQLite as its backend; the Phase 3 MSSQL work and this boundary keep that a contained change.

## 8. PowerShell 7 verification

Run on PowerShell 7.6.6 (portable copy, .NET 10) on 2026-10-09.

| Component | Result |
|---|---|
| LogaPe | **Fixed and passing.** The Event Log sink used `New-EventLog`/`Write-EventLog`, which PowerShell 7 removed; it now calls `[System.Diagnostics.EventLog]`. All 43 module tests pass on 7, and all 7 examples run on both 5.1 and 7. |
| aPeSecrets | **Passing,** 17/17 unit tests on both 5.1 and 7. One test (CR10) had always failed on hosts without the CyberArk Credential Provider; fixed by checking `AppID` before looking for the SDK. The live `CP`/`CCP`/`Conjur` paths still need the lab on 7. |
| `Export-LocalGroups.ps1` | **Passing.** Parallel scans, ADSI, LogaPe logging, retries and masking all match 5.1. CSV encoding differed (7 writes UTF-8 without a byte-order mark); all three scripts now pick `utf8BOM` on 7, so output is byte-identical on both. |
| `Export-LocalLinuxGroups.ps1` | Needs the lab (Posh-SSH isn't installed here). |
| `Export-ADObjects.ps1` / ActiveDirectory module | Needs the lab (RSAT isn't installed here). |
| SQLite prototype | **Passing** (Section 4.1). |

## 9. Open questions

60. **`KeepRuns` default:** 90 runs?
61. **Credentials for scan-target exports:** `ComputersToScan.csv` needs a credential source per computer. Should a Phase 1 export config carry a default credential source, or does that wait for Phase 2?
62. **Minimum PowerShell 7 version:** 7.6 (what was tested), or also 7.4? 7.4 runs on .NET 8, which still satisfies `Microsoft.Data.Sqlite` (`net8.0`), but it would need its own test pass.
