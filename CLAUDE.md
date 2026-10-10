# aPeDiscovery: Claude Code project notes

PowerShell scripts that export Active Directory group/membership data and per-computer local Windows/Linux user, group and sudo-rights data to CSV, using CyberArk-resolved credentials. Runtime target is Windows PowerShell 5.1 (or PowerShell 7+); no `Set-StrictMode` or `#Requires` is used anywhere, so strict mode is not enabled.

## Folder map
- `Export-ADObjects.ps1`, `Export-LocalGroups.ps1`, `Export-LocalLinuxGroups.ps1`: the three entry-point scripts (AD groups, local Windows, local Linux).
- `Install-aPeDiscovery.ps1`: installs/updates the host prerequisites and all three repositories. It must stay Windows PowerShell 5.1-compatible, because it runs before PowerShell 7 exists. Test system-changing parts only with `-WhatIf`, or into a scratch `-InstallRoot` with `-Components Repositories`.
- `Modules/`: `ADHelpers.psm1`, `NetworkHelpers.psm1`, `LocalComputerScanner.psm1`, `LocalLinuxComputerScanner.psm1` (783 lines — grep for the function and read a line range; don't read the whole file).
- `Config/`: `.example.json`/`.example.csv` templates (tracked) plus the real `ScanConfig.json`/`LocalScanConfig.json`/`LinuxScanConfig.json`/`ComputersToScan.csv`/`LinuxComputersToScan.csv` (gitignored, real domain/computer/credential data).
- `Output/`: gitignored runtime output/log/archive location — don't read from here for facts.
- `Secrets/`: gitignored credential files (Export-Clixml, SSH keys).
- Credential resolution itself lives in the sibling `../aPeSecrets` project (`Modules/CredentialResolver.psm1`); all three scripts import it by relative path.
- Logging is the sibling `../LogaPe` module (`LogaPe/LogaPe.psd1`), imported by relative path. Entry scripts create one active logger per run; each scanner runspace creates its own logger on the same file (`-Logger $logger`) and calls `Remove-Logger` when done. Every `New-Logger` call passes `-EnableDefaultMasking`; keep it on any new logger. Don't reintroduce a local logging module.
- External references are in `C:\Code\References\`. Check there before guessing at API behavior.

## Tests
<!-- TODO: no Tests folder or Pester runner exists in this repo (confirmed: no *.Tests.ps1 files, no Pester references). Testing is manual — see Claude_Docs/Testing_Guide.md. If a test runner is added later, fill this in. -->
- Redirect any script output to a file and read only the summary or failures. Don't stream full output into the conversation.

## Code rules (details in the linked sections, not repeated here)
- Config/credential-source options and schema: `Claude_Docs/Reference_Configuration.md`.
- CSV output column layouts: `Claude_Docs/Reference_CSV-Schemas.md`.
- Manual validation steps per feature: `Claude_Docs/Testing_Guide.md`.
- Design/implementation status per discovery target: `Claude_Docs/Design_AD-Discovery.md`, `Claude_Docs/Design_Local-Windows-Discovery.md`, `Claude_Docs/Design_Local-Linux-Discovery.md`.

## Documentation layout
- `README.md` (root): an **overview only**. It covers purpose, requirements, a quick start and a short feature list, and links to `User_Docs/` and `Claude_Docs/` for everything else. Put detail in a doc and link to it rather than adding it to the README.
- `Claude_Docs/` holds every doc Claude creates or works from, named `<Stage>_<Topic-With-Hyphens>.md`:
  - `Planning_`: proposals and backlogs that aren't built yet. Once built, the doc becomes `Design_` or is renamed `Archive_Planning_...`.
  - `Design_`: how the current system works. Keep it current. Archive it only when the feature is removed or replaced.
  - `Testing_`: test plans, open findings and known issues. Closed findings move to `Archive_Testing_...`.
  - `Reference_`: rules that apply at every stage (lessons learned, conventions, interface contracts).
  - `Archive_<OriginalStage>_<Topic>.md`: finished or superseded material. **Don't read `Archive_*` unless the user asks or the task needs history.**
- `User_Docs/`: end-user documentation, usually written near the end of the project from `Claude_Docs/Planning_User-Docs-Backlog.md`. It's output, not a source of facts. Take facts from the code and `Claude_Docs/`.
- When you make a user-visible change, add one line for it to `Planning_User-Docs-Backlog.md`.
- Keep each doc to about 500 lines. Past that, move closed or old content into an `Archive_` file. Don't keep revision logs, because git has the history. Put dates in file names only for point-in-time snapshots, such as reviews.
- Rename docs with `git mv`, and update every link to them in the same change.
- If a doc is large, find the target with grep and read a narrow range. Keep table rows to one or two sentences.

## Docs: what to update for each kind of change
| Change | Update |
|---|---|
| New feature or behavior change in a discovery script | The matching `Claude_Docs/Design_*.md` (AD / Local-Windows / Local-Linux); `Claude_Docs/Reference_CSV-Schemas.md` if columns changed |
| New/changed config option or credential source | `Claude_Docs/Reference_Configuration.md` |
| New manual validation step or gotcha found while testing | `Claude_Docs/Testing_Guide.md` |
| Backlog item opened or closed | `Claude_Docs/Planning_Open-Items.md` |
| Any user-visible change (new CSV field, new script parameter, setup step) | One line in `Claude_Docs/Planning_User-Docs-Backlog.md`; update `User_Docs/` if it already covers that area |
| Anything the scanning host must have or allow (software, module, account right, port, folder, policy) | `Claude_Docs/Reference_Scanning-Host-Requirements.md`: add or update an `HR-*` row; never renumber IDs. If the install script can provide it, update `Install-aPeDiscovery.ps1` too |
| A new or changed network connection (destination, port, protocol) | `Claude_Docs/Reference_Network-Firewall-Requirements.md` and the matching `HR-NET-*` row |
| Changes to accounts/privileges, data collected, credential handling, or commands run on targets | `Claude_Docs/Reference_Security-Team-Brief.md` (including its findings table) |

- For "verify the docs are updated", use a subagent to diff the branch against this checklist and report the gaps only.

## Git
- Don't work directly on `main`. Create a topic branch named `YYYY-MM-DD-<topic>` and open a PR into `main` with `gh`.
- Commit, push, open a PR or merge only when asked. "Commit and push" means both.

## Live testing
- Lab environment details are in `Live-Testing.local.md` in the project root. That file is gitignored. **Read it only when a task involves live testing.** Never copy its contents into tracked files, commit messages or PR descriptions.
- If `Live-Testing.local.md` is missing, ask for the details. Don't guess.
- Live tests are defined by label (`LT-*`) in `Claude_Docs/Testing_Live-Test-Definitions.md`, with `{Placeholder}` values only. `Live-Testing.local.md` fills in the placeholders per environment and tracks which labels have run. Add new tests to the definitions file, never lab values.
- Never write secrets into any file, log or commit message, including `Live-Testing.local.md`. That file names *where* the credentials live, not the credentials themselves.
- When an example, doc or test needs a password placeholder, use `ThisIsMy_FAKE_Password6!`. It's obviously fake, and it satisfies typical complexity rules.
