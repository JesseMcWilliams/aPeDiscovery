# aPeDiscovery: Live Test Definitions

> **Stage: Testing.** Repeatable live tests against a real environment, each with a short label. This file is tracked, so it holds **no lab details**: every environment-specific value is a `{Placeholder}`. The gitignored `Live-Testing.local.md` supplies the values for each environment and lists which labels to run. Live tests run only when asked (see CLAUDE.md, "Live testing").

## How to use
1. Pick a label below and an environment from `Live-Testing.local.md`.
2. Replace each `{Placeholder}` with that environment's value.
3. Run the command from the repo root, and check every "Pass when" item.
4. Record the result (date, pass/fail) in `Live-Testing.local.md`'s "Tests to run" table, and in the matching `Testing_` checklist row if the project has one.

## Placeholders

Add a row for each value a test needs. Examples are fake, and show only the shape of the value.

| Placeholder | Meaning | Example (fake) |
|---|---|---|
| `{Profile}` | The saved profile or configuration name the tool runs with | `Lab_Automation` |
| `{Username}` | The account the test signs in as, when the output should be checked against it | `svc_example` |
| `{Shell}` | The PowerShell edition to run under: `powershell.exe -NoProfile -ExecutionPolicy Bypass` (5.1) or `pwsh -NoProfile` (7) | `pwsh -NoProfile` |
| `{OutputDir}` | A scratch folder for output, outside the repo | `C:\Temp\live-test` |

## Tests

### LT-EXAMPLE-01: Replace this example
One line on what the test proves, and what it needs first (other labels, one-time setup).

```powershell
{Shell} -File .\<Script>.ps1 -Profile '{Profile}' -OutputFolder '{OutputDir}'
```

- **Pass when:** the exit code is 0, and the output shows `Signed in as : {Username}`.
- **Notes:** anything that changes the result, such as token reuse, rate limits or required delays.

## Adding a test
- Group tests under a heading, and give each one the next label in its group (`LT-<GROUP>-<NN>`, for example `LT-LOGON-01`). Never reuse or renumber a label: `Live-Testing.local.md` refers to it.
- Use placeholders for every environment-specific value. Put real values only in `Live-Testing.local.md`.
- Each test needs a runnable command and concrete "Pass when" items, so it can be repeated by anyone, or by Claude, without rediscovering the steps.
- A password placeholder, if one is ever needed in an example, is `ThisIsMy_FAKE_Password6!`.
