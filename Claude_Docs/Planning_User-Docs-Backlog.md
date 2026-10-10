# aPeDiscovery: User Docs Backlog

> **Stage: Planning.** Add one line per user-visible change when it's made. At the end of the project, `User_Docs/` is written from this list instead of re-reading the project history. Once an entry is covered in `User_Docs/`, delete it.

| Date | Change | User doc / section it affects |
|---|---|---|
| 2026-10-09 | New `Install-aPeDiscovery.ps1`: installs or updates PowerShell 7, the three repositories, Posh-SSH and the AD module; offline bundles via `-DownloadOnly`/`-PackagePath`. | Installation (new section); Scheduled-Task-Setup's deployment note |
| 2026-10-09 | `Export-ADGroups.ps1` renamed to `Export-ADObjects.ps1`; output CSV names unchanged. Existing Scheduled Tasks must point at the new name. | Scheduled-Task-Setup (updated); any setup/upgrade notes |
| 2026-10-09 | Logging now uses the sibling LogaPe module (must be checked out next to aPeDiscovery). Log lines read `<timestamp> \| <Level> \| <message>`, with levels `Information`/`Warning`/`Error` instead of `INFO`/`WARN`/`ERROR`. Secret-looking `key=value`/`key: value` text (password, token, secret, apikey, connectionstring) is masked as `***` in logs. | Prerequisites/install; log monitoring or alerting |
| 2026-10-09 | PowerShell 7 is the recommended runtime; 5.1 still works. CSVs are UTF-8 with a byte-order mark on both. | Prerequisites |
| 2026-10-09 | New `LinuxLocalUsers.csv` column `BadPasswordAttempts` (pam_faillock count; blank when not tracked or no sudo). | Linux output reference |
| 2026-10-09 | Linux scans refuse SSH hosts whose key isn't trusted yet (`AcceptNewHostKey` now defaults to `false`). Enroll each host once with `New-SSHTrustedHost` as the task account after checking its fingerprint. | Linux setup; Scheduled-Task-Setup |
