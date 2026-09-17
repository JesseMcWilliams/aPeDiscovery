# Scheduled Task setup

All three scripts return a process exit code (`0` success, `1` one or more domains/computers failed) and write their own timestamped log file, so a Scheduled Task only needs to run `powershell.exe`/`pwsh.exe` and can rely on the exit code for basic pass/fail alerting.

## Register with PowerShell (`ScheduledTasks` module)

Run this as the account that will own the task (or `-Credential` to target a different Run As account). Adjust paths, `-At` time, and the Run As account for your environment.

```powershell
$action = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\aPeDiscovery\Export-ADGroups.ps1"' `
    -WorkingDirectory 'C:\aPeDiscovery'

$trigger = New-ScheduledTaskTrigger -Daily -At 2:00am

$principal = New-ScheduledTaskPrincipal `
    -UserId 'CONTOSO\svc-apediscovery' `
    -LogonType Password `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopOnIdleEnd `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Register-ScheduledTask -TaskName 'aPeDiscovery - AD Group Export' `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# Register-ScheduledTask prompts for the Run As account's password interactively
# unless you pass -User/-Password to Register-ScheduledTask directly instead of
# building a Principal; consult `Get-Help Register-ScheduledTask -Full` for the
# exact parameter set on your PowerShell version.
```

Repeat with a second action pointing at `Export-LocalGroups.ps1` for the local Windows-computer discovery task, and a third pointing at `Export-LocalLinuxGroups.ps1` for the Linux discovery task, each on whatever schedule fits (none needs to run at the same time as the others).

## Credential separation

Keep two credential concerns distinct:

1. **The Task Scheduler Run As account** — the identity `powershell.exe` itself runs as. This account needs local logon rights on the host running the script, (for `Export-ADGroups.ps1`) the RSAT `ActiveDirectory` PowerShell module installed, and (for `Export-LocalLinuxGroups.ps1`) the `Posh-SSH` PowerShell module installed. It does **not** need rights in the target domains/computers if every domain/computer entry uses `CP`/`CCP`/`Conjur`/`PSCredential` rather than `CurrentUser`.
2. **The per-domain / per-computer scan credentials** — resolved at runtime by `CredentialResolver.psm1` from CyberArk (or a pre-exported `PSCredential` file), as configured in `ScanConfig.json` / `ComputersToScan.csv` / `LinuxComputersToScan.csv`. These are what actually authenticate to each target domain/computer.

## Monitoring

- Check the process exit code (`$LASTEXITCODE` if invoked from a wrapper script, or the Task Scheduler task's "Last Run Result") to detect partial failures.
- The per-run log file under `<OutputDirectory>\Logs` contains one `ERROR` line per failed domain/computer with the underlying exception message, while the run otherwise continues.
