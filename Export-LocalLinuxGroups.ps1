<#
.SYNOPSIS
    Discovers local users, local groups, local group membership, and per-account
    sudo rights on a list of Linux computers over SSH, and exports the results to
    CSV files for import into another tool.
.PARAMETER ComputersCsvPath
    Path to the input CSV of computers to scan. Defaults to
    .\Config\LinuxComputersToScan.csv. See Config\LinuxComputersToScan.example.csv
    for the expected columns (including per-computer credential pointers).
.PARAMETER ConfigPath
    Path to the JSON run configuration (output/log locations, retention,
    concurrency, timeouts). Defaults to .\Config\LinuxScanConfig.json.
.PARAMETER ComputerFilter
    Optional list of ComputerName values to restrict this run to (for testing
    a single machine without editing the input CSV).
.OUTPUTS
    <OutputDirectory>\LinuxLocalUsers.csv
    <OutputDirectory>\LinuxLocalGroups.csv
    <OutputDirectory>\LinuxLocalGroupMembers.csv
    <OutputDirectory>\LinuxSudoRights.csv
    <OutputDirectory>\LinuxScanErrors.csv
    Timestamped copies of all five are kept under <OutputDirectory>\Archive.
.NOTES
    Connects over SSH using the Posh-SSH module (New-SSHSession/Invoke-SSHCommand/
    Remove-SSHSession) - chosen over plink.exe per project direction, and verified
    live against a real Ubuntu VM. Reachability is checked via a direct TCP connect
    to port 22, the same pattern Export-LocalGroups.ps1 uses for port 445.

    Computers are scanned through a runspace pool sized by the config's
    MaxConcurrency (default 1, i.e. sequential) - this mirrors Export-LocalGroups.ps1's
    architecture exactly, including the requirement to call
    InitialSessionState.ImportPSModule() once per module path rather than once with
    every path in a single array (confirmed live to silently fail on the Windows
    tool - see Modules\LocalComputerScanner.psm1's equivalent note).

    Every discovered account's `sudo -n -l -U <user>` output is captured in one
    remote command per computer (a single bash for-loop, one SSH round trip),
    rather than one Invoke-SSHCommand call per account, which would multiply SSH
    round trips by the number of accounts on the box.

    Password-state fields (PasswordState/PasswordLastSet/PasswordNeverExpires) and
    sudo rights both depend on the connecting account having usable sudo access;
    when it doesn't, sudo itself fails fast (confirmed live: no password prompt,
    no hang) and those fields/rows are simply left blank/None rather than causing
    the scan to fail - see Modules\LocalLinuxComputerScanner.psm1.

    This is a first implementation covering Phase 1-4 of
    Docs\Design-Local-Linux-Discovery.md (connectivity, users/groups/membership,
    password-aging fields, sudo rights). Phase 5 (LinuxDatabases.csv/
    LinuxSoftware.csv/LinuxServiceAccounts.csv) and per-account SSH login
    eligibility are designed but not yet implemented - see the design doc's
    Progress Tracker for what's left.

    Exit code 0 = every enabled computer succeeded. Exit code 1 = at least one
    computer failed (see the ERROR lines in the log, or LinuxScanErrors.csv);
    other computers still ran.
#>
[CmdletBinding()]
param(
    [string] $ComputersCsvPath = (Join-Path $PSScriptRoot 'Config\LinuxComputersToScan.csv'),
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'Config\LinuxScanConfig.json'),
    [string[]] $ComputerFilter
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    throw "The Posh-SSH module is required (Install-Module Posh-SSH) but was not found."
}

$loggingModulePath = Join-Path $PSScriptRoot 'Modules\Logging.psm1'
$credentialModulePath = Join-Path $PSScriptRoot 'Modules\CredentialResolver.psm1'
$networkModulePath = Join-Path $PSScriptRoot 'Modules\NetworkHelpers.psm1'
$scannerModulePath = Join-Path $PSScriptRoot 'Modules\LocalLinuxComputerScanner.psm1'
$poshSshModulePath = (Get-Module -ListAvailable -Name Posh-SSH | Select-Object -First 1).Path

Import-Module $loggingModulePath -Force
Import-Module $credentialModulePath -Force
Import-Module $networkModulePath -Force
Import-Module $scannerModulePath -Force
Import-Module Posh-SSH -Force

if (-not (Test-Path -Path $ComputersCsvPath)) {
    throw "Computers CSV not found at '$ComputersCsvPath'. See Config\LinuxComputersToScan.example.csv."
}
if (-not (Test-Path -Path $ConfigPath)) {
    throw "Configuration file not found at '$ConfigPath'. See Config\LinuxScanConfig.example.json."
}
$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
if (-not $config.OutputDirectory) { throw "Config is missing required property 'OutputDirectory'." }

New-Item -ItemType Directory -Path $config.OutputDirectory -Force | Out-Null
$logDirectory = if ($config.LogDirectory) { $config.LogDirectory } else { Join-Path $config.OutputDirectory 'Logs' }
$logPath = Initialize-DiscoveryLog -LogDirectory $logDirectory -BaseName 'Export-LocalLinuxGroups'

$maxConcurrency = if ($config.MaxConcurrency) { [int]$config.MaxConcurrency } else { 1 }
if ($maxConcurrency -lt 1) { throw "Config 'MaxConcurrency' must be 1 or greater." }
$connectTimeoutMs = if ($config.ConnectTimeoutMs) { [int]$config.ConnectTimeoutMs } else { 2000 }
$sshConnectTimeoutSeconds = if ($config.SshConnectTimeoutSeconds) { [int]$config.SshConnectTimeoutSeconds } else { 15 }
$commandTimeoutSeconds = if ($config.CommandTimeoutSeconds) { [int]$config.CommandTimeoutSeconds } else { 60 }
$acceptNewHostKey = if ($null -ne $config.AcceptNewHostKey) { [bool]$config.AcceptNewHostKey } else { $true }
$retryCount = if ($config.RetryCount) { [int]$config.RetryCount } else { 0 }
$retryDelaySeconds = if ($config.RetryDelaySeconds) { [int]$config.RetryDelaySeconds } else { 5 }

Write-DiscoveryLog -LogPath $logPath -Message "Starting Linux local discovery export using computers list '$ComputersCsvPath' (MaxConcurrency=$maxConcurrency)."

$computers = Import-Csv -Path $ComputersCsvPath
$scanTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$userRows = [System.Collections.Generic.List[object]]::new()
$groupRows = [System.Collections.Generic.List[object]]::new()
$memberRows = [System.Collections.Generic.List[object]]::new()
$sudoRightsRows = [System.Collections.Generic.List[object]]::new()
$scanErrorRows = [System.Collections.Generic.List[object]]::new()
$hadFailures = $false

$targets = [System.Collections.Generic.List[object]]::new()
foreach ($row in $computers) {
    if ($row.PSObject.Properties['Enabled'] -and $row.Enabled -match '^(0|false)$') {
        Write-DiscoveryLog -LogPath $logPath -Message "Skipping disabled entry '$($row.ComputerName)'."
        continue
    }
    if ($ComputerFilter -and ($row.ComputerName -notin $ComputerFilter)) {
        continue
    }
    $targets.Add($row)
}

if ($targets.Count -eq 0) {
    Write-DiscoveryLog -Level WARN -LogPath $logPath -Message 'No enabled computers matched; nothing to scan.'
}

$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
# Same real bug as Export-LocalGroups.ps1: ImportPSModule(string[]) must be called once per path.
foreach ($modulePath in @($loggingModulePath, $credentialModulePath, $networkModulePath, $scannerModulePath, $poshSshModulePath)) {
    if ($modulePath) { $iss.ImportPSModule(@($modulePath)) }
}
$pool = [runspacefactory]::CreateRunspacePool(1, $maxConcurrency, $iss, $Host)
$pool.Open()

$jobs = [System.Collections.Generic.List[object]]::new()

try {
    foreach ($row in $targets) {
        $credentialParams = @{}
        if ($row.CredentialParamsJson) {
            ($row.CredentialParamsJson | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $credentialParams[$_.Name] = $_.Value }
        }

        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddCommand('Invoke-LocalLinuxComputerScan').AddParameters(@{
            ComputerName              = $row.ComputerName
            CredentialSource          = $row.CredentialSource
            CredentialParams          = $credentialParams
            ScanTimestamp             = $scanTimestamp
            LogPath                   = $logPath
            ConnectTimeoutMs          = $connectTimeoutMs
            SshConnectTimeoutSeconds  = $sshConnectTimeoutSeconds
            CommandTimeoutSeconds     = $commandTimeoutSeconds
            AcceptNewHostKey          = $acceptNewHostKey
            RetryCount                = $retryCount
            RetryDelaySeconds         = $retryDelaySeconds
        })

        $jobs.Add([pscustomobject]@{
            ComputerName = $row.ComputerName
            PowerShell   = $ps
            Handle       = $ps.BeginInvoke()
        })
    }

    foreach ($job in $jobs) {
        $scanResult = $null
        try {
            $scanResult = $job.PowerShell.EndInvoke($job.Handle)
        } catch {
            $hadFailures = $true
            Write-DiscoveryLog -Level ERROR -LogPath $logPath -Message "Computer '$($job.ComputerName)' failed unexpectedly: $($_.Exception.Message)"
            $scanErrorRows.Add([pscustomobject]@{
                ScanTimestamp = $scanTimestamp
                ComputerName  = $job.ComputerName
                ErrorMessage  = $_.Exception.Message
            })
            continue
        } finally {
            $job.PowerShell.Dispose()
        }

        foreach ($result in $scanResult) {
            if ($result.Success) {
                foreach ($u in $result.UserRows) { $userRows.Add($u) }
                foreach ($g in $result.GroupRows) { $groupRows.Add($g) }
                foreach ($m in $result.MemberRows) { $memberRows.Add($m) }
                foreach ($s in $result.SudoRightsRows) { $sudoRightsRows.Add($s) }
            } else {
                $hadFailures = $true
                $scanErrorRows.Add([pscustomobject]@{
                    ScanTimestamp = $scanTimestamp
                    ComputerName  = $result.ComputerName
                    ErrorMessage  = $result.ErrorMessage
                })
            }
        }
    }
} finally {
    $pool.Close()
    $pool.Dispose()
}

$usersCsvPath = Join-Path $config.OutputDirectory 'LinuxLocalUsers.csv'
$groupsCsvPath = Join-Path $config.OutputDirectory 'LinuxLocalGroups.csv'
$membersCsvPath = Join-Path $config.OutputDirectory 'LinuxLocalGroupMembers.csv'
$sudoRightsCsvPath = Join-Path $config.OutputDirectory 'LinuxSudoRights.csv'
$scanErrorsCsvPath = Join-Path $config.OutputDirectory 'LinuxScanErrors.csv'

$userRows | Export-Csv -Path $usersCsvPath -NoTypeInformation -Encoding UTF8
$groupRows | Export-Csv -Path $groupsCsvPath -NoTypeInformation -Encoding UTF8
$memberRows | Export-Csv -Path $membersCsvPath -NoTypeInformation -Encoding UTF8
$sudoRightsRows | Export-Csv -Path $sudoRightsCsvPath -NoTypeInformation -Encoding UTF8
$scanErrorRows | Export-Csv -Path $scanErrorsCsvPath -NoTypeInformation -Encoding UTF8

$archiveDirectory = Join-Path $config.OutputDirectory 'Archive'
New-Item -ItemType Directory -Path $archiveDirectory -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
Copy-Item -Path $usersCsvPath -Destination (Join-Path $archiveDirectory "LinuxLocalUsers_$stamp.csv")
Copy-Item -Path $groupsCsvPath -Destination (Join-Path $archiveDirectory "LinuxLocalGroups_$stamp.csv")
Copy-Item -Path $membersCsvPath -Destination (Join-Path $archiveDirectory "LinuxLocalGroupMembers_$stamp.csv")
Copy-Item -Path $sudoRightsCsvPath -Destination (Join-Path $archiveDirectory "LinuxSudoRights_$stamp.csv")
Copy-Item -Path $scanErrorsCsvPath -Destination (Join-Path $archiveDirectory "LinuxScanErrors_$stamp.csv")

$retentionCount = if ($config.ArchiveRetentionCount) { [int]$config.ArchiveRetentionCount } else { 30 }
foreach ($prefix in 'LinuxLocalUsers', 'LinuxLocalGroups', 'LinuxLocalGroupMembers', 'LinuxSudoRights', 'LinuxScanErrors') {
    Get-ChildItem -Path $archiveDirectory -Filter "$prefix`_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -Skip $retentionCount | Remove-Item -Force
}

Write-DiscoveryLog -LogPath $logPath -Message "Export complete. Users: $($userRows.Count), groups: $($groupRows.Count), membership rows: $($memberRows.Count), sudo-rights rows: $($sudoRightsRows.Count), failed computers: $($scanErrorRows.Count)."

if ($hadFailures) {
    Write-DiscoveryLog -Level WARN -LogPath $logPath -Message 'One or more computers failed; see ERROR entries above.'
    exit 1
}
exit 0
