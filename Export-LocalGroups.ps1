<#
.SYNOPSIS
    Discovers local users, local groups, and local group membership on a list
    of computers, and exports the results to CSV files for import into another
    tool.
.PARAMETER ComputersCsvPath
    Path to the input CSV of computers to scan. Defaults to
    .\Config\ComputersToScan.csv. See Config\ComputersToScan.example.csv for
    the expected columns (including per-computer credential pointers).
.PARAMETER ConfigPath
    Path to the JSON run configuration (output/log locations, retention,
    concurrency, filters). Defaults to .\Config\LocalScanConfig.json.
.PARAMETER ComputerFilter
    Optional list of ComputerName values to restrict this run to (for testing
    a single machine without editing the input CSV).
.OUTPUTS
    <OutputDirectory>\LocalUsers.csv
    <OutputDirectory>\LocalGroups.csv
    <OutputDirectory>\LocalGroupMembers.csv
    <OutputDirectory>\LocalDatabases.csv
    <OutputDirectory>\LocalSoftware.csv
    <OutputDirectory>\LocalScanErrors.csv
    <OutputDirectory>\LocalServiceAccounts.csv
    <OutputDirectory>\LocalDatabasesListening.csv
    <OutputDirectory>\LocalGmsaServiceAccounts.csv
    Timestamped copies of all nine are kept under <OutputDirectory>\Archive.
.NOTES
    Uses the ADSI WinNT provider (System.DirectoryServices) rather than
    PowerShell Remoting or CIM, so it works without WinRM/PSRemoting enabled
    on targets, as long as the account can authenticate over RPC/SAM (the same
    mechanism Computer Management's "Local Users and Groups" snap-in uses
    against a remote machine). Reachability is checked via a direct TCP
    connect to port 445 rather than ICMP, since ICMP can be blocked while 445
    (the actual dependency) is not.

    Computers are scanned through a runspace pool sized by the config's
    MaxConcurrency (default 1, i.e. sequential) - the same per-computer logic
    (Modules\LocalComputerScanner.psm1) runs whether MaxConcurrency is 1 or
    higher, so there is only one code path for what a "scan" means.

    Config can narrow what's captured: ExcludeUserNames/ExcludeGroupNames
    (exact names or wildcard patterns). See Docs\Configuration.md.

    Also detects known database engines from their Windows service names (the same WinNT bind
    already exposes Service-class children, confirmed live - no extra connectivity needed), and
    probes each detected engine's default port on that computer to report whether it's actually
    listening. The signature list (service name pattern -> engine/default port) defaults to
    Modules\LocalComputerScanner.psm1's Get-DefaultDatabaseSignatures, or can be overridden via
    DatabaseSignatures in LocalScanConfig.json.

    The same mechanism is available for arbitrary "other software" via SoftwareSignatures in
    LocalScanConfig.json (service name pattern -> name/category/optional default port) - unlike
    DatabaseSignatures, there is no built-in default list, since what counts as interesting "other
    software" is inherently environment-specific; nothing is checked unless SoftwareSignatures is
    populated. See Docs\Configuration.md for the steps to add entries to either list.

    A computer that fails is retried up to RetryCount additional times (default 0 - no retry),
    waiting RetryDelaySeconds between attempts, before being recorded as failed - useful for
    absorbing a transient network blip in an unattended nightly run. Every computer that still fails
    after retries gets a row in LocalScanErrors.csv (ComputerName, ErrorMessage), not just a log line,
    so a downstream tool can track failing hosts the same structured way it tracks everything else.

    Every service (not just ones matching DatabaseSignatures/SoftwareSignatures) has its logon
    ("Run As") account read and classified into BuiltIn/Virtual/Blank (excluded as noise) or
    User/LikelyGmsaOrMsa (kept in LocalServiceAccounts.csv) - this answers "what services run as
    this account" across the estate, which needs every service's account, not just recognized ones.
    The gMSA/MSA classification is a naming-convention heuristic (a trailing '$'), not an
    authoritative AD lookup - see Modules\LocalComputerScanner.psm1's Get-ServiceAccountType.

    LocalDatabasesListening.csv is the subset of LocalDatabases.csv where Listening = True - a
    convenience view, not a separate detection path; every row in it also still appears in
    LocalDatabases.csv. Likewise, LocalGmsaServiceAccounts.csv is the subset of
    LocalServiceAccounts.csv where AccountType = LikelyGmsaOrMsa, kept separately so it can be
    handed to an AD cross-reference step that flags any account in it that AD does NOT actually
    recognize as a real gMSA/MSA (a rogue or manually-named account impersonating the naming
    convention) - every row in it also still appears in LocalServiceAccounts.csv.

    Exit code 0 = every enabled computer succeeded. Exit code 1 = at least one
    computer failed (see the ERROR lines in the log, or LocalScanErrors.csv); other computers still ran.
#>
[CmdletBinding()]
param(
    [string] $ComputersCsvPath = (Join-Path $PSScriptRoot 'Config\ComputersToScan.csv'),
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'Config\LocalScanConfig.json'),
    [string[]] $ComputerFilter
)

$ErrorActionPreference = 'Stop'

$loggingModulePath = Join-Path $PSScriptRoot 'Modules\Logging.psm1'
$credentialModulePath = Join-Path $PSScriptRoot '..\aPeSecrets\Modules\CredentialResolver.psm1'
$networkModulePath = Join-Path $PSScriptRoot 'Modules\NetworkHelpers.psm1'
$scannerModulePath = Join-Path $PSScriptRoot 'Modules\LocalComputerScanner.psm1'

Import-Module $loggingModulePath -Force
Import-Module $credentialModulePath -Force
Import-Module $networkModulePath -Force
Import-Module $scannerModulePath -Force

if (-not (Test-Path -Path $ComputersCsvPath)) {
    throw "Computers CSV not found at '$ComputersCsvPath'. See Config\ComputersToScan.example.csv."
}
if (-not (Test-Path -Path $ConfigPath)) {
    throw "Configuration file not found at '$ConfigPath'. See Config\LocalScanConfig.example.json."
}
$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
if (-not $config.OutputDirectory) { throw "Config is missing required property 'OutputDirectory'." }

New-Item -ItemType Directory -Path $config.OutputDirectory -Force | Out-Null
$logDirectory = if ($config.LogDirectory) { $config.LogDirectory } else { Join-Path $config.OutputDirectory 'Logs' }
$logPath = Initialize-DiscoveryLog -LogDirectory $logDirectory -BaseName 'Export-LocalGroups'

$maxConcurrency = if ($config.MaxConcurrency) { [int]$config.MaxConcurrency } else { 1 }
if ($maxConcurrency -lt 1) { throw "Config 'MaxConcurrency' must be 1 or greater." }
$connectTimeoutMs = if ($config.ConnectTimeoutMs) { [int]$config.ConnectTimeoutMs } else { 2000 }
$excludeUserNames = if ($config.ExcludeUserNames) { @($config.ExcludeUserNames) } else { @() }
$excludeGroupNames = if ($config.ExcludeGroupNames) { @($config.ExcludeGroupNames) } else { @() }
$databaseSignatures = if ($config.DatabaseSignatures) { @($config.DatabaseSignatures) } else { @(Get-DefaultDatabaseSignatures) }
$softwareSignatures = if ($config.SoftwareSignatures) { @($config.SoftwareSignatures) } else { @() }
$retryCount = if ($config.RetryCount) { [int]$config.RetryCount } else { 0 }
$retryDelaySeconds = if ($config.RetryDelaySeconds) { [int]$config.RetryDelaySeconds } else { 5 }

Write-DiscoveryLog -LogPath $logPath -Message "Starting local group export using computers list '$ComputersCsvPath' (MaxConcurrency=$maxConcurrency)."

$computers = Import-Csv -Path $ComputersCsvPath
$scanTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

$userRows = [System.Collections.Generic.List[object]]::new()
$groupRows = [System.Collections.Generic.List[object]]::new()
$memberRows = [System.Collections.Generic.List[object]]::new()
$databaseRows = [System.Collections.Generic.List[object]]::new()
$softwareRows = [System.Collections.Generic.List[object]]::new()
$scanErrorRows = [System.Collections.Generic.List[object]]::new()
$serviceAccountRows = [System.Collections.Generic.List[object]]::new()
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
# ImportPSModule(string[]) must be called once per module path here, not once with all four paths
# in a single array - confirmed live: passing all four at once silently resolves to a *different*
# overload that joins them into one space-separated string and then fails to import anything,
# with no error surfaced until a runspace tries to call a command none of the modules actually
# loaded.
foreach ($modulePath in @($loggingModulePath, $credentialModulePath, $networkModulePath, $scannerModulePath)) {
    $iss.ImportPSModule(@($modulePath))
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
        [void]$ps.AddCommand('Invoke-LocalComputerScan').AddParameters(@{
            ComputerName      = $row.ComputerName
            CredentialSource  = $row.CredentialSource
            CredentialParams  = $credentialParams
            ScanTimestamp     = $scanTimestamp
            LogPath           = $logPath
            ConnectTimeoutMs  = $connectTimeoutMs
            ExcludeUserNames   = $excludeUserNames
            ExcludeGroupNames  = $excludeGroupNames
            DatabaseSignatures = $databaseSignatures
            SoftwareSignatures = $softwareSignatures
            RetryCount         = $retryCount
            RetryDelaySeconds  = $retryDelaySeconds
        })

        $jobs.Add([pscustomobject]@{
            ComputerName = $row.ComputerName
            PowerShell   = $ps
            Handle       = $ps.BeginInvoke()
        })
    }

    foreach ($job in $jobs) {
        $scanResults = $null
        try {
            $scanResults = $job.PowerShell.EndInvoke($job.Handle)
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

        foreach ($result in $scanResults) {
            if ($result.Success) {
                foreach ($u in $result.UserRows) { $userRows.Add($u) }
                foreach ($g in $result.GroupRows) { $groupRows.Add($g) }
                foreach ($m in $result.MemberRows) { $memberRows.Add($m) }
                foreach ($d in $result.DatabaseRows) { $databaseRows.Add($d) }
                foreach ($s in $result.SoftwareRows) { $softwareRows.Add($s) }
                foreach ($sa in $result.ServiceAccountRows) { $serviceAccountRows.Add($sa) }
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

$usersCsvPath = Join-Path $config.OutputDirectory 'LocalUsers.csv'
$groupsCsvPath = Join-Path $config.OutputDirectory 'LocalGroups.csv'
$membersCsvPath = Join-Path $config.OutputDirectory 'LocalGroupMembers.csv'
$databasesCsvPath = Join-Path $config.OutputDirectory 'LocalDatabases.csv'
$softwareCsvPath = Join-Path $config.OutputDirectory 'LocalSoftware.csv'
$scanErrorsCsvPath = Join-Path $config.OutputDirectory 'LocalScanErrors.csv'
$serviceAccountsCsvPath = Join-Path $config.OutputDirectory 'LocalServiceAccounts.csv'
$listeningDatabasesCsvPath = Join-Path $config.OutputDirectory 'LocalDatabasesListening.csv'
$gmsaServiceAccountsCsvPath = Join-Path $config.OutputDirectory 'LocalGmsaServiceAccounts.csv'

# Both are convenience views derived from data already collected above, not separate detection
# paths - every row in either one also still appears in its full source file.
$listeningDatabaseRows = @($databaseRows | Where-Object { $_.Listening -eq $true })
$gmsaServiceAccountRows = @($serviceAccountRows | Where-Object { $_.AccountType -eq 'LikelyGmsaOrMsa' })

$userRows | Export-Csv -Path $usersCsvPath -NoTypeInformation -Encoding UTF8
$groupRows | Export-Csv -Path $groupsCsvPath -NoTypeInformation -Encoding UTF8
$memberRows | Export-Csv -Path $membersCsvPath -NoTypeInformation -Encoding UTF8
$databaseRows | Export-Csv -Path $databasesCsvPath -NoTypeInformation -Encoding UTF8
$softwareRows | Export-Csv -Path $softwareCsvPath -NoTypeInformation -Encoding UTF8
$scanErrorRows | Export-Csv -Path $scanErrorsCsvPath -NoTypeInformation -Encoding UTF8
$serviceAccountRows | Export-Csv -Path $serviceAccountsCsvPath -NoTypeInformation -Encoding UTF8
$listeningDatabaseRows | Export-Csv -Path $listeningDatabasesCsvPath -NoTypeInformation -Encoding UTF8
$gmsaServiceAccountRows | Export-Csv -Path $gmsaServiceAccountsCsvPath -NoTypeInformation -Encoding UTF8

$archiveDirectory = Join-Path $config.OutputDirectory 'Archive'
New-Item -ItemType Directory -Path $archiveDirectory -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
Copy-Item -Path $usersCsvPath -Destination (Join-Path $archiveDirectory "LocalUsers_$stamp.csv")
Copy-Item -Path $groupsCsvPath -Destination (Join-Path $archiveDirectory "LocalGroups_$stamp.csv")
Copy-Item -Path $membersCsvPath -Destination (Join-Path $archiveDirectory "LocalGroupMembers_$stamp.csv")
Copy-Item -Path $databasesCsvPath -Destination (Join-Path $archiveDirectory "LocalDatabases_$stamp.csv")
Copy-Item -Path $softwareCsvPath -Destination (Join-Path $archiveDirectory "LocalSoftware_$stamp.csv")
Copy-Item -Path $scanErrorsCsvPath -Destination (Join-Path $archiveDirectory "LocalScanErrors_$stamp.csv")
Copy-Item -Path $serviceAccountsCsvPath -Destination (Join-Path $archiveDirectory "LocalServiceAccounts_$stamp.csv")
Copy-Item -Path $listeningDatabasesCsvPath -Destination (Join-Path $archiveDirectory "LocalDatabasesListening_$stamp.csv")
Copy-Item -Path $gmsaServiceAccountsCsvPath -Destination (Join-Path $archiveDirectory "LocalGmsaServiceAccounts_$stamp.csv")

$retentionCount = if ($config.ArchiveRetentionCount) { [int]$config.ArchiveRetentionCount } else { 30 }
foreach ($prefix in 'LocalUsers', 'LocalGroups', 'LocalGroupMembers', 'LocalDatabases', 'LocalSoftware', 'LocalScanErrors', 'LocalServiceAccounts', 'LocalDatabasesListening', 'LocalGmsaServiceAccounts') {
    Get-ChildItem -Path $archiveDirectory -Filter "$prefix`_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -Skip $retentionCount | Remove-Item -Force
}

Write-DiscoveryLog -LogPath $logPath -Message "Export complete. Users: $($userRows.Count), groups: $($groupRows.Count), membership rows: $($memberRows.Count), database services: $($databaseRows.Count) ($($listeningDatabaseRows.Count) listening), other software services: $($softwareRows.Count), failed computers: $($scanErrorRows.Count), service accounts of interest: $($serviceAccountRows.Count) ($($gmsaServiceAccountRows.Count) likely gMSA/MSA)."

if ($hadFailures) {
    Write-DiscoveryLog -Level WARN -LogPath $logPath -Message 'One or more computers failed; see ERROR entries above.'
    exit 1
}
exit 0
