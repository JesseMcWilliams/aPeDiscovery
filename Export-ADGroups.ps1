<#
.SYNOPSIS
    Exports Active Directory group and direct-membership details for one or more
    domains, as configured in a JSON config file, to CSV files for import into
    another tool.
.PARAMETER ConfigPath
    Path to the JSON scan configuration. Defaults to .\Config\ScanConfig.json.
.PARAMETER DomainFilter
    Optional list of DomainName values to restrict this run to (for testing a
    single domain without editing the config).
.OUTPUTS
    <OutputDirectory>\ADGroups.csv
    <OutputDirectory>\ADGroupMembers.csv
    <OutputDirectory>\ADComputers.csv (only when at least one domain has a Computers block configured)
    Timestamped copies are kept under <OutputDirectory>\Archive.
.NOTES
    Exit code 0 = every enabled domain succeeded. Exit code 1 = at least one
    domain failed (see the ERROR lines in the log); other domains still ran.

    Per-domain config can narrow what's exported: ExcludeOUs (skip a sub-tree
    within an otherwise-scanned base), IncludeGroupCategories/IncludeGroupScopes
    (only Security/Distribution, or only DomainLocal/Global/Universal groups),
    and ExcludeGroupNames (exact names or wildcard patterns, matched against
    SamAccountName). See Docs\Configuration.md.

    Computer object discovery is opt-in per domain: only runs when that domain's
    config entry has a 'Computers' property (even an empty object enables it with
    defaults). It has its own independent BaseOU/OUDepth/ExcludeOUs - separate
    from the group scan's, since computers and groups are commonly organized
    under different parts of the tree - plus NameFilter and OSTypeFilter
    (wildcard patterns; a computer is included only if it matches at least one
    pattern in each filter that's set). OSTypeFilter matches AD's own
    'operatingSystem' attribute, which a computer sets itself at domain-join
    time and only refreshes periodically - it can be blank or stale, not a
    live, verified fact about what's actually running today. See
    Docs\Configuration.md.
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'Config\ScanConfig.json'),
    [string[]] $DomainFilter
)

$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Modules\Logging.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\aPeSecrets\Modules\CredentialResolver.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Modules\ADHelpers.psm1') -Force

if (-not (Test-Path -Path $ConfigPath)) {
    throw "Configuration file not found at '$ConfigPath'. See Config\ScanConfig.example.json."
}
$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

if (-not $config.OutputDirectory) { throw "Config is missing required property 'OutputDirectory'." }
if (-not $config.Domains -or $config.Domains.Count -eq 0) { throw "Config must define at least one entry in 'Domains'." }

New-Item -ItemType Directory -Path $config.OutputDirectory -Force | Out-Null
$logDirectory = if ($config.LogDirectory) { $config.LogDirectory } else { Join-Path $config.OutputDirectory 'Logs' }
$logPath = Initialize-DiscoveryLog -LogDirectory $logDirectory -BaseName 'Export-ADGroups'

Write-DiscoveryLog -LogPath $logPath -Message "Starting AD group export using config '$ConfigPath'."

$scanTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$groupRows = [System.Collections.Generic.List[object]]::new()
$memberRows = [System.Collections.Generic.List[object]]::new()
$computerRows = [System.Collections.Generic.List[object]]::new()
$hadFailures = $false

foreach ($domain in $config.Domains) {

    if ($domain.PSObject.Properties['Enabled'] -and -not $domain.Enabled) {
        Write-DiscoveryLog -LogPath $logPath -Message "Skipping disabled domain entry '$($domain.DomainName)'."
        continue
    }
    if ($DomainFilter -and ($domain.DomainName -notin $DomainFilter)) {
        continue
    }

    Write-DiscoveryLog -LogPath $logPath -Message "Starting scan of domain '$($domain.DomainName)'."
    try {
        $credentialParams = @{}
        if ($domain.CredentialParams) {
            $domain.CredentialParams.PSObject.Properties | ForEach-Object { $credentialParams[$_.Name] = $_.Value }
        }
        $credential = Get-ResolvedCredential -Source $domain.CredentialSource -Params $credentialParams -LogPath $logPath

        $adParams = @{ Server = if ($domain.Server) { $domain.Server } else { $domain.DomainName } }
        if ($credential) { $adParams.Credential = $credential }

        $baseOU = if ($domain.BaseOU) { $domain.BaseOU } else { (Get-ADDomain @adParams).DistinguishedName }
        $ouDepth = if ($null -ne $domain.OUDepth) { [int]$domain.OUDepth } else { -1 }

        $searchBases = Get-ScopedOrganizationalUnits -BaseOU $baseOU -Depth $ouDepth -AdParams $adParams

        $excludeOUs = if ($domain.ExcludeOUs) { @($domain.ExcludeOUs) } else { @() }
        if ($excludeOUs.Count -gt 0) {
            $beforeCount = $searchBases.Count
            $searchBases = @($searchBases | Where-Object {
                $candidateOU = $_
                -not ($excludeOUs | Where-Object { $candidateOU -eq $_ -or $candidateOU -like "*,$_" })
            })
            Write-DiscoveryLog -LogPath $logPath -Message "Domain '$($domain.DomainName)': excluded $($beforeCount - $searchBases.Count) OU(s) via ExcludeOUs."
        }

        Write-DiscoveryLog -LogPath $logPath -Message "Domain '$($domain.DomainName)': scanning $($searchBases.Count) OU(s) under '$baseOU' (depth $ouDepth)."

        $includeGroupCategories = if ($domain.IncludeGroupCategories) { @($domain.IncludeGroupCategories) } else { @() }
        $includeGroupScopes = if ($domain.IncludeGroupScopes) { @($domain.IncludeGroupScopes) } else { @() }
        $excludeGroupNames = if ($domain.ExcludeGroupNames) { @($domain.ExcludeGroupNames) } else { @() }

        foreach ($category in $includeGroupCategories) {
            if ($category -notin @('Security', 'Distribution')) {
                throw "Invalid IncludeGroupCategories value '$category'. Must be 'Security' or 'Distribution'."
            }
        }
        foreach ($scope in $includeGroupScopes) {
            if ($scope -notin @('DomainLocal', 'Global', 'Universal')) {
                throw "Invalid IncludeGroupScopes value '$scope'. Must be 'DomainLocal', 'Global', or 'Universal'."
            }
        }

        $memberCache = @{}
        $domainGroupCount = 0
        $domainFilteredGroupCount = 0

        foreach ($ou in $searchBases) {
            $groups = Get-ADGroup -SearchBase $ou -SearchScope OneLevel -Filter * `
                -Properties Description, ManagedBy, whenCreated, whenChanged, member @adParams

            foreach ($group in $groups) {
                if ($includeGroupCategories.Count -gt 0 -and $group.GroupCategory -notin $includeGroupCategories) {
                    $domainFilteredGroupCount++
                    continue
                }
                if ($includeGroupScopes.Count -gt 0 -and $group.GroupScope -notin $includeGroupScopes) {
                    $domainFilteredGroupCount++
                    continue
                }
                if ($excludeGroupNames.Count -gt 0 -and ($excludeGroupNames | Where-Object { $group.SamAccountName -like $_ })) {
                    $domainFilteredGroupCount++
                    continue
                }

                $domainGroupCount++
                $groupRows.Add([pscustomobject]@{
                    ScanTimestamp     = $scanTimestamp
                    DomainName        = $domain.DomainName
                    GroupName         = $group.SamAccountName
                    DistinguishedName = $group.DistinguishedName
                    ObjectGUID        = $group.ObjectGUID
                    SID               = $group.SID.Value
                    GroupCategory     = $group.GroupCategory
                    GroupScope        = $group.GroupScope
                    Description       = $group.Description
                    ManagedBy         = $group.ManagedBy
                    WhenCreated       = $group.whenCreated
                    WhenChanged       = $group.whenChanged
                    ParentOU          = $ou
                    MemberCount       = $group.member.Count
                })

                # Prefer Get-ADGroupMember (direct members only, no -Recursive) for
                # clean SamAccountName/ObjectClass/SID resolution. It is known to
                # fail on some foreignSecurityPrincipal members from trusted
                # domains, so fall back to resolving the raw 'member' DNs.
                $members = $null
                try {
                    $members = Get-ADGroupMember -Identity $group.DistinguishedName @adParams -ErrorAction Stop |
                        ForEach-Object {
                            [pscustomobject]@{
                                Name        = if ($_.SamAccountName) { $_.SamAccountName } else { $_.Name }
                                DN          = $_.DistinguishedName
                                SID         = if ($_.SID) { $_.SID.Value } else { $null }
                                ObjectClass = $_.objectClass
                            }
                        }
                } catch {
                    Write-DiscoveryLog -Level WARN -LogPath $logPath -Message "Get-ADGroupMember failed for '$($group.SamAccountName)' ($($_.Exception.Message)); falling back to raw member DN resolution."
                    $members = foreach ($memberDN in $group.member) {
                        if (-not $memberCache.ContainsKey($memberDN)) {
                            try {
                                $obj = Get-ADObject -Identity $memberDN -Properties SamAccountName, ObjectSid @adParams
                                $memberCache[$memberDN] = [pscustomobject]@{
                                    Name        = if ($obj.SamAccountName) { $obj.SamAccountName } else { $obj.Name }
                                    DN          = $obj.DistinguishedName
                                    SID         = if ($obj.ObjectSid) { $obj.ObjectSid.Value } else { $null }
                                    ObjectClass = $obj.ObjectClass
                                }
                            } catch {
                                Write-DiscoveryLog -Level WARN -LogPath $logPath -Message "Could not resolve member '$memberDN' of group '$($group.SamAccountName)': $($_.Exception.Message)"
                                $memberCache[$memberDN] = [pscustomobject]@{ Name = $memberDN; DN = $memberDN; SID = $null; ObjectClass = 'unknown' }
                            }
                        }
                        $memberCache[$memberDN]
                    }
                }

                foreach ($member in $members) {
                    $memberRows.Add([pscustomobject]@{
                        ScanTimestamp          = $scanTimestamp
                        DomainName             = $domain.DomainName
                        GroupName              = $group.SamAccountName
                        GroupDistinguishedName = $group.DistinguishedName
                        GroupSID               = $group.SID.Value
                        MemberName             = $member.Name
                        MemberDistinguishedName = $member.DN
                        MemberSID              = $member.SID
                        MemberObjectClass      = $member.ObjectClass
                    })
                }
            }
        }

        Write-DiscoveryLog -LogPath $logPath -Message "Completed scan of domain '$($domain.DomainName)': $domainGroupCount group(s) exported, $domainFilteredGroupCount skipped by IncludeGroupCategories/IncludeGroupScopes/ExcludeGroupNames filters."

        if ($domain.PSObject.Properties['Computers']) {
            $computerConfig = $domain.Computers

            $computerBaseOU = if ($computerConfig.BaseOU) { $computerConfig.BaseOU } else { (Get-ADDomain @adParams).DistinguishedName }
            $computerOuDepth = if ($null -ne $computerConfig.OUDepth) { [int]$computerConfig.OUDepth } else { -1 }
            $computerSearchBases = Get-ScopedOrganizationalUnits -BaseOU $computerBaseOU -Depth $computerOuDepth -AdParams $adParams

            $computerExcludeOUs = if ($computerConfig.ExcludeOUs) { @($computerConfig.ExcludeOUs) } else { @() }
            if ($computerExcludeOUs.Count -gt 0) {
                $computerSearchBases = @($computerSearchBases | Where-Object {
                    $candidateOU = $_
                    -not ($computerExcludeOUs | Where-Object { $candidateOU -eq $_ -or $candidateOU -like "*,$_" })
                })
            }

            $computerNameFilter = if ($computerConfig.NameFilter) { @($computerConfig.NameFilter) } else { @() }
            $osTypeFilter = if ($computerConfig.OSTypeFilter) { @($computerConfig.OSTypeFilter) } else { @() }

            Write-DiscoveryLog -LogPath $logPath -Message "Domain '$($domain.DomainName)': scanning $($computerSearchBases.Count) OU(s) under '$computerBaseOU' for computer objects (depth $computerOuDepth)."

            $domainComputerCount = 0
            $domainFilteredComputerCount = 0

            foreach ($ou in $computerSearchBases) {
                $computers = Get-ADComputer -SearchBase $ou -SearchScope OneLevel -Filter * `
                    -Properties Description, DNSHostName, OperatingSystem, OperatingSystemVersion, Enabled, LastLogonTimestamp, whenCreated, whenChanged @adParams

                foreach ($adComputer in $computers) {
                    $computerName = $adComputer.SamAccountName -replace '\$$', ''

                    if ($computerNameFilter.Count -gt 0 -and -not ($computerNameFilter | Where-Object { $computerName -like $_ })) {
                        $domainFilteredComputerCount++
                        continue
                    }
                    if ($osTypeFilter.Count -gt 0 -and -not ($osTypeFilter | Where-Object { $adComputer.OperatingSystem -like $_ })) {
                        $domainFilteredComputerCount++
                        continue
                    }

                    $domainComputerCount++
                    $lastLogon = try {
                        if ($adComputer.LastLogonTimestamp) { [DateTime]::FromFileTime($adComputer.LastLogonTimestamp) } else { $null }
                    } catch { $null }

                    $computerRows.Add([pscustomobject]@{
                        ScanTimestamp        = $scanTimestamp
                        DomainName           = $domain.DomainName
                        ComputerName         = $computerName
                        SamAccountName       = $adComputer.SamAccountName
                        DNSHostName          = $adComputer.DNSHostName
                        DistinguishedName    = $adComputer.DistinguishedName
                        ObjectGUID           = $adComputer.ObjectGUID
                        SID                  = $adComputer.SID.Value
                        Enabled              = $adComputer.Enabled
                        OperatingSystem      = $adComputer.OperatingSystem
                        OperatingSystemVersion = $adComputer.OperatingSystemVersion
                        Description          = $adComputer.Description
                        LastLogonTimestamp   = $lastLogon
                        WhenCreated          = $adComputer.whenCreated
                        WhenChanged          = $adComputer.whenChanged
                        ParentOU             = $ou
                    })
                }
            }

            Write-DiscoveryLog -LogPath $logPath -Message "Completed computer scan of domain '$($domain.DomainName)': $domainComputerCount computer(s) exported, $domainFilteredComputerCount skipped by NameFilter/OSTypeFilter."
        }
    } catch {
        $hadFailures = $true
        Write-DiscoveryLog -Level ERROR -LogPath $logPath -Message "Domain '$($domain.DomainName)' failed: $($_.Exception.Message)"
        continue
    }
}

$groupsCsvPath = Join-Path $config.OutputDirectory 'ADGroups.csv'
$membersCsvPath = Join-Path $config.OutputDirectory 'ADGroupMembers.csv'
$computersCsvPath = Join-Path $config.OutputDirectory 'ADComputers.csv'
$groupRows | Export-Csv -Path $groupsCsvPath -NoTypeInformation -Encoding UTF8
$memberRows | Export-Csv -Path $membersCsvPath -NoTypeInformation -Encoding UTF8
$computerRows | Export-Csv -Path $computersCsvPath -NoTypeInformation -Encoding UTF8

$archiveDirectory = Join-Path $config.OutputDirectory 'Archive'
New-Item -ItemType Directory -Path $archiveDirectory -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
Copy-Item -Path $groupsCsvPath -Destination (Join-Path $archiveDirectory "ADGroups_$stamp.csv")
Copy-Item -Path $membersCsvPath -Destination (Join-Path $archiveDirectory "ADGroupMembers_$stamp.csv")
Copy-Item -Path $computersCsvPath -Destination (Join-Path $archiveDirectory "ADComputers_$stamp.csv")

$retentionCount = if ($config.ArchiveRetentionCount) { [int]$config.ArchiveRetentionCount } else { 30 }
foreach ($prefix in 'ADGroups', 'ADGroupMembers', 'ADComputers') {
    Get-ChildItem -Path $archiveDirectory -Filter "$prefix`_*.csv" | Sort-Object LastWriteTime -Descending | Select-Object -Skip $retentionCount | Remove-Item -Force
}

Write-DiscoveryLog -LogPath $logPath -Message "Export complete. Groups: $($groupRows.Count), membership rows: $($memberRows.Count), computers: $($computerRows.Count). Output: '$groupsCsvPath', '$membersCsvPath', '$computersCsvPath'."

if ($hadFailures) {
    Write-DiscoveryLog -Level WARN -LogPath $logPath -Message 'One or more domains failed; see ERROR entries above.'
    exit 1
}
exit 0
