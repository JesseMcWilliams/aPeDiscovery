function Get-DefaultDatabaseSignatures {
    <#
    .SYNOPSIS
        Built-in list of {Engine, ServicePattern, DefaultPort} used to recognize a database engine
        from its Windows service name, when LocalScanConfig.json doesn't supply its own
        DatabaseSignatures list.
    .NOTES
        ServicePattern is matched with -like against the service's short name (not its
        DisplayName). SQL Server named instances (MSSQL$<name>) get DefaultPort = $null
        deliberately - unlike the default instance (fixed at 1433), a named instance's TCP port is
        dynamic unless statically configured, so guessing 1433 for it would be misleading rather
        than helpful.
    #>
    [CmdletBinding()]
    param()

    return @(
        [pscustomobject]@{ Engine = 'SQL Server'; ServicePattern = 'MSSQLSERVER'; DefaultPort = 1433 }
        [pscustomobject]@{ Engine = 'SQL Server (named instance)'; ServicePattern = 'MSSQL$*'; DefaultPort = $null }
        [pscustomobject]@{ Engine = 'MySQL'; ServicePattern = 'MySQL*'; DefaultPort = 3306 }
        [pscustomobject]@{ Engine = 'MariaDB'; ServicePattern = 'MariaDB*'; DefaultPort = 3306 }
        [pscustomobject]@{ Engine = 'PostgreSQL'; ServicePattern = 'postgresql*'; DefaultPort = 5432 }
        [pscustomobject]@{ Engine = 'Oracle Database'; ServicePattern = 'OracleService*'; DefaultPort = 1521 }
        [pscustomobject]@{ Engine = 'Oracle Listener'; ServicePattern = '*TNSListener*'; DefaultPort = 1521 }
        [pscustomobject]@{ Engine = 'MongoDB'; ServicePattern = 'MongoDB*'; DefaultPort = 27017 }
    )
}

function script:ConvertTo-ServiceStartTypeName {
    <#
    .SYNOPSIS
        Decodes the WinNT provider's numeric Service StartType into the standard Win32
        SERVICE_START_TYPE name.
    #>
    param([int] $StartType)

    switch ($StartType) {
        0 { 'Boot' }
        1 { 'System' }
        2 { 'Automatic' }
        3 { 'Manual' }
        4 { 'Disabled' }
        default { "Unknown ($StartType)" }
    }
}

function script:Get-ServiceAccountType {
    <#
    .SYNOPSIS
        Classifies a Windows service's ServiceAccountName into BuiltIn, Virtual, LikelyGmsaOrMsa,
        User, or Blank.
    .DESCRIPTION
        Verified live against a real machine's full service list before writing this: built-in
        identities appear as 'LocalSystem', 'NT AUTHORITY\LocalService', or
        'NT AUTHORITY\NetworkService'; per-service virtual accounts (increasingly SQL Server's
        default) appear as 'NT SERVICE\<ServiceName>'; kernel drivers have no logon account concept
        and return blank. What's left is either a real local (.\name) or domain (DOMAIN\name)
        user account, or a gMSA/standalone MSA, which uses the identical DOMAIN\name syntax but
        with a trailing '$' - the standard, unambiguous Microsoft naming convention for managed
        service accounts.
    .NOTES
        The gMSA/MSA classification is a NAMING-CONVENTION HEURISTIC, not an authoritative check
        against AD's msDS-GroupManagedServiceAccount object class - this script has no AD
        connectivity of its own (that's Export-ADGroups.ps1's domain). In practice this convention
        is essentially always followed, but nothing prevents a real user account from also being
        named with a trailing '$'.
    #>
    param([string] $ServiceAccountName)

    if ([string]::IsNullOrWhiteSpace($ServiceAccountName)) { return 'Blank' }

    $trimmed = $ServiceAccountName.Trim()

    if ($trimmed -in @('LocalSystem', 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService', 'NT AUTHORITY\System')) {
        return 'BuiltIn'
    }
    if ($trimmed -like 'NT SERVICE\*') {
        return 'Virtual'
    }
    if ($trimmed -like '*$') {
        return 'LikelyGmsaOrMsa'
    }
    return 'User'
}

function script:ConvertTo-ServiceStatusName {
    <#
    .SYNOPSIS
        Decodes the WinNT provider's numeric Service Status into the standard Win32
        SERVICE_STATUS.dwCurrentState name.
    #>
    param([int] $Status)

    switch ($Status) {
        1 { 'Stopped' }
        2 { 'StartPending' }
        3 { 'StopPending' }
        4 { 'Running' }
        5 { 'ContinuePending' }
        6 { 'PausePending' }
        7 { 'Paused' }
        default { "Unknown ($Status)" }
    }
}

function Invoke-LocalComputerScan {
    <#
    .SYNOPSIS
        Scans a single computer's local users, local groups, local group membership, known database
        engine services, and known other-software services over ADSI/WinNT, and returns the result
        rows plus a success/failure outcome.
    .DESCRIPTION
        Factored out of Export-LocalGroups.ps1 so the exact same per-computer logic runs whether
        it's invoked directly (one computer) or as a unit of work inside a runspace pool (many
        computers, throttled by MaxConcurrency) - there is only one code path for what a "scan" of
        a computer means, not a sequential version and a separate parallel version.

        Database and other-software detection both reuse the same WinNT bind already open for
        users/groups (the provider also exposes Service-class children - confirmed live, no extra
        connectivity or credential needed) and pattern-match each service's name against
        DatabaseSignatures / SoftwareSignatures respectively. When a matched signature has a
        DefaultPort, that port is probed on this same computer via Test-TcpPortOpen to report
        whether it's actually listening on the network, not just installed. Unlike
        DatabaseSignatures (which defaults to a built-in list via Get-DefaultDatabaseSignatures),
        SoftwareSignatures has no built-in default - it only checks for what the caller supplies in
        LocalScanConfig.json, since "other software" is inherently more environment-specific than
        the small set of well-known database engines.

        RetryCount lets a transient failure (a network blip, a momentary auth hiccup) retry the
        whole per-computer scan rather than failing the computer outright on the first error; each
        attempt clears any rows a partial earlier attempt had already collected, so a later success
        never leaves duplicate or stale rows behind.

        Every service (not just ones matching DatabaseSignatures/SoftwareSignatures) has its
        ServiceAccountName read and classified (Get-ServiceAccountType) into BuiltIn/Virtual/Blank
        (excluded as noise) or User/LikelyGmsaOrMsa (kept, in ServiceAccountRows) - this answers "what
        services run as this account", which needs every service's logon identity, not just ones
        recognized by name. The gMSA/MSA classification is a naming-convention heuristic (a trailing
        '$'), not an authoritative AD lookup.
    .NOTES
        Never logs the resolved credential's password - only Get-DiscoveryCredential's source and
        outcome are observable via the log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $CredentialSource,
        [hashtable] $CredentialParams = @{},
        [Parameter(Mandatory)] [string] $ScanTimestamp,
        [string] $LogPath,
        [int] $ConnectTimeoutMs = 2000,
        [string[]] $ExcludeUserNames = @(),
        [string[]] $ExcludeGroupNames = @(),
        [object[]] $DatabaseSignatures = (Get-DefaultDatabaseSignatures),
        [object[]] $SoftwareSignatures = @(),
        [int] $RetryCount = 0,
        [int] $RetryDelaySeconds = 5
    )

    # ADS_USER_FLAG_ENUM bit values.
    $ADS_UF_ACCOUNTDISABLE = 0x0002
    $ADS_UF_DONT_EXPIRE_PASSWD = 0x10000

    $result = [pscustomobject]@{
        ComputerName = $ComputerName
        Success      = $false
        ErrorMessage = ''
        UserRows     = [System.Collections.Generic.List[object]]::new()
        GroupRows    = [System.Collections.Generic.List[object]]::new()
        MemberRows   = [System.Collections.Generic.List[object]]::new()
        DatabaseRows = [System.Collections.Generic.List[object]]::new()
        SoftwareRows = [System.Collections.Generic.List[object]]::new()
        ServiceAccountRows = [System.Collections.Generic.List[object]]::new()
    }

    $maxAttempts = $RetryCount + 1
    $attempt = 0
    while ($attempt -lt $maxAttempts) {
        $attempt++
        # Cleared at the start of every attempt, including the first, so a partial success on an
        # earlier attempt (e.g. users enumerated fine, then the connection dropped mid-group-loop)
        # never leaves duplicate or stale rows behind after a later attempt succeeds.
        $result.UserRows.Clear()
        $result.GroupRows.Clear()
        $result.MemberRows.Clear()
        $result.DatabaseRows.Clear()
        $result.SoftwareRows.Clear()
        $result.ServiceAccountRows.Clear()
        $result.ErrorMessage = ''

        try {
            Write-DiscoveryLog -LogPath $LogPath -Message "Starting scan of computer '$ComputerName' (attempt $attempt/$maxAttempts)."

            if (-not (Test-TcpPortOpen -ComputerName $ComputerName -Port 445 -TimeoutMs $ConnectTimeoutMs)) {
                throw "Port 445 (SMB/RPC) is not reachable; skipping. Verify the computer is online and that port 445 is not blocked from this host."
            }

            $credential = Get-DiscoveryCredential -Source $CredentialSource -Params $CredentialParams -LogPath $LogPath

            if ($credential) {
                $computerEntry = New-Object System.DirectoryServices.DirectoryEntry(
                    "WinNT://$ComputerName,computer",
                    $credential.UserName,
                    $credential.GetNetworkCredential().Password)
            } else {
                $computerEntry = New-Object System.DirectoryServices.DirectoryEntry("WinNT://$ComputerName,computer")
            }
            # Forces the bind now so an authentication/connectivity failure surfaces here rather than
            # partway through enumeration below.
            $null = $computerEntry.RefreshCache()

            foreach ($child in $computerEntry.Children) {
                switch ($child.SchemaClassName) {
                    'user' {
                        $userName = $child.Name.ToString()
                        if ($ExcludeUserNames.Count -gt 0 -and ($ExcludeUserNames | Where-Object { $userName -like $_ })) {
                            continue
                        }

                        $sidBytes = $child.InvokeGet('objectSID')
                        $flags = [int]$child.InvokeGet('UserFlags')
                        $lastLogin = try { $child.InvokeGet('LastLogin') } catch { $null }

                        # PasswordAge is seconds elapsed (as measured by the target's own clock)
                        # since the password was last set - converted here to an approximate
                        # absolute timestamp (this host's clock minus that many seconds) since an
                        # absolute date is more directly useful to a downstream tool than "age at
                        # scan time." Approximate because of ordinary clock skew between this host
                        # and the target, not because the underlying value itself is unreliable.
                        $passwordLastSet = try { (Get-Date).AddSeconds(-([double]$child.InvokeGet('PasswordAge'))) } catch { $null }
                        $passwordExpired = try { [bool][int]$child.InvokeGet('PasswordExpired') } catch { $null }
                        $badPasswordAttempts = try { [int]$child.InvokeGet('BadPasswordAttempts') } catch { $null }

                        $result.UserRows.Add([pscustomobject]@{
                            ScanTimestamp        = $ScanTimestamp
                            ComputerName         = $ComputerName
                            UserName             = $userName
                            SID                  = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                            Description          = $child.Properties['Description'].Value
                            Disabled             = [bool]($flags -band $ADS_UF_ACCOUNTDISABLE)
                            PasswordNeverExpires = [bool]($flags -band $ADS_UF_DONT_EXPIRE_PASSWD)
                            LastLogin            = $lastLogin
                            PasswordLastSet      = $passwordLastSet
                            PasswordExpired      = $passwordExpired
                            BadPasswordAttempts  = $badPasswordAttempts
                        })
                    }
                    'group' {
                        $groupName = $child.Name.ToString()
                        if ($ExcludeGroupNames.Count -gt 0 -and ($ExcludeGroupNames | Where-Object { $groupName -like $_ })) {
                            continue
                        }

                        $groupSidBytes = $child.InvokeGet('objectSID')
                        $groupSid = (New-Object System.Security.Principal.SecurityIdentifier($groupSidBytes, 0)).Value

                        $result.GroupRows.Add([pscustomobject]@{
                            ScanTimestamp = $ScanTimestamp
                            ComputerName  = $ComputerName
                            GroupName     = $groupName
                            SID           = $groupSid
                            Description   = $child.Properties['Description'].Value
                        })

                        foreach ($member in $child.Invoke('Members')) {
                            $adsPath = $member.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $member, $null)
                            $memberName = $member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null)
                            $memberClass = $member.GetType().InvokeMember('Class', 'GetProperty', $null, $member, $null)

                            $originAuthority = $null
                            if ($adsPath -match '^WinNT://([^/]+)/') { $originAuthority = $Matches[1] }
                            $memberOrigin = if ($originAuthority -eq $ComputerName -or $originAuthority -eq $env:COMPUTERNAME) { 'Local' } else { $originAuthority }

                            $result.MemberRows.Add([pscustomobject]@{
                                ScanTimestamp     = $ScanTimestamp
                                ComputerName      = $ComputerName
                                GroupName         = $groupName
                                GroupSID          = $groupSid
                                MemberName        = $memberName
                                MemberOrigin      = $memberOrigin
                                MemberObjectClass = $memberClass
                            })
                        }
                    }
                    'Service' {
                        $serviceName = $child.Name.ToString()

                        # Captured for every service regardless of DatabaseSignatures/SoftwareSignatures
                        # matching - this answers "what runs as this account", a different question
                        # from "what recognized software is this" and needs every service's account,
                        # not just ones matching a known signature. BuiltIn/Virtual/Blank accounts are
                        # excluded as noise (never what a PAM-adjacent lookup is after); LikelyGmsaOrMsa
                        # is kept (flagged, not dropped) since the trailing-'$' classification is a
                        # naming-convention heuristic, not an authoritative check against AD - see
                        # Get-ServiceAccountType.
                        $serviceAccountName = try { $child.InvokeGet('ServiceAccountName') } catch { $null }
                        $accountType = Get-ServiceAccountType -ServiceAccountName $serviceAccountName
                        if ($accountType -in @('User', 'LikelyGmsaOrMsa')) {
                            $result.ServiceAccountRows.Add([pscustomobject]@{
                                ScanTimestamp      = $ScanTimestamp
                                ComputerName       = $ComputerName
                                ServiceName        = $serviceName
                                DisplayName        = $child.InvokeGet('DisplayName')
                                ServiceAccountName = $serviceAccountName
                                AccountType        = $accountType
                                StartType          = ConvertTo-ServiceStartTypeName -StartType ([int]$child.InvokeGet('StartType'))
                                Status             = ConvertTo-ServiceStatusName -Status ([int]$child.InvokeGet('Status'))
                                Path               = $child.InvokeGet('Path')
                            })
                        }

                        # Checked independently, not else-if: a service could plausibly match both a
                        # database and a general-software signature, and each list is maintained for
                        # a different purpose (see DatabaseSignatures/SoftwareSignatures in
                        # Docs\Configuration.md), so neither check should suppress the other.
                        $dbSignature = $DatabaseSignatures | Where-Object { $serviceName -like $_.ServicePattern } | Select-Object -First 1
                        if ($dbSignature) {
                            $portListening = $null
                            if ($null -ne $dbSignature.DefaultPort) {
                                $portListening = Test-TcpPortOpen -ComputerName $ComputerName -Port ([int]$dbSignature.DefaultPort) -TimeoutMs $ConnectTimeoutMs
                            }

                            $result.DatabaseRows.Add([pscustomobject]@{
                                ScanTimestamp = $ScanTimestamp
                                ComputerName  = $ComputerName
                                Engine        = $dbSignature.Engine
                                ServiceName   = $serviceName
                                DisplayName   = $child.InvokeGet('DisplayName')
                                Path          = $child.InvokeGet('Path')
                                StartType     = ConvertTo-ServiceStartTypeName -StartType ([int]$child.InvokeGet('StartType'))
                                Status        = ConvertTo-ServiceStatusName -Status ([int]$child.InvokeGet('Status'))
                                DefaultPort   = $dbSignature.DefaultPort
                                Listening     = $portListening
                            })
                        }

                        $softwareSignature = $SoftwareSignatures | Where-Object { $serviceName -like $_.ServicePattern } | Select-Object -First 1
                        if ($softwareSignature) {
                            $portListening = $null
                            if ($null -ne $softwareSignature.DefaultPort) {
                                $portListening = Test-TcpPortOpen -ComputerName $ComputerName -Port ([int]$softwareSignature.DefaultPort) -TimeoutMs $ConnectTimeoutMs
                            }

                            $result.SoftwareRows.Add([pscustomobject]@{
                                ScanTimestamp = $ScanTimestamp
                                ComputerName  = $ComputerName
                                Name          = $softwareSignature.Name
                                Category      = $softwareSignature.Category
                                ServiceName   = $serviceName
                                DisplayName   = $child.InvokeGet('DisplayName')
                                Path          = $child.InvokeGet('Path')
                                StartType     = ConvertTo-ServiceStartTypeName -StartType ([int]$child.InvokeGet('StartType'))
                                Status        = ConvertTo-ServiceStatusName -Status ([int]$child.InvokeGet('Status'))
                                DefaultPort   = $softwareSignature.DefaultPort
                                Listening     = $portListening
                            })
                        }
                    }
                }
            }

            $result.Success = $true
            Write-DiscoveryLog -LogPath $LogPath -Message "Completed scan of '$ComputerName': $($result.UserRows.Count) local user(s), $($result.GroupRows.Count) local group(s), $($result.DatabaseRows.Count) database service(s), $($result.SoftwareRows.Count) other software service(s), $($result.ServiceAccountRows.Count) service(s) running as a user/gMSA account."
        } catch {
            $result.ErrorMessage = $_.Exception.Message
            if ($attempt -lt $maxAttempts) {
                Write-DiscoveryLog -Level WARN -LogPath $LogPath -Message "Computer '$ComputerName' attempt $attempt/$maxAttempts failed: $($_.Exception.Message). Retrying in $RetryDelaySeconds second(s)."
                Start-Sleep -Seconds $RetryDelaySeconds
            } else {
                Write-DiscoveryLog -Level ERROR -LogPath $LogPath -Message "Computer '$ComputerName' failed after $attempt attempt(s): $($_.Exception.Message)"
            }
        }

        if ($result.Success) { break }
    }

    return $result
}

Export-ModuleMember -Function Invoke-LocalComputerScan, Get-DefaultDatabaseSignatures
