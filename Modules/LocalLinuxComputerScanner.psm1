function script:ConvertTo-LinuxPasswordState {
    <#
    .SYNOPSIS
        Classifies a /etc/shadow field-2 value per the states confirmed live against a real Linux
        VM (see Docs\Design-Local-Linux-Discovery.md, Section 6).
    #>
    param([string] $ShadowField2)

    if ($ShadowField2 -eq '*') { return 'SystemNoLogin' }
    if ($ShadowField2 -eq '!*') { return 'SystemNoLoginLocked' }
    if ($ShadowField2 -eq '!!') { return 'NeverSet' }
    if ($ShadowField2 -eq '!') { return 'LockedNoHash' }
    if ($ShadowField2 -like '!*') { return 'PasswordSetButLocked' }
    if ($ShadowField2 -match '^\$') { return 'PasswordSet' }
    return 'Unknown'
}

function script:ConvertTo-LinuxSudoAccess {
    <#
    .SYNOPSIS
        Classifies one account's `sudo -n -l -U <user>` output block, using the exact message
        patterns confirmed live (self-check and -U-check word their "no access" case differently).
    #>
    param([string] $BlockText)

    if ($BlockText -match 'may not run sudo|is not allowed to run sudo') { return 'None' }
    if ([string]::IsNullOrWhiteSpace($BlockText)) { return 'Unknown' }
    if ($BlockText -match 'NOPASSWD') { return 'PasswordlessSomeOrAll' }
    if ($BlockText -match '\(.*:.*\)') { return 'PasswordRequired' }
    return 'Unknown'
}

function script:Get-LinuxSectionLines {
    <#
    .SYNOPSIS
        Slices the lines between two marker lines out of the full output array. Both markers must
        be present or this throws - callers treat that as a parse failure for the whole attempt.
    #>
    param(
        [Parameter(Mandatory)] [string[]] $Lines,
        [Parameter(Mandatory)] [string] $StartMarker,
        [Parameter(Mandatory)] [string] $EndMarker
    )

    $startIndex = [array]::IndexOf($Lines, $StartMarker)
    $endIndex = [array]::IndexOf($Lines, $EndMarker)
    if ($startIndex -lt 0 -or $endIndex -lt 0 -or $endIndex -le $startIndex) {
        throw "Could not find expected section between '$StartMarker' and '$EndMarker' in remote output."
    }
    if ($endIndex -eq $startIndex + 1) { return @() }
    return $Lines[($startIndex + 1)..($endIndex - 1)]
}

function Invoke-LocalLinuxComputerScan {
    <#
    .SYNOPSIS
        Scans a single Linux computer's local users, local groups, local group membership, and
        per-account sudo rights over SSH (Posh-SSH), and returns the result rows plus a
        success/failure outcome.
    .DESCRIPTION
        Mirrors Invoke-LocalComputerScan's shape and role exactly (Modules\LocalComputerScanner.psm1)
        so Export-LocalLinuxGroups.ps1 can run it through the same kind of RunspacePool/retry
        architecture as Export-LocalGroups.ps1 - the two scripts differ in how they connect and what
        they read, not in their concurrency/retry/error-handling shape.

        A single SSH command per attempt collects /etc/passwd, /etc/group, a sudo-derived
        /etc/shadow projection, and every discovered account's `sudo -n -l -U <user>` output, using
        marker lines to delimit sections - Invoke-SSHCommand's .Output is a string ARRAY (confirmed
        live), so sections are found by marker-line index, not by splitting a joined string.

        Every `sudo -n ...` step degrades gracefully when the connecting account has no sudo rights
        at all: sudo itself fails fast with no password prompt in that case (confirmed live), so the
        shadow/sudo sections simply come back as sudo's own "not allowed" text instead of hanging -
        this is treated as "no data available", not a scan failure.
    .NOTES
        Never logs the resolved credential's password/passphrase, and never parses/logs raw
        /etc/shadow content (password hashes) - only the specific derived fields
        (locked/hasset/never-expires-ish, last-change day, max-age) are ever extracted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [string] $CredentialSource,
        [hashtable] $CredentialParams = @{},
        [Parameter(Mandatory)] [string] $ScanTimestamp,
        [string] $LogPath,
        [int] $ConnectTimeoutMs = 2000,
        [int] $SshConnectTimeoutSeconds = 15,
        [int] $CommandTimeoutSeconds = 60,
        [bool] $AcceptNewHostKey = $true,
        [int] $RetryCount = 0,
        [int] $RetryDelaySeconds = 5
    )

    $result = [pscustomobject]@{
        ComputerName   = $ComputerName
        Success        = $false
        ErrorMessage   = ''
        UserRows       = [System.Collections.Generic.List[object]]::new()
        GroupRows      = [System.Collections.Generic.List[object]]::new()
        MemberRows     = [System.Collections.Generic.List[object]]::new()
        SudoRightsRows = [System.Collections.Generic.List[object]]::new()
    }

    # Single combined remote command: every account's sudo rights are checked in one remote bash
    # for-loop (one SSH round trip for the whole computer) rather than one Invoke-SSHCommand call
    # per account, which would be far slower across many accounts.
    $remoteCommand = @'
echo '===PASSWD==='
cat /etc/passwd
echo '===GROUP==='
cat /etc/group
echo '===SHADOW==='
sudo -n awk -F: '{print $1":"$2":"$3":"$5}' /etc/shadow 2>&1
echo '===SUDO==='
for u in $(cut -d: -f1 /etc/passwd); do echo "===SUDOUSER:$u==="; sudo -n -l -U "$u" 2>&1; done
echo '===END==='
'@

    $maxAttempts = $RetryCount + 1
    $attempt = 0
    while ($attempt -lt $maxAttempts) {
        $attempt++
        $result.UserRows.Clear()
        $result.GroupRows.Clear()
        $result.MemberRows.Clear()
        $result.SudoRightsRows.Clear()
        $result.ErrorMessage = ''
        $session = $null

        try {
            Write-DiscoveryLog -LogPath $LogPath -Message "Starting scan of computer '$ComputerName' (attempt $attempt/$maxAttempts)."

            if (-not (Test-TcpPortOpen -ComputerName $ComputerName -Port 22 -TimeoutMs $ConnectTimeoutMs)) {
                throw "Port 22 (SSH) is not reachable; skipping. Verify the computer is online and that port 22 is not blocked from this host."
            }

            $credential = Get-DiscoveryCredential -Source $CredentialSource -Params $CredentialParams -LogPath $LogPath
            if (-not $credential) {
                throw "CredentialSource '$CredentialSource' resolved to no credential - Linux SSH scanning always needs a username, even for key-based auth (used for the key's passphrase)."
            }

            $sshParams = @{
                ComputerName      = $ComputerName
                Credential        = $credential
                Port              = 22
                ConnectionTimeout = $SshConnectTimeoutSeconds
                ErrorAction       = 'Stop'
            }
            if ($AcceptNewHostKey) { $sshParams.AcceptKey = $true }
            if ($CredentialParams.ContainsKey('KeyFilePath') -and $CredentialParams.KeyFilePath) {
                $sshParams.KeyFile = $CredentialParams.KeyFilePath
            }

            $session = New-SSHSession @sshParams
            $sshResult = Invoke-SSHCommand -SSHSession $session -Command $remoteCommand -TimeOut $CommandTimeoutSeconds
            if ($sshResult.ExitStatus -ne 0 -and -not $sshResult.Output) {
                throw "Remote command returned no output (ExitStatus=$($sshResult.ExitStatus))."
            }

            $lines = @($sshResult.Output)

            # --- /etc/passwd -> UserRows (shadow fields merged in below once shadow is parsed) ---
            $passwdLines = Get-LinuxSectionLines -Lines $lines -StartMarker '===PASSWD===' -EndMarker '===GROUP==='
            $usersByName = @{}
            foreach ($line in $passwdLines) {
                if (-not $line) { continue }
                $fields = $line -split ':'
                if ($fields.Count -lt 7) { continue }
                $userRow = [pscustomobject]@{
                    ScanTimestamp       = $ScanTimestamp
                    ComputerName        = $ComputerName
                    UserName            = $fields[0]
                    UID                 = $fields[2]
                    PrimaryGID          = $fields[3]
                    Description         = $fields[4]
                    HomeDirectory       = $fields[5]
                    Shell               = $fields[6]
                    PasswordState       = $null
                    PasswordLastSet     = $null
                    PasswordNeverExpires = $null
                }
                $usersByName[$fields[0]] = $userRow
                $result.UserRows.Add($userRow)
            }

            # --- /etc/group -> GroupRows + MemberRows ---
            $groupLines = Get-LinuxSectionLines -Lines $lines -StartMarker '===GROUP===' -EndMarker '===SHADOW==='
            foreach ($line in $groupLines) {
                if (-not $line) { continue }
                $fields = $line -split ':'
                if ($fields.Count -lt 3) { continue }
                $groupName = $fields[0]
                $gid = $fields[2]
                $result.GroupRows.Add([pscustomobject]@{
                    ScanTimestamp = $ScanTimestamp
                    ComputerName  = $ComputerName
                    GroupName     = $groupName
                    GID           = $gid
                })
                $memberList = if ($fields.Count -ge 4) { $fields[3] } else { '' }
                foreach ($memberName in ($memberList -split ',' | Where-Object { $_ })) {
                    $result.MemberRows.Add([pscustomobject]@{
                        ScanTimestamp = $ScanTimestamp
                        ComputerName  = $ComputerName
                        GroupName     = $groupName
                        GID           = $gid
                        MemberName    = $memberName
                    })
                }
            }

            # --- /etc/shadow (sudo-derived projection) -> merged into UserRows ---
            # Comes back as sudo's own "not allowed"/"password is required" text instead of real
            # data when the connecting account has no usable sudo access - detected by checking
            # whether the lines actually look like the expected 4-field projection before trusting
            # any of them, rather than assuming success.
            $shadowLines = Get-LinuxSectionLines -Lines $lines -StartMarker '===SHADOW===' -EndMarker '===SUDO==='
            $shadowLinesLookValid = @($shadowLines | Where-Object { $_ }).Count -gt 0 -and
                -not @($shadowLines | Where-Object { $_ -and ($_ -notmatch '^[^:]+:[^:]*:[^:]*:[^:]*$') }).Count
            if ($shadowLinesLookValid) {
                foreach ($line in $shadowLines) {
                    if (-not $line) { continue }
                    $fields = $line -split ':'
                    if ($fields.Count -lt 4 -or -not $usersByName.ContainsKey($fields[0])) { continue }
                    $userRow = $usersByName[$fields[0]]
                    $userRow.PasswordState = ConvertTo-LinuxPasswordState -ShadowField2 $fields[1]
                    $userRow.PasswordLastSet = if ($fields[2] -match '^\d+$') {
                        [DateTime]::Parse('1970-01-01Z').AddDays([double]$fields[2])
                    } else { $null }
                    $userRow.PasswordNeverExpires = if ([string]::IsNullOrEmpty($fields[3])) {
                        $true
                    } elseif ($fields[3] -match '^\d+$' -and [int]$fields[3] -ge 99999) {
                        $true
                    } elseif ($fields[3] -match '^\d+$') {
                        $false
                    } else {
                        $null
                    }
                }
            } else {
                Write-DiscoveryLog -Level WARN -LogPath $LogPath -Message "Computer '$ComputerName': /etc/shadow data unavailable (likely no sudo access for this account) - password-state fields left blank."
            }

            # --- sudo rights, every discovered account -> SudoRightsRows ---
            $sudoLines = Get-LinuxSectionLines -Lines $lines -StartMarker '===SUDO===' -EndMarker '===END==='
            $userMarkerIndices = [System.Collections.Generic.List[object]]::new()
            for ($i = 0; $i -lt $sudoLines.Count; $i++) {
                if ($sudoLines[$i] -match '^===SUDOUSER:(.+)===$') {
                    $userMarkerIndices.Add([pscustomobject]@{ Index = $i; UserName = $Matches[1] })
                }
            }
            for ($j = 0; $j -lt $userMarkerIndices.Count; $j++) {
                $blockStart = $userMarkerIndices[$j].Index + 1
                $blockEnd = if ($j + 1 -lt $userMarkerIndices.Count) { $userMarkerIndices[$j + 1].Index - 1 } else { $sudoLines.Count - 1 }
                $blockLines = if ($blockStart -le $blockEnd) { $sudoLines[$blockStart..$blockEnd] } else { @() }
                $blockText = ($blockLines -join "`n").Trim()

                $result.SudoRightsRows.Add([pscustomobject]@{
                    ScanTimestamp     = $ScanTimestamp
                    ComputerName      = $ComputerName
                    UserName          = $userMarkerIndices[$j].UserName
                    SudoAccess        = ConvertTo-LinuxSudoAccess -BlockText $blockText
                    RawSudoListOutput = $blockText
                })
            }

            $result.Success = $true
            Write-DiscoveryLog -LogPath $LogPath -Message "Completed scan of '$ComputerName': $($result.UserRows.Count) local user(s), $($result.GroupRows.Count) local group(s), $($result.SudoRightsRows.Count) sudo-rights row(s)."
        } catch {
            $result.ErrorMessage = $_.Exception.Message
            if ($attempt -lt $maxAttempts) {
                Write-DiscoveryLog -Level WARN -LogPath $LogPath -Message "Computer '$ComputerName' attempt $attempt/$maxAttempts failed: $($_.Exception.Message). Retrying in $RetryDelaySeconds second(s)."
                Start-Sleep -Seconds $RetryDelaySeconds
            } else {
                Write-DiscoveryLog -Level ERROR -LogPath $LogPath -Message "Computer '$ComputerName' failed after $attempt attempt(s): $($_.Exception.Message)"
            }
        } finally {
            if ($session) {
                try { Remove-SSHSession -SSHSession $session -ErrorAction SilentlyContinue | Out-Null } catch {}
            }
        }

        if ($result.Success) { break }
    }

    return $result
}

Export-ModuleMember -Function Invoke-LocalLinuxComputerScan
