function script:ConvertTo-LinuxPasswordState {
    <#
    .SYNOPSIS
        Classifies a /etc/shadow field-2 value per the states confirmed live against a real Linux
        VM (see Claude_Docs\Design_Local-Linux-Discovery-Data-Model.md, Section 6).
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

function script:Resolve-LinuxServiceAccountName {
    <#
    .SYNOPSIS
        Resolves the real account a systemd unit's process actually runs as, for
        LinuxServiceAccounts.csv - preferring the live process owner over the unit's own
        (often-misleading) `User=` property.
    .NOTES
        Confirmed live: `systemctl show`'s `User=` is often blank even for services that don't
        actually run as root, because a wrapper (pg_ctlcluster for PostgreSQL, similarly sshd) starts
        as root and drops privileges internally before systemd's tracked MainPID settles on the real
        worker process - in PostgreSQL's case, MainPID ends up being the real `postgres` process
        itself, so looking up MainPID's owner in a live process table (ps -eo pid,user) resolves it
        correctly where `User=` alone would not. Falls back to `User=` only when no live PID exists to
        check (the unit isn't currently running), and to 'root' - systemd's own documented default -
        when neither resolves anything.
    #>
    param([hashtable] $Props, [hashtable] $PidToOwner)

    $mainPid = $Props['MainPID']
    if ($mainPid -and $mainPid -ne '0' -and $PidToOwner.ContainsKey($mainPid)) { return $PidToOwner[$mainPid] }
    if ($Props['User']) { return $Props['User'] }
    return 'root'
}

function script:ConvertTo-HashtableFromPSObject {
    <#
    .SYNOPSIS
        Converts a nested JSON object (as ConvertFrom-Json produces a PSCustomObject, not a
        hashtable) into a flat hashtable, so it can be passed to Get-ResolvedCredential -Params.
    #>
    param($InputObject)

    $ht = @{}
    if ($InputObject) {
        $InputObject.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }
    }
    return $ht
}

function Get-DefaultLinuxDatabaseSignatures {
    <#
    .SYNOPSIS
        Default systemd-unit-name signatures for recognizing database engines, mirroring
        Modules\LocalComputerScanner.psm1's Get-DefaultDatabaseSignatures for the Windows tool.
    .NOTES
        Only PostgreSQL (`postgresql*`) has been verified against a real installed engine (see
        Claude_Docs\Design_Local-Linux-Discovery-Data-Model.md Section 6b, and
        Claude_Docs\Archive_Design_Local-Linux-Discovery-Revision-Log.md, Round 7). MySQL/MariaDB/MongoDB entries
        are starter guesses at the standard Debian/Ubuntu package unit names, flagged as unverified -
        no such engine has been available on the test VM to confirm against.
    #>
    return @(
        [pscustomobject]@{ Engine = 'PostgreSQL'; UnitPattern = 'postgresql*'; DefaultPort = 5432 }
        [pscustomobject]@{ Engine = 'MySQL/MariaDB'; UnitPattern = 'mysql.service'; DefaultPort = 3306 }
        [pscustomobject]@{ Engine = 'MySQL/MariaDB'; UnitPattern = 'mariadb.service'; DefaultPort = 3306 }
        [pscustomobject]@{ Engine = 'MongoDB'; UnitPattern = 'mongod.service'; DefaultPort = 27017 }
    )
}

function script:Get-LinuxSectionLines {
    <#
    .SYNOPSIS
        Slices the lines between two marker lines out of the full output array. Both markers must
        be present or this throws - callers treat that as a parse failure for the whole attempt.
    #>
    param(
        # AllowEmptyString/AllowNull: without these, PowerShell's Mandatory [string[]] binder throws
        # a misleadingly-worded "Cannot bind argument ... because it is an empty string" for the
        # WHOLE array if even one element is blank/null - confirmed live: the sudo ticket-refresh
        # section (added for elevation - see Section 5a) is the first command in this script whose
        # success case produces zero output, so it's the first time a blank line legitimately shows
        # up in the captured output at all.
        [Parameter(Mandatory)] [AllowEmptyString()] [AllowNull()] [string[]] $Lines,
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
        /etc/shadow projection, every discovered account's `sudo -n -l -U <user>` output, and a
        directory-join check, using marker lines to delimit sections - Invoke-SSHCommand's .Output
        is a string ARRAY (confirmed live), so sections are found by marker-line index, not by
        splitting a joined string.

        Directory-join detection (DirectoryJoined on every user/group row) checks whether `sssd` is
        actually active AND has a real /etc/sssd/sssd.conf, or whether `winbind` is active - NOT
        merely whether /etc/nsswitch.conf mentions "sss" (confirmed live: this project's own test VM
        has "sss" in nsswitch.conf's passwd/group lines from its base image, but sssd is inactive
        with no sssd.conf at all - a real false-positive trap if nsswitch.conf alone were trusted).
        Local users/groups/membership are still collected exactly as before on a directory-joined
        host; the flag only tells a downstream consumer that some entries may be directory-sourced
        rather than genuinely local, per user direction - it's informational, not a filter.

        Every `sudo -n ...` step degrades gracefully when the connecting account has no sudo rights
        at all: sudo itself fails fast with no password prompt in that case (confirmed live), so the
        shadow/sudo sections simply come back as sudo's own "not allowed" text instead of hanging -
        this is treated as "no data available", not a scan failure.

        Sudo elevation (decided 2026-09-17 - see Claude_Docs\Design_Local-Linux-Discovery-Sudo-Elevation.md,
        Round 11): a resolved sudo password (reused from the primary credential when it's
        password-based, or from SudoCredentialSource/SudoCredentialParams when the primary is
        key-based or an explicit override is configured) is piped into ONE `sudo -S -p '' -v` ticket
        refresh at the very top of the remote command - confirmed live that this makes every
        subsequent `sudo -n` call in the same script succeed for the rest of that script's run,
        without needing the password again. This exposes the password to the target's own process
        list only once per computer per attempt, not once per `sudo -n` call (of which there can be
        dozens - one per discovered account). The refresh is skipped (falls straight through to the
        existing -n-only behavior) when no sudo credential can be resolved at all - the account may
        already have NOPASSWD rights, or elevation simply stays unavailable, exactly as before this
        was added.

        The refresh's own success/failure is checked afterward with `sudo -n true` (a trivial no-op
        command), NOT `sudo -n -v` - confirmed live that `-v` (validate) does not honor a `NOPASSWD`
        grant the way running an actual exempted command does: `sudo -n -v` failed with "interactive
        authentication is required" for an account with a real, working `NOPASSWD: ALL` rule, while
        `sudo -n true`/`sudo -n whoami`/`sudo -n -l` all succeeded for that same account in the same
        session. Using `-v` for this check would have logged a false "elevation not established"
        warning on every NOPASSWD-only computer despite every actual command succeeding correctly.

        Phase 5 (database/software/service-account detection, see Design doc Section 6b): every
        registered service unit is enumerated once (`systemctl list-unit-files` UNION `systemctl
        list-units`, deduplicated - `list-unit-files` alone misses instantiated template units like
        `postgresql@18-main.service`, confirmed live) and every unit's properties are fetched in ONE
        `systemctl show <unit1> <unit2> ...` call rather than one call per unit - confirmed live that
        multi-unit output preserves argument order exactly and separates each unit's block with a
        blank line, so unit names are zipped back to their property blocks by position. Signature
        matches (`DatabaseSignatures`/`SoftwareSignatures`, matched against `UnitPattern`) become
        `LinuxDatabases.csv`/`LinuxSoftware.csv` rows; every unit becomes a `LinuxServiceAccounts.csv`
        candidate. Listening confirmation and unrecognized-port detection both come from a single
        `sudo -n ss -tlnp` capture per computer (reusing the same elevation this function already
        establishes for Phase 3/4 - no extra sudo mechanism needed).

        Service-account resolution deliberately does NOT rely on `ss -tlnp`'s process-owner field the
        way Section 6b originally proposed - confirmed live that a unit's `MainPID`, looked up against
        a single `ps -eo pid,user` capture, already gives the real running owner (e.g. `postgres` for
        `postgresql@18-main.service`, whose `MainPID` **is** the actual postgres process, not
        `pg_ctlcluster`'s own launcher PID) for both listening AND non-listening services alike, which
        is more general than a `ss`-based cross-reference that only covers services with an open port.
        Falls back to the unit's own `User=` property (or `root` when both are unavailable) only when
        no live PID exists to check. `ss -tlnp` itself is used solely for its unique value: which
        ports are actually listening, not who owns the listening process.

        Per-account SSH login eligibility (SshPasswordLoginPossible/SshKeyLoginPossible on every user
        row): `sudo -n sshd -T` gives the fully-resolved effective config (not a `sshd_config` grep,
        which would miss anything left at its compiled-in default). `SshPasswordLoginPossible`
        requires PasswordAuthentication=yes, a real usable password (PasswordState = PasswordSet,
        not locked/never-set/system), an interactive shell (present in /etc/shells), and - for root
        specifically - PermitRootLogin not set to a password-blocking value. `SshKeyLoginPossible`
        requires PubkeyAuthentication=yes, a non-empty `~/.ssh/authorized_keys` (checked via `sudo -n
        test -s`, needed to read another account's 0700 home directory), and the same interactive-
        shell requirement. Simplification: only the default `~/.ssh/authorized_keys` path is checked,
        not a customized `AuthorizedKeysFile` directive - see Claude_Docs\Planning_Open-Items.md. Both fields are left
        `$null` (not `False`) when the underlying data couldn't be obtained (no sudo), so a downstream
        consumer can distinguish "confirmed not possible" from "unknown".
    .NOTES
        Never logs the resolved credential's or sudo credential's password/passphrase, and never
        parses/logs raw /etc/shadow content (password hashes) - only the specific derived fields
        (locked/hasset/never-expires-ish, last-change day, max-age) are ever extracted. The password
        is base64-encoded before being embedded in the remote command text solely to avoid any shell
        metacharacter in the password breaking the remote script's syntax - this is not a security
        measure (base64 is trivially reversible) and does not change what's exposed on the wire (SSH
        already encrypts the whole command) or on the target's process list while `sudo -S` runs.
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
        [int] $RetryDelaySeconds = 5,
        [object[]] $DatabaseSignatures = @(),
        [object[]] $SoftwareSignatures = @()
    )

    $result = [pscustomobject]@{
        ComputerName                 = $ComputerName
        Success                      = $false
        ErrorMessage                 = ''
        UserRows                     = [System.Collections.Generic.List[object]]::new()
        GroupRows                    = [System.Collections.Generic.List[object]]::new()
        MemberRows                   = [System.Collections.Generic.List[object]]::new()
        SudoRightsRows               = [System.Collections.Generic.List[object]]::new()
        DatabaseRows                 = [System.Collections.Generic.List[object]]::new()
        SoftwareRows                 = [System.Collections.Generic.List[object]]::new()
        ServiceAccountRows           = [System.Collections.Generic.List[object]]::new()
        UnrecognizedListeningPortRows = [System.Collections.Generic.List[object]]::new()
    }

    # Single combined remote command: every account's sudo rights are checked in one remote bash
    # for-loop (one SSH round trip for the whole computer) rather than one Invoke-SSHCommand call
    # per account, which would be far slower across many accounts. __SUDO_REFRESH__ is substituted
    # per-attempt below, once a sudo credential (if any) has been resolved.
    $remoteCommandTemplate = @'
echo '===PASSWD==='
cat /etc/passwd
echo '===GROUP==='
cat /etc/group
echo '===SUDOREFRESH==='
__SUDO_REFRESH__
sudo -n true 2>&1
echo '===SHADOW==='
sudo -n awk -F: '{print $1":"$2":"$3":"$5}' /etc/shadow 2>&1
echo '===SUDO==='
for u in $(cut -d: -f1 /etc/passwd); do echo "===SUDOUSER:$u==="; sudo -n -l -U "$u" 2>&1; done
echo '===DIRJOIN==='
systemctl is-active sssd 2>&1
test -f /etc/sssd/sssd.conf && echo HAS_SSSD_CONF || echo NO_SSSD_CONF
systemctl is-active winbind 2>&1
echo '===UNITSHOW==='
for u in $({ systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{print $1}'; systemctl list-units --type=service --no-legend --no-pager --all --plain 2>/dev/null | awk '{print $1}'; } | sort -u); do
    echo "===UNIT:$u==="
    systemctl show "$u" --no-pager --property=Description,ActiveState,SubState,UnitFileState,ExecStart,User,MainPID 2>&1
done
echo '===LISTENING==='
sudo -n ss -tlnp 2>&1
echo '===PROCOWNERS==='
ps -eo pid,user --no-headers 2>&1
echo '===SSHDT==='
sudo -n sshd -T 2>&1
echo '===SHELLS==='
cat /etc/shells 2>&1
echo '===AUTHKEYS==='
for u in $(cut -d: -f1 /etc/passwd); do
    home=$(getent passwd "$u" 2>/dev/null | cut -d: -f6)
    echo "===AUTHUSER:$u==="
    if [ -n "$home" ] && sudo -n test -s "$home/.ssh/authorized_keys" 2>/dev/null; then
        echo YES
    else
        echo NO
    fi
done
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
        $result.DatabaseRows.Clear()
        $result.SoftwareRows.Clear()
        $result.ServiceAccountRows.Clear()
        $result.UnrecognizedListeningPortRows.Clear()
        $result.ErrorMessage = ''
        $session = $null

        try {
            Write-DiscoveryLog -LogPath $LogPath -Message "Starting scan of computer '$ComputerName' (attempt $attempt/$maxAttempts)."

            if (-not (Test-TcpPortOpen -ComputerName $ComputerName -Port 22 -TimeoutMs $ConnectTimeoutMs)) {
                throw "Port 22 (SSH) is not reachable; skipping. Verify the computer is online and that port 22 is not blocked from this host."
            }

            $credential = Get-ResolvedCredential -Source $CredentialSource -Params $CredentialParams -LogPath $LogPath
            if (-not $credential) {
                throw "CredentialSource '$CredentialSource' resolved to no credential - Linux SSH scanning always needs a username, even for key-based auth (used for the key's passphrase)."
            }

            $isKeyBasedAuth = $CredentialParams.ContainsKey('KeyFilePath') -and $CredentialParams.KeyFilePath
            $sudoPassword = $null
            if ($CredentialParams.ContainsKey('SudoCredentialSource') -and $CredentialParams.SudoCredentialSource) {
                # Explicit override - honored regardless of primary auth type, since a sudo password
                # can genuinely differ from the login password even when both are password-based.
                try {
                    $sudoCredParams = ConvertTo-HashtableFromPSObject -InputObject $CredentialParams.SudoCredentialParams
                    $sudoCredential = Get-ResolvedCredential -Source $CredentialParams.SudoCredentialSource -Params $sudoCredParams -LogPath $LogPath
                    if ($sudoCredential) { $sudoPassword = $sudoCredential.GetNetworkCredential().Password }
                } catch {
                    Write-DiscoveryLog -Level WARN -LogPath $LogPath -Message "Computer '$ComputerName': failed to resolve SudoCredentialSource ('$($CredentialParams.SudoCredentialSource)') - sudo elevation will not be attempted this attempt. $($_.Exception.Message)"
                }
            } elseif (-not $isKeyBasedAuth) {
                # Primary auth is password-based and no override was given - reuse it for sudo, per
                # the decided rule (Design doc Section 5a): sudo's own PAM default wants the same
                # account's login password anyway.
                $sudoPassword = $credential.GetNetworkCredential().Password
            }
            # else: primary auth is key-based and no SudoCredentialSource was configured - no sudo
            # password is available; the remote script's existing -n-only behavior handles this
            # exactly as it did before elevation existed (NOPASSWD accounts still work; everything
            # else degrades gracefully to blank/Unknown fields).

            $sudoRefreshLine = if ($sudoPassword) {
                $sudoPasswordBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($sudoPassword))
                "echo `"`$(echo $sudoPasswordBase64 | base64 -d)`" | sudo -S -p '' -v 2>&1"
            } else {
                'true'
            }
            $remoteCommand = $remoteCommandTemplate.Replace('__SUDO_REFRESH__', $sudoRefreshLine)
            $sudoPassword = $null

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
            if (-not $sshResult.Output) {
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
                    DirectoryJoined     = $null
                    SshPasswordLoginPossible = $null
                    SshKeyLoginPossible      = $null
                }
                $usersByName[$fields[0]] = $userRow
                $result.UserRows.Add($userRow)
            }

            # --- /etc/group -> GroupRows + MemberRows ---
            $groupLines = Get-LinuxSectionLines -Lines $lines -StartMarker '===GROUP===' -EndMarker '===SUDOREFRESH==='
            foreach ($line in $groupLines) {
                if (-not $line) { continue }
                $fields = $line -split ':'
                if ($fields.Count -lt 3) { continue }
                $groupName = $fields[0]
                $gid = $fields[2]
                $result.GroupRows.Add([pscustomobject]@{
                    ScanTimestamp   = $ScanTimestamp
                    ComputerName    = $ComputerName
                    GroupName       = $groupName
                    GID             = $gid
                    DirectoryJoined = $null
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

            # --- sudo ticket refresh outcome (logging only - never gates whether shadow/sudo data
            # is trusted, since the checks below already verify that independently) ---
            $sudoRefreshLines = @(Get-LinuxSectionLines -Lines $lines -StartMarker '===SUDOREFRESH===' -EndMarker '===SHADOW===' | Where-Object { $_ })
            if ($sudoRefreshLines.Count -gt 0) {
                Write-DiscoveryLog -Level WARN -LogPath $LogPath -Message "Computer '$ComputerName': sudo elevation was not established for this attempt ($($sudoRefreshLines -join ' / ')) - shadow/sudo-rights data will reflect whatever access already existed without it."
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
            $sudoLines = Get-LinuxSectionLines -Lines $lines -StartMarker '===SUDO===' -EndMarker '===DIRJOIN==='
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

            # --- directory-join detection -> DirectoryJoined on every user/group row ---
            # nsswitch.conf mentioning "sss" is NOT trusted on its own (confirmed live: it can be
            # present from a base image even when sssd was never actually configured/joined) - only
            # an actually-active sssd with a real sssd.conf, or an actually-active winbind, counts.
            $dirJoinLines = @(Get-LinuxSectionLines -Lines $lines -StartMarker '===DIRJOIN===' -EndMarker '===UNITSHOW===' | Where-Object { $null -ne $_ })
            $sssdActive = if ($dirJoinLines.Count -ge 1) { $dirJoinLines[0] } else { $null }
            $sssdConfPresent = if ($dirJoinLines.Count -ge 2) { $dirJoinLines[1] -eq 'HAS_SSSD_CONF' } else { $false }
            $winbindActive = if ($dirJoinLines.Count -ge 3) { $dirJoinLines[2] } else { $null }
            $isDirectoryJoined = ($sssdActive -eq 'active' -and $sssdConfPresent) -or ($winbindActive -eq 'active')
            foreach ($u in $result.UserRows) { $u.DirectoryJoined = $isDirectoryJoined }
            foreach ($g in $result.GroupRows) { $g.DirectoryJoined = $isDirectoryJoined }
            if ($isDirectoryJoined) {
                Write-DiscoveryLog -Level WARN -LogPath $LogPath -Message "Computer '$ComputerName' appears to be joined to a directory (sssd/winbind active) - some accounts/groups in this run's output may be directory-sourced, not genuinely local."
            }

            # --- unit enumeration + properties -> matched against DatabaseSignatures/SoftwareSignatures,
            # and every unit considered for LinuxServiceAccounts.csv. One `systemctl show` call per
            # unit (marker-delimited, same pattern as the SUDOUSER loop) rather than one call for all
            # units at once - confirmed live that a single unqueryable unit (a bare template like
            # `alsa-card-wait@.service`, listed in list-unit-files but not directly showable) makes a
            # combined multi-unit call abort after only a couple of units instead of continuing; the
            # per-unit loop degrades to one failed block for that unit and keeps going normally, at
            # negligible cost (353 real units in ~1.7 seconds on the test VM). `--plain` on
            # `list-units` avoids a real, separate bug: without it, a unit shown with a colored status
            # bullet (a UTF-8 "●" character) in the default tabular output gets misread by `awk '{print
            # $1}'` as if the bullet itself were the unit name.
            $unitShowLines = @(Get-LinuxSectionLines -Lines $lines -StartMarker '===UNITSHOW===' -EndMarker '===LISTENING===')
            $unitMarkerIndices2 = [System.Collections.Generic.List[object]]::new()
            for ($i = 0; $i -lt $unitShowLines.Count; $i++) {
                if ($unitShowLines[$i] -match '^===UNIT:(.+)===$') {
                    $unitMarkerIndices2.Add([pscustomobject]@{ Index = $i; UnitName = $Matches[1] })
                }
            }
            $unitNames = [System.Collections.Generic.List[string]]::new()
            $unitPropsList = [System.Collections.Generic.List[hashtable]]::new()
            for ($i = 0; $i -lt $unitMarkerIndices2.Count; $i++) {
                $blockStart = $unitMarkerIndices2[$i].Index + 1
                $blockEnd = if ($i + 1 -lt $unitMarkerIndices2.Count) { $unitMarkerIndices2[$i + 1].Index - 1 } else { $unitShowLines.Count - 1 }
                $props = @{}
                if ($blockStart -le $blockEnd) {
                    foreach ($bl in ($unitShowLines[$blockStart..$blockEnd] | Where-Object { $_ })) {
                        $eq = $bl.IndexOf('=')
                        if ($eq -gt 0) { $props[$bl.Substring(0, $eq)] = $bl.Substring($eq + 1) }
                    }
                }
                $unitNames.Add($unitMarkerIndices2[$i].UnitName)
                $unitPropsList.Add($props)
            }

            # --- ss -tlnp (needs the same elevation established above) -> listening port table ---
            $listeningLines = @(Get-LinuxSectionLines -Lines $lines -StartMarker '===LISTENING===' -EndMarker '===PROCOWNERS===' | Where-Object { $_ })
            $procOwnerLines = @(Get-LinuxSectionLines -Lines $lines -StartMarker '===PROCOWNERS===' -EndMarker '===SSHDT===' | Where-Object { $_ })
            $pidToOwner = @{}
            foreach ($line in $procOwnerLines) {
                $procFields = $line.Trim() -split '\s+', 2
                if ($procFields.Count -eq 2) { $pidToOwner[$procFields[0]] = $procFields[1] }
            }
            $listeningPorts = [System.Collections.Generic.List[object]]::new()
            $listeningDataAvailable = $false
            foreach ($line in $listeningLines) {
                if ($line -notmatch '^LISTEN\s') { continue }
                $listeningDataAvailable = $true
                $lsFields = $line -split '\s+'
                if ($lsFields.Count -lt 4) { continue }
                $localAddrPort = $lsFields[3]
                $lastColon = $localAddrPort.LastIndexOf(':')
                if ($lastColon -lt 0) { continue }
                $port = $localAddrPort.Substring($lastColon + 1)
                $procMatch = [regex]::Match($line, 'users:\(\("([^"]+)",pid=(\d+)')
                $listeningPorts.Add([pscustomobject]@{
                    Port        = $port
                    ProcessName = if ($procMatch.Success) { $procMatch.Groups[1].Value } else { $null }
                    PID         = if ($procMatch.Success) { $procMatch.Groups[2].Value } else { $null }
                })
            }
            if (-not $listeningDataAvailable) {
                Write-DiscoveryLog -Level WARN -LogPath $LogPath -Message "Computer '$ComputerName': listening-port data unavailable (likely no sudo access for this account) - Listening/database/software port checks left blank, LinuxUnrecognizedListeningPorts.csv skipped for this computer."
            }

            $matchedPorts = [System.Collections.Generic.List[string]]::new()
            for ($i = 0; $i -lt $unitNames.Count; $i++) {
                $unitName = $unitNames[$i]
                $props = $unitPropsList[$i]

                foreach ($sig in $DatabaseSignatures) {
                    if ($unitName -notlike $sig.UnitPattern) { continue }
                    $listening = $null
                    if ($sig.DefaultPort) {
                        $matchedPorts.Add([string]$sig.DefaultPort)
                        $listening = if ($listeningDataAvailable) { ($listeningPorts | Where-Object { $_.Port -eq [string]$sig.DefaultPort }).Count -gt 0 } else { $null }
                    }
                    $result.DatabaseRows.Add([pscustomobject]@{
                        ScanTimestamp = $ScanTimestamp
                        ComputerName  = $ComputerName
                        Engine        = $sig.Engine
                        UnitName      = $unitName
                        Description   = $props['Description']
                        Status        = "$($props['ActiveState'])/$($props['SubState'])"
                        StartType     = $props['UnitFileState']
                        Path          = $props['ExecStart']
                        DefaultPort   = $sig.DefaultPort
                        Listening     = $listening
                    })
                }
                foreach ($sig in $SoftwareSignatures) {
                    if ($unitName -notlike $sig.UnitPattern) { continue }
                    $listening = $null
                    if ($sig.DefaultPort) {
                        $matchedPorts.Add([string]$sig.DefaultPort)
                        $listening = if ($listeningDataAvailable) { ($listeningPorts | Where-Object { $_.Port -eq [string]$sig.DefaultPort }).Count -gt 0 } else { $null }
                    }
                    $result.SoftwareRows.Add([pscustomobject]@{
                        ScanTimestamp = $ScanTimestamp
                        ComputerName  = $ComputerName
                        Name          = $sig.Name
                        Category      = $sig.Category
                        UnitName      = $unitName
                        Description   = $props['Description']
                        Status        = "$($props['ActiveState'])/$($props['SubState'])"
                        StartType     = $props['UnitFileState']
                        Path          = $props['ExecStart']
                        DefaultPort   = $sig.DefaultPort
                        Listening     = $listening
                    })
                }

                $resolvedAccount = Resolve-LinuxServiceAccountName -Props $props -PidToOwner $pidToOwner
                if ($resolvedAccount -ne 'root') {
                    $result.ServiceAccountRows.Add([pscustomobject]@{
                        ScanTimestamp      = $ScanTimestamp
                        ComputerName       = $ComputerName
                        UnitName           = $unitName
                        Description        = $props['Description']
                        ServiceAccountName = $resolvedAccount
                        StartType          = $props['UnitFileState']
                        Status             = "$($props['ActiveState'])/$($props['SubState'])"
                        Path               = $props['ExecStart']
                    })
                }
            }

            if ($listeningDataAvailable) {
                foreach ($lp in $listeningPorts) {
                    if ($matchedPorts -contains $lp.Port) { continue }
                    $result.UnrecognizedListeningPortRows.Add([pscustomobject]@{
                        ScanTimestamp = $ScanTimestamp
                        ComputerName  = $ComputerName
                        Port          = $lp.Port
                        ProcessName   = $lp.ProcessName
                        PID           = $lp.PID
                        ProcessOwner  = if ($lp.PID -and $pidToOwner.ContainsKey($lp.PID)) { $pidToOwner[$lp.PID] } else { $null }
                    })
                }
            }

            # --- per-account SSH login eligibility (SshPasswordLoginPossible/SshKeyLoginPossible) ---
            # Needs the same sudo elevation as Phase 3/4: `sshd -T` (the fully-resolved effective
            # config) and reading another account's authorized_keys both require it. Degrades to
            # leaving both fields blank/null when sudo isn't available, same pattern as PasswordState.
            $sshdtLines = @(Get-LinuxSectionLines -Lines $lines -StartMarker '===SSHDT===' -EndMarker '===SHELLS===' | Where-Object { $_ })
            $sshdSettings = @{}
            foreach ($line in $sshdtLines) {
                $parts = $line -split '\s+', 2
                if ($parts.Count -eq 2) { $sshdSettings[$parts[0]] = $parts[1] }
            }
            $sshdtDataAvailable = $sshdSettings.ContainsKey('passwordauthentication') -or $sshdSettings.ContainsKey('pubkeyauthentication')
            if (-not $sshdtDataAvailable) {
                Write-DiscoveryLog -Level WARN -LogPath $LogPath -Message "Computer '$ComputerName': effective sshd configuration unavailable (likely no sudo access for this account) - SshPasswordLoginPossible/SshKeyLoginPossible left blank."
            }

            $validShells = @{}
            foreach ($line in (Get-LinuxSectionLines -Lines $lines -StartMarker '===SHELLS===' -EndMarker '===AUTHKEYS===' | Where-Object { $_ })) {
                $validShells[$line.Trim()] = $true
            }

            $authKeysLines = @(Get-LinuxSectionLines -Lines $lines -StartMarker '===AUTHKEYS===' -EndMarker '===END===')
            $authKeyMarkerIndices = [System.Collections.Generic.List[object]]::new()
            for ($i = 0; $i -lt $authKeysLines.Count; $i++) {
                if ($authKeysLines[$i] -match '^===AUTHUSER:(.+)===$') {
                    $authKeyMarkerIndices.Add([pscustomobject]@{ Index = $i; UserName = $Matches[1] })
                }
            }
            $hasAuthorizedKeys = @{}
            for ($i = 0; $i -lt $authKeyMarkerIndices.Count; $i++) {
                $blockStart = $authKeyMarkerIndices[$i].Index + 1
                $blockEnd = if ($i + 1 -lt $authKeyMarkerIndices.Count) { $authKeyMarkerIndices[$i + 1].Index - 1 } else { $authKeysLines.Count - 1 }
                $blockText = if ($blockStart -le $blockEnd) { ($authKeysLines[$blockStart..$blockEnd] -join '').Trim() } else { '' }
                $hasAuthorizedKeys[$authKeyMarkerIndices[$i].UserName] = ($blockText -eq 'YES')
            }

            if ($sshdtDataAvailable) {
                $passwordAuthEnabled = $sshdSettings['passwordauthentication'] -eq 'yes'
                $pubkeyAuthEnabled = $sshdSettings['pubkeyauthentication'] -eq 'yes'
                $permitRootLogin = $sshdSettings['permitrootlogin']
                foreach ($userRow in $result.UserRows) {
                    $shellIsInteractive = $validShells.ContainsKey($userRow.Shell)

                    $rootPasswordBlocked = ($userRow.UserName -eq 'root') -and ($permitRootLogin -in @('prohibit-password', 'without-password', 'no'))
                    $hasUsablePassword = $userRow.PasswordState -eq 'PasswordSet'
                    $userRow.SshPasswordLoginPossible = if ($null -eq $userRow.PasswordState) { $null } else {
                        $passwordAuthEnabled -and $hasUsablePassword -and $shellIsInteractive -and -not $rootPasswordBlocked
                    }

                    $authKeysKnown = $hasAuthorizedKeys.ContainsKey($userRow.UserName)
                    $userRow.SshKeyLoginPossible = if (-not $authKeysKnown) { $null } else {
                        $pubkeyAuthEnabled -and $hasAuthorizedKeys[$userRow.UserName] -and $shellIsInteractive
                    }
                }
            }

            $result.Success = $true
            Write-DiscoveryLog -LogPath $LogPath -Message "Completed scan of '$ComputerName': $($result.UserRows.Count) local user(s), $($result.GroupRows.Count) local group(s), $($result.SudoRightsRows.Count) sudo-rights row(s), $($result.DatabaseRows.Count) database service(s), $($result.SoftwareRows.Count) other software service(s), $($result.ServiceAccountRows.Count) service account(s) of interest."
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

Export-ModuleMember -Function Invoke-LocalLinuxComputerScan, Get-DefaultLinuxDatabaseSignatures
