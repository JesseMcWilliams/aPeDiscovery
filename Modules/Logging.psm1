function Initialize-DiscoveryLog {
    <#
    .SYNOPSIS
        Creates a timestamped log file under the given directory and returns its full path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LogDirectory,
        [Parameter(Mandatory)] [string] $BaseName
    )

    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logPath = Join-Path -Path $LogDirectory -ChildPath "$BaseName`_$stamp.log"
    New-Item -ItemType File -Path $logPath -Force | Out-Null
    return $logPath
}

function Write-DiscoveryLog {
    <#
    .SYNOPSIS
        Writes a single timestamped, leveled line to the console and (optionally) a log file.
    .NOTES
        Callers must never pass secret values (passwords, API keys, tokens) into -Message.

        The file write is guarded by a named Mutex keyed on the log path, since Export-LocalGroups.ps1
        can call this concurrently from multiple runspaces (one per computer being scanned) - plain
        Add-Content has no coordination across concurrent writers to the same file and can throw or
        interleave partial lines without it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')] [string] $Level = 'INFO',
        [string] $LogPath
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    switch ($Level) {
        'WARN' { Write-Warning -Message $Message }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }

    if ($LogPath) {
        $hashBytes = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($LogPath))
        $hashHex = ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
        $mutex = New-Object System.Threading.Mutex($false, "aPeDiscovery_Log_$hashHex")
        $acquired = $false
        try {
            $acquired = $mutex.WaitOne(5000)
            Add-Content -Path $LogPath -Value $line -Encoding UTF8
        } finally {
            if ($acquired) { $mutex.ReleaseMutex() }
            $mutex.Dispose()
        }
    }
}

Export-ModuleMember -Function Initialize-DiscoveryLog, Write-DiscoveryLog
