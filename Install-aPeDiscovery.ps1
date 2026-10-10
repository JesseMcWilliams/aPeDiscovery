#Requires -Version 5.1
<#
.SYNOPSIS
    Installs or updates aPeDiscovery and its prerequisites on a scanning host.
.DESCRIPTION
    Every run brings the host to the requested state, so the same command installs and updates:
    anything missing is installed, anything older than requested is updated, and anything already
    current is left alone. Runs on Windows PowerShell 5.1 because PowerShell 7 may not exist yet.

    Components (see Claude_Docs\Reference_Scanning-Host-Requirements.md for the HR-* IDs):
      PowerShell       PowerShell 7 (MSI, all users). The download is checked against GitHub's
                       published SHA-256 and Microsoft's Authenticode signature. HR-OS-03
      Repositories     aPeDiscovery, aPeSecrets and LogaPe as sibling folders under -InstallRoot,
                       pinned to the commit -Ref resolves to, then unblocked. HR-FS-01..03
      PoshSSH          Posh-SSH for PowerShell 7, all users. HR-MOD-02
      ActiveDirectory  The RSAT ActiveDirectory module (Windows feature). HR-MOD-01
    It also reports, but never installs, the CyberArk Credential Provider (HR-CA-01).

    Repository updates are tracked in a manifest (.ape-install.json) in each repository folder,
    listing every file this script installed and its SHA-256. An update replaces or removes only
    those files, so configs, output, logs and secrets are never touched. A tracked file that was
    edited locally is copied to .ape-backup\<timestamp>\ before it's overwritten. A folder that is
    a git clone (has .git) is left alone: update it with git pull.

    Offline hosts: run with -DownloadOnly -PackagePath <folder> on a connected machine, copy the
    folder across, then run with -PackagePath <folder> on the scanning host.
.PARAMETER InstallRoot
    Parent folder for the three repositories. Default C:\aPe.
.PARAMETER Ref
    Branch, tag or commit to install for all three repositories. Default main.
.PARAMETER Components
    Which components to install or update. Default: all four.
.PARAMETER PowerShellVersion
    'Latest' (default: the newest stable release) or a version such as '7.6.6'. Must be 7.6 or later.
.PARAMETER PoshSshVersion
    A Posh-SSH version to pin to. Default: the newest in the PowerShell Gallery.
.PARAMETER PackagePath
    Offline bundle folder. With -DownloadOnly, it's where the bundle is written.
.PARAMETER DownloadOnly
    Build an offline bundle in -PackagePath and install nothing. Needs no administrator rights.
.PARAMETER FeatureSource
    Windows 10/11 only: a Features on Demand source for the RSAT capability on hosts without
    Windows Update access.
.EXAMPLE
    .\Install-aPeDiscovery.ps1
    Installs or updates everything under C:\aPe from main.
.EXAMPLE
    .\Install-aPeDiscovery.ps1 -Components Repositories -Ref v1.2.0 -WhatIf
    Shows what updating only the repositories to tag v1.2.0 would change.
.EXAMPLE
    .\Install-aPeDiscovery.ps1 -DownloadOnly -PackagePath D:\aPeBundle
    .\Install-aPeDiscovery.ps1 -PackagePath D:\aPeBundle
    Builds an offline bundle, then installs from it.
.NOTES
    Exit code 0 = every selected component succeeded (or was already current). 1 = at least one
    failed; see the summary table and the transcript in <InstallRoot>\InstallLogs.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $InstallRoot = 'C:\aPe',
    [string] $Ref = 'main',
    [ValidateSet('PowerShell', 'Repositories', 'PoshSSH', 'ActiveDirectory')]
    [string[]] $Components = @('PowerShell', 'Repositories', 'PoshSSH', 'ActiveDirectory'),
    [string] $PowerShellVersion = 'Latest',
    [string] $PoshSshVersion,
    [string] $PackagePath,
    [switch] $DownloadOnly,
    [string] $FeatureSource
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is many times slower with the progress bar on 5.1.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$GitHubOwner = 'JesseMcWilliams'
$Repositories = @('aPeDiscovery', 'aPeSecrets', 'LogaPe')
$MinimumPowerShell = [version]'7.6.0'
$PwshPath = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
$ManifestName = '.ape-install.json'
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Results = [System.Collections.Generic.List[object]]::new()

#region Helpers

function Add-Result {
    param([string] $Component, [string] $Status, [string] $Detail, [string] $Ids = '')
    $Results.Add([pscustomobject]@{ Component = $Component; Status = $Status; Detail = $Detail; Ids = $Ids })
    $color = 'Gray'
    if ($Status -eq 'Failed') { $color = 'Red' } elseif ($Status -in 'Installed', 'Updated', 'Downloaded') { $color = 'Green' } elseif ($Status -in 'Missing', 'Skipped') { $color = 'Yellow' }
    Write-Host ('[{0}] {1}: {2}' -f $Status, $Component, $Detail) -ForegroundColor $color
}

function Test-Administrator {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Sha256Hex {
    # SHA256CryptoServiceProvider, not Get-FileHash: on .NET Framework, Get-FileHash's SHA256 is
    # the managed implementation, which throws on hosts that enforce FIPS mode.
    param([string] $Path)
    $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    $stream = [System.IO.File]::OpenRead($Path)
    try { return -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Invoke-GitHubApi {
    param([string] $Path)
    return Invoke-RestMethod -Uri ('https://api.github.com/{0}' -f $Path) -UseBasicParsing -Headers @{ 'User-Agent' = 'Install-aPeDiscovery'; Accept = 'application/vnd.github+json' }
}

function Save-Download {
    param([string] $Uri, [string] $OutFile)
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -Headers @{ 'User-Agent' = 'Install-aPeDiscovery' }
}

function Invoke-Pwsh {
    # Runs a command in the installed PowerShell 7 and returns its output lines.
    param([string] $Command)
    $output = & $PwshPath -NoProfile -NonInteractive -Command $Command 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('pwsh exited {0}: {1}' -f $LASTEXITCODE, ($output -join ' ')) }
    return $output
}

function ConvertTo-Version {
    param([string] $Text)
    if ($Text -match '(\d+\.\d+\.\d+)') { return [version]$Matches[1] }
    return $null
}

#endregion

#region PowerShell 7

function Get-PowerShellRelease {
    # Returns the MSI to install: version, file name, URL (or local path) and expected SHA-256.
    if ($PackagePath -and -not $DownloadOnly) {
        $msi = Get-ChildItem -Path $PackagePath -Filter 'PowerShell-*-win-x64.msi' | Sort-Object Name | Select-Object -Last 1
        if (-not $msi) { throw ('No PowerShell-*-win-x64.msi in {0}.' -f $PackagePath) }
        $shaFile = '{0}.sha256' -f $msi.FullName
        if (-not (Test-Path $shaFile)) { throw ('Missing {0}; rebuild the bundle with -DownloadOnly.' -f $shaFile) }
        return [pscustomobject]@{ Version = (ConvertTo-Version $msi.Name); Name = $msi.Name; Source = $msi.FullName; Sha256 = (Get-Content $shaFile -Raw).Trim(); IsLocal = $true }
    }
    $release = if ($PowerShellVersion -eq 'Latest') { Invoke-GitHubApi 'repos/PowerShell/PowerShell/releases/latest' } else { Invoke-GitHubApi ('repos/PowerShell/PowerShell/releases/tags/v{0}' -f $PowerShellVersion) }
    $asset = $release.assets | Where-Object { $_.name -match '^PowerShell-[\d\.]+-win-x64\.msi$' } | Select-Object -First 1
    if (-not $asset) { throw ('Release {0} has no win-x64 MSI.' -f $release.tag_name) }
    if (-not $asset.digest -or $asset.digest -notmatch '^sha256:([0-9a-f]{64})$') { throw ('GitHub published no SHA-256 for {0}; refusing to install an unverified download.' -f $asset.name) }
    return [pscustomobject]@{ Version = (ConvertTo-Version $release.tag_name); Name = $asset.name; Source = $asset.browser_download_url; Sha256 = $Matches[1]; IsLocal = $false }
}

function Assert-PowerShellMsi {
    param([string] $Path, [string] $ExpectedSha256)
    $actual = Get-Sha256Hex $Path
    if ($actual -ne $ExpectedSha256.ToLowerInvariant()) { throw ('SHA-256 mismatch for {0}: expected {1}, got {2}.' -f $Path, $ExpectedSha256, $actual) }
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw ('Authenticode check failed for {0}: status {1}, signer {2}.' -f $Path, $signature.Status, $signature.SignerCertificate.Subject)
    }
}

function Install-PowerShell7 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $component = 'PowerShell 7'
    try {
        $release = Get-PowerShellRelease
        if ($release.Version -lt $MinimumPowerShell) { throw ('Version {0} is below the minimum {1}.' -f $release.Version, $MinimumPowerShell) }

        if ($DownloadOnly) {
            $target = Join-Path $PackagePath $release.Name
            Save-Download -Uri $release.Source -OutFile $target
            Assert-PowerShellMsi -Path $target -ExpectedSha256 $release.Sha256
            Set-Content -Path ('{0}.sha256' -f $target) -Value $release.Sha256 -Encoding ASCII
            Add-Result $component 'Downloaded' ('{0}, SHA-256 and signature verified' -f $release.Name) 'HR-OS-03'
            return
        }

        $installed = $null
        if (Test-Path $PwshPath) { $installed = ConvertTo-Version ((& $PwshPath -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()') -join '') }
        if ($installed -and $installed -ge $release.Version) {
            Add-Result $component 'UpToDate' ('{0} installed (requested {1})' -f $installed, $release.Version) 'HR-OS-03'
            return
        }
        $action = if ($installed) { 'Update {0} to {1}' -f $installed, $release.Version } else { 'Install {0}' -f $release.Version }
        if (-not $PSCmdlet.ShouldProcess($PwshPath, $action)) { Add-Result $component 'Skipped' ('WhatIf: {0}' -f $action) 'HR-OS-03'; return }
        if (-not (Test-Administrator)) { throw 'Installing PowerShell 7 needs an elevated (Run as administrator) session.' }

        $msiPath = $release.Source
        if (-not $release.IsLocal) {
            $msiPath = Join-Path $env:TEMP $release.Name
            Save-Download -Uri $release.Source -OutFile $msiPath
        }
        Assert-PowerShellMsi -Path $msiPath -ExpectedSha256 $release.Sha256

        $msiLog = Join-Path $script:LogDir ('PowerShell-msi_{0}.log' -f $Stamp)
        $msiArgs = @('/i', ('"{0}"' -f $msiPath), '/qn', '/norestart', 'ADD_PATH=1', 'REGISTER_MANIFEST=1', 'ENABLE_PSREMOTING=0', '/l*v', ('"{0}"' -f $msiLog))
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
        if ($process.ExitCode -notin 0, 3010, 1641) { throw ('msiexec exited {0}; see {1}.' -f $process.ExitCode, $msiLog) }
        $note = if ($process.ExitCode -ne 0) { ' (restart required)' } else { '' }
        $status = if ($installed) { 'Updated' } else { 'Installed' }
        Add-Result $component $status ('{0}{1}' -f $release.Version, $note) 'HR-OS-03'
    } catch {
        Add-Result $component 'Failed' $_.Exception.Message 'HR-OS-03'
    }
}

#endregion

#region Repositories

function Get-RepositoryArchive {
    # Returns the commit SHA and a local zip path for one repository at -Ref.
    param([string] $Name, [string] $WorkDir)
    if ($PackagePath -and -not $DownloadOnly) {
        $zip = Get-ChildItem -Path $PackagePath -Filter ('{0}-*.zip' -f $Name) | Where-Object { $_.BaseName -match ('^{0}-([0-9a-f]{{40}})$' -f $Name) } | Select-Object -First 1
        if (-not $zip) { throw ('No {0}-<commit>.zip in {1}.' -f $Name, $PackagePath) }
        $null = $zip.BaseName -match '-([0-9a-f]{40})$'
        return [pscustomobject]@{ Commit = $Matches[1]; Zip = $zip.FullName }
    }
    $commit = (Invoke-GitHubApi ('repos/{0}/{1}/commits/{2}' -f $GitHubOwner, $Name, $Ref)).sha
    $zipPath = Join-Path $WorkDir ('{0}-{1}.zip' -f $Name, $commit)
    if (-not (Test-Path $zipPath)) { Save-Download -Uri ('https://codeload.github.com/{0}/{1}/zip/{2}' -f $GitHubOwner, $Name, $commit) -OutFile $zipPath }
    return [pscustomobject]@{ Commit = $commit; Zip = $zipPath }
}

function Install-Repository {
    [CmdletBinding(SupportsShouldProcess)]
    param([string] $Name)
    $component = 'Repository {0}' -f $Name
    $ids = 'HR-FS-01..03'
    try {
        if ($DownloadOnly) {
            $archive = Get-RepositoryArchive -Name $Name -WorkDir $PackagePath
            Add-Result $component 'Downloaded' ('{0} at {1}' -f $Ref, $archive.Commit.Substring(0, 7)) $ids
            return
        }

        $destination = Join-Path $InstallRoot $Name
        if (Test-Path (Join-Path $destination '.git')) {
            Add-Result $component 'Skipped' ('{0} is a git clone; update it with git pull' -f $destination) $ids
            return
        }

        $manifestPath = Join-Path $destination $ManifestName
        $oldManifest = $null
        if (Test-Path $manifestPath) { $oldManifest = Get-Content $manifestPath -Raw | ConvertFrom-Json }

        # Scratch space for downloads; created even under -WhatIf, since it changes nothing on the host.
        $workDir = Join-Path $env:TEMP ('ape-install-{0}' -f $Stamp)
        New-Item -ItemType Directory -Path $workDir -Force -WhatIf:$false | Out-Null
        $archive = Get-RepositoryArchive -Name $Name -WorkDir $workDir

        if ($oldManifest -and $oldManifest.Commit -eq $archive.Commit) {
            if ($PSCmdlet.ShouldProcess($destination, 'Unblock files')) { Get-ChildItem -Path $destination -Recurse -File | Unblock-File }
            Add-Result $component 'UpToDate' ('{0} at {1}' -f $Ref, $archive.Commit.Substring(0, 7)) $ids
            return
        }

        $action = if ($oldManifest) { 'Update from {0} to {1}' -f $oldManifest.Commit.Substring(0, 7), $archive.Commit.Substring(0, 7) } else { 'Install {0} at {1}' -f $Ref, $archive.Commit.Substring(0, 7) }
        if (-not $PSCmdlet.ShouldProcess($destination, $action)) { Add-Result $component 'Skipped' ('WhatIf: {0}' -f $action) $ids; return }

        # GitHub archives hold one top-level folder (<repo>-<commit>); its contents are the repository.
        $staging = Join-Path $workDir ('{0}-extract' -f $Name)
        Expand-Archive -Path $archive.Zip -DestinationPath $staging -Force
        $sourceRoot = (Get-ChildItem -Path $staging -Directory | Select-Object -First 1).FullName

        $oldFiles = @{}
        if ($oldManifest) { foreach ($entry in $oldManifest.Files) { $oldFiles[$entry.Path] = $entry.Sha256 } }
        $backupRoot = Join-Path $destination ('.ape-backup\{0}' -f $Stamp)
        $newFiles = [System.Collections.Generic.List[object]]::new()
        $backedUp = 0

        foreach ($file in Get-ChildItem -Path $sourceRoot -Recurse -File) {
            $relative = $file.FullName.Substring($sourceRoot.Length + 1)
            $target = Join-Path $destination $relative
            $newHash = Get-Sha256Hex $file.FullName
            if (Test-Path $target) {
                $currentHash = Get-Sha256Hex $target
                $expectedHash = $oldFiles[$relative]
                # Back up a file that differs from both what we installed last time and the new version:
                # a local edit, or a file this script never installed.
                if ($currentHash -ne $newHash -and $currentHash -ne $expectedHash) {
                    $backupPath = Join-Path $backupRoot $relative
                    New-Item -ItemType Directory -Path (Split-Path $backupPath -Parent) -Force | Out-Null
                    Copy-Item -Path $target -Destination $backupPath -Force
                    $backedUp++
                }
            }
            New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
            Copy-Item -Path $file.FullName -Destination $target -Force
            $newFiles.Add([pscustomobject]@{ Path = $relative; Sha256 = $newHash })
        }

        # Remove only files the previous install put there that the new version no longer has.
        $newPaths = @{}
        foreach ($entry in $newFiles) { $newPaths[$entry.Path] = $true }
        $removed = 0
        foreach ($oldPath in $oldFiles.Keys) {
            if ($newPaths.ContainsKey($oldPath)) { continue }
            $stale = Join-Path $destination $oldPath
            if (-not (Test-Path $stale)) { continue }
            if ((Get-Sha256Hex $stale) -ne $oldFiles[$oldPath]) {
                $backupPath = Join-Path $backupRoot $oldPath
                New-Item -ItemType Directory -Path (Split-Path $backupPath -Parent) -Force | Out-Null
                Copy-Item -Path $stale -Destination $backupPath -Force
                $backedUp++
            }
            Remove-Item -Path $stale -Force
            $removed++
        }

        Get-ChildItem -Path $destination -Recurse -File | Unblock-File
        [pscustomobject]@{
            Repository   = ('{0}/{1}' -f $GitHubOwner, $Name)
            Ref          = $Ref
            Commit       = $archive.Commit
            InstalledUtc = (Get-Date).ToUniversalTime().ToString('o')
            Files        = $newFiles
        } | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding UTF8

        $status = if ($oldManifest) { 'Updated' } else { 'Installed' }
        $detail = '{0} at {1}: {2} files, {3} removed, {4} backed up' -f $Ref, $archive.Commit.Substring(0, 7), $newFiles.Count, $removed, $backedUp
        if ($backedUp -gt 0) { $detail = '{0} (to {1})' -f $detail, $backupRoot }
        Add-Result $component $status $detail $ids
    } catch {
        Add-Result $component 'Failed' $_.Exception.Message $ids
    }
}

#endregion

#region Posh-SSH

function Install-PoshSsh {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $component = 'Posh-SSH'
    try {
        if ($DownloadOnly) {
            $modulesDir = Join-Path $PackagePath 'Modules'
            New-Item -ItemType Directory -Path $modulesDir -Force | Out-Null
            if (Test-Path $PwshPath) {
                $versionArg = if ($PoshSshVersion) { " -Version '{0}'" -f $PoshSshVersion } else { '' }
                $null = Invoke-Pwsh ("Save-PSResource -Name Posh-SSH -Repository PSGallery -TrustRepository -Path '{0}'{1}" -f $modulesDir, $versionArg)
            } else {
                # Windows PowerShell 5.1's Save-Module may first ask to install the NuGet provider.
                $saveArgs = @{ Name = 'Posh-SSH'; Path = $modulesDir; Repository = 'PSGallery'; Force = $true }
                if ($PoshSshVersion) { $saveArgs.RequiredVersion = $PoshSshVersion }
                Save-Module @saveArgs
            }
            $saved = Get-ChildItem -Path (Join-Path $modulesDir 'Posh-SSH') -Directory | Select-Object -Last 1
            Add-Result $component 'Downloaded' $saved.Name 'HR-MOD-02'
            return
        }
        if (-not (Test-Path $PwshPath)) {
            if ($WhatIfPreference) { Add-Result $component 'Skipped' 'WhatIf: would install after PowerShell 7' 'HR-MOD-02'; return }
            throw 'PowerShell 7 is not installed; install it first (component PowerShell).'
        }

        $installed = ConvertTo-Version ((Invoke-Pwsh '$m = Get-Module -ListAvailable Posh-SSH | Sort-Object Version -Descending | Select-Object -First 1; if ($m) { $m.Version.ToString() }') -join '')
        $sourceDir = $null
        if ($PackagePath) {
            $sourceDir = Get-ChildItem -Path (Join-Path $PackagePath 'Modules\Posh-SSH') -Directory -ErrorAction SilentlyContinue | Sort-Object { [version]$_.Name } | Select-Object -Last 1
            if (-not $sourceDir) { throw ('No Modules\Posh-SSH\<version> in {0}.' -f $PackagePath) }
            $wanted = [version]$sourceDir.Name
        } elseif ($PoshSshVersion) {
            $wanted = [version]$PoshSshVersion
        } else {
            $wanted = ConvertTo-Version ((Invoke-Pwsh '(Find-PSResource -Name Posh-SSH -Repository PSGallery).Version.ToString()') -join '')
        }

        if ($installed -and $installed -ge $wanted) { Add-Result $component 'UpToDate' ('{0} installed' -f $installed) 'HR-MOD-02'; return }
        $action = if ($installed) { 'Update {0} to {1}' -f $installed, $wanted } else { 'Install {0}' -f $wanted }
        if (-not $PSCmdlet.ShouldProcess('Posh-SSH (PowerShell 7, all users)', $action)) { Add-Result $component 'Skipped' ('WhatIf: {0}' -f $action) 'HR-MOD-02'; return }
        if (-not (Test-Administrator)) { throw 'Installing Posh-SSH for all users needs an elevated session.' }

        if ($sourceDir) {
            $target = Join-Path $env:ProgramFiles ('PowerShell\Modules\Posh-SSH\{0}' -f $sourceDir.Name)
            New-Item -ItemType Directory -Path $target -Force | Out-Null
            Copy-Item -Path (Join-Path $sourceDir.FullName '*') -Destination $target -Recurse -Force
            Get-ChildItem -Path $target -Recurse -File | Unblock-File
        } else {
            $null = Invoke-Pwsh ("Install-PSResource -Name Posh-SSH -Version '{0}' -Repository PSGallery -Scope AllUsers -TrustRepository -Reinstall" -f $wanted)
        }
        $status = if ($installed) { 'Updated' } else { 'Installed' }
        Add-Result $component $status ('{0}' -f $wanted) 'HR-MOD-02'
    } catch {
        Add-Result $component 'Failed' $_.Exception.Message 'HR-MOD-02'
    }
}

#endregion

#region ActiveDirectory (RSAT)

function Install-ActiveDirectoryModule {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $component = 'ActiveDirectory module'
    try {
        if ($DownloadOnly) { Add-Result $component 'Skipped' 'Windows feature; not part of the bundle (see -FeatureSource)' 'HR-MOD-01'; return }
        if (Get-Module -ListAvailable -Name ActiveDirectory) { Add-Result $component 'UpToDate' 'Present' 'HR-MOD-01'; return }
        # ProductType is WinNT on Windows 10/11; ServerNT or LanmanNT on Windows Server.
        $isServer = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType -ne 'WinNT'
        $action = if ($isServer) { 'Install-WindowsFeature RSAT-AD-PowerShell' } else { 'Add-WindowsCapability Rsat.ActiveDirectory.DS-LDS.Tools' }
        if (-not $PSCmdlet.ShouldProcess('This computer', $action)) { Add-Result $component 'Skipped' ('WhatIf: {0}' -f $action) 'HR-MOD-01'; return }
        if (-not (Test-Administrator)) { throw 'Installing RSAT needs an elevated session.' }

        if ($isServer) {
            $result = Install-WindowsFeature -Name RSAT-AD-PowerShell
            if (-not $result.Success) { throw ('Install-WindowsFeature failed: {0}' -f $result.ExitCode) }
        } else {
            $capability = Get-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools*' | Select-Object -First 1
            $capArgs = @{ Online = $true; Name = $capability.Name }
            if ($FeatureSource) { $capArgs.Source = $FeatureSource; $capArgs.LimitAccess = $true }
            $null = Add-WindowsCapability @capArgs
        }
        Add-Result $component 'Installed' $action 'HR-MOD-01'
    } catch {
        Add-Result $component 'Failed' $_.Exception.Message 'HR-MOD-01'
    }
}

#endregion

#region Main

if ($DownloadOnly -and -not $PackagePath) { throw '-DownloadOnly needs -PackagePath (where to write the bundle).' }
if ($PackagePath -and -not $DownloadOnly -and -not (Test-Path $PackagePath)) { throw ('PackagePath {0} not found.' -f $PackagePath) }

$script:LogDir = if ($DownloadOnly) { $PackagePath } else { Join-Path $InstallRoot 'InstallLogs' }
if (-not $WhatIfPreference) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }
if ($DownloadOnly) { New-Item -ItemType Directory -Path $PackagePath -Force | Out-Null }
$transcribing = $false
if (-not $WhatIfPreference) {
    Start-Transcript -Path (Join-Path $script:LogDir ('Install-aPeDiscovery_{0}.log' -f $Stamp)) | Out-Null
    $transcribing = $true
}

try {
    $mode = if ($DownloadOnly) { 'Building offline bundle in {0}' -f $PackagePath } elseif ($PackagePath) { 'Installing from bundle {0}' -f $PackagePath } else { 'Installing from the internet' }
    Write-Host ('{0}. Root: {1}. Ref: {2}. Components: {3}.' -f $mode, $InstallRoot, $Ref, ($Components -join ', '))

    # Order matters: Posh-SSH installs through PowerShell 7.
    if ('PowerShell' -in $Components) { Install-PowerShell7 }
    if ('Repositories' -in $Components) {
        if (-not $DownloadOnly -and -not $WhatIfPreference) { New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null }
        foreach ($repository in $Repositories) { Install-Repository -Name $repository }
    }
    if ('PoshSSH' -in $Components) { Install-PoshSsh }
    if ('ActiveDirectory' -in $Components) { Install-ActiveDirectoryModule }

    if (-not $DownloadOnly) {
        $cliPath = 'C:\Program Files\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe'
        if (Test-Path $cliPath) { Add-Result 'CyberArk Credential Provider' 'UpToDate' 'Present (not managed by this script)' 'HR-CA-01' }
        else { Add-Result 'CyberArk Credential Provider' 'Missing' 'Not at the default path. Needed only for CP credential sources; install it separately.' 'HR-CA-01' }
    }
} finally {
    Write-Host ''
    $Results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    if ($transcribing) { Stop-Transcript | Out-Null }
}

if ($Results | Where-Object Status -eq 'Failed') { exit 1 }
exit 0

#endregion
