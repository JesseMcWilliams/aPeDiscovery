#Requires -Version 5.1
<#
    Shared credential resolution for the aPeDiscovery scripts.

    Supported sources: CurrentUser, PSCredential, CP, CCP, Conjur.

    IMPORTANT - verify before production use:
    The CP, CCP, and Conjur helpers below implement each product's documented
    integration pattern (AAM Credential Provider CLI, CCP/AIMWebService REST API,
    and Conjur's authn + secrets REST API). Exact details such as install paths,
    web service virtual-directory names, supported query parameters, and
    authentication options vary by product version and by how your environment
    is configured. Confirm every value in the CredentialParams for each
    domain/computer entry (AppID, Safe, Object/Query, BaseUrl, ApplianceUrl,
    Account, etc.) against your own CyberArk deployment before relying on this
    in production, and treat this module as a starting point rather than a
    verified-against-your-tenant implementation.
#>

function Get-DiscoveryCredential {
    <#
    .SYNOPSIS
        Resolves a PSCredential (or $null for CurrentUser) from a named source.
    .PARAMETER Source
        One of CurrentUser, PSCredential, CP, CCP, Conjur.
    .PARAMETER Params
        Hashtable of source-specific parameters. See Docs\Configuration.md.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('CurrentUser', 'PSCredential', 'CP', 'CCP', 'Conjur')] [string] $Source,
        [hashtable] $Params = @{},
        [string] $LogPath
    )

    switch ($Source) {
        'CurrentUser' { return $null }
        'PSCredential' { return Get-CredentialFromFile -Params $Params }
        'CP' { return Get-CredentialFromCP -Params $Params }
        'CCP' { return Get-CredentialFromCCP -Params $Params }
        'Conjur' { return Get-CredentialFromConjur -Params $Params }
    }
}

function Get-CredentialFromFile {
    param([hashtable] $Params)

    if (-not $Params.CredentialFilePath) {
        throw "PSCredential source requires 'CredentialFilePath' in CredentialParams."
    }
    if (-not (Test-Path -Path $Params.CredentialFilePath)) {
        throw "Credential file not found at '$($Params.CredentialFilePath)'."
    }

    # Export-Clixml encrypts via DPAPI for the user+machine that created it, so
    # this file must have been exported by the same account that will run this
    # script (e.g. the scheduled task's Run As identity, on the same host).
    return Import-Clixml -Path $Params.CredentialFilePath
}

function Get-CredentialFromCP {
    param([hashtable] $Params)

    $sdkPath = if ($Params.ClipasswordsdkPath) {
        $Params.ClipasswordsdkPath
    } else {
        'C:\Program Files (x86)\CyberArk\ApplicationPasswordSdk\CLIPasswordSDK.exe'
    }

    if (-not (Test-Path -Path $sdkPath)) {
        throw "CLIPasswordSDK.exe not found at '$sdkPath'. Confirm the Credential Provider (CP) is installed on this host, or set 'ClipasswordsdkPath' in CredentialParams to its actual location."
    }
    if (-not $Params.AppID) {
        throw "CP source requires 'AppID' in CredentialParams."
    }

    $query = $Params.Query
    if (-not $query) {
        $parts = [System.Collections.Generic.List[string]]::new()
        if ($Params.Safe) { $parts.Add("Safe=$($Params.Safe)") }
        if ($Params.Folder) { $parts.Add("Folder=$($Params.Folder)") }
        if ($Params.Object) { $parts.Add("Object=$($Params.Object)") }
        if ($parts.Count -eq 0) {
            throw "CP source requires either 'Query', or one or more of 'Safe'/'Folder'/'Object', in CredentialParams."
        }
        $query = $parts -join ';'
    }

    $arguments = @(
        'GetPassword'
        '/p', "AppDescs.AppID=$($Params.AppID)"
        '/p', "Query=$query"
        '/o', 'Password,PassProps.UserName'
    )

    $output = & $sdkPath @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "CLIPasswordSDK GetPassword failed for AppID '$($Params.AppID)' (exit code $LASTEXITCODE). Verify the AppID/Safe/Folder/Object values and that this host is registered with the CP. (Output withheld in case it echoed the query back with sensitive values.)"
    }

    $resultLine = ($output | Select-Object -Last 1)
    $map = @{}
    foreach ($token in ($resultLine -split ',')) {
        if ($token -match '^(?<k>[^=]+)=(?<v>.*)$') {
            $map[$Matches.k.Trim()] = $Matches.v
        }
    }

    if (-not $map.ContainsKey('Password')) {
        throw "CLIPasswordSDK did not return a Password value for AppID '$($Params.AppID)'. Verify the AppID/Safe/Folder/Object/Query values."
    }

    $userName = if ($map.ContainsKey('PassProps.UserName')) { $map['PassProps.UserName'] } elseif ($Params.UserName) { $Params.UserName } else {
        throw "CP did not return PassProps.UserName and no fallback 'UserName' was provided in CredentialParams."
    }

    $securePassword = ConvertTo-SecureString -String $map['Password'] -AsPlainText -Force
    return New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword
}

function Get-CredentialFromCCP {
    param([hashtable] $Params)

    if (-not $Params.BaseUrl) {
        throw "CCP source requires 'BaseUrl' in CredentialParams (e.g. https://ccp.contoso.com)."
    }
    if (-not $Params.AppID) {
        throw "CCP source requires 'AppID' in CredentialParams."
    }

    $queryPairs = [System.Collections.Generic.List[string]]::new()
    $queryPairs.Add("AppID=$([uri]::EscapeDataString($Params.AppID))")
    if ($Params.Query) {
        $queryPairs.Add("Query=$([uri]::EscapeDataString($Params.Query))")
    } else {
        if ($Params.Safe) { $queryPairs.Add("Safe=$([uri]::EscapeDataString($Params.Safe))") }
        if ($Params.Object) { $queryPairs.Add("Object=$([uri]::EscapeDataString($Params.Object))") }
        if ($Params.Folder) { $queryPairs.Add("Folder=$([uri]::EscapeDataString($Params.Folder))") }
    }
    if ($Params.Reason) { $queryPairs.Add("Reason=$([uri]::EscapeDataString($Params.Reason))") }

    $uri = '{0}/AIMWebService/api/Accounts?{1}' -f $Params.BaseUrl.TrimEnd('/'), ($queryPairs -join '&')

    $invokeParams = @{ Uri = $uri; Method = 'Get'; ErrorAction = 'Stop' }
    if ($Params.ClientCertificateThumbprint) {
        $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$($Params.ClientCertificateThumbprint)" -ErrorAction SilentlyContinue
        if (-not $cert) { $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$($Params.ClientCertificateThumbprint)" -ErrorAction SilentlyContinue }
        if (-not $cert) { throw "Client certificate with thumbprint '$($Params.ClientCertificateThumbprint)' was not found in LocalMachine\My or CurrentUser\My." }
        $invokeParams.Certificate = $cert
    }

    try {
        $response = Invoke-RestMethod @invokeParams
    } catch {
        throw "CCP request for AppID '$($Params.AppID)' failed: $($_.Exception.Message). Verify BaseUrl, the AIMWebService virtual directory name, and network/TLS connectivity to the CCP server."
    }

    if (-not $response.Content) {
        throw "CCP response for AppID '$($Params.AppID)' did not include a Content (password) field. Verify Safe/Object/Query and that the account is accessible to this AppID."
    }

    $securePassword = ConvertTo-SecureString -String $response.Content -AsPlainText -Force
    return New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $response.UserName, $securePassword
}

function Get-CredentialFromConjur {
    param([hashtable] $Params)

    foreach ($required in 'ApplianceUrl', 'Account', 'AuthnLogin', 'Identifier') {
        if (-not $Params[$required]) {
            throw "Conjur source requires '$required' in CredentialParams."
        }
    }

    $apiKey = $null
    if ($Params.ApiKeyPath) {
        if (-not (Test-Path -Path $Params.ApiKeyPath)) { throw "Conjur API key file not found at '$($Params.ApiKeyPath)'." }
        $apiKey = (Get-Content -Path $Params.ApiKeyPath -Raw).Trim()
    } elseif ($Params.ApiKeyEnvVar) {
        $apiKey = [Environment]::GetEnvironmentVariable($Params.ApiKeyEnvVar)
        if (-not $apiKey) { throw "Environment variable '$($Params.ApiKeyEnvVar)' is not set or is empty." }
    } else {
        throw "Conjur source requires either 'ApiKeyPath' or 'ApiKeyEnvVar' in CredentialParams to locate this host's Conjur API key."
    }

    $applianceUrl = $Params.ApplianceUrl.TrimEnd('/')
    $account = $Params.Account
    $authnLoginEncoded = [uri]::EscapeDataString($Params.AuthnLogin)

    try {
        $token = Invoke-RestMethod -Uri "$applianceUrl/authn/$account/$authnLoginEncoded/authenticate" -Method Post -Body $apiKey -ContentType 'text/plain' -ErrorAction Stop
    } catch {
        throw "Conjur authentication for host '$($Params.AuthnLogin)' failed: $($_.Exception.Message). Verify ApplianceUrl, Account, AuthnLogin, and the API key."
    }
    $tokenBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($token))

    $identifierEncoded = [uri]::EscapeDataString($Params.Identifier)
    try {
        $secretValue = Invoke-RestMethod -Uri "$applianceUrl/secrets/$account/variable/$identifierEncoded" -Method Get -Headers @{ Authorization = "Token token=`"$tokenBase64`"" } -ErrorAction Stop
    } catch {
        throw "Conjur secret retrieval for '$($Params.Identifier)' failed: $($_.Exception.Message)."
    }

    $userName = $null
    if ($Params.UserName) {
        $userName = $Params.UserName
    } elseif ($Params.UsernameIdentifier) {
        $usernameIdentifierEncoded = [uri]::EscapeDataString($Params.UsernameIdentifier)
        try {
            $userName = Invoke-RestMethod -Uri "$applianceUrl/secrets/$account/variable/$usernameIdentifierEncoded" -Method Get -Headers @{ Authorization = "Token token=`"$tokenBase64`"" } -ErrorAction Stop
        } catch {
            throw "Conjur username retrieval from '$($Params.UsernameIdentifier)' failed: $($_.Exception.Message)."
        }
    } else {
        throw "Conjur source requires either 'UserName' (literal) or 'UsernameIdentifier' (a second Conjur variable path) in CredentialParams."
    }

    $securePassword = ConvertTo-SecureString -String $secretValue -AsPlainText -Force
    return New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword
}

Export-ModuleMember -Function Get-DiscoveryCredential
