function Test-TcpPortOpen {
    <#
    .SYNOPSIS
        Lightweight TCP connect test with a short timeout.
    .DESCRIPTION
        Used instead of an ICMP ping (Test-Connection) for reachability checks, since ICMP can be
        blocked by firewalls between the scanning host and a target that is otherwise fully
        reachable on the port the scan actually depends on - a ping-based check would then skip a
        perfectly reachable computer. Connecting directly to the real dependency's port avoids
        that false negative.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [int] $Port,
        [int] $TimeoutMs = 2000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $completed = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs)
        if ($completed -and $client.Connected) {
            $client.EndConnect($asyncResult)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

Export-ModuleMember -Function Test-TcpPortOpen
