function Get-ScopedOrganizationalUnits {
    <#
    .SYNOPSIS
        Returns the base OU plus every descendant OU up to a maximum depth.
    .DESCRIPTION
        AD's own -SearchScope only supports Base/OneLevel/Subtree, so an
        arbitrary depth limit has to be built manually: enumerate every OU
        under the base, then keep the ones whose OU-component depth relative
        to the base is <= Depth.
    .PARAMETER Depth
        0 = only the base OU itself. 1 = base OU + its immediate children.
        -1 (or any negative value) = unlimited (equivalent to Subtree).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $BaseOU,
        [Parameter(Mandatory)] [int] $Depth,
        [Parameter(Mandatory)] [hashtable] $AdParams
    )

    if ($Depth -lt 0) {
        $descendants = Get-ADOrganizationalUnit -SearchBase $BaseOU -SearchScope Subtree -Filter * @AdParams |
            Select-Object -ExpandProperty DistinguishedName
        return , $BaseOU + $descendants
    }

    if ($Depth -eq 0) {
        return , $BaseOU
    }

    # Count RDN components, treating a comma preceded by a backslash as an
    # escaped literal (e.g. "OU=Smith\, Co") rather than a component separator.
    $baseComponentCount = ([regex]::Matches($BaseOU, '(?<!\\),')).Count + 1

    $result = [System.Collections.Generic.List[string]]::new()
    $result.Add($BaseOU)

    $descendants = Get-ADOrganizationalUnit -SearchBase $BaseOU -SearchScope Subtree -Filter * @AdParams
    foreach ($ou in $descendants) {
        $componentCount = ([regex]::Matches($ou.DistinguishedName, '(?<!\\),')).Count + 1
        $relativeDepth = $componentCount - $baseComponentCount
        if ($relativeDepth -le $Depth) {
            $result.Add($ou.DistinguishedName)
        }
    }

    return $result
}

Export-ModuleMember -Function Get-ScopedOrganizationalUnits
