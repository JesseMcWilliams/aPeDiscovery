# aPeDiscovery: network and firewall requirements

> **Stage: Reference.** For the network and firewall teams: every connection aPeDiscovery makes, so rules can be opened before deployment. Keep it current: any change that adds or removes a connection updates this file in the same change. Item IDs (`HR-NET-<NN>`) are shared with [Reference_Scanning-Host-Requirements.md](Reference_Scanning-Host-Requirements.md); never reuse or renumber one.

**Last updated:** 2026-10-09

## Summary

- **All connections start at the scanning host.** No inbound connections to it are needed today. A web interface is planned for a later phase, and would change this.
- **Production scans need:**
  - AD Web Services (TCP 9389), DNS and Kerberos to domain controllers;
  - SMB (TCP 445) to Windows targets;
  - SSH (TCP 22) to Linux targets;
  - HTTPS or the Vault port for CyberArk.
- **Installation and updates need** outbound HTTPS to GitHub and the PowerShell Gallery. Alternatively, use the install script's offline bundle and open nothing extra.
- **Scope:** "domain controllers" and "targets" means every domain and computer listed in the scan configs, including domains with no trust to the scanning host's domain.

## Ports by purpose

**Required** means the scan fails for that domain or computer without it. **Recommended** means it works without it, but less well (noted per row). **Optional** means only if that feature is configured.

### Active Directory (`Export-ADObjects.ps1`)

| ID | Destination | Protocol / port | Need | Notes |
|---|---|---|---|---|
| HR-NET-01 | Domain controllers of every scanned domain | TCP 9389 (AD Web Services) | Required | The ActiveDirectory PowerShell module does all its queries through AD Web Services, not directly over LDAP. |
| HR-NET-03 | DNS servers that resolve every scanned domain and its DCs | UDP/TCP 53 | Required | For untrusted domains, this host's DNS must still resolve them (conditional forwarders), or the domain's `Server` must be an IP address. |
| HR-NET-10 | Domain controllers of every scanned domain | TCP/UDP 88 (Kerberos) | Recommended | Authenticates the scan account. Without it, Windows falls back to NTLM where the domain allows it; domains that block NTLM will fail. |
| HR-NET-02 | Domain controllers of every scanned domain | UDP 389 (CLDAP, DC locator) | Optional | Only used to find a DC when a domain's `Server` isn't set. Setting `Server` per domain avoids it. TCP 389/636 (LDAP/LDAPS) aren't used. |

### Windows computers (`Export-LocalGroups.ps1`)

| ID | Destination | Protocol / port | Need | Notes |
|---|---|---|---|---|
| HR-NET-04 | Every Windows target | TCP 445 (SMB) | Required | Local users, groups and services are read over SMB. The target's own Windows Firewall must allow "File and Printer Sharing (SMB-In)" from the scanning host. TCP 135/139 and WinRM (5985/5986) aren't used. |
| HR-NET-10 | DCs of each target's domain | TCP/UDP 88 | Recommended | As above, for domain scan accounts. |
| HR-NET-09 | Every Windows target | TCP 1433, 3306, 5432, 1521, 27017 (default database signatures), plus any port in configured `SoftwareSignatures` | Optional | A single connect test only, to fill the `Listening` column. If blocked, the service is reported as not listening (a false negative); the scan still succeeds. |

### Linux computers (`Export-LocalLinuxGroups.ps1`)

| ID | Destination | Protocol / port | Need | Notes |
|---|---|---|---|---|
| HR-NET-05 | Every Linux target | TCP 22 (SSH) | Required | One SSH session per computer. The target's host firewall (firewalld, iptables, nftables) must allow it from the scanning host, and `sshd` must allow the scan account (`AllowUsers`/`AllowGroups`/`Match` blocks). Listening ports on Linux are read on the target itself (`ss`), so no extra ports are needed. |

### CyberArk credential retrieval

Only for the credential sources the configs use.

| ID | Destination | Protocol / port | Need | Notes |
|---|---|---|---|---|
| HR-NET-08 | CyberArk Vault | TCP 1858 (default) | Required for `CP` | Made by the Credential Provider service on the scanning host, not by the scripts. |
| HR-NET-06 | CCP web server (`BaseUrl`) | TCP 443 | Required for `CCP` | HTTPS; may use a client certificate. |
| HR-NET-07 | Conjur appliance or tenant (`ApplianceUrl`) | TCP 443 | Required for `Conjur` | HTTPS |

### Installation and updates (`Install-aPeDiscovery.ps1`)

Only while the install script runs. Not needed when it runs from an offline bundle (`-PackagePath`).

| ID | Destination | Protocol / port | Need | Notes |
|---|---|---|---|---|
| HR-NET-11 | `api.github.com`, `github.com`, `codeload.github.com`, and GitHub's download hosts (`*.githubusercontent.com`) | TCP 443 | Install/update | Finds and downloads PowerShell 7 and the three repositories. Release downloads redirect to a GitHub download host. Allow the wildcard, or confirm the exact host in your proxy logs. |
| HR-NET-12 | `www.powershellgallery.com` and its download host | TCP 443 | Install/update | Posh-SSH. The gallery redirects package downloads to a separate host; confirm it in your proxy logs. |
| HR-NET-13 | Windows Update or your WSUS server | TCP 443/80 (or your WSUS port) | Install, Windows 10/11 hosts only | Installing the AD module on a client OS downloads it as a Windows feature. Windows Server installs it from local files. |

### Later phases (not needed yet)

| ID | Destination | Protocol / port | Phase | Notes |
|---|---|---|---|---|
| HR-NET-14 | The target MSSQL server for direct import | TCP 1433 (or the instance's port) | 3 | Direct import replaces handing over CSV files. |
| HR-NET-15 | Inbound to the scanning host (or a separate web server) | TCP 443 | 4 | Web interface. Its design will settle where it runs. |

## Firewall request template

Copy one row per rule:

| Source | Destination | Port / protocol | Purpose | ID |
|---|---|---|---|---|
| `<scanning host>` | `<DCs of domain X>` | TCP 9389; TCP/UDP 88; UDP/TCP 53 to `<DNS servers>` | AD discovery | HR-NET-01/10/03 |
| `<scanning host>` | `<Windows targets>` | TCP 445 | Windows local discovery | HR-NET-04 |
| `<scanning host>` | `<Linux targets>` | TCP 22 | Linux local discovery | HR-NET-05 |
| `<scanning host>` | `<Vault>` | TCP 1858 | CyberArk CP | HR-NET-08 |
| `<scanning host>` | `<CCP server>` | TCP 443 | CyberArk CCP | HR-NET-06 |

## Traffic profile

So the network team knows what normal looks like:

- **Scheduled bursts, not continuous traffic.** Each scheduled task runs, then exits.
- **Windows and Linux scans are parallel.** Up to `MaxConcurrency` targets (set per config) are contacted at once, with one short SMB or SSH session per target.
- **AD scans** run one domain at a time: a series of queries over AD Web Services.
- **Volume:** small per target (user, group and service lists). AD volume grows with the number of objects in scope.
