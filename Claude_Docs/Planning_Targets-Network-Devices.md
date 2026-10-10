# Target research: enterprise network devices

> **Stage: Planning.** Research on discovering local and privileged accounts on switches, routers, firewalls and load balancers. Nothing here is built. Coverage status: [Planning_Target-Coverage.md](Planning_Target-Coverage.md). Questions referenced as (Qnn) are in [Planning_Questions.md](Planning_Questions.md).

**Researched:** 2026-10-09

## Common approach

- **What matters on network devices:**
  - **local accounts:** the break-glass and fallback accounts used when TACACS+/RADIUS is unreachable, and their privilege levels;
  - **AAA configuration:** which servers, and whether local fallback is allowed;
  - **API keys and API admin accounts;**
  - **SNMP credentials,** which are effectively passwords.

  With central AAA in place, most people log on with directory identities. The privileged things to vault are the local fallback accounts, the enable secret and the API accounts.
- **Collection runs on the scanning host;** nothing runs on the device. The order of preference:
  1. **The vendor REST/XML API or NETCONF/RESTCONF:** structured data, read-only roles available.
  2. **SSH CLI:** `show running-config` sections, parsed on the scanning host.
  3. **SNMPv3:** only for model and version inventory, not accounts.
- **The parsed result only:** device configs contain password hashes, SNMP keys and pre-shared keys. The collector extracts usernames, privilege levels and AAA settings **in memory** and never stores the config text (Q87).
- **Scan identity:** a read-only role through central AAA where possible, so there's no local account to manage per device. Otherwise, a local read-only account vaulted in CyberArk.
- **Inventory source:** the network team's source of truth (NetBox, Infoblox, SolarWinds, Cisco DNA/ISE, Panorama, FortiManager). Central managers often expose admin accounts for every managed device through one API.

## 1. Cisco IOS / IOS XE / NX-OS

| Item | Detail |
|---|---|
| Collect | `username <name> privilege <n>` lines; the `enable secret` presence (not its value); `aaa authentication login`/`aaa authorization exec` method lists, and whether `local` is a fallback; `tacacs server`/`radius server` definitions; `ip ssh` version; `line vty` `transport input` (Telnet allowed?); SNMP users and community presence. |
| Method | RESTCONF/NETCONF (IOS XE: the `Cisco-IOS-XE-native` YANG model), or SSH `show running-config | section username|aaa|line vty|snmp`. |
| Least privilege | **Caveat:** RESTCONF/NETCONF on IOS XE requires **privilege level 15**, so it can't be read-only on the device itself. Use TACACS+ **command authorization** to allow only `show` commands for the scan account over SSH, or accept a privilege-15 account restricted by AAA. |
| Pitfalls | Type 7 passwords are reversible: flag any found, but never store the value. NX-OS uses roles (`network-admin`, `network-operator`) instead of privilege levels. |

## 2. Juniper Junos

| Item | Detail |
|---|---|
| Collect | `system login user` entries and their `class` (`super-user`, `operator`, `read-only`, custom classes); `system authentication-order`; remote templates (`remote`); root authentication presence. |
| Method | NETCONF over SSH (`get-configuration` with a `system login` filter); `show configuration system login | display json`. |
| Least privilege | A login class with read-only permissions (`view`, `view-configuration`); `view-configuration` is needed to see the login section. |

## 3. Palo Alto Networks (PAN-OS, Panorama)

| Item | Detail |
|---|---|
| Collect | Administrators (`mgt-config users`), their role (Superuser, Device admin, custom Admin Role profiles), authentication profile (local vs. SAML/RADIUS/TACACS+); API-key-capable admins; Panorama-pushed admins. |
| Method | XML API over HTTPS: `type=config&action=get&xpath=/config/mgt-config/users`. Panorama covers managed firewalls centrally. |
| Least privilege | A custom Admin Role profile with XML API **Configuration read** only, or "Superuser (read-only)". The API key is generated per admin; store it in CyberArk and rotate it. |
| Pitfalls | API keys don't expire unless key lifetime is configured, so set it. Local admins on each firewall can differ from Panorama's. |

## 4. Fortinet FortiGate (FortiOS, FortiManager)

| Item | Detail |
|---|---|
| Collect | `config system admin` entries (`accprofile`, trusted hosts, two-factor setting, remote/wildcard admins); REST API admins (`config system api-user`). |
| Method | FortiOS REST API over HTTPS: `GET /api/v2/cmdb/system/admin` and `/api/v2/cmdb/system/api-user`, using a REST API admin token with a **read-only** access profile. |
| Least privilege | A REST API administrator with a read-only `accprofile` and `trusthost` limited to the scanning host. Only a `super_admin` can create one. |
| Pitfalls | Admins with no `trusthost` entries can log in from anywhere, so flag them. |

## 5. Other common platforms

| Platform | Admin data | Method |
|---|---|---|
| **F5 BIG-IP** | `auth user` (role per partition), remote-role mappings | iControl REST `GET /mgmt/tm/auth/user` with an Auditor/Guest role |
| **Arista EOS** | `username ... role`, AAA | eAPI (JSON-RPC over HTTPS) `show running-config section username` with a read-only role |
| **Check Point** | Administrators, permission profiles | Management API `show-administrators` with a read-only profile |
| **Aruba/HPE switches** | Local manager/operator, AAA | REST API or SSH CLI |

## 6. Security practices

- **Prefer central AAA** (TACACS+ with command authorization) for the scan identity, with every command logged.
- **Vault the local fallback accounts** in CyberArk (the main onboarding target), with one per device or a managed shared account by policy.
- **Encrypted management only:** SSH v2, HTTPS, NETCONF over SSH. **Never Telnet or HTTP**; report devices that still allow them.
- **SNMPv3 authPriv** (SHA-2, AES) for any SNMP the scanner uses. SNMPv1/v2c community strings travel in cleartext and are themselves credentials to discover and rotate.
- **Restrict the scan identity by source address** (trusted hosts, management ACLs) to the scanning host.
- **Read-only API tokens** with a lifetime, stored in CyberArk.

## Sources

- [Cisco DevNet: RESTCONF user guide](https://developer.cisco.com/site/odp/documents/user-guide-restconf/)
- [AlphaPrep: NETCONF/RESTCONF on IOS XE](https://blog.alphaprep.net/configuring-and-verifying-netconf-and-restconf-on-cisco-ios-xe-for-ccnp-350-401-encor/)
- [Palo Alto Networks: enabling API access](https://docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security/pan-os-api-authentication)
- [Fortinet: REST API administrator](https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/399023)
- [CIS Cisco NX-OS: AAA with TACACS+](https://www.tenable.com/audits/items/CIS_Cisco_NX-OS-v1.1.0_Level_1.audit:270d8503a2fb27633f693198b40360b2)
- [NetworkLessons: local privilege authorization fallback](https://forum.networklessons.com/t/local-privilege-authorization-fallback/4045)
- [SNMP security best practices (BMC Helix)](https://docs.helixops.ai/bin/IT-Operations-Management/Operations-Management/BMC-Helix-Network-Management/NetworkManagement/Miscellaneous/SNMP-Security-Best-Practices/)
