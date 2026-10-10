# Target research: enterprise hypervisors

> **Stage: Planning.** Research on discovering privileged access to virtualization platforms. Whoever controls the hypervisor controls every VM on it, so these accounts are top-tier. Nothing here is built. Coverage status: [Planning_Target-Coverage.md](Planning_Target-Coverage.md). Questions referenced as (Qnn) are in [Planning_Questions.md](Planning_Questions.md).

**Researched:** 2026-10-09

## Common approach

- **Two layers on each platform:**
  - the **management plane** (vCenter, Prism Central, SCVMM or Windows Admin Center), with its roles and permissions;
  - the **hosts themselves** (ESXi, AHV/CVM, Hyper-V hosts), with their local accounts.

  Both need covering: host-local accounts (`root` on ESXi, `nutanix`/`admin` on CVMs, local Administrators on Hyper-V hosts) bypass the management plane.
- **Collection runs on the scanning host,** through the management API. Hyper-V hosts are Windows, so the Windows scan covers them, plus the `Hyper-V Administrators` group.
- **Scan identity:** a read-only role in the management plane, vaulted in CyberArk; directory-backed (AD/SSO) where possible.
- **Also collect the VM inventory** (name, guest OS, DNS name, power state). It's an inventory source for the OS scans, and it shows which VMs run on which host.

## 1. VMware vSphere (vCenter and ESXi)

| Item | Detail |
|---|---|
| Collect (vCenter) | Roles and their privileges; **permissions** (principal, role, object, propagate), especially Administrator role assignments at the root and datacenter level; SSO users and groups (`vsphere.local` Administrators, `SolutionUsers`); identity sources. |
| Collect (ESXi) | Local accounts (`Get-VMHostAccount`) and host permissions; **lockdown mode** state and the **exception users** list (`QueryLockdownExceptions()`); SSH and ESXi Shell service state. |
| Method | vSphere API through PowerCLI (`Get-VIPermission`, `Get-VIRole`, `Get-VMHostAccount`, `Get-View` of `HostAccessManager`), or the vSphere Automation REST API. |
| Least privilege | The built-in **Read-only** role, granted at the vCenter root with propagation. Reading SSO users and groups needs a vCenter SSO account with read access to SSO. |
| Pitfalls | In lockdown mode, ESXi rejects direct connections except from exception users, so read host-level data **through vCenter** where possible (Q89). PowerCLI is another dependency for the install script (HR-MOD). |
| Transport | HTTPS 443 to vCenter (and to ESXi if read directly). |

## 2. Nutanix (Prism Central, Prism Element, AHV)

| Item | Detail |
|---|---|
| Collect | Prism Central IAM: local users, directory/IdP users and groups, **roles** (Super Admin, Prism Admin, custom roles), **authorization policies** (role plus scope plus identities), service accounts and API keys. Per cluster: Prism Element local users (the default `admin`); CVM and AHV host local accounts (`nutanix`, `admin`, `root`). |
| Method | Prism Central **v4 REST API** (IAM namespace) over HTTPS with an API key (`X-ntnx-api-key`), or v3 for older versions. CVM and host local accounts need SSH, with the Linux collector adapted to the CVM. |
| Least privilege | **Prism Viewer** role (view-only) for the API identity. |
| Pitfalls | The Prism Element `admin` and CVM `nutanix` passwords are often set the same, or left at default after deployment, so flag them. v4 API availability depends on the Prism Central version (Q88). |
| Transport | HTTPS 9440 to Prism Central and Prism Element; SSH 22 to CVMs for host-level accounts. |

## 3. Microsoft Hyper-V

| Item | Detail |
|---|---|
| Collect | On each host: local **Administrators** and **Hyper-V Administrators** members (full control of every VM on that host); VM inventory (`Get-VM`); failover cluster membership. If SCVMM is used: user roles (Administrator, Fabric Administrator, Tenant Administrator) and run-as accounts, which store credentials. If Windows Admin Center is used: its gateway access and RBAC. |
| Method | Hosts: the Windows scan (local groups), plus a `Get-VM` inventory over WinRM/JEA. SCVMM: the VMM PowerShell module (`Get-SCUserRole`, `Get-SCRunAsAccount`) against the VMM server. |
| Least privilege | Reading local groups needs the Windows scan's access (F4, or JEA). `Get-VM` needs `Hyper-V Administrators`, which is full control of the host's VMs. A JEA endpoint exposing only `Get-VM` avoids granting that to the scan identity. |
| Pitfalls | SCVMM run-as accounts hold credentials for hosts and guests. They're CyberArk onboarding candidates in their own right. |

## 4. Others (only if present, Q70)

| Platform | Admin data | Method |
|---|---|---|
| **Proxmox VE** | `pveum user list`, ACLs, API tokens, `root@pam` | REST API (8006) with a PVEAuditor role |
| **Red Hat OpenShift Virtualization / KubeVirt** | Kubernetes RBAC (ClusterRoleBindings to `cluster-admin`) | Kubernetes API with a read-only ClusterRole |
| **Citrix Hypervisor / XenServer** | Pool admins (RBAC roles: Pool Admin, Pool Operator, Read Only) | XAPI with the Read Only role |

## 5. Security practices

- **Treat hypervisor admins as Tier 0** (same tier as domain admins): vault them, require MFA, and separate them from day-to-day accounts.
- **Lockdown mode on ESXi,** with an empty exception-users list unless justified (STIG guidance); manage hosts through vCenter.
- **Directory-backed identities** for management planes, with local accounts kept only as break-glass and vaulted.
- **The scan identity is read-only, on the management plane only,** and restricted by source IP where the platform allows it.
- **API keys** have a lifetime, live in CyberArk, and are scoped to view-only roles.

## Sources

- [VMware blog: lockdown mode exception users](https://blogs.vmware.com/vsphere/?p=16881)
- [Lockdown mode exception users and Get-VMHostAccount](https://www.yelof.com/2015/03/27/vsphere-6-0-lockdown-mode-exception-users/)
- [STIG: vSphere 8 ESXi exception users](https://www.stigviewer.com/stigs/vmware_vsphere_80_esxi_v1/2023-10-11/finding/V-258760)
- [Nutanix: fine-grained RBAC with Prism Central](https://www.nutanix.com/blog/fine-grained-rbac-with-nutanix-prism-central)
- [Nutanix community: Prism user permissions](https://next.nutanix.com/prism-for-infra-and-it-ops-26/prism-user-permissions-what-are-the-options-37266)
- [TechTarget: Hyper-V Administrators security group](https://www.techtarget.com/searchitoperations/tip/Manage-host-VM-access-with-a-Hyper-V-administrators-security-group)
- [Axonius: Hyper-V over PowerShell remoting](https://docs.axonius.com/docs/hyperv-pwsh)
