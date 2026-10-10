# Target research: enterprise databases

> **Stage: Planning.** Research on discovering privileged logins and roles inside database engines. None of this is built; today the Windows and Linux scans only detect that a database is installed and listening. Coverage status: [Planning_Target-Coverage.md](Planning_Target-Coverage.md). Questions referenced as (Qnn) are in [Planning_Questions.md](Planning_Questions.md).

**Researched:** 2026-10-09

## Common approach

- **Finding instances:** reuse what the OS scans already find (`LocalDatabases.csv`, `LinuxDatabases.csv`), plus AD `MSSQLSvc/` SPNs, to build the instance list. No network-wide port scanning.
- **Transport:** each engine's native protocol over TLS, from the scanning host. Nothing runs on the database server.
- **Scan identity:** one dedicated, **read-only** login per instance (or one managed account per engine), stored in CyberArk. **Never** `sa`, `SYS`, `postgres`, `root` or an instance owner. The queries below read catalog metadata only, not user data.
- **What to collect:**
  - every login/user and whether it's enabled, locked or expired;
  - its authentication type (database password, Windows/Kerberos, OS, external);
  - membership in **administrative roles** and holders of **system-level privileges**;
  - the engine's built-in super accounts and their state.
- **Client libraries:** SQL Server needs no extra install (.NET's SqlClient). PostgreSQL and MySQL need open-source .NET drivers (Npgsql, MySqlConnector). Oracle needs its managed .NET driver (ODP.NET Managed, no Oracle Client install). Db2 needs IBM's .NET driver. These are copied into the repo like SQLite, subject to licensing (Q85).

## 1. Microsoft SQL Server

| Item | Detail |
|---|---|
| Privileged | Members of `sysadmin`, `securityadmin`, `serveradmin`; holders of `CONTROL SERVER`, `IMPERSONATE ANY LOGIN`, `ALTER ANY LOGIN`; `sa` state; per-database `db_owner` (optional, much larger). |
| Queries | `sys.server_principals` (type, `is_disabled`); `sys.server_role_members` joined to principals; `sys.server_permissions` where `permission_name IN ('CONTROL SERVER','IMPERSONATE ANY LOGIN','ALTER ANY LOGIN')`; `LOGINPROPERTY(name,'IsLocked')` and `'PasswordLastSetTime'`. |
| Least privilege | `VIEW ANY DEFINITION` and `VIEW SERVER STATE` (SQL 2022+: `VIEW SERVER SECURITY STATE`); no fixed server role. |
| Auth | Windows authentication (Kerberos) as a domain scan account is preferred; it removes a SQL password. TLS required (`Encrypt=True`, trusted certificate). |
| Pitfalls | Windows groups as logins (`BUILTIN\Administrators`, domain groups) need expanding through AD or the Windows scan; AG/FCI listener names vs. node names. |

## 2. Oracle Database

| Item | Detail |
|---|---|
| Privileged | Holders of the `DBA` role; `SYSDBA`, `SYSOPER`, `SYSBACKUP`, `SYSDG`, `SYSKM`, `SYSASM` (`V$PWFILE_USERS`); powerful system privileges such as `ANY` privileges and `GRANT ANY ROLE` (`DBA_SYS_PRIVS`); default accounts (`SYS`, `SYSTEM`) and their state; OS authentication through the OS `dba` group (see the Linux scan). |
| Queries | `DBA_USERS` (account status, profile, authentication type, last login); `DBA_ROLE_PRIVS`; `DBA_SYS_PRIVS`; `V$PWFILE_USERS`; in multitenant, `CDB_*` views from the root container to cover every PDB. |
| Least privilege | `CREATE SESSION` and `SELECT_CATALOG_ROLE` (or `SELECT ANY DICTIONARY`). No `DBA`. |
| Transport | Oracle Net (TCP 1521 by default) with native network encryption or TLS (TCPS 2484). |
| Pitfalls | The OS `dba`/`oinstall` group membership grants `SYSDBA` without any database login, so correlate with the OS scan. Proxy users and enterprise users (OUD/OID) authenticate outside the database. |

## 3. PostgreSQL

| Item | Detail |
|---|---|
| Privileged | Roles with `rolsuper`, `rolcreaterole`, `rolreplication`, `rolbypassrls`; members of `pg_read_all_data`, `pg_write_all_data`, `pg_execute_server_program`, `pg_read_server_files`, `pg_write_server_files` (paths to OS command execution). |
| Queries | `pg_roles` (attributes, `rolcanlogin`, `rolvaliduntil`); `pg_auth_members` (membership, including nested); `pg_hba_file_rules` for who may connect from where and how. |
| Least privilege | A login role that's a member of `pg_monitor` (and `pg_read_all_settings`). `pg_hba_file_rules` needs superuser by default; reading it as non-superuser needs an explicit grant on the view or function (Q84). |
| Transport | TCP 5432 with `sslmode=verify-full`. |
| Pitfalls | `trust` and `peer` entries in `pg_hba.conf` grant access without passwords, so report them. The local `postgres` OS account usually has passwordless superuser through `peer`. |

## 4. MySQL and MariaDB

| Item | Detail |
|---|---|
| Privileged | Accounts with global `SUPER` (deprecated in 8.0 but still common), `ALL PRIVILEGES ON *.*`, `GRANT OPTION`, `CREATE USER`, `FILE`, `PROCESS`, `SHUTDOWN`, and 8.0 dynamic admin privileges (`SYSTEM_VARIABLES_ADMIN`, `CONNECTION_ADMIN`, `ROLE_ADMIN`, ...); roles (8.0+); `root@%` vs `root@localhost`. |
| Queries | `mysql.user` (host, plugin, `account_locked`, `password_last_changed`); `information_schema.USER_PRIVILEGES`; `mysql.global_grants` (dynamic privileges); `mysql.role_edges`. MariaDB: `mysql.global_priv`. |
| Least privilege | `SELECT` on the `mysql` schema system tables only. |
| Transport | TCP 3306 with TLS (`REQUIRE SSL` on the scan account). |
| Pitfalls | An account is user **plus host**; the same username on different hosts is a different account. `auth_socket`/`unix_socket` plugin accounts log in as OS users without a password. |

## 5. IBM Db2 (LUW)

| Item | Detail |
|---|---|
| Privileged | Instance level: `SYSADM`, `SYSCTRL`, `SYSMAINT`, `SYSMON`, which are granted by **OS group** through `SYSADM_GROUP` etc. in `db2 get dbm cfg`; when unset, `SYSADM` defaults to the instance owner's primary group. Database level: `DBADM`, `SECADM`, `ACCESSCTRL`, `DATAACCESS` (`SYSCAT.DBAUTH`), plus roles (`SYSCAT.ROLEAUTH`). |
| Queries | `SYSCAT.DBAUTH WHERE DBADMAUTH='Y' OR SECURITYADMAUTH='Y' OR ...`; `SYSIBMADM.DBMCFG` for the group parameters; `AUTH_LIST_AUTHORITIES_FOR_AUTHID` for effective authorities. |
| Least privilege | `CONNECT` plus `SELECT` on the catalog views (granted to `PUBLIC` by default in many installs). |
| Transport | DRDA (default TCP 50000) with SSL. |
| Pitfalls | Instance authorities live in OS groups, so the real privileged list comes from the OS scan of those group members. Db2 for z/OS is a different product, covered with the mainframe. |

## 6. Security practices (all engines)

- **Least privilege and separation:** a dedicated scan login per engine; catalog-read only; no access to application data; no `GRANT OPTION`.
- **TLS with certificate validation** on every connection; reject engines that only offer cleartext (report them instead).
- **Prefer integrated authentication** (Windows/Kerberos) over database passwords where the engine supports it.
- **Restrict the scan login to the scanning host:** SQL Server logon trigger or firewall, `pg_hba.conf` host rule, MySQL `user@'scanner-ip'`, Oracle valid-node checking.
- **Expect auditing:** catalog queries by the scan login appear in database audit trails (SQL Server Audit, Oracle Unified Auditing, pgAudit); agree this with DBAs and security.

## Sources

- [SQLAuthority: list sysadmin logins](https://blog.sqlauthority.com/2017/01/11/sql-server-query-get-list-logins-system-admin-sysadmin-permission)
- [Microsoft Learn: sys.server_role_members](https://learn.microsoft.com/th-th/sql/relational-databases/system-catalog-views/sys-server-role-members-transact-sql?view=sql-server-2017)
- [Oracle: managing users and security](https://docs.oracle.com/cd/E17781_01/server.112/e18804/users_secure.htm)
- [PostgreSQL: pg_roles](https://stuff.mit.edu/afs/sipb/project/postgres-8.2/doc/html/view-pg-roles.html)
- [CIS MySQL 8.0 benchmark: SUPER not granted to non-admins](https://www.tenable.com/audits/items/CIS_MySQL_8.0_Community_Benchmark_v1.1.0_Level_1_Database.audit:165e45adcf7d900839b7d5564777768a)
- [IBM: sysadm_group parameter](https://www.ibm.com/docs/en/SSHRBY/com.ibm.db2.luw.admin.config.doc/doc/r0000311.html)
- [STIG: Db2 SECADM authority](https://stigviewer.com/stig/ibm_db2_v10.5_luw/2023-06-11/finding/V-213686)
- [Qualys: authenticated scanning of SQL Server](https://cdn2.qualys.com/docs/qualys-authenticated-scanning-ms-sql-server-2005-plus.pdf)
