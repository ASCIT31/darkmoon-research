# Vulnerability Assessment Report — s3awsscript.pwnedlabs.io

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T11:07:28Z  
**Target:** s3awsscript.pwnedlabs.io  
**Campaign:** camp_20260802_611cece1  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🟠 HIGH — Urgent Remediation Required

The system tested (**s3awsscript.pwnedlabs.io**) has significant security weaknesses. 2 high severity vulnerabilities were identified requiring urgent attention.

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Authorized cloud assessment of AWS account 427648302155 identified 9 findings (2 high, 5 medium, 2 low). The most critical issue is a publicly shared unencrypted EBS snapshot (snap-063e77bc260a7f1ae) that allows any AWS account to clone and mount the full filesystem, potentially exposing credentials, SSH keys, and application data. Additionally, S3 bucket 'mega-big-tech' is publicly accessible for anonymous listing and download. IAM user s3user has no MFA and plaintext long-term credentials.

**Overall Risk Level: HIGH**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 0 | 0 | 0 |
| HIGH | 2 | 0 | 2 |
| MEDIUM | 5 | 0 | 5 |
| LOW | 2 | 0 | 2 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **9** | **0** | **9** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_9a7987` | Public EBS Snapshot Exposes Unencrypted Instance D... | HIGH | 7.5 | Confirmed | `arn:aws:ec2:us-east-1:427648302155:snapshot/snap-0...` |
| 2 | `vuln_7a343b` | AWS Access Keys Stored in Plaintext on Filesystem | HIGH | 7.5 | Confirmed | `~/.aws/credentials` |
| 3 | `vuln_803dce` | S3 Bucket 'mega-big-tech' Publicly Accessible — Li... | MEDIUM | 5.3 | Confirmed | `mega-big-tech.s3.amazonaws.com/` |
| 4 | `vuln_788eec` | Long-Term IAM Access Keys for s3user — No MFA Enfo... | MEDIUM | 5.3 | Confirmed | `arn:aws:iam::427648302155:user/s3user` |
| 5 | `vuln_b7300d` | Overly Permissive IAM Policy — s3user Has ec2:Desc... | MEDIUM | 5.3 | Confirmed | `arn:aws:iam::427648302155:user/s3user` |
| 6 | `vuln_5f459a` | S3 Account-Level Public Access Block Not Enforced ... | MEDIUM | 5.3 | Confirmed | `s3://mega-big-tech` |
| 7 | `vuln_cbdfaa` | All 5 EBS Snapshots Lack Encryption — Data-at-Rest... | MEDIUM | 4.7 | Confirmed | `arn:aws:ec2:us-east-1:427648302155:snapshot/*` |
| 8 | `vuln_5d6175` | EC2 Instance and AMI IDs Exposed via EBS Snapshot ... | LOW | 3.7 | Confirmed | `arn:aws:ec2:us-east-1:427648302155:snapshot/*` |
| 9 | `vuln_0a115c` | IAM User 's3user' Has No Self-Introspection Permis... | LOW | 3.1 | Confirmed | `arn:aws:iam::427648302155:user/s3user` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Public EBS Snapshot Exposes Unencrypted Instance Data

| Field | Value |
|-------|-------|
| **ID** | `vuln_9a7987` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.10` |
| **Endpoint** | `arn:aws:ec2:us-east-1:427648302155:snapshot/snap-063e77bc260a7f1ae` |
| **Component** | EBS Snapshot createVolumePermission |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-02T11:02:07Z |

#### Description

EBS snapshot snap-063e77bc260a7f1ae is shared publicly (restorable-by-user-ids includes 'all'). This 8GB unencrypted snapshot was created from instance i-04a13bebeb74c8ac9 for AMI ami-0f7676154cc2f9015. Any AWS user in any account can create a volume from this snapshot, attach it to an EC2 instance, and read all data — including potential credentials, application code, database files, SSH keys, and configuration files. The snapshot is unencrypted, making the data directly accessible without any KMS key access.

#### Technical Analysis

By querying AWS EC2 describe-snapshots with --restorable-by-user-ids all, we confirmed that snapshot snap-063e77bc260a7f1ae is publicly shared to all AWS accounts. This 8GB unencrypted snapshot (from instance i-04a13bebeb74c8ac9, AMI ami-0f7676154cc2f9015) can be mounted by any AWS user worldwide. Any attacker can create a volume from this snapshot in their own account, attach it to an EC2 instance, and read the entire filesystem — extracting credentials, SSH keys, application source code, database files, and any other sensitive data stored on the original instance's root volume. The lack of encryption means no KMS key access is needed to read the data.

#### Exploitation Commands

```bash
aws ec2 describe-snapshots --restorable-by-user-ids all --owner-ids 427648302155 --region us-east-1 --output json
aws ec2 describe-snapshots --snapshot-ids snap-063e77bc260a7f1ae --region us-east-1 --output json
```

#### Evidence / Logs

```
$ aws ec2 describe-snapshots --restorable-by-user-ids all --owner-ids 427648302155 --region us-east-1
{
    "Snapshots": [
        {
            "SnapshotId": "snap-063e77bc260a7f1ae",
            "VolumeId": "vol-0e7e4049b0146e808",
            "State": "completed",
            "OwnerId": "427648302155",
            "Description": "Created by CreateImage(i-04a13bebeb74c8ac9) for ami-0f7676154cc2f9015",
            "VolumeSize": 8,
            "Encrypted": false,
            "StorageTier": "standard"
        }
    ]
}

The query --restorable-by-user-ids all returns this snapshot, proving it is publicly shared.
5 total snapshots exist in the account; only 1 is public.
```

#### Remediation

1. Immediately remove public sharing: aws ec2 modify-snapshot-attribute --snapshot-id snap-063e77bc260a7f1ae --attribute createVolumePermission --operation-type remove --group-names all. 2. Enable EBS encryption by default for the account. 3. Review all snapshots for public sharing. 4. Implement AWS Config rules to detect public snapshots (ec2-ebs-snapshot-public-restorable-check). 5. Consider rotating any credentials that may have been on the original instance.

---

### 3.2 — AWS Access Keys Stored in Plaintext on Filesystem

| Field | Value |
|-------|-------|
| **ID** | `vuln_7a343b` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `credential_exposure` |
| **MITRE ATT&CK** | `T1552.001` — Unsecured Credentials: Credentials In Files |
| **ISO 27001** | `A.5.33` |
| **Endpoint** | `~/.aws/credentials` |
| **Component** | AWS Credentials File |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-02T11:05:16Z |

#### Description

The AWS access key (AKIAXXXXXXXXXXREDACTED) and secret access key for IAM user 's3user' are stored in plaintext in ~/.aws/credentials. These long-term credentials provide persistent access to AWS account 427648302155 with permissions including ec2:DescribeSnapshots (confirmed), sts:GetSessionToken (confirmed), and potentially other actions. The credentials have no expiration and no MFA requirement, making them high-value targets for credential theft. If this host is compromised, the attacker immediately gains AWS access.

#### Technical Analysis

Long-term AWS access keys for IAM user s3user are stored in plaintext at ~/.aws/credentials on the local filesystem. The access key AKIAXXXXXXXXXXREDACTED and corresponding secret access key provide persistent access to AWS account 427648302155. These credentials were confirmed working by successfully calling sts:get-caller-identity. The credentials do not expire and have no MFA requirement, representing a significant risk if the host is compromised through any vector.

#### Exploitation Commands

```bash
cat ~/.aws/credentials
aws sts get-caller-identity
```

#### Evidence / Logs

```
$ cat ~/.aws/credentials
[default]
aws_access_key_id = AKIAXXXXXXXXXXREDACTED
aws_secret_access_key = [REDACTED_AWS_SECRET]

$ aws sts get-caller-identity
{
    "UserId": "AIDAWHEOTHRF62U7I6AWZ",
    "Account": "427648302155",
    "Arn": "arn:aws:iam::427648302155:user/s3user"
}
```

#### Remediation

1. Rotate the access keys immediately. 2. Use IAM roles with temporary credentials (e.g., via EC2 instance profiles or SSO) instead of long-term access keys. 3. If access keys must be used, encrypt the credentials file and use AWS credential provider chains. 4. Implement key rotation policies using AWS Config.

---

### 3.3 — S3 Bucket 'mega-big-tech' Publicly Accessible — Listing and Object Read Enabled

| Field | Value |
|-------|-------|
| **ID** | `vuln_803dce` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.10` |
| **Endpoint** | `https://mega-big-tech.s3.amazonaws.com/` |
| **Component** | S3 Bucket Policy |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-02T11:01:45Z |

#### Description

The S3 bucket 'mega-big-tech' allows unauthenticated (anonymous) listing and reading of all objects. Any internet user can enumerate and download all 19 objects (product images) from the bucket without any credentials. While the current contents are product images, this misconfiguration exposes the bucket to data exfiltration if sensitive data is ever placed in it. Public ListBucket and GetObject permissions are enabled via bucket policy.

#### Technical Analysis

The S3 bucket 'mega-big-tech' in AWS account 427648302155 has a bucket policy that allows public (unauthenticated) access for ListBucket and GetObject operations. Using --no-sign-request (anonymous), we successfully listed all 19 objects and downloaded a sample object (banner.jpg, 3.0 MB). This confirms unrestricted public read access. While the data is currently product images, this misconfiguration violates the principle of least privilege and could lead to data exposure if any sensitive content is placed in this bucket.

#### Exploitation Commands

```bash
aws s3 ls s3://mega-big-tech --no-sign-request --recursive
curl -s http://mega-big-tech.s3.amazonaws.com/
aws s3api get-object --bucket mega-big-tech --key images/banner.jpg /tmp/banner.jpg --no-sign-request
```

#### Evidence / Logs

```
$ aws s3 ls s3://mega-big-tech --no-sign-request --recursive
2023-06-25 22:40:57          0 images/
2023-06-25 22:42:34    3184176 images/banner.jpg
... (19 objects total, all publicly readable)

$ curl -s http://mega-big-tech.s3.amazonaws.com/ | head
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>mega-big-tech</Name>
<IsTruncated>false</IsTruncated>
(Full XML listing returned with all 19 keys visible)

$ aws s3api get-object --bucket mega-big-tech --key images/banner.jpg /tmp/banner.jpg --no-sign-request
{"AcceptRanges":"bytes","ContentLength":3184176,"ContentType":"image/jpeg","ServerSideEncryption":"AES256"}
```

#### Remediation

1. Enable S3 Block Public Access at the account level and bucket level. 2. Review and restrict the bucket policy to remove public read permissions. 3. Use CloudFront with Origin Access Identity/Control for serving public content instead of direct S3 access. 4. Enable S3 access logging to monitor access patterns.

---

### 3.4 — Long-Term IAM Access Keys for s3user — No MFA Enforcement Detected

| Field | Value |
|-------|-------|
| **ID** | `vuln_788eec` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1078.004` — Valid Accounts: Cloud Accounts |
| **ISO 27001** | `A.8.5` |
| **Endpoint** | `arn:aws:iam::427648302155:user/s3user` |
| **Component** | AWS IAM Access Keys |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-02T11:04:34Z |

#### Description

The IAM user 's3user' uses long-term access keys (AKIAXXXXXXXXXXREDACTED) with no MFA enforcement. The user can successfully call sts:GetSessionToken to mint temporary session credentials without MFA, confirming no MFA condition is enforced. Long-term access keys without MFA are a common attack surface — if the key is leaked (e.g., in code repositories, logs, or configuration files), an attacker gains persistent access without any additional authentication factor.

#### Technical Analysis

The IAM user s3user has long-term access keys (AKIA...) stored in ~/.aws/credentials. There is no MFA enforcement as demonstrated by the ability to generate session tokens via sts:GetSessionToken without providing an MFA token. The access key ID AKIAXXXXXXXXXXREDACTED provides persistent access to the AWS account. If this key is leaked or compromised, there is no secondary authentication factor to prevent unauthorized access.

#### Exploitation Commands

```bash
aws sts get-session-token
aws sts get-caller-identity
```

#### Evidence / Logs

```
$ aws sts get-session-token
{
    "Credentials": {
        "AccessKeyId": "ASIAXXXXXXXXXXREDACTED",
        "SecretAccessKey": "[REDACTED_AWS_SECRET]",
        "SessionToken": "IQoJb3JpZ2luX2VjEBQa...",
        "Expiration": "2026-08-02T23:04:15Z"
    }
}
Session token generated successfully without MFA, confirming no MFA enforcement.
```

#### Remediation

1. Enable MFA for the s3user account. 2. Add an IAM policy condition requiring MFA (aws:MultiFactorAuthPresent) for sensitive operations. 3. Rotate access keys regularly. 4. Consider using IAM roles with temporary credentials instead of long-term access keys. 5. Implement AWS Config rule 'iam-user-mfa-enabled'.

---

### 3.5 — Overly Permissive IAM Policy — s3user Has ec2:DescribeSnapshots Without Least Privilege

| Field | Value |
|-------|-------|
| **ID** | `vuln_b7300d` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1580` — Cloud Infrastructure Discovery |
| **ISO 27001** | `A.5.15` |
| **Endpoint** | `arn:aws:iam::427648302155:user/s3user` |
| **Component** | AWS IAM Policy |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-02T11:06:30Z |

#### Description

The IAM user 's3user' (named for S3 operations) has ec2:DescribeSnapshots permissions that appear unrelated to its intended S3 purpose. This permission allowed the user to enumerate all 5 EBS snapshots in the account, discovering a publicly shared snapshot. The principle of least privilege is violated — a user named 's3user' should only have S3-related permissions. The ec2:DescribeSnapshots permission enables infrastructure reconnaissance, specifically revealing instance IDs, AMI IDs, volume sizes, and encryption status of all snapshots. Notably, the s3user does NOT have s3:ListAllMyBuckets or s3:ListBucket (with signed requests), suggesting its IAM policy was misconfigured.

#### Technical Analysis

The IAM user s3user has an unusual permission set that violates least privilege. Despite its name suggesting S3-only access, it has ec2:DescribeSnapshots but NOT s3:ListAllMyBuckets or s3:ListBucket (with signed requests). This misconfiguration allowed the user to discover all EBS snapshots in the account including a publicly shared one. The permission was confirmed by successfully running describe-snapshots while all S3 operations (with authenticated requests) and all IAM introspection operations were denied.

#### Exploitation Commands

```bash
aws ec2 describe-snapshots --owner-ids 427648302155 --region us-east-1 --output json
aws s3 ls (denied)
aws s3 ls s3://mega-big-tech (denied with signed request)
aws iam list-attached-user-policies --user-name s3user (denied)
```

#### Evidence / Logs

```
The s3user can:
- ec2:DescribeSnapshots → SUCCESS (5 snapshots enumerated)
- sts:GetCallerIdentity → SUCCESS
- sts:GetSessionToken → SUCCESS

The s3user CANNOT:
- s3:ListAllMyBuckets → AccessDenied
- s3:ListBucket (signed) → AccessDenied
- iam:* → All AccessDenied
- ec2:DescribeInstances → AccessDenied
- All other services tested → AccessDenied

This represents a misconfigured policy granting EC2 describe permissions to a user intended for S3 operations.
```

#### Remediation

1. Review and restrict the IAM policy for s3user to only required S3 actions. 2. Remove ec2:DescribeSnapshots if not needed for the user's function. 3. Implement IAM Access Analyzer to detect over-permissive policies. 4. Use resource tags and conditions to restrict snapshot access to specific resources.

---

### 3.6 — S3 Account-Level Public Access Block Not Enforced — Public Buckets Possible

| Field | Value |
|-------|-------|
| **ID** | `vuln_5f459a` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.10` |
| **Endpoint** | `s3://mega-big-tech` |
| **Component** | S3 Block Public Access |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-02T11:06:47Z |

#### Description

The S3 account-level public access block is either not configured or not fully enforced, as evidenced by the mega-big-tech bucket being publicly accessible for anonymous listing and object download. AWS S3 Block Public Access at the account level would prevent any bucket from being made public, regardless of individual bucket policies or ACLs. The fact that the mega-big-tech bucket allows public ListBucket and GetObject operations proves that account-level S3 Block Public Access is not fully enabled.

#### Technical Analysis

The existence of a publicly accessible S3 bucket (mega-big-tech) in the account proves that the S3 account-level public access block is not fully enabled. If BlockPublicPolicy and RestrictPublicBuckets were enabled at the account level, the bucket's public policy would be ineffective and anonymous access would be blocked. The confirmed ability to list and download objects without authentication (--no-sign-request) demonstrates this control is absent.

#### Exploitation Commands

```bash
aws s3 ls s3://mega-big-tech --no-sign-request
aws s3control get-public-access-block --account-id 427648302155 (denied but public bucket proves it's not enabled)
```

#### Evidence / Logs

```
$ aws s3 ls s3://mega-big-tech --no-sign-request
(19 objects listed without authentication)

$ aws s3control get-public-access-block --account-id 427648302155
AccessDenied (cannot verify directly, but public bucket existence proves it's not fully enforced)
```

#### Remediation

1. Enable S3 Block Public Access at the account level (all 4 settings). 2. Use CloudFront with Origin Access Identity for any content that needs to be publicly served. 3. Monitor with AWS Config rule 's3-account-level-public-access-blocks-periodic'. 4. Review all existing bucket policies for public access before enabling account-level block.

---

### 3.7 — All 5 EBS Snapshots Lack Encryption — Data-at-Rest Not Protected

| Field | Value |
|-------|-------|
| **ID** | `vuln_cbdfaa` |
| **Severity** | MEDIUM |
| **CVSS Score** | 4.7 |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1530` — Data from Cloud Storage |
| **ISO 27001** | `A.8.24` |
| **Endpoint** | `arn:aws:ec2:us-east-1:427648302155:snapshot/*` |
| **Component** | EBS Encryption |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-02T11:02:25Z |

#### Description

All 5 EBS snapshots in AWS account 427648302155 are unencrypted (Encrypted: false). This means data at rest on these volumes is not protected by AWS KMS encryption. If any snapshot is inadvertently shared or if an attacker gains access to the account, the data can be read without needing KMS key access. The snapshots range from 8GB to 30GB and were created from 5 different EC2 instances.

#### Technical Analysis

All 5 EBS snapshots in the account are unencrypted. This was confirmed by running aws ec2 describe-snapshots which returned Encrypted: false for every snapshot. Without encryption, the data on these volumes is not protected at rest. If any snapshot is shared (as demonstrated with snap-063e77bc260a7f1ae which is public), the data is immediately accessible without KMS key authorization. AWS best practice mandates enabling EBS encryption by default.

#### Exploitation Commands

```bash
aws ec2 describe-snapshots --owner-ids 427648302155 --region us-east-1 --output json
```

#### Evidence / Logs

```
All 5 snapshots show "Encrypted": false:
snap-063e77bc260a7f1ae (8GB, from i-04a13bebeb74c8ac9)
snap-0b571dbdf3b083680 (8GB, from i-0818fc03538cab138)
snap-034f445652ec55382 (8GB, from i-0ed437a2196e0eeea)
snap-0cf170479a668f06b (20GB, from i-08017de93a35721a4)
snap-02eb8145e3a7b9840 (30GB, from i-04cc1c2c7ec1af1b5)
```

#### Remediation

1. Enable EBS encryption by default for the account in all regions. 2. Create encrypted copies of existing snapshots and delete the unencrypted originals. 3. Ensure all new EBS volumes use encryption. 4. Use AWS Config rule 'encrypted-volumes' to detect non-compliant volumes.

---

### 3.8 — EC2 Instance and AMI IDs Exposed via EBS Snapshot Descriptions

| Field | Value |
|-------|-------|
| **ID** | `vuln_5d6175` |
| **Severity** | LOW |
| **CVSS Score** | 3.7 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `information_disclosure` |
| **MITRE ATT&CK** | `T1580` — Cloud Infrastructure Discovery |
| **ISO 27001** | `A.5.9` |
| **Endpoint** | `arn:aws:ec2:us-east-1:427648302155:snapshot/*` |
| **Component** | EBS Snapshot Descriptions |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-02T11:05:39Z |

#### Description

Five EBS snapshots in the account expose EC2 instance IDs and AMI IDs through their descriptions. This information disclosure reveals the infrastructure topology of 5 EC2 instances and their corresponding AMIs, which can be used for targeted attacks. Exposed instances: i-04a13bebeb74c8ac9 (ami-0f7676154cc2f9015), i-0818fc03538cab138 (ami-07865f41135ebcf24), i-0ed437a2196e0eeea (ami-05d8b0c7cc6275389), i-08017de93a35721a4 (ami-0badfa7437713c089), i-04cc1c2c7ec1af1b5 (ami-09ca94ccd85a1d23d).

#### Technical Analysis

By querying ec2:DescribeSnapshots, which the s3user has permission to call, we enumerated 5 EBS snapshots. Each snapshot's description field reveals the source EC2 instance ID and the AMI ID it was created from. This provides an attacker with infrastructure reconnaissance data — instance IDs can be used for targeted attacks, and AMI IDs can reveal the software stack in use. Combined with the public snapshot finding, this creates a clear attack path for data exfiltration.

#### Exploitation Commands

```bash
aws ec2 describe-snapshots --owner-ids 427648302155 --region us-east-1 --output json
```

#### Evidence / Logs

```
5 snapshots reveal instance/AMI topology:
snap-063e77bc260a7f1ae: i-04a13bebeb74c8ac9 → ami-0f7676154cc2f9015 (8GB, PUBLIC)
snap-0b571dbdf3b083680: i-0818fc03538cab138 → ami-07865f41135ebcf24 (8GB)
snap-034f445652ec55382: i-0ed437a2196e0eeea → ami-05d8b0c7cc6275389 (8GB)
snap-0cf170479a668f06b: i-08017de93a35721a4 → ami-0badfa7437713c089 (20GB)
snap-02eb8145e3a7b9840: i-04cc1c2c7ec1af1b5 → ami-09ca94ccd85a1d23d (30GB)
```

#### Remediation

1. Use custom descriptions for snapshots that don't reveal infrastructure details. 2. Restrict ec2:DescribeSnapshots permissions to only necessary users. 3. Implement resource-level permissions for EC2 describe operations.

---

### 3.9 — IAM User 's3user' Has No Self-Introspection Permissions — Shadow Permissions Model

| Field | Value |
|-------|-------|
| **ID** | `vuln_0a115c` |
| **Severity** | LOW |
| **CVSS Score** | 3.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1087.004` — Account Discovery: Cloud Account |
| **ISO 27001** | `A.5.15` |
| **Endpoint** | `arn:aws:iam::427648302155:user/s3user` |
| **Component** | AWS IAM |
| **Discovered by** | `aws` |
| **Discovered at** | 2026-08-02T11:03:32Z |

#### Description

The IAM user 's3user' cannot enumerate its own permissions (iam:GetUser, iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:ListGroupsForUser, iam:SimulatePrincipalPolicy are all denied). This creates a shadow permissions model where the user has undocumented capabilities (confirmed: ec2:DescribeSnapshots) without any ability to self-audit. While this is not directly exploitable, it indicates poor IAM hygiene and makes it difficult for administrators and users to understand the effective permissions, violating the principle of least surprise.

#### Technical Analysis

The IAM user s3user in account 427648302155 has no ability to enumerate its own IAM policies, group memberships, or effective permissions. Despite this, the user has at least ec2:DescribeSnapshots permission granted through some policy attachment. This lack of self-introspection creates a shadow permissions model and indicates the account lacks proper IAM visibility controls. AWS best practice recommends at minimum allowing users to view their own policies to ensure transparency.

#### Exploitation Commands

```bash
aws iam get-user --output json
aws iam list-attached-user-policies --user-name s3user --output json
aws iam list-user-policies --user-name s3user --output json
aws iam list-groups-for-user --user-name s3user --output json
```

#### Evidence / Logs

```
All IAM self-introspection calls returned AccessDenied:
- iam:GetUser → AccessDenied
- iam:ListAttachedUserPolicies → AccessDenied
- iam:ListUserPolicies → AccessDenied
- iam:ListGroupsForUser → AccessDenied
- iam:SimulatePrincipalPolicy → AccessDenied
- iam:ListAccessKeys → AccessDenied

Yet the user has ec2:DescribeSnapshots permission (confirmed working).
```

#### Remediation

1. Grant iam:Get*/List* for the user's own resources using an IAM policy with a condition on aws:username. 2. Implement AWS IAM Access Analyzer to understand effective permissions. 3. Use AWS Config rules to ensure IAM policy visibility.

---

## 4. REMEDIATION ROADMAP

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Public EBS Snapshot Exposes Unencrypted Instance Data | High |
| AWS Access Keys Stored in Plaintext on Filesystem | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| S3 Bucket 'mega-big-tech' Publicly Accessible — Listing and ... | High |
| Long-Term IAM Access Keys for s3user — No MFA Enforcement De... | High |
| Overly Permissive IAM Policy — s3user Has ec2:DescribeSnapsh... | High |
| S3 Account-Level Public Access Block Not Enforced — Public B... | High |
| All 5 EBS Snapshots Lack Encryption — Data-at-Rest Not Prote... | High |

### P3 — Long term (< 1 month)

| Finding | Effort |
|---------|--------|
| EC2 Instance and AMI IDs Exposed via EBS Snapshot Descriptio... | High |
| IAM User 's3user' Has No Self-Introspection Permissions — Sh... | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T11:07:28Z*  
*Campaign: camp_20260802_611cece1 | Target: s3awsscript.pwnedlabs.io*
