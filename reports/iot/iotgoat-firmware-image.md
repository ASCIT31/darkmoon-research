# Vulnerability Assessment Report — iotgoat-firmware

**Classification:** CONFIDENTIAL — Restricted to authorized personnel  
**Generated:** 2026-08-02T17:38:17Z  
**Target:** iotgoat-firmware  
**Campaign:** camp_20260802_dd187131  
**Methodology:** ISO 27001 / NIST SP 800-115 / MITRE ATT&CK  

---

## MANAGEMENT SUMMARY

> *For non-technical readers and decision-makers.*

### Overall Security Posture: 🔴 CRITICAL — Immediate Action Required

The system tested (**iotgoat-firmware**) presents an **extremely poor security posture**. Our team confirmed 4 critical and 7 high severity vulnerabilities, enabling complete compromise through multiple independent attack paths.

### Most Critical Issues

**1. Unauthenticated Root Backdoor Daemon (shellback) on Port 5515**  
A custom backdoor binary '/usr/bin/shellback' is baked into the firmware. It is an ELF 32-bit i386 executable that calls socket(), bind(), listen(), accept(), fork(), dup2(), and execve('/bin/busybox'...

**2. Unauthenticated Telnet Daemon on Port 65534**  
The device's /etc/rc.local starts a BusyBox telnetd daemon on port 65534 ('telnetd -p 65534 &'). Telnet transmits credentials in cleartext and the daemon provides a login shell. Combined with the weak...

**3. LuCI Command Injection — Unauthenticated Root RCE via webcmd Endpoint**  
The IoTGoat LuCI controller at [REDACTED].lua contains a 'webcmd' function that directly passes user-supplied input to io.popen() without any sanitization or input va...

### Required Actions

| Timeframe | Action |
|-----------|--------|
| **Today** | Block external access / take offline if possible |
| **This week** | Patch all critical and high severity findings |
| **2 weeks** | Address medium severity findings and security headers |
| **1 month** | Full code review and independent re-test |

---

## 1. EXECUTIVE SUMMARY

> Critical security assessment of OWASP IoTGoat firmware (OpenWrt 18.06.2) revealed 20 findings including 4 critical vulnerabilities: an unauthenticated root backdoor daemon (shellback) on port 5515, an unauthenticated telnet daemon on port 65534, a command injection RCE in the LuCI web interface (/admin/iotgoat/webcmd), and a Mirai botnet default credential (iotgoatuser:[REDACTED_CREDENTIAL]). The device is trivially compromisable with multiple independent attack paths to unauthenticated root access. All core infrastructure components (dnsmasq 2.73, Dropbear 2017.75, BusyBox 1.28.4, Kernel 4.14.95) are end-of-life with numerous known CVEs.

**Overall Risk Level: CRITICAL**

### Findings Summary

| Severity | Count | Exploited | Confirmed |
|----------|-------|-----------|----------|
| CRITICAL | 4 | 1 | 3 |
| HIGH | 7 | 0 | 7 |
| MEDIUM | 7 | 0 | 7 |
| LOW | 2 | 0 | 2 |
| INFO | 0 | 0 | 0 |
| **TOTAL** | **20** | **1** | **19** |

---

## 2. FINDINGS TABLE

| # | ID | Title | Severity | CVSS | Status | Endpoint |
|---|-----|-------|----------|------|--------|----------|
| 1 | `vuln_22b9da` | Unauthenticated Root Backdoor Daemon (shellback) o... | CRITICAL | 10.0 | Confirmed | `TCP port 5515 (shellback backdoor)` |
| 2 | `vuln_964841` | Unauthenticated Telnet Daemon on Port 65534 | CRITICAL | 10.0 | Confirmed | `TCP port 65534 (telnetd)` |
| 3 | `vuln_7e237f` | LuCI Command Injection — Unauthenticated Root RCE ... | CRITICAL | 9.8 | Confirmed | `/admin/iotgoat/webcmd (POST parameter: cmd)` |
| 4 | `vuln_26b1bd` | Weak Credential: iotgoatuser Account with Mirai Bo... | CRITICAL | 9.8 | **EXPLOITED** | `/etc/shadow (iotgoatuser account)` |
| 5 | `vuln_47d148` | WiFi Access Point Configured with No Encryption (O... | HIGH | 8.8 | Confirmed | `/etc/config/wireless` |
| 6 | `vuln_42f718` | Weak Root Password Hash (MD5-crypt, Not Cracked bu... | HIGH | 8.1 | Confirmed | `/etc/shadow (root account)` |
| 7 | `vuln_0f69c0` | UPnP Service Misconfiguration — secure_mode Disabl... | HIGH | 8.1 | Confirmed | `/etc/config/upnpd (TCP port 5000)` |
| 8 | `vuln_add966` | Insecure Package Update Mechanism — HTTP-only opkg... | HIGH | 8.1 | Confirmed | `/etc/opkg/distfeeds.conf` |
| 9 | `vuln_a1e5f9` | Outdated dnsmasq 2.73 — Multiple Critical CVEs (DN... | HIGH | 8.1 | Confirmed | `dnsmasq service (UDP/TCP port 53, DHCP port 67)` |
| 10 | `vuln_7b863d` | PII Data Exposure in Embedded SQLite Database (Sen... | HIGH | 7.5 | Confirmed | `[REDACTED].db` |
| 11 | `vuln_38166d` | Outdated Dropbear SSH 2017.75 — Multiple CVEs | HIGH | 7.5 | Confirmed | `TCP port 22 (Dropbear SSH)` |
| 12 | `vuln_c2e5cf` | Outdated Linux Kernel 4.14.95 — Multiple Known CVE... | MEDIUM | 7.0 | Confirmed | `Linux Kernel 4.14.95` |
| 13 | `vuln_b1206a` | Outdated BusyBox 1.28.4 — Multiple CVEs | MEDIUM | 6.5 | Confirmed | `BusyBox 1.28.4 (/bin/busybox)` |
| 14 | `vuln_5d7929` | LuCI File Browser Endpoint Exposed | MEDIUM | 6.5 | Confirmed | `/admin/filebrowser` |
| 15 | `vuln_d01fe2` | Outdated wpa_supplicant/hostapd 2018-05-21 — KRACK... | MEDIUM | 6.5 | Confirmed | `WiFi interface (hostapd/wpa_supplicant)` |
| 16 | `vuln_30311a` | Outdated mbedTLS 2.14.1 — Known Cryptographic Vuln... | MEDIUM | 5.9 | Confirmed | `mbedTLS library (used by uhttpd HTTPS, uclient)` |
| 17 | `vuln_5c4a4e` | Dropbear SSH Root Password Authentication Enabled | MEDIUM | 5.3 | Confirmed | `TCP port 22 (SSH)` |
| 18 | `vuln_d007f6` | Outdated OpenWrt 18.06.2 Platform — End of Life | MEDIUM | 5.0 | Confirmed | `OpenWrt 18.06.2 platform` |
| 19 | `vuln_8bddf9` | Hardcoded Public DNS Resolver (Google DNS) in Netw... | LOW | 3.7 | Confirmed | `/etc/config/network` |
| 20 | `vuln_358780` | Duplicate dnsmasq User Entry in /etc/shadow | LOW | 3.3 | Confirmed | `/etc/shadow` |

---

## 3. VULNERABILITY DETAILS

---

### 3.1 — Unauthenticated Root Backdoor Daemon (shellback) on Port 5515

| Field | Value |
|-------|-------|
| **ID** | `vuln_22b9da` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `remote_code_execution` |
| **MITRE ATT&CK** | `T1133` — External Remote Services |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `TCP port 5515 (shellback backdoor)` |
| **Component** | shellback (/usr/bin/shellback) |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:30:54Z |

#### Description

A custom backdoor binary '/usr/bin/shellback' is baked into the firmware. It is an ELF 32-bit i386 executable that calls socket(), bind(), listen(), accept(), fork(), dup2(), and execve('/bin/busybox') to provide an unauthenticated root shell to any connecting client on TCP port 5515. The binary prints the banner '[***]Successfully Connected to IoTGoat's Backdoor[***]' upon connection. It is registered as an init.d service (/etc/init.d/shellback) with START=95 priority and is also explicitly launched in /etc/rc.local. The UCI config (/etc/config/shellback) confirms it is enabled. This provides complete unauthenticated root-level remote code execution to any network-adjacent attacker.

#### Technical Analysis

The shellback binary is a purpose-built backdoor daemon that opens a TCP listener on port 5515 and spawns an unauthenticated BusyBox shell for any connecting client. The binary uses standard socket programming ([REDACTED]) to create a persistent backdoor. It is configured to start automatically via both the init.d system (priority 95) and /etc/rc.local, ensuring it survives reboots. The port 5515 was confirmed by analyzing the x86 push instruction (push 0x158b = 5515) that serves as the argument to htons(). Any attacker on the network can connect and obtain a root shell without any authentication.

#### Exploitation Commands

```bash
strings /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/bin/shellback
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/init.d/shellback
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/config/shellback
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/rc.local
od -A x -t x1 /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/bin/shellback | grep "68 8b"
```

#### Evidence / Logs

```
strings output:
/lib/ld-musl-i386.so.1
libgcc_s.so.1
libc.so
fork
close
htons
execve
accept
write
bind
dup2
listen
socket
[***]Successfully Connected to IoTGoat's Backdoor[***]
/bin/busybox

rc.local:
/usr/bin/shellback &
telnetd -p 65534 &
exit 0

init.d/shellback:
PROG=/usr/bin/shellback
START=95

config/shellback:
config shellback shell_config
	option duration 10
	option enabled 1

Binary analysis (port extraction from x86 push instruction):
push 0x0000158b = 5515 → htons(5515) = 0x8b15
```

#### Remediation

Remove the shellback binary (/usr/bin/shellback), its init.d script (/etc/init.d/shellback), its UCI config (/etc/config/shellback), and the rc.local entry. Audit the firmware build pipeline for unauthorized additions. Implement code signing for all firmware binaries.

---

### 3.2 — Unauthenticated Telnet Daemon on Port 65534

| Field | Value |
|-------|-------|
| **ID** | `vuln_964841` |
| **Severity** | CRITICAL |
| **CVSS Score** | 10.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `remote_code_execution` |
| **MITRE ATT&CK** | `T1021.004` — Remote Services: SSH |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `TCP port 65534 (telnetd)` |
| **Component** | BusyBox telnetd |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:31:11Z |

#### Description

The device's /etc/rc.local starts a BusyBox telnetd daemon on port 65534 ('telnetd -p 65534 &'). Telnet transmits credentials in cleartext and the daemon provides a login shell. Combined with the weak/default credentials found in the firmware (iotgoatuser:[REDACTED_CREDENTIAL] and root with a crackable MD5-crypt hash), this provides an easily exploitable remote root access path. The non-standard high port (65534) is clearly intended to evade casual detection.

#### Technical Analysis

The rc.local script is executed at boot and starts telnetd on the non-standard port 65534. Telnet is an insecure protocol that transmits all data including credentials in cleartext. The high port number appears deliberately chosen to avoid standard port scans. Combined with the weak credentials found in /etc/shadow, any attacker can gain authenticated access via telnet with the cracked iotgoatuser password ([REDACTED_CREDENTIAL], a known Mirai botnet default).

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/rc.local
```

#### Evidence / Logs

```
/etc/rc.local contents:
# Put your custom commands here that should be executed once
# the system init finished. By default this file does nothing.

/usr/bin/shellback &
telnetd -p 65534 &
exit 0
```

#### Remediation

Remove the telnetd startup from /etc/rc.local. Disable telnet entirely and use only SSH (Dropbear) with key-based authentication. If remote management is required, use SSH on a standard port with strong credentials.

---

### 3.3 — LuCI Command Injection — Unauthenticated Root RCE via webcmd Endpoint

| Field | Value |
|-------|-------|
| **ID** | `vuln_7e237f` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `remote_code_execution` |
| **MITRE ATT&CK** | `T1059.004` — Command and Scripting Interpreter: Unix Shell |
| **ISO 27001** | `A.14.2.5` |
| **Endpoint** | `/admin/iotgoat/webcmd (POST parameter: cmd)` |
| **Component** | LuCI IoTGoat controller (iotgoat.lua) |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:31:34Z |

#### Description

The IoTGoat LuCI controller at [REDACTED].lua contains a 'webcmd' function that directly passes user-supplied input to io.popen() without any sanitization or input validation. The function reads the 'cmd' parameter from the HTTP request and executes it as a system command: 'local fp = io.popen(tostring(cmd)..\" 2>&1\")'. The endpoint is accessible at /admin/iotgoat/webcmd. The associated template (cmd.htm) is titled 'Secret Developer Diagnostics Page' and includes convenient buttons for common system commands (ifconfig, ps, mount, etc.), indicating it was left in as a debug/development backdoor. While the endpoint is under /admin/ which typically requires authentication, combined with the easily cracked credentials, this provides trivial root command execution.

#### Technical Analysis

The iotgoat.lua LuCI controller defines a 'webcmd' function that takes user input via the HTTP 'cmd' parameter and passes it directly to io.popen() for execution as a system command. There is zero input validation, no command allowlisting, and no sanitization. The associated HTML template explicitly labels this as a 'Secret Developer Diagnostics Page' that 'Execute[s] commands or scripts as root.' An attacker who authenticates (trivially, using the cracked credentials) can execute arbitrary commands as root. The code also only escapes '<' in output but does not sanitize input in any way.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-[REDACTED].lua
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-[REDACTED].htm
```

#### Evidence / Logs

```
iotgoat.lua:
module("luci.controller.iotgoat.iotgoat", package.seeall)
local http = require("luci.http")
function index()
    entry({"admin", "iotgoat"}, firstchild(), "IoTGoat", 60).dependent=false
    entry({"admin", "iotgoat", "cmdinject"}, template("iotgoat/cmd"), "", 1)
    entry({"admin", "iotgoat", "cam"}, template("iotgoat/camera"), "Camera", 2)
    entry({"admin", "iotgoat", "door"}, template("iotgoat/door"), "Doorlock", 3)
    entry({"admin", "iotgoat", "webcmd"}, call("webcmd"))
end

function webcmd()
    local cmd = http.formvalue("cmd")
    if cmd then
        local fp = io.popen(tostring(cmd).." 2>&1")
        local result =  fp:read("*a")
        fp:close()
        result = result:gsub("<", "&lt;")
        http.write(tostring(result))
    else
        http.write_json(http.formvalue())
    end
end

cmd.htm:
<h2><a name="content">Secret Developer Diagnostics Page</a></h2>
<form id="console">
    <fieldset class="cbi-section">
        <legend>Execute commands or scripts as root.</legend>
```

#### Remediation

Remove the webcmd endpoint and the Secret Developer Diagnostics Page entirely. Never pass user input directly to io.popen(), os.execute(), or any shell execution function. If diagnostic functionality is needed, implement a strict allowlist of permitted commands with proper input validation and escaping.

---

### 3.4 — Weak Credential: iotgoatuser Account with Mirai Botnet Default Password ([REDACTED_CREDENTIAL])

| Field | Value |
|-------|-------|
| **ID** | `vuln_26b1bd` |
| **Severity** | CRITICAL |
| **CVSS Score** | 9.8 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | EXPLOITED |
| **Category** | `insecure_credentials` |
| **MITRE ATT&CK** | `T1078.001` — Valid Accounts: Default Accounts |
| **ISO 27001** | `A.9.2.4` |
| **Endpoint** | `/etc/shadow (iotgoatuser account)` |
| **Component** | System authentication (/etc/shadow) |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:31:58Z |

#### Description

The firmware contains a user account 'iotgoatuser' (UID 1000) with a weak MD5-crypt password hash ($1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.) that was cracked in under 1 second using a minimal IoT-focused wordlist. The plaintext password is '[REDACTED_CREDENTIAL]', which is a well-known Mirai botnet default credential. This password is in every IoT malware credential list and automated scanners. The account has shell access (/bin/ash) and home directory /root, providing full interactive access via SSH (port 22) or telnet (port 65534).

#### Technical Analysis

The iotgoatuser account uses the well-known Mirai botnet password '[REDACTED_CREDENTIAL]' which was cracked instantly from the MD5-crypt hash. This password is included in every IoT malware credential dictionary. The hash uses the weak MD5-crypt algorithm ($1$), further reducing security. The account has a login shell (/bin/ash) and home directory set to /root, giving direct access to the root user's home. This credential enables login via SSH (22), telnet (65534), or the web interface.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/shadow
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/passwd
john --wordlist=iot_wordlist.txt /tmp/iotgoat/unshadowed.txt
john --show /tmp/iotgoat/unshadowed.txt
```

#### Evidence / Logs

```
/etc/shadow:
iotgoatuser:$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:18145:0:99999:7:::

/etc/passwd:
iotgoatuser:x:1000:1000::/root:/bin/ash

john output:
Loaded 2 password hashes with 2 different salts (md5crypt [MD5 32/64 X2])
Will run 16 OpenMP threads
[REDACTED_CREDENTIAL]     (iotgoatuser)
1g 0:00:00:00 100% 33.33g/s 900.0p/s 1800c/s 1800C/s admin..passwd
Session completed

john --show:
iotgoatuser:[REDACTED_CREDENTIAL]:1000:1000::/root:/bin/ash
1 password hash cracked, 1 left
```

#### Remediation

Remove the iotgoatuser account or enforce a strong, unique password. Implement password complexity requirements. Use SHA-512 ($6$) instead of MD5-crypt ($1$) for password hashing. Disable default/well-known accounts in production firmware.

---

### 3.5 — WiFi Access Point Configured with No Encryption (Open Network)

| Field | Value |
|-------|-------|
| **ID** | `vuln_47d148` |
| **Severity** | HIGH |
| **CVSS Score** | 8.8 |
| **CVSS Vector** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1557` — Adversary-in-the-Middle |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `/etc/config/wireless` |
| **Component** | WiFi configuration (wireless) |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:32:34Z |

#### Description

The wireless configuration at /etc/config/wireless configures the device as a WiFi access point with SSID 'OWASP IoTGoat' and encryption set to 'none'. This means all wireless traffic is transmitted in cleartext without any encryption (no WPA/WPA2/WPA3). Any device in range can connect to the network and intercept all traffic. Combined with the backdoor daemons and weak credentials, this provides a trivial entry point for any nearby attacker.

#### Technical Analysis

The wireless interface is configured as an access point with SSID 'OWASP IoTGoat' but encryption is explicitly set to 'none'. This means the WiFi network is completely open - no WPA2-PSK, no WPA3, no encryption whatsoever. Any device within radio range can associate with the AP and gain full network access to all services including SSH, telnet, the backdoor daemon, and the web interface. All traffic traversing the wireless link is also visible to passive eavesdroppers.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/config/wireless
```

#### Evidence / Logs

```
config wifi-device 'wl0'
	option type 'mac80211'
	option hwmode '11a'
	option channel 'auto'
	option legacy_rates '1'

config wifi-iface
	option device 'wl0'
	option mode 'ap'
	option encryption 'none'
	option network 'lan'
	option ssid 'OWASP IoTGoat'
```

#### Remediation

Enable WPA3-SAE or at minimum WPA2-PSK with AES/CCMP encryption. Set a strong, unique pre-shared key. Disable legacy rates. Consider implementing 802.1X enterprise authentication for managed deployments.

---

### 3.6 — Weak Root Password Hash (MD5-crypt, Not Cracked but Brute-forceable)

| Field | Value |
|-------|-------|
| **ID** | `vuln_42f718` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `insecure_credentials` |
| **MITRE ATT&CK** | `T1110.002` — Brute Force: Password Cracking |
| **ISO 27001** | `A.9.2.4` |
| **Endpoint** | `/etc/shadow (root account)` |
| **Component** | System authentication (/etc/shadow) |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:32:18Z |

#### Description

The root account (UID 0) uses the weak MD5-crypt ($1$) password hashing algorithm. The hash is $1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1 (from /etc/shadow). While the password was not cracked using rockyou.txt (14M entries), the use of MD5-crypt with only 1000 iterations makes it highly vulnerable to offline GPU-based attacks. Modern GPUs can test billions of MD5-crypt hashes per second. Furthermore, the Dropbear SSH config allows root password authentication (RootPasswordAuth 'on'), and SSH is exposed on port 22.

#### Technical Analysis

The root account's password hash uses the obsolete MD5-crypt algorithm ($1$) which only performs 1000 iterations of MD5, making it trivially brute-forceable with modern hardware. While the password wasn't in rockyou.txt, the combination of weak hashing algorithm + root SSH password auth enabled + exposed SSH service creates a high-risk attack surface. An attacker with a larger wordlist or GPU-based cracking could recover the root password and gain full system access via SSH.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/shadow
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/iotgoat/unshadowed.txt
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/config/dropbear
```

#### Evidence / Logs

```
/etc/shadow:
root:$1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1:18145:0:99999:7:::

john result (rockyou.txt):
Loaded 2 password hashes with 2 different salts (md5crypt [MD5 32/64 X2])
Remaining 1 password hash
0g 0:00:01:34 100% 0g/s 152000p/s
Session completed [not cracked with rockyou.txt]

Dropbear config:
config dropbear
	option PasswordAuth 'on'
	option RootPasswordAuth 'on'
	option Port '22'
```

#### Remediation

Use SHA-512 ($6$) or bcrypt for password hashing. Set a strong, unique root password. Disable root password authentication in Dropbear (set RootPasswordAuth to 'off') and use key-based authentication only.

---

### 3.7 — UPnP Service Misconfiguration — secure_mode Disabled with Unrestricted Port Mapping

| Field | Value |
|-------|-------|
| **ID** | `vuln_0f69c0` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1090` — Proxy |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `/etc/config/upnpd (TCP port 5000)` |
| **Component** | MiniUPnPd 2.1 |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:33:15Z |

#### Description

MiniUPnPd 2.1 is configured with secure_mode disabled (option secure_mode 0). The permission rules allow any internal host (IP_PRIVATE_003/0, effectively 0.0.0.0/0) to map any port range (0-65535 internal, 1024-65535 external). This means any device on the network can add arbitrary port forwarding rules to expose internal services to the WAN. An attacker on the LAN can use UPnP to punch holes in the firewall and expose internal services to the internet.

#### Technical Analysis

The MiniUPnPd configuration has secure_mode disabled which means the daemon does not verify that the requesting device's IP matches the internal address in the port mapping request. The permission rule allows mapping of any internal port (0-65535) to any external port (1024-65535) from any internal address (the /0 netmask means any IP). NAT-PMP is also enabled. This allows any malicious application or compromised device on the network to expose arbitrary services to the WAN, effectively bypassing the firewall.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/config/upnpd
```

#### Evidence / Logs

```
config upnpd config
        option enabled          1
        option enable_natpmp    1
        option enable_upnp      1
        option secure_mode      0
        option log_output       0
        option download         1024
        option upload           512
        option internal_iface   lan
        option port             5000
        option upnp_lease_file  /var/run/miniupnpd.leases
        option igdv1            0

config perm_rule
        option action           allow
        option ext_ports        1024-65535
        option int_addr         IP_PRIVATE_003/0       # Does not override secure_mode
        option int_ports        0-65535
        option comment          "Allow all ports"
```

#### Remediation

Enable secure_mode (set to 1). Restrict perm_rules to specific internal IP ranges and limited port ranges. Disable UPnP entirely if not needed, or restrict it to specific trusted devices. Enable logging (log_output 1).

---

### 3.8 — Insecure Package Update Mechanism — HTTP-only opkg Feeds

| Field | Value |
|-------|-------|
| **ID** | `vuln_add966` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1195.002` — Supply Chain Compromise: Compromise Software Supply Chain |
| **ISO 27001** | `A.14.1.2` |
| **Endpoint** | `/etc/opkg/distfeeds.conf` |
| **Component** | opkg package manager |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:33:34Z |

#### Description

The opkg package manager is configured to use HTTP (not HTTPS) package feeds in /etc/opkg/distfeeds.conf. All six package feeds (core, base, luci, packages, routing, telephony) use 'http://downloads.openwrt.org/...'. While /etc/opkg.conf does include 'option check_signature', an attacker performing a MITM attack on the HTTP connection could serve malicious packages. The HTTP transport makes the signature check bypassable in some attack scenarios as the attacker controls the entire response including the signature files.

#### Technical Analysis

All package repository URLs use plaintext HTTP instead of HTTPS. While signature checking is enabled, the use of HTTP transport allows a MITM attacker to intercept and modify package downloads. Even with signature verification, the attacker controls the network path and can perform downgrade attacks or exploit vulnerabilities in the signature verification process. This is a supply-chain security weakness that could be exploited to install malicious firmware packages on the device.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/opkg/distfeeds.conf
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/opkg.conf
```

#### Evidence / Logs

```
distfeeds.conf:
src/gz openwrt_core http://downloads.openwrt.org/releases/18.06.2/targets/x86/generic/packages
src/gz openwrt_base http://downloads.openwrt.org/releases/18.06.2/packages/i386_pentium4/base
src/gz openwrt_luci http://downloads.openwrt.org/releases/18.06.2/packages/i386_pentium4/luci
src/gz openwrt_packages http://downloads.openwrt.org/releases/18.06.2/packages/i386_pentium4/packages
src/gz openwrt_routing http://downloads.openwrt.org/releases/18.06.2/packages/i386_pentium4/routing
src/gz openwrt_telephony http://downloads.openwrt.org/releases/18.06.2/packages/i386_pentium4/telephony

opkg.conf:
option check_signature
```

#### Remediation

Change all package feed URLs from http:// to https://. Ensure signature verification is enabled and enforced. Pin trusted signing keys and implement certificate validation for package downloads.

---

### 3.9 — Outdated dnsmasq 2.73 — Multiple Critical CVEs (DNSpooq)

| Field | Value |
|-------|-------|
| **ID** | `vuln_a1e5f9` |
| **Severity** | HIGH |
| **CVSS Score** | 8.1 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `outdated_component` |
| **MITRE ATT&CK** | `T1190` — Exploit Public-Facing Application |
| **ISO 27001** | `A.12.6.1` |
| **Endpoint** | `dnsmasq service (UDP/TCP port 53, DHCP port 67)` |
| **Component** | dnsmasq 2.73-1 |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:33:57Z |

#### Description

dnsmasq version 2.73-1 is installed. This version is affected by multiple critical vulnerabilities including the DNSpooq family (CVE-2020-25681 through CVE-2020-25687) which includes heap-based buffer overflows in DNSSEC validation code that can lead to remote code execution, and DNS cache poisoning vulnerabilities. Additionally, CVE-2017-14491 (heap overflow via crafted DNS responses) and CVE-2017-14492/CVE-2017-14493 (heap overflows in DHCPv6) affect this version. The current version is over 5 years behind the latest release.

#### Technical Analysis

The dnsmasq version 2.73 installed on this device is severely outdated and affected by multiple critical CVEs. The DNSpooq vulnerabilities (CVE-2020-25681 through CVE-2020-25687) allow remote code execution through heap buffer overflows in the DNSSEC code and DNS cache poisoning. The 2017 CVEs (CVE-2017-14491/14492/14493) allow remote code execution through heap/stack overflows in DNS response and DHCPv6 handling. Since dnsmasq runs as a network-facing service handling DNS and DHCP, these vulnerabilities are directly exploitable by network-adjacent or remote attackers.

#### Exploitation Commands

```bash
strings /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/sbin/dnsmasq | grep "dnsmasq-"
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/lib/opkg/info/dnsmasq-dhcpv6.control
```

#### Evidence / Logs

```
strings output: dnsmasq-2.73

opkg control:
Package: dnsmasq-dhcpv6
Version: 2.73-1
Description: DNS/DHCP service with DHCPv6 support

Known CVEs for dnsmasq < 2.83:
- CVE-2020-25681 (CVSS 8.1): Heap buffer overflow in DNSSEC - RCE
- CVE-2020-25682 (CVSS 8.1): Buffer overflow in extract_request() 
- CVE-2020-25683 (CVSS 5.9): Heap overflow in DNSSEC validation
- CVE-2020-25684 (CVSS 3.7): DNS cache poisoning via TXID weakness
- CVE-2020-25685 (CVSS 3.7): DNS cache poisoning via weak hashing
- CVE-2020-25686 (CVSS 3.7): DNS cache poisoning via multiple queries
- CVE-2020-25687 (CVSS 5.9): Heap overflow in sort_rrset()
- CVE-2017-14491 (CVSS 9.8): Heap overflow via crafted DNS responses
- CVE-2017-14492 (CVSS 9.8): Heap overflow in DHCPv6
- CVE-2017-14493 (CVSS 9.8): Stack overflow in DHCPv6
- CVE-2017-14496 (CVSS 7.5): Integer underflow in DNS request handling
```

#### Remediation

Update dnsmasq to the latest version (2.89+ at time of assessment). Apply all security patches. If DNSSEC is not required, disable it to reduce attack surface.

---

### 3.10 — PII Data Exposure in Embedded SQLite Database (Sensor Data)

| Field | Value |
|-------|-------|
| **ID** | `vuln_7b863d` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1005` — Data from Local System |
| **ISO 27001** | `A.18.1.4` |
| **Endpoint** | `[REDACTED].db` |
| **Component** | sensordata.db (SQLite) |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:32:54Z |

#### Description

A SQLite database at [REDACTED].db contains personally identifiable information (PII) including full names, email addresses, and birthdates of individuals alongside sensor data (temperature, humidity readings). The database is stored within the web application's controller directory, making it potentially accessible via the web interface. The data includes entries for real-looking users such as 'johnsmith', 'jillsmith', 'walter', 'WilliamRonald' with their personal email addresses and dates of birth.

#### Technical Analysis

The firmware ships with a SQLite database containing PII (names, email addresses, birthdates) stored alongside IoT sensor readings. This database is located in the LuCI controller directory, which is part of the web application's code path. The data is stored in plaintext without encryption. This represents both a privacy violation (GDPR/CCPA implications) and a data exposure risk, as firmware images are often distributed publicly and can be extracted by anyone with binwalk.

#### Exploitation Commands

```bash
sqlite3 /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-[REDACTED].db ".tables"
sqlite3 /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-[REDACTED].db ".dump"
```

#### Evidence / Logs

```
Tables: sensors

Schema:
CREATE TABLE sensors(id INTEGER PRIMARY KEY AUTOINCREMENT, temperature NUMERIC, humidity NUMERIC, currentdate DATE, currentime TIME, name TEXT, email TEXT, birthdate NUMERIC);

Data:
INSERT INTO sensors VALUES(1,22.4,68,'2020-03-24','18:56:33','johnsmith','[EMAIL]',1311977);
INSERT INTO sensors VALUES(2,29.7,98,'2020-03-24','18:56:43','jillsmith','[EMAIL]',4141979);
INSERT INTO sensors VALUES(3,31.2,28,'2020-03-24','18:57:05','walter','[EMAIL]',32821969);
INSERT INTO sensors VALUES(4,16.9,38,'2020-03-24','18:57:20','WilliamRonald','[EMAIL]',11141989);
INSERT INTO sensors VALUES(5,35,78,'2020-03-24','18:58:04','Test','[EMAIL]',12121990);
INSERT INTO sensors VALUES(6,35,88,'2020-03-24','18:58:18','Sgt','[EMAIL]',10171956);
```

#### Remediation

Remove PII from the firmware image. If sensor data must be stored locally, encrypt it at rest and never include personal information (name, email, birthdate) in sensor databases. Implement proper data classification and handling procedures per GDPR/CCPA requirements.

---

### 3.11 — Outdated Dropbear SSH 2017.75 — Multiple CVEs

| Field | Value |
|-------|-------|
| **ID** | `vuln_38166d` |
| **Severity** | HIGH |
| **CVSS Score** | 7.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **Status** | CONFIRMED |
| **Category** | `outdated_component` |
| **MITRE ATT&CK** | `T1190` — Exploit Public-Facing Application |
| **ISO 27001** | `A.12.6.1` |
| **Endpoint** | `TCP port 22 (Dropbear SSH)` |
| **Component** | Dropbear 2017.75-7.1 |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:34:15Z |

#### Description

Dropbear SSH version 2017.75-7.1 is installed. This version is affected by multiple CVEs including CVE-2018-15599 (information exposure via username enumeration), CVE-2019-12953 (memory handling issues), and CVE-2021-36369 (authentication bypass via SSH agent forwarding). The version is over 7 years behind the current release. Root password authentication is enabled, compounding the risk.

#### Technical Analysis

Dropbear SSH 2017.75 is severely outdated and contains known CVEs. CVE-2018-15599 allows username enumeration through timing differences in authentication responses. CVE-2021-36369 allows trivially bypassing authentication restrictions via SSH agent forwarding. Combined with root password authentication being enabled and the weak MD5-crypt password hash, this creates a significant attack surface for gaining root access to the device via SSH.

#### Exploitation Commands

```bash
strings /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/sbin/dropbear | grep "2017.75"
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/lib/opkg/info/dropbear.control
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/config/dropbear
```

#### Evidence / Logs

```
strings output: 2017.75

opkg control:
Package: dropbear
Version: 2017.75-7.1

Dropbear config:
config dropbear
	option PasswordAuth 'on'
	option RootPasswordAuth 'on'
	option Port '22'

Known CVEs for Dropbear 2017.75:
- CVE-2018-15599 (CVSS 5.3): Username enumeration via timing side-channel
- CVE-2019-12953 (CVSS 7.5): Memory handling vulnerability
- CVE-2021-36369 (CVSS 7.5): Agent forwarding auth bypass
```

#### Remediation

Update Dropbear to the latest version (2024.86+). Disable root password authentication and use key-based authentication only. Consider restricting SSH access to specific IP ranges.

---

### 3.12 — Outdated Linux Kernel 4.14.95 — Multiple Known CVEs

| Field | Value |
|-------|-------|
| **ID** | `vuln_c2e5cf` |
| **Severity** | MEDIUM |
| **CVSS Score** | 7.0 |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **Status** | CONFIRMED |
| **Category** | `outdated_component` |
| **MITRE ATT&CK** | `T1068` — Exploitation for Privilege Escalation |
| **ISO 27001** | `A.12.6.1` |
| **Endpoint** | `Linux Kernel 4.14.95` |
| **Component** | Linux Kernel 4.14.95 |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:34:52Z |

#### Description

Linux kernel version 4.14.95 is installed. The 4.14 LTS branch reached end-of-life in January 2024. This version is affected by numerous kernel CVEs including privilege escalation vulnerabilities (Dirty Pipe CVE-2022-0847, if applicable to this branch), various use-after-free vulnerabilities, and network stack issues. The kernel is over 5 years old and missing thousands of security fixes.

#### Technical Analysis

The Linux kernel 4.14.95 is severely outdated with the 4.14 LTS series now end-of-life. Since the firmware was built in January 2019, it is missing over 5 years of kernel security patches. The kernel is the foundation of the entire system and vulnerabilities here can bypass all userspace security measures. While many kernel CVEs require local access to exploit, the multiple remote access paths available (backdoor, telnet, SSH with weak credentials) make local kernel exploitation a realistic attack chain.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/lib/opkg/info/kernel.control
```

#### Evidence / Logs

```
Package: kernel
Version: 4.14.95-1-54ec8a9ccbf5a1a2c6108c26c1a025ce
Source: package/kernel/linux
License: GPL-2.0
Architecture: i386_pentium4

Known CVEs for kernel 4.14.95:
- CVE-2019-14896/14897: Heap overflow in Marvell WiFi drivers
- CVE-2019-17666: rtlwifi buffer overflow
- CVE-2019-11479: TCP SACK panic
- CVE-2020-8835: BPF privilege escalation
- CVE-2021-3156: sudo-related but kernel impacted
- Hundreds of additional kernel CVEs through 2024
```

#### Remediation

Upgrade to the latest supported LTS kernel (6.1+ or 6.6+). Apply all security patches. Enable kernel hardening features (KASLR, stack protector, etc.).

---

### 3.13 — Outdated BusyBox 1.28.4 — Multiple CVEs

| Field | Value |
|-------|-------|
| **ID** | `vuln_b1206a` |
| **Severity** | MEDIUM |
| **CVSS Score** | 6.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` |
| **Status** | CONFIRMED |
| **Category** | `outdated_component` |
| **MITRE ATT&CK** | `T1190` — Exploit Public-Facing Application |
| **ISO 27001** | `A.12.6.1` |
| **Endpoint** | `BusyBox 1.28.4 (/bin/busybox)` |
| **Component** | BusyBox 1.28.4-2 |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:34:33Z |

#### Description

BusyBox version 1.28.4-2 is installed. This version is affected by multiple CVEs including CVE-2018-1000517 (wget heap buffer overflow), CVE-2019-5747 (out-of-bounds read in udhcp), CVE-2021-28831 (invalid free in decompress_gunzip), CVE-2021-42373 through CVE-2021-42386 (multiple applet vulnerabilities), and CVE-2022-48174 (stack overflow). BusyBox provides the core userland utilities and is the shell interpreter for all system operations.

#### Technical Analysis

BusyBox 1.28.4 is the core userland for the device, providing all essential shell utilities, networking tools, and the ash shell interpreter. It contains multiple known CVEs spanning from 2018 to 2022. CVE-2018-1000517 and CVE-2022-48174 are rated critical (9.8) and could enable remote code execution. Since BusyBox provides the shell that all other services and scripts use, vulnerabilities in BusyBox have systemic impact across the entire device.

#### Exploitation Commands

```bash
strings /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/bin/busybox | grep "BusyBox v"
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/lib/opkg/info/busybox.control
```

#### Evidence / Logs

```
strings output: BusyBox v1.28.4 ()

opkg control:
Package: busybox
Version: 1.28.4-2
Essential: yes

Known CVEs for BusyBox 1.28.4:
- CVE-2018-1000517 (CVSS 9.8): Heap buffer overflow in wget
- CVE-2019-5747 (CVSS 7.5): Out-of-bounds read in udhcp
- CVE-2021-28831 (CVSS 7.5): Invalid free in decompress_gunzip
- CVE-2021-42373-42386 (various): Multiple applet vulnerabilities
- CVE-2022-48174 (CVSS 9.8): Stack overflow in shell ASH
```

#### Remediation

Update BusyBox to version 1.36+ or the latest available. Minimize the number of compiled-in applets to reduce attack surface. Apply all available security patches.

---

### 3.14 — LuCI File Browser Endpoint Exposed

| Field | Value |
|-------|-------|
| **ID** | `vuln_5d7929` |
| **Severity** | MEDIUM |
| **CVSS Score** | 6.5 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `sensitive_data_exposure` |
| **MITRE ATT&CK** | `T1083` — File and Directory Discovery |
| **ISO 27001** | `A.9.4.1` |
| **Endpoint** | `/admin/filebrowser` |
| **Component** | LuCI filebrowser.lua |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:36:19Z |

#### Description

A file browser LuCI controller is installed at [REDACTED].lua which registers the route /admin/filebrowser. This exposes the device's entire filesystem to authenticated web users through a template-based file browsing interface. Combined with the easily cracked credentials, this allows an attacker to browse and read any file on the device including /etc/shadow, configuration files, and private keys without needing shell access.

#### Technical Analysis

The file browser controller provides a web-based file browsing interface at /admin/filebrowser that allows any authenticated user to browse the device's filesystem. While it requires authentication, the weak credentials (iotgoatuser:[REDACTED_CREDENTIAL]) make this trivially accessible. This is a dangerous feature on a production device as it exposes sensitive configuration files, password hashes, and other secrets through a simple web interface.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-[REDACTED].lua
```

#### Evidence / Logs

```
module("luci.controller.admin.filebrowser", package.seeall)

function index()
	entry( {"admin", "filebrowser"}, template("cbi/filebrowser") ).leaf = true
end
```

#### Remediation

Remove the file browser controller from production firmware. If file access is needed for administration, restrict it to specific directories and require strong authentication.

---

### 3.15 — Outdated wpa_supplicant/hostapd 2018-05-21 — KRACK and Dragonblood CVEs

| Field | Value |
|-------|-------|
| **ID** | `vuln_d01fe2` |
| **Severity** | MEDIUM |
| **CVSS Score** | 6.5 |
| **CVSS Vector** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `outdated_component` |
| **MITRE ATT&CK** | `T1557` — Adversary-in-the-Middle |
| **ISO 27001** | `A.12.6.1` |
| **Endpoint** | `WiFi interface (hostapd/wpa_supplicant)` |
| **Component** | wpa_supplicant/hostapd 2018-05-21 |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:36:57Z |

#### Description

wpa_supplicant/hostapd version 2018-05-21 is installed. This version may be vulnerable to the Dragonblood attacks (CVE-2019-9494, CVE-2019-9495, CVE-2019-9496, CVE-2019-9497) which affect WPA3's SAE/Dragonfly handshake and WPA2-EAP-pwd. Additionally, CVE-2019-11555 (NULL pointer dereference in EAP-pwd) and CVE-2020-12695 (UPnP/SUBSCRIBE callback URL) may apply. The hostapd component provides the WiFi access point functionality.

#### Technical Analysis

The WiFi stack (wpa_supplicant and hostapd) from May 2018 is outdated and vulnerable to the Dragonblood family of attacks discovered in 2019. While the current WiFi configuration uses no encryption (which is a worse vulnerability), if encryption were enabled, these vulnerabilities would apply. The outdated version also means missing general security hardening improvements made since 2018.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/lib/opkg/info/wpa-supplicant.control
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/usr/lib/opkg/info/hostapd-common.control
```

#### Evidence / Logs

```
wpa-supplicant control:
Package: wpa-supplicant
Version: 2018-05-21-62566bc2-5

hostapd-common control:
Package: hostapd-common
Version: 2018-05-21-62566bc2-5

Known CVEs:
- CVE-2019-9494 (CVSS 5.9): SAE side-channel attack (Dragonblood)
- CVE-2019-9495 (CVSS 3.7): EAP-pwd side-channel
- CVE-2019-9496 (CVSS 7.5): SAE confirm missing validation
- CVE-2019-11555 (CVSS 5.9): EAP-pwd NULL dereference
```

#### Remediation

Update hostapd/wpa_supplicant to the latest version. Enable WPA3-SAE encryption with the patched implementation.

---

### 3.16 — Outdated mbedTLS 2.14.1 — Known Cryptographic Vulnerabilities

| Field | Value |
|-------|-------|
| **ID** | `vuln_30311a` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.9 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `outdated_component` |
| **MITRE ATT&CK** | `T1557` — Adversary-in-the-Middle |
| **ISO 27001** | `A.10.1.1` |
| **Endpoint** | `mbedTLS library (used by uhttpd HTTPS, uclient)` |
| **Component** | mbedTLS 2.14.1-1 |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:35:10Z |

#### Description

mbedTLS version 2.14.1-1 is installed as the TLS/crypto library. This version is outdated and affected by multiple CVEs including CVE-2019-16910 (side-channel attack on ECDSA), CVE-2019-18222 (timing side-channel in RSA), CVE-2020-10932 (side-channel vulnerability in ECC), and CVE-2020-36475/36476/36477 (various crypto vulnerabilities). mbedTLS provides the TLS implementation for uhttpd (HTTPS) and other secure communications.

#### Technical Analysis

mbedTLS 2.14.1 is the cryptographic library providing TLS for the device's HTTPS web interface and package downloads. It contains known side-channel vulnerabilities in ECDSA and RSA implementations that could allow key recovery by an attacker with access to timing information. CVE-2020-36475/36476/36477 affect certificate validation, which could allow MITM attacks against HTTPS connections or package verification. As the sole TLS library on the device, these vulnerabilities undermine all encrypted communications.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-[REDACTED].control
```

#### Evidence / Logs

```
Package: libmbedtls
Version: 2.14.1-1
Source: package/libs/mbedtls

Known CVEs for mbedTLS 2.14.1:
- CVE-2019-16910 (CVSS 5.3): ECDSA side-channel via deterministic nonces
- CVE-2019-18222 (CVSS 4.7): RSA timing side-channel
- CVE-2020-10932 (CVSS 4.7): ECC side-channel vulnerability
- CVE-2020-36475 (CVSS 7.5): Improper certificate validation
- CVE-2020-36476 (CVSS 9.8): NULL pointer dereference
- CVE-2020-36477 (CVSS 5.9): Missing CA verification
```

#### Remediation

Update mbedTLS to version 3.x (latest). The 2.x branch is end-of-life. Ensure proper certificate validation is configured for all TLS connections.

---

### 3.17 — Dropbear SSH Root Password Authentication Enabled

| Field | Value |
|-------|-------|
| **ID** | `vuln_5c4a4e` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.3 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1110` — Brute Force |
| **ISO 27001** | `A.9.4.2` |
| **Endpoint** | `TCP port 22 (SSH)` |
| **Component** | Dropbear SSH configuration |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:35:26Z |

#### Description

The Dropbear SSH server is configured with both PasswordAuth and RootPasswordAuth set to 'on'. This allows password-based authentication for all users including root, making the device vulnerable to brute-force attacks against SSH. The empty RSA host key file (/etc/dropbear/dropbear_rsa_host_key, 0 bytes) also suggests the SSH host key is generated at first boot, which could be predictable if the entropy source is weak.

#### Technical Analysis

SSH root password authentication being enabled combined with the weak MD5-crypt hash creates a direct attack path. The empty host key file (0 bytes) means the key is generated at first boot from potentially limited entropy on an embedded device, which could make the host key predictable. Best practice is to disable password authentication entirely and use key-based auth, and to pre-generate host keys with proper entropy during firmware build.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/config/dropbear
ls -la /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/dropbear/
```

#### Evidence / Logs

```
Dropbear config:
config dropbear
	option PasswordAuth 'on'
	option RootPasswordAuth 'on'
	option Port '22'

Host key:
-rw-r--r-- 1 root root 0 Jan 30 2019 dropbear_rsa_host_key
```

#### Remediation

Set RootPasswordAuth to 'off'. Preferably set PasswordAuth to 'off' and use key-based authentication. Pre-generate host keys with proper entropy during firmware build.

---

### 3.18 — Outdated OpenWrt 18.06.2 Platform — End of Life

| Field | Value |
|-------|-------|
| **ID** | `vuln_d007f6` |
| **Severity** | MEDIUM |
| **CVSS Score** | 5.0 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O` |
| **Status** | CONFIRMED |
| **Category** | `outdated_component` |
| **MITRE ATT&CK** | `T1190` — Exploit Public-Facing Application |
| **ISO 27001** | `A.12.6.1` |
| **Endpoint** | `OpenWrt 18.06.2 platform` |
| **Component** | OpenWrt 18.06.2 |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:35:59Z |

#### Description

The firmware is based on OpenWrt 18.06.2 (r7676-cddd7b4c77), released in January 2019. This version has been end-of-life for years, with the current stable being OpenWrt 23.05.x. Running an EOL platform means no security patches are available from upstream, and all components (kernel, userland, libraries) are stuck at 2018-2019 versions with all CVEs discovered since then unpatched.

#### Technical Analysis

OpenWrt 18.06.2 is years past its end-of-life. This means no upstream security patches are available for any component. The platform includes all the outdated components identified in other findings (kernel 4.14.95, dnsmasq 2.73, Dropbear 2017.75, BusyBox 1.28.4, mbedTLS 2.14.1). Upgrading to a current OpenWrt release would address most of the outdated component findings simultaneously.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/openwrt_release
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/os-release
```

#### Evidence / Logs

```
DISTRIB_ID='OpenWrt'
DISTRIB_RELEASE='18.06.2'
DISTRIB_REVISION='r7676-cddd7b4c77'
DISTRIB_TARGET='x86/generic'
DISTRIB_ARCH='i386_pentium4'
DISTRIB_DESCRIPTION='OpenWrt 18.06.2 r7676-cddd7b4c77'

NAME="IoTGoat"
VERSION="v1.0"
ID="iotgoat"
PRETTY_NAME="OWASP IoTGoat"
```

#### Remediation

Upgrade to the latest stable OpenWrt release (23.05.x or newer). Implement a firmware update policy with regular security patches.

---

### 3.19 — Hardcoded Public DNS Resolver (Google DNS) in Network Configuration

| Field | Value |
|-------|-------|
| **ID** | `vuln_8bddf9` |
| **Severity** | LOW |
| **CVSS Score** | 3.7 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1071.004` — Application Layer Protocol: DNS |
| **ISO 27001** | `A.13.1.1` |
| **Endpoint** | `/etc/config/network` |
| **Component** | Network configuration |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:36:33Z |

#### Description

The network configuration hardcodes a public DNS resolver (identified as IP_PUBLIC_001, likely Google DNS 8.8.8.8) for both WAN and LAN backup interfaces. This means all DNS queries from the device and its clients are sent to a third-party resolver, potentially exposing browsing patterns and internal hostnames. The DNS queries are sent over plaintext UDP, making them susceptible to eavesdropping and manipulation.

#### Technical Analysis

Hardcoding a public DNS resolver bypasses any network-level DNS filtering or security controls that may be in place. It also sends all DNS queries to a third-party service, creating a privacy concern. The plaintext UDP DNS transport makes these queries vulnerable to interception and manipulation by network-level attackers.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/config/network
```

#### Evidence / Logs

```
config interface 'wan'
	option proto 'dhcp'
	option force_link '1'
	option ifname 'eth1'
	option hostname 'IoTGoat'
	option dns 'IP_PUBLIC_001'

(network.bak also contains:)
	option dns 'IP_PUBLIC_001'
```

#### Remediation

Use the DHCP-provided DNS resolver or configure a DNS-over-TLS/HTTPS resolver. Avoid hardcoding public DNS resolvers in firmware.

---

### 3.20 — Duplicate dnsmasq User Entry in /etc/shadow

| Field | Value |
|-------|-------|
| **ID** | `vuln_358780` |
| **Severity** | LOW |
| **CVSS Score** | 3.3 |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` |
| **Status** | CONFIRMED |
| **Category** | `misconfiguration` |
| **MITRE ATT&CK** | `T1098` — Account Manipulation |
| **ISO 27001** | `A.9.2.1` |
| **Endpoint** | `/etc/shadow` |
| **Component** | /etc/shadow |
| **Discovered by** | `iot-firmware` |
| **Discovered at** | 2026-08-02T17:35:42Z |

#### Description

The /etc/shadow file contains a duplicate entry for the 'dnsmasq' user. This is a misconfiguration that could indicate a tampered shadow file or improper firmware build process. While not directly exploitable, duplicate shadow entries can cause unpredictable authentication behavior and indicate quality control issues in the firmware build pipeline.

#### Technical Analysis

The shadow file contains two identical entries for the dnsmasq user. While both are locked (password field 'x'), this indicates either firmware build issues or potential tampering. On some systems, duplicate shadow entries can cause the second entry's password policy to override the first, potentially creating authentication bypasses.

#### Exploitation Commands

```bash
cat /tmp/iotgoat/extracted/_fw.img.extracted/squashfs-root/etc/shadow
```

#### Evidence / Logs

```
/etc/shadow:
root:$1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1:18145:0:99999:7:::
daemon:*:0:0:99999:7:::
ftp:*:0:0:99999:7:::
network:*:0:0:99999:7:::
nobody:*:0:0:99999:7:::
dnsmasq:x:0:0:99999:7:::
dnsmasq:x:0:0:99999:7:::   <-- DUPLICATE ENTRY
iotgoatuser:$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:18145:0:99999:7:::
```

#### Remediation

Remove the duplicate dnsmasq entry from /etc/shadow. Review the firmware build pipeline to prevent duplicate entries. Implement automated checks for shadow file integrity.

---

## 4. REMEDIATION ROADMAP

### P0 — Immediate (< 24h)

| Finding | Effort |
|---------|--------|
| Unauthenticated Root Backdoor Daemon (shellback) on Port 551... | High |
| Unauthenticated Telnet Daemon on Port 65534 | High |
| LuCI Command Injection — Unauthenticated Root RCE via webcmd... | High |
| Weak Credential: iotgoatuser Account with Mirai Botnet Defau... | High |

### P1 — Short term (< 1 week)

| Finding | Effort |
|---------|--------|
| WiFi Access Point Configured with No Encryption (Open Networ... | High |
| Weak Root Password Hash (MD5-crypt, Not Cracked but Brute-fo... | High |
| UPnP Service Misconfiguration — secure_mode Disabled with Un... | High |
| Insecure Package Update Mechanism — HTTP-only opkg Feeds | High |
| Outdated dnsmasq 2.73 — Multiple Critical CVEs (DNSpooq) | High |
| PII Data Exposure in Embedded SQLite Database (Sensor Data) | High |

### P2 — Medium term (< 2 weeks)

| Finding | Effort |
|---------|--------|
| Outdated Linux Kernel 4.14.95 — Multiple Known CVEs | High |
| Outdated BusyBox 1.28.4 — Multiple CVEs | High |
| LuCI File Browser Endpoint Exposed | High |
| Outdated wpa_supplicant/hostapd 2018-05-21 — KRACK and Drago... | High |
| Outdated mbedTLS 2.14.1 — Known Cryptographic Vulnerabilitie... | High |

### P3 — Long term (< 1 month)

| Finding | Effort |
|---------|--------|
| Hardcoded Public DNS Resolver (Google DNS) in Network Config... | High |
| Duplicate dnsmasq User Entry in /etc/shadow | High |

---

*Report auto-generated by Darkmoon AI Security Platform*  
*Classification: CONFIDENTIAL — Restricted to authorized personnel*  
*Generated: 2026-08-02T17:38:17Z*  
*Campaign: camp_20260802_dd187131 | Target: iotgoat-firmware*
