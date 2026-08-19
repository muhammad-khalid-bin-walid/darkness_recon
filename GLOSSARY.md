# Dark Recon Framework — Glossary

## Vulnerability Classes

| Abbreviation | Full Name | Description |
|---|---|---|
| IDOR | Insecure Direct Object Reference | Accessing resources by manipulating object identifiers in requests |
| SSRF | Server-Side Request Forgery | Making the server issue requests to unintended internal/external resources |
| XSS | Cross-Site Scripting | Injecting malicious scripts into web pages viewed by other users |
| SQLi | SQL Injection | Inserting SQL queries via user input to manipulate the database |
| XXE | XML External Entity | Exploiting XML parsers to access internal files or make SSRF requests |
| SSTI | Server-Side Template Injection | Injecting template code that executes on the server |
| CSRF | Cross-Site Request Forgery | Forcing authenticated users to execute unintended actions |
| RCE | Remote Code Execution | Executing arbitrary commands on the target server |
| LFI | Local File Inclusion | Reading arbitrary files from the server filesystem |
| AOF | Authentication Bypass | Circumventing authentication mechanisms without credentials |
| PrivEsc | Privilege Escalation | Elevating access from lower to higher privilege levels |
| Open Redirect | Open Redirect | Redirecting users to untrusted external sites via manipulated URLs |
| Clickjacking | Clickjacking | Tricking users into clicking transparent overlays on legitimate pages |
| Cache Poisoning | Web Cache Poisoning | Injecting malicious responses into shared caches |
| CRLF Injection | CRLF Injection | Injecting HTTP response headers via user input |
| HTTP Smuggling | HTTP Request Smuggling | Exploiting parsing differences between proxies and backends |
| Desync | HTTP Desync | Request smuggling causing desynchronization between proxies |

## Severity Levels

| Level | CVSS Range | Description | Action |
|---|---|---|---|
| Critical | 9.0–10.0 | Immediate exploitation risk, full compromise | Submit within 24h |
| High | 7.0–8.9 | Significant impact, relatively easy to exploit | Submit within 48h |
| Medium | 4.0–6.9 | Moderate impact or requires specific conditions | Include in report |
| Low | 0.1–3.9 | Limited impact, defense-in-depth improvement | Include in report |
| Info | 0.0 | Informational finding, no direct risk | Internal note |

## Framework Terms

| Term | Definition |
|---|---|
| Phase | A single unit of work within a scan (e.g., subdomain_enum, fuzz, nuclei) |
| Track | A logical grouping of phases (e.g., Recon, Web/API, Cloud, Business Logic) |
| Finding | A discovered vulnerability or security observation |
| Asset | A discovered resource (domain, IP, service, endpoint) |
| Endpoint | A discovered URL or API endpoint |
| Credential | A discovered secret, key, or authentication material |
| ScanRun | A single execution of the framework against a target |
| Scope | The set of authorized targets for a given engagement |
| Bridge | The Python↔Shell interface (write_finding, write_asset, py_log) |
| Checkpoint | Saved state allowing a phase to resume after interruption |
| Confidence | How certain we are that a finding is genuine (confirmed/high/medium/low/unverified) |
| Delta | The difference between two consecutive scans of the same target |
| Correlation | Linking findings across phases into attack paths |
| Deduplication | Merging duplicate findings from different tools into one record |
| Entity Resolution | Merging duplicate assets discovered via different naming conventions |
| Flywheel | The feedback loop where validated findings improve future detection |
| CVSS | Common Vulnerability Scoring System — standardized severity metric |
| ASVS | Application Security Verification Standard — OWASP verification framework |
| SARIF | Static Analysis Results Interchange Format — standard for tool output |
| SBOM | Software Bill of Materials — inventory of all software components |
| SRI | Subresource Integrity — cryptographic hash for third-party script verification |
| IOC | Indicator of Compromise — artifact indicating breach or attack |
| TTP | Tactics, Techniques, and Procedures — attacker behavior patterns |
| ICS/SCADA | Industrial Control Systems / Supervisory Control and Data Acquisition |

## Confidence Levels

| Level | Description |
|---|---|
| confirmed | Reproduced independently, impact demonstrated |
| high | Strong evidence from multiple tools, low false-positive risk |
| medium | Single tool detection, plausible but not independently verified |
| low | Weak signal, may be false positive |
| unverified | Detected but not yet validated |

## Evidence Types

| Type | Description |
|---|---|
| screenshot | Visual capture of the vulnerable state |
| response_diff | Before/after response comparison |
| poc_curl | Reproducible curl command |
| poc_python | Reproducible Python script |
| http_traffic | Full HTTP request/response pair |
| header_capture | Relevant HTTP headers at time of discovery |
| log_excerpt | Tool output showing the finding |

## Tool Categories

| Category | Purpose | Examples |
|---|---|---|
| Recon | Passive discovery and enumeration | subfinder, amass, theHarvester |
| Active Scan | Direct interaction with targets | nuclei, nikto, sqlmap |
| Passive Scan | Observation without direct interaction | Shodan, Censys, Certificate Transparency |
| Exploitation | Safe validation of vulnerabilities | Custom PoC scripts (read-only) |
| Reporting | Output generation and formatting | Custom report generators |
