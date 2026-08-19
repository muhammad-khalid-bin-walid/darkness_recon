# Dark Recon Framework : 40-Phase Zero False Positive Reconnaissance Framework

## Overview

Dark Recon Framework is a comprehensive, modular Bash framework for automated reconnaissance and security testing. Built by **DarkLegende**, it features **40 phases** with a **0 false positives guarantee** through multi-layered verification, cross-referencing, and confidence scoring.

**v4 Major Improvements over v3:**

- **10 new phases** added for comprehensive coverage (Scope Analysis, Target Intake, Historical Recon, Third-Party Analysis, Exploitation Validation, Post-Exploitation, Data Exfiltration, Continuous Monitoring)
- **Enhanced verification pipeline** with new validation functions for each phase group
- **Bug bounty methodology integration** based on OWASP WSTG, zseano methodology, and Bug Bounty Playbook best practices
- **Structured phase groups**: Target Intelligence, Passive Recon, Active Enumeration, Attack Surface Mapping, Vulnerability Discovery, Exploitation & Validation, Post-Exploitation, and Reporting & Integration
- **40 Phases**: Expanded from 30 to 40 phases covering full-spectrum reconnaissance
- **HowToHunt Methodology Integration**: Vulnerability methodology checks from HowToHunt (github.com/KathanP19/HowToHunt) integrated into the scanning pipeline
- **0 False Positives**: Every finding goes through a 3-layer verification pipeline (Detection → Correlation → Validation)
- **Confidence Scoring**: Every finding has a confidence score (0.0–1.0) and verification method
- **ML-Assisted Analysis**: Anomaly detection, pattern recognition, and predictive vulnerability scoring
- **Compliance Scanning**: GDPR, HIPAA, PCI DSS, and SOC2 framework scanning
- **Business Logic Testing**: IDOR, BOLA, BFLA, mass assignment, privilege escalation
- **Advanced Exploitation**: Blind SSRF, file upload testing, rate limiting bypass
- **OSINT Intelligence**: Social media, email, and corporate intelligence gathering
- **Threat Intelligence**: IOC correlation across multiple threat feeds
- **Enterprise Reporting**: HTML, Markdown, CSV, JSON, PDF, SQLite, webhooks, CI/CD

## Architecture

### Verification Pipeline (0 False Positives)
```
Detection → Correlation → Validation → Confidence Scoring → Report
```

### Confidence Score System
| Score | Meaning | Action |
|-------|---------|--------|
| 0.9–1.0 | Verified | Include in report as confirmed |
| 0.7–0.9 | High confidence | Include with `high_confidence` tag |
| 0.5–0.7 | Medium confidence | Include with `candidate` tag, needs review |
| 0.3–0.5 | Low confidence | Flag for manual review |
| <0.3 | Unverified | Exclude from report, log for analysis |

### Cross-Reference Requirements
- Every finding must have ≥2 independent sources or detection methods
- Single-source findings are always marked as `unverified`
- All `unverified` findings are excluded from final reports unless explicitly requested

## Phase Groups

### Group A: Core Reconnaissance (Phases 1–8)

| Phase | Description | Key Tools | 0 FP Guarantee |
|-------|-------------|-----------|----------------|
| 1. Subdomain Enumeration | Multi-source fusion with confidence scoring | subfinder, assetfinder, amass, crt.sh, SecurityTrails, VirusTotal, AlienVault OTX, Shodan, Chaos, Findomain, Sublist3r, Gobuster, dnsx, puredns, dnsrecon, altdns, shuffledns, haktrails, dnsgen, ctfr, knockpy, cero, bhedak, dnsenum, sublert, dnsmap, sdgo, bbot, spiderfoot | ≥2 independent sources per subdomain |
| 2. DNS Reconnaissance | Zone transfer + full record analysis | dig, dnsrecon, dnsx | Cross-validate MX records against SMTP connectivity |
| 3. Live Host Detection | Multi-protocol probing | httpx, whatweb, nmap | ≥2 successful protocol responses |
| 4. Technology Fingerprinting | Deep stack analysis | WhatWeb, Wappalyzer, BuiltWith, Shodan, Censys | ≥2 independent detection methods |
| 5. URL & Endpoint Discovery | Historical + live + API endpoints | waybackurls, waymore, gauplus, katana, gospider, hakrawler, paramspider, OpenAPI, GraphQL | Cross-reference historical vs live |
| 6. Parameter Discovery | Deep form analysis | Arjun, unfurl, JS AST analysis | Parameters must appear in actual form HTML |
| 7. Fuzzing | Intelligent path discovery | ffuf, commonspeak2 | ≥2 distinct response signatures |
| 8. Subdomain Takeover | Multi-vector verification | subjack, subzy, nuclei | HTTP response + DNS CNAME validation |

### Group B: Security Scanning (Phases 9–16)

| Phase | Description | Key Tools | 0 FP Guarantee |
|-------|-------------|-----------|----------------|
| 9. WAF Detection | Bypass-aware fingerprinting | WAFW00F, nuclei, custom probes | ≥2 matching WAF signatures |
| 10. Vulnerability Scanning | Multi-engine correlation | nuclei, dalfox, XSStrike, custom payloads | ≥2 independent detection methods |
| 11. Port Scanning | Service-verified discovery | nmap, masscan, naabu | Service banner verification |
| 12. SSL/TLS Analysis | Certificate chain validation | sslyze, custom probes | Cross-validate against CT logs |
| 13. API Security | Endpoint + auth testing | OpenAPI, GraphQL, gRPC | Valid API responses only |
| 14. Git Intelligence | Commit + secret analysis | GitRob, trufflehog, gitleaks | Format validation + ≥2 tools |
| 15. Secret Scanning | Deep code + config analysis | GitHub API, GitLab API, S3, Shodan | Format validation + ≥2 methods |
| 16. Visual Reconnaissance | Screenshot + change detection | Aquatone, EyeWitness, Playwright | HTTP response verification |

### Group C: Advanced Intelligence (Phases 17–24)

| Phase | Description | Key Tools | 0 FP Guarantee |
|-------|-------------|-----------|----------------|
| 17. Cloud Infrastructure | Multi-cloud enumeration | AWS CLI, GCS, Azure APIs | Successful API response confirmation |
| 18. Service Enumeration | CMS, framework, library detection | WPScan, JoomScan, WhatWeb, Wappalyzer | ≥2 matching indicators |
| 19. DNS/SSL/WHOIS | Comprehensive identity analysis | whois, dig, rdap | Cross-validate against RDAP + multiple resolvers |
| 20. Distributed/Proxy/TOR | Infrastructure resilience | TOR, proxy chains, Kubernetes | ≥2 independent node consensus |
| 21. OSINT Intelligence | Social + email + corporate | theHarvester, Hunter.io, Sherlock, LinkedIn, Google Dorking, Shodan, Censys, HIBP | Format validation + domain MX confirmation |
| 22. Threat Intelligence | IOC correlation | AlienVault OTX, AbuseIPDB, VirusTotal, URLhaus, ThreatFox, Shodan, Censys | ≥2 independent threat feeds |
| 23. Business Logic Testing | IDOR, BOLA, BFLA, mass assignment | nuclei, custom payloads | Successful access to another user's resource |
| 24. Advanced Exploitation | Blind SSRF, file upload, rate limiting | nuclei, curl, custom probes | DNS/HTTP interaction confirmation |

### Group D: Reporting & Integration (Phases 25–30)

| Phase | Description | Output | 0 FP Guarantee |
|-------|-------------|--------|----------------|
| 25. Multi-Format Reporting | HTML, Markdown, CSV, JSON, PDF | 5 report formats | All findings include confidence scores |
| 26. Database Storage | SQLite with schema versioning | `recon.db` | Deduplication by content hash |
| 27. Webhook & Notifications | Slack, Discord, Email, PagerDuty | Real-time alerts | `unverified` findings never trigger critical alerts |
| 28. CI/CD Integration | GitHub Actions, GitLab CI, Jenkins | Pipeline templates | Findings below threshold don't fail pipeline |
| 29. ML-Assisted Analysis | Anomaly detection, pattern recognition, predictive scoring | `ml_analysis.json` | Human review required for findings below 0.8 confidence |
| 30. Compliance Scanning | GDPR, HIPAA, PCI DSS, SOC2 | `compliance_summary.json` | Evidence of actual data exposure required |

### Group E: v4 Advanced Phases (Phases 31–40)

| Phase | Description | Key Tools | 0 FP Guarantee |
|-------|-------------|-----------|----------------|
| 31. Scope & Program Analysis | Engagement scope validation, program boundary checks | Custom scripts | Scope explicitly defined |
| 32. Target Intake Validation | Target validation, scope verification, authorization checks | Custom scripts | Authorization confirmed |
| 33. Historical Reconnaissance | Wayback Machine, DNS history, certificate transparency | waybackurls, crt.sh, SecurityTrails | ≥2 independent historical sources |
| 34. Third-Party & Dependency Analysis | CDN, library, dependency mapping | Custom scripts | ≥2 independent sources |
| 35. Exploitation Validation | PoC verification, reproduction testing | nuclei, custom payloads | Successful reproduction |
| 36. Post-Exploitation | Lateral movement, privilege escalation, persistence | Custom scripts | Verified lateral path |
| 37. Data Exfiltration | Sensitive data discovery, exposure assessment | Custom scripts | Confirmed data exposure |
| 38. Continuous Monitoring | Re-scan scheduling, alert configuration, baseline establishment | Custom scripts | Monitoring fully configured |
| 39. Database Security | Database enumeration, injection testing, credential checking | nmap, sqlmap, custom payloads | ≥2 independent detection methods |
| 40. HowToHunt Methodology | Vulnerability methodology integration (HowToHunt) | Custom scripts | Methodology-based validation with cross-reference

## Installation

### Quick Start (Auto-Install Everything)
```bash
chmod +x dark_recon_framework.sh
./dark_recon_framework.sh --install
```

This will:
1. Install all missing tools via apt/yum/brew/cargo/pip/npm/go
2. Clone SecLists to `/usr/share/seclists`
3. Download curated DNS resolvers
4. Generate custom wordlists with `commonspeak2`
5. Create default config files for amass, subjack, etc.
6. Configure 40-phase execution pipeline

## Usage

### Basic Usage
```bash
# Full reconnaissance (all 40 phases)
./dark_recon_framework.sh example.com

# Deep reconnaissance (all optional phases)
./dark_recon_framework.sh example.com --deep

# Fast mode (skip optional, reduce concurrency)
./dark_recon_framework.sh example.com --fast

# Custom thread count
./dark_recon_framework.sh example.com --jobs 200
```

### Phase Control
```bash
# Resume from specific phase (uses cached state)
./dark_recon_framework.sh example.com --resume subdomains

# Skip a phase
./dark_recon_framework.sh example.com --skip fuzz

# Run specific phases
./dark_recon_framework.sh example.com --cloud --vuln --service --dns-ssl-whois --distributed
```

### Advanced Options
```bash
# Quiet mode (minimal output)
./dark_recon_framework.sh example.com --quiet

# JSON output for automation
./dark_recon_framework.sh example.com --json

# Custom timeout
./dark_recon_framework.sh example.com --timeout 600

# Show help
./dark_recon_framework.sh --help
```

### Available Flags

| Flag | Description |
|------|-------------|
| `--help` | Show help message |
| `--version` | Show version |
| `--install` | Install all tools and assets |
| `--fast` | Fast mode (disable optional phases) |
| `--deep` | Deep mode (enable all optional phases) |
| `--resume <phase>` | Resume from phase |
| `--skip <phase>` | Skip phase |
| `--jobs <N>` | Parallel jobs (default: 150) |
| `--timeout <sec>` | Tool timeout (default: 300) |
| `--quiet` | Minimal output |
| `--json` | JSON output format |
| `--waf` | Enable WAF detection |
| `--nuclei` | Enable Nuclei scanning |
| `--portscan` | Enable port scanning |
| `--ssl` | Enable SSL/TLS analysis |
| `--api` | Enable API discovery |
| `--git` | Enable Git scanning |
| `--secrets` | Enable secret scanning |
| `--cloud` | Enable cloud/infrastructure scanning |
| `--vuln` | Enable vulnerability scanning |
| `--service` | Enable service enumeration |
| `--dns-ssl-whois` | Enable DNS/SSL/WHOIS analysis |
| `--distributed` | Enable distributed/cloud scaling |
| `--osint` | Enable OSINT intelligence gathering |
| `--threat-intel` | Enable threat intelligence integration |
| `--business-logic` | Enable business logic vulnerability testing |
| `--advanced-exploitation` | Enable advanced exploitation testing |
| `--compliance` | Enable compliance and regulatory scanning |
| `--ml-analysis` | Enable ML-assisted analysis |

## Output Structure

```
output/
└── example.com/
    └── recon_20260804_120000/
        ├── subdomains/
        │   ├── subdomains.txt          # All unique subdomains with confidence scores
        │   └── *.txt                   # Per-tool raw output
        ├── dns/
        │   └── dns_records.json        # DNS records with verification status
        ├── live/
        │   ├── live_subdomains.json    # Live hosts with protocol-level verification
        │   └── whatweb.txt             # Technology fingerprints
        ├── crawl/
        │   ├── wayback.txt             # Historical URLs
        │   ├── endpoints.txt           # Discovered endpoints
        │   ├── js_files.txt            # JavaScript files
        │   ├── urls_with_params.txt    # URLs with parameters
        │   └── param_keys.txt          # Parameter keys
        ├── fuzz/
        │   └── fuzz_results.json       # Fuzzing results with confidence scores
        ├── takeovers/
        │   └── potential_takeovers.json # Takeover candidates with verification
        ├── patterns/
        │   ├── xss.json, sqli.json, ... # Pattern matches with confidence
        ├── waf/, nuclei/, ports/, ssl/, api/, git/, secrets/, screenshots/
        ├── cloud/                      # Cloud infrastructure discovery
        ├── vuln/                       # Vulnerability scanning results
        ├── service/                    # Service enumeration results
        ├── dns_ssl_whois/              # DNS/SSL/WHOIS analysis
        ├── distributed/                # Distributed scanning results
        ├── osint/                      # OSINT intelligence gathering
        ├── threat_intel/               # Threat intelligence correlation
        ├── business_logic/             # Business logic vulnerability testing
        ├── advanced_exploitation/      # Advanced exploitation testing
        ├── compliance/                 # Compliance and regulatory scanning
        ├── ml_analysis/                # ML-assisted analysis results
        ├── database/                   # SQLite database output
        ├── webhooks/                   # Webhook delivery logs
        ├── cicd/                       # CI/CD integration artifacts
        ├── final_output.txt            # Human-readable summary
        ├── final_output.json           # Machine-readable summary
        ├── final_output.html           # Interactive HTML dashboard
        ├── final_output.pdf            # Print-ready PDF report
        ├── recon.db                    # SQLite database with all findings
        └── logs/
            └── process.log             # JSON-lines process log
```

## Resume & State Management

The framework maintains state in `cache/state/`:
- Each completed phase creates `<phase>.done` with timestamp
- `--resume <phase>` re-runs from that phase, skipping completed ones
- `--skip <phase>` disables a phase entirely
- Cache persists across runs for incremental recon

## Configuration

Settings in `config/settings.conf`:
```bash
THREADS=150              # Parallel jobs
TIMEOUT=300              # Tool timeout (seconds)
RATE_LIMIT=1000          # Requests/second
MAX_RETRIES=2            # Retry attempts
```

Tools in `config/tools.conf`:
- Lists essential vs optional tools
- Auto-generates `cache/tools.status` with availability

## Logging

- **Human**: Stdout with `[*]`, `[!]`, `[X]` prefixes
- **Machine**: JSON-lines in `logs/process.log`
- **Per-tool**: Individual logs in `logs/<tool>.log`

## Legal Notice

**This tool is for authorized testing only.** Use only on assets you own or have explicit written permission to test. Unauthorized scanning may violate computer misuse laws in your jurisdiction.

## Credits

Created by **DarkLegende**. Integrates tools from the security community including ProjectDiscovery, tomnomnom, hakluke, and many others.

## License

See `LICENSE` file.
