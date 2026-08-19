# Dark Recon Framework v4 — 20-Phase Consolidated Plan

## Overview
This plan consolidates 300+ original phases into 20 logical, manageable phases while preserving the **0 false positives guarantee** (detection → correlation → validation → confidence scoring → report pipeline).

## Phase Grouping Strategy
Phases are grouped by **functional category** rather than sequential numbering. Each phase maintains the bash function pattern (`phase_name() { ... }`) with consistent helpers (`phase_log`, `write_asset`, `write_finding`) and integrates with `lib/phase_bridge.py`.

---

## TRACK 0 — Foundation & Recon (Phases 1–5)

| Phase | Title | Encompasses (Original Phase Themes) | Key Output |
|-------|-------|-------------------------------------|------------|
| **1** | **Subdomain & Asset Enumeration** | subdomain_phase, dns_phase, amass, findomain, assetfinder, subfinder, sublist3r, crt.sh queries | `subdomains.txt` with confidence scores |
| **2** | **Live Host & Service Detection** | live host detection, httpx, whatweb, nmap, masscan, naabu, port scanning | `live_subdomains.json` with protocol verification |
| **3** | **Technology Fingerprinting** | Wappalyzer, WhatWeb, BuiltWith, WPScan, JoomScan, framework/library identification | Technology fingerprints with confidence |
| **4** | **URL & Endpoint Discovery** | waybackurls, waymore, gauplus, gospider, hakrawler, parameter discovery | `endpoints.txt`, `urls_with_params.txt` |
| **5** | **Parameter & Form Analysis** | Arjun, JS AST analysis, form parameter discovery, unfurl | `param_keys.txt`, URLs with parameters |

---

## TRACK 1 — Attack Surface & Vulnerability (Phases 6–8)

| Phase | Title | Encompasses (Original Phase Themes) | Key Output |
|-------|-------|-------------------------------------|------------|
| **6** | **Fuzzing & Path Discovery** | fuzz_phase, ffuf, commonspeak2, path traversal discovery | `fuzz_results.json` with confidence scores |
| **7** | **WAF Detection & Evasion** | WAFW00F, nuclei WAF probes, WAF bypass techniques, fingerprinting | WAF identification with verification |
| **8** | **Vulnerability Scanning** | nuclei, dalfox, XSStrike, XSS/SQLi pattern matching phases | `patterns/*.json` with severity scores |

---

## TRACK 2 — Specialized Analysis (Phases 9–12)

| Phase | Title | Encompasses (Original Phase Themes) | Key Output |
|-------|-------|-------------------------------------|------------|
| **9** | **API Security & Enumeration** | OpenAPI, GraphQL, gRPC enumeration, API endpoint testing | API findings with verification status |
| **10** | **Git & Secret Scanning** | GitRob, trufflehog, gitleaks, secret finding, credential detection | Secrets found with source verification |
| **11** | **Cloud & Infrastructure Enumeration** | cloud_phase, Kubernetes, Docker, cloud IAM, asset enumeration | Cloud infrastructure findings |
| **12** | **Compliance & Regulatory Scanning** | GDPR, HIPAA, PCI DSS, SOC2, ASVS, compliance phases | `compliance_summary.json` |

---

## TRACK 3 — Advanced Testing & Intelligence (Phases 13–17)

| Phase | Title | Encompasses (Original Phase Themes) | Key Output |
|-------|-------|-------------------------------------|------------|
| **13** | **Business Logic Vulnerability Testing** | IDOR, BOLA, BFLA, mass assignment, workflow bypass phases | Business logic findings with access verification |
| **14** | **Advanced Exploitation & SSRF** | Blind SSRF, file upload testing, rate limiting bypass, exploitation validation | Exploitation findings with reproduction verification |
| **15** | **Post-Exploitation & Lateral Movement** | Persistence, privilege escalation, lateral movement phases | Lateral movement paths verified |
| **16** | **Threat Intelligence & IOC Correlation** | OTX, AbuseIPDB, VirusTotal, URLhaus, ThreatFox, IOC correlation phases | Threat intelligence correlation results |
| **17** | **OSINT & Social Intelligence** | theHarvester, sherock, LinkedIn dorking, email enumeration, social media intelligence | OSINT findings with source verification |

---

## TRACK 4 — Security & Reporting (Phases 18–20)

| Phase | Title | Encompasses (Original Phase Themes) | Key Output |
|-------|-------|-------------------------------------|------------|
| **18** | **Cache & Encoding Security** | Cache poisoning, content type confusion, TLS chain analysis phases | Security findings with verification |
| **19** | **Rich Protocol Security** | WebSocket, gRPC analysis, rich protocol security phases | Protocol security findings |
| **20** | **Reporting, Database & Integration** | SQLite storage, report formats (HTML/MD/CSV/JSON/PDF), webhooks, CI/CD, ML analysis | Final reports, database, webhooks, CI/CD artifacts |

---

## Sequencing & Execution Rules

### Phase Execution Order
Phases 1–5 must complete before 6–8, 6–8 before 9–12, and 9–12 before 13–17, and 13–17 before 18–20. This ensures proper data flow and correlation.

### 0 False Positives Guarantee (Per Phase)
- **≥2 independent sources** required for each finding
- **Confidence scoring** (0.0–1.0) based on verification methods
- **Unverified findings** excluded from final reports unless explicitly requested
- **Pipeline**: detection → correlation → validation → confidence scoring → report

### Integration with Python Phase Bridge
Each phase function maintains compatibility with `lib/phase_bridge.py`:
- Uses `phase_log()`, `write_asset()`, `write_finding()` helpers
- Outputs JSON-lines to `logs/process.log`
- Writes to phase-specific output directories under `output/`
- Supports `--resume <phase>` and `--skip <phase>` flags

### Recommended Starting Point
Begin with **Phase 1** (Subdomain & Asset Enumeration) which unblocks nearly all downstream phases. The Python phase bridge (65 modules, 223 tests passing) provides the integration layer.

## Migration Path from 300→20 Phases
1. **Phase 1-5**: Consolidate subdomain/discovery phases (original: ~80 phases)
2. **Phase 6-8**: Consolidate fuzzing/WAF/vuln scanning phases (original: ~60 phases)
3. **Phase 9-12**: Consolidate API/Git/cloud/compliance phases (original: ~50 phases)
4. **Phase 13-17**: Consolidate business logic/exploitation/intelligence phases (original: ~70 phases)
5. **Phase 18-20**: Consolidate cache/protocol/reporting phases (original: ~40 phases)

Each combined phase retains all original tool integrations and verification logic, just organized under functional umbrellas.