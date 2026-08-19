# HowToHunt Methodology Integration

Integration of the [HowToHunt](https://github.com/KathanP19/HowToHunt) vulnerability methodology into Dark Recon Framework v4.

## Overview

HowToHunt is a collaborative repository of step-by-step guides, methodologies, and hands-on techniques for finding specific vulnerabilities. This integration adds structured vulnerability methodology checks to the reconnaissance pipeline.

## Methodology Categories

| Category | Phase Mapping | Description |
|----------|--------------|-------------|
| XSS | vuln | Cross-Site Scripting test cases |
| SQLi | vuln | SQL Injection test cases |
| SSRF | advanced_exploitation | Server-Side Request Forgery |
| IDOR | business_logic | Insecure Direct Object Reference |
| CORS | business_logic | Cross-Origin Resource Sharing misconfigurations |
| CSRF | business_logic | Cross-Site Request Forgery |
| File Upload | advanced_exploitation | File upload vulnerability testing |
| WAF Bypasses | waf | Web Application Firewall bypass techniques |
| Auth Bypass | advanced_exploitation | Authentication bypass methodologies |
| JWT | api | JSON Web Token security testing |
| GraphQL | api | GraphQL-specific vulnerability testing |
| XXE | vuln | XML External Entity injection |
| SSTI | vuln | Server-Side Template Injection |
| Host Header | dns_ssl_whois | Host header injection attacks |
| Open Redirection | vuln | Open redirect vulnerability testing |
| Rate Limit | advanced_exploitation | Rate limiting bypass techniques |
| Race Condition | advanced_exploitation | Race condition testing |
| Parameter Pollution | params | Parameter pollution testing |
| Tabnabbing | business_logic | Tabnabbing and UI redressing |
| Password Reset | business_logic | Password reset functionality testing |
| MFA Bypass | business_logic | Multi-factor authentication bypass |
| SAML | api | SAML-based authentication testing |
| OAuth | api | OAuth flow security testing |
| Sensitive Info Leaks | secrets | Sensitive information disclosure |
| EXIF Geo Data | screenshots | EXIF and geolocation data exposure |
| Broken Auth | business_logic | Broken authentication and session management |
| CMS | tech | CMS-specific vulnerability testing |
| CVES | vuln | Known CVE exploitation checks |
| Subdomain Takeover | takeovers | Subdomain takeover methodology |
| HTTP Desync | waf | HTTP request desync attacks |
| Status Code Bypass | waf | Status code-based bypass techniques |
| Weak Password Policy | business_logic | Weak password policy testing |
| Find Origin IP | recon | Origin IP discovery techniques |
| Web Source Review | recon | Source code review methodology |

## Usage

The HowToHunt methodology is automatically applied during relevant phases. Each vulnerability category includes:

1. **Test cases** - Specific payloads and techniques
2. **Tools** - Recommended tools for each test case
3. **Verification** - How to confirm findings
4. **References** - Links to original HowToHunt guides

## Integration with 0 False Positives Pipeline

Every HowToHunt methodology finding goes through the standard verification pipeline:

```
Detection → Correlation → Validation → Confidence Scoring → Report
```

Findings must have ≥2 independent sources or methods to be included in reports.