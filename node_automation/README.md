# Dark Recon Framework v4 - Browser Automation Package

## Overview
Node.js automation package for browser-based reconnaissance operations, integrated with the Dark Recon Framework v4 20-phase consolidated structure.

## Features
- **Puppeteer-powered browser automation** for headless reconnaissance
- **Axios HTTP client** for API-based data gathering
- **JSDOM** for DOM analysis and technology fingerprinting
- **20-phase integration** aligned with the consolidated framework plan
- **Configurable target, phase, and thread settings**
- **Headless/headful mode** toggling for debugging

## Installation

```bash
# Clone or navigate to the package
cd dark-recon-framework/node_automation

# Install dependencies
npm install

# This will install:
# - puppeteer (browser automation)
# - axios (HTTP client)
# - jsdom (DOM analysis)
```

## Usage

### Basic Example
```bash
# Run subdomain enumeration (Phase 1) against a target
node bin/automation.js example.com 1

# Run technology fingerprinting (Phase 3)
node bin/automation.js example.com 3

# Run with custom settings
node bin/automation.js example.com 1 --headless=false --threads 4 --timeout 600
```

### Command-Line Arguments
| Argument | Description | Default |
|----------|-------------|---------|
| `target` | Target domain for reconnaissance | Required |
| `phase` | Phase number (1-20) | 1 |
| `output` | Output directory path | ./output |
| `threads` | Number of concurrent threads | 1 |
| `timeout` | Tool timeout in seconds | 300 |
| `--headless` | Run browser without UI | true |

### Phase Support
The automation package currently supports Phases 1-4 with full browser automation:

| Phase | Description | Tools Integrated |
|-------|-------------|-----------------|
| **1** | Subdomain Enumeration | subfinder, assetfinder, findomain, crt.sh |
| **2** | Live Host Detection | httpx, whatweb, nmap, naabu |
| **3** | Technology Fingerprinting | whatweb, wappalyzer, builtwith |
| **4** | URL & Endpoint Discovery | waybackurls, gauplus, gospider |
| **5-20** | Configuration ready (data collection methods documented) |

## Architecture

### Directory Structure
```
node_automation/
├── package.json          # Node.js package configuration
├── README.md            # This documentation
├── bin/
│   └── automation.js    # Main entry point
├── lib/
│   └── (utility modules)
└── scripts/
    └── (additional scripts)
```

### Integration with Framework
The automation package interfaces with the Dark Recon Framework through:

1. **Phase Mapping**: Each phase number (1-20) maps to specific reconnaissance capabilities
2. **Output Format**: Results are structured for integration with framework output directories
3. **Logging**: JSON-lines compatible logging for process.log integration
4. **Bridge Compatibility**: Designed to work with `lib/phase_bridge.py` for Python integration

## Technical Details

### Puppeteer Integration
The package uses Puppeteer to control headless Chrome for:
- Running web-based reconnaissance tools
- DOM analysis and technology detection
- Capturing screenshots and HTML snapshots
- Bypassing basic bot detection

### HTTP Analysis
Axios is used for:
- Wayback Machine API queries
- SSL/TLS certificate retrieval
- Headers and fingerprint collection
- Subdomain enumeration services

### DOM Analysis
JSDOM enables:
- CMS detection (WordPress, Joomla, Drupal)
- JavaScript framework identification (React, Vue, Angular)
- Meta tag and structure analysis
- Script and stylesheet inventory

## Development

### Adding New Phases
To add support for additional phases:

1. Edit `bin/automation.js` to add a case statement in `runPipeline()`
2. Implement the execution function (e.g., `executeSubdomainEnum()`)
3. Update `PHASE_CAPABILITIES` with the new phase details
4. Add any required dependencies to `package.json`

### Testing
```bash
# Run a quick test
node bin/automation.js example.com 1

# Verify output structure
ls output/example.com/recon_*/
```

## License
MIT License - see the LICENSE file in the root framework directory for details.

## Credits
Created by **DarkLegende** as part of the Dark Recon Framework v4 initiative.
Integrates tools and methodologies from the security community including ProjectDiscovery, tomnomnom, hakluke, and many others.