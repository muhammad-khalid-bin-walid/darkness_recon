# Dark Recon Framework — FAQ

## General

### What is Dark Recon?
Dark Recon is an automated security reconnaissance framework with 300 phases across 22 tracks. It discovers assets, identifies vulnerabilities, validates findings, and generates reports for bug bounty submissions and security assessments.

### What languages is it built in?
- **Shell (Bash):** Phase scripts, orchestration, tool wrappers
- **Python:** Data schema, validation, scoring, correlation, ML analysis
- **JSON:** Configuration, findings storage, structured output

### Does it require root/admin?
No. All phases run as a regular user. Some optional phases (raw port scanning) benefit from elevated privileges but degrade gracefully without them.

### How do I install it?
```bash
git clone <repo>
cd dark_recon_framework
pip install -r requirements.txt
# Optional: install security tools (nmap, nuclei, subfinder, etc.)
bash core/core.sh --check-health
```

### What tools does it use?
20+ integrated tools: subfinder, amass, httpx, nuclei, nmap, nikto, sqlmap, gobuster, whatweb, theHarvester, and more. See `tool_registry.py` for the full list.

---

## Configuration

### How do I set a target?
```bash
./dark_recon.sh --target example.com
# or
source core/core.sh && run_scan example.com
```

### How do I configure scope?
Edit `config/scope.conf`:
```json
{
  "allowed_domains": ["example.com", "*.example.com"],
  "excluded_paths": ["/admin", "/internal"],
  "rate_limit": 10
}
```

### How do I enable/disable specific phases?
Edit `phases/phase_manager.sh` — set `PHASE_ENABLED[phase_name]=0` to disable.

### Where is output stored?
`output/{target}/recon_{timestamp}/` — each phase writes to its own subdirectory.

---

## Performance

### How do I speed up a scan?
1. Disable expensive phases you don't need: `PHASE_ENABLED[fuzz]=0`
2. Reduce scan depth: `--depth quick`
3. Use checkpoint resume: interrupted phases resume where they left off
4. Limit parallel workers: `--workers 4`

### How does checkpoint/resume work?
Each phase saves state before and after execution. If a run is interrupted:
```bash
./dark_recon.sh --target example.com --resume
```
Completed phases are skipped, incomplete phases restart from the last checkpoint.

### How do I run a single phase?
```bash
./dark_recon.sh --target example.com --phase nuclei
# or
./dark_recon.sh --target example.com --track 3
```

### What's the difference between --depth quick and --depth full?
- **quick:** Skips expensive phases (fuzzing, brute-force, deep crawling)
- **normal:** Default balanced mode
- **full:** All phases including time-intensive validation

---

## Findings

### How are findings scored?
Findings are scored using a confidence engine that weights:
- Tool reliability (known false-positive rates)
- Number of independent confirmations
- Evidence quality (screenshot > response > header)
- Time since last validation

### How does deduplication work?
Findings are deduplicated using normalized fingerprints:
- URL + parameter + vuln_class = unique finding
- Same vulnerability from multiple tools → single finding with higher confidence
- See `lib/dedup.py` for the algorithm

### How do I export findings?
```bash
./dark_recon.sh --target example.com --export sarif
./dark_recon.sh --target example.com --export csv
./dark_recon.sh --target example.com --export defectdojo
```

### Can I integrate with Jira/Linear?
Yes. Configure `config/integrations.conf`:
```json
{
  "jira": {"url": "...", "project": "SEC", "token": "..."},
  "linear": {"team": "...", "token": "..."}
}
```

---

## Troubleshooting

### A phase says "tool not found"
Install the required tool or enable graceful degradation:
```bash
# Check what's installed
bash core/core.sh --check-health

# Install missing tools
apt install nmap  # or brew install nmap
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Scan is running very slowly
1. Check network connectivity: `ping example.com`
2. Reduce rate limits in `config/scope.conf`
3. Disable WAF-detection phases if you're behind one
4. Check for rate limiting: look for 429 responses in logs

### Findings look like false positives
1. Check confidence level — only submit `confirmed` or `high` findings
2. Review evidence: `output/{target}/recon_{timestamp}/{phase}/findings.jsonl`
3. Manually verify using the provided PoC commands
4. Add to suppression list: `config/false_positives.conf`

### Phase crashed mid-execution
The framework isolates phase failures. Check:
```bash
cat output/{target}/recon_{timestamp}/{phase}/count.txt
# If count is 0 or missing, the phase failed
# Resume from checkpoint:
./dark_recon.sh --target example.com --resume
```

### How do I debug a specific phase?
```bash
# Dry run (shows what would execute)
./dark_recon.sh --target example.com --dry-run --phase nuclei

# Verbose mode
./dark_recon.sh --target example.com --phase nuclei --verbose

# Run phase directly
bash phases/nuclei_phase.sh example.com
```

### Schema validation is failing
Common causes:
- Missing required fields in findings JSON
- Invalid severity value (must be: critical/high/medium/low/info)
- Malformed JSON in output files
- Fix: `python lib/schema.py --validate output/{target}/`
