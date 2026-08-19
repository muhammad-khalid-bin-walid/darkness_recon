# Dark Recon Framework — Runbooks

## Runbook 1: Tool Not Found

**Symptoms:** Phase logs `ERROR: Required tool 'X' not found in PATH`

**Diagnosis:**
```bash
bash core/core.sh --check-health
which nmap subfinder nuclei httpx
```

**Resolution:**
```bash
# Debian/Ubuntu
apt update && apt install -y nmap

# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Verify
nmap --version && subfinder -version && nuclei -version
```

**Prevention:** Run `--check-health` before starting any scan.

---

## Runbook 2: Rate Limited (HTTP 429)

**Symptoms:** Phase logs many `429 Too Many Requests`, findings count is low

**Diagnosis:**
```bash
grep -r "429" output/{target}/recon_*/
grep -r "rate.limit" output/{target}/recon_*/
```

**Resolution:**
1. Reduce rate limit in `config/scope.conf`:
   ```json
   {"rate_limit": 5, "backoff_seconds": 30}
   ```
2. Enable proxy rotation if configured
3. Wait 5-10 minutes before retrying
4. Use `--resume` to continue from checkpoint

**Prevention:** Set conservative rate limits for unfamiliar targets.

---

## Runbook 3: Target Unreachable

**Symptoms:** Phase logs `ERROR: Connection refused` or `ERROR: DNS resolution failed`

**Diagnosis:**
```bash
ping -c 3 {target}
dig {target}
curl -I https://{target}
nslookup {target}
```

**Resolution:**
1. DNS failure → check target spelling, try IP directly
2. Connection refused → target may be down, retry in 15 min
3. Timeout → check firewall rules, try from different network
4. SSL error → check certificate validity

**Prevention:** Run a quick connectivity check before deep scanning.

---

## Runbook 4: Schema Validation Failed

**Symptoms:** `ERROR: Schema validation failed` in logs, findings not saved

**Diagnosis:**
```bash
python lib/schema.py --validate output/{target}/recon_{timestamp}/{phase}/
cat output/{target}/recon_{timestamp}/{phase}/findings.jsonl | head -5
```

**Resolution:**
1. Check for missing required fields (type, severity, domain)
2. Fix malformed JSON: `python -m json.tool file.json`
3. Check severity values: must be `critical`, `high`, `medium`, `low`, or `info`
4. Re-run the phase: `bash phases/{phase}_phase.sh {target}`

**Prevention:** All `write_finding` calls use the validated bridge.

---

## Runbook 5: Disk Space Issues

**Symptoms:** `ERROR: No space left on device`, partial output files

**Diagnosis:**
```bash
df -h
du -sh output/{target}/
find output/ -name "*.pcap" -o -name "*.har" | head -10
```

**Resolution:**
1. Clean old scan data: `rm -rf output/{old_target}/`
2. Remove large artifacts: `find output/ -name "*.pcap" -delete`
3. Compress old results: `tar -czf output/{target}.tar.gz output/{target}/`
4. Clear checkpoint cache: `rm -rf output/{target}/.checkpoints/`

**Prevention:** Run `--cleanup` after completing a scan.

---

## Runbook 6: Phase Crashed (Partial Results)

**Symptoms:** Phase count is 0 or very low, `ERROR` in phase logs

**Diagnosis:**
```bash
cat output/{target}/recon_{timestamp}/{phase}/count.txt
ls -la output/{target}/recon_{timestamp}/{phase}/
cat output/{target}/.checkpoints/{phase}.json
```

**Resolution:**
1. Check checkpoint state: should show `status: "running"` or `"failed"`
2. Partial results may still be valid — check what was collected
3. Resume: `./dark_recon.sh --target {target} --resume`
4. Or re-run just that phase: `bash phases/{phase}_phase.sh {target}`

**Prevention:** Phases save checkpoints before and after execution.

---

## Runbook 7: Memory/Resource Exhaustion

**Symptoms:** Process killed (OOM), system becomes unresponsive

**Diagnosis:**
```bash
free -m
top -bn1 | head -20
dmesg | grep -i "out of memory" | tail -5
```

**Resolution:**
1. Reduce parallel workers: `--workers 2`
2. Disable memory-intensive phases:
   ```bash
   PHASE_ENABLED[distributed]=0
   PHASE_ENABLED[ml_analysis]=0
   ```
3. Increase swap space
4. Run phases sequentially: `--sequential`

**Prevention:** Monitor resource usage during initial scans.

---

## Runbook 8: Network Timeout / DNS Issues

**Symptoms:** `ERROR: Connection timed out`, `ERROR: DNS resolution failed`

**Diagnosis:**
```bash
dig {target} @8.8.8.8
dig {target} @1.1.1.1
traceroute {target}
curl -v --connect-timeout 10 https://{target}
```

**Resolution:**
1. Try alternative DNS: add to `/etc/resolv.conf`
2. Increase timeouts in phase config
3. Check for DNS-based blocking (some networks block recon tools)
4. Use DNS-over-HTTPS if DNS is blocked

**Prevention:** Configure reliable DNS servers before scanning.

---

## Runbook 9: Findings Are All Low/Info Severity

**Symptoms:** All findings have low or info severity, no actionable vulnerabilities

**Diagnosis:**
```bash
cat output/{target}/recon_{timestamp}/findings.jsonl | python3 -c "
import json, sys
from collections import Counter
severities = Counter(json.loads(l).get('severity','?') for l in sys.stdin)
print(severities)
"
```

**Resolution:**
1. This is normal for well-hardened targets
2. Review info findings for potential chains
3. Ensure all active scanning phases are enabled
4. Check if rate limiting is blocking deeper tests
5. Try a different target or scope expansion

**Prevention:** Set realistic expectations based on target's security maturity.

---

## Runbook 10: Report Generation Failed

**Symptoms:** `ERROR` during report phase, no HTML/PDF output

**Diagnosis:**
```bash
ls -la output/{target}/recon_{timestamp}/reports/
cat output/{target}/recon_{timestamp}/reports/errors.log
```

**Resolution:**
1. Check required tools: `pandoc`, `wkhtmltopdf`, `python3-jinja2`
2. Verify findings file exists and is valid JSON
3. Generate manually: `bash phases/reporting_phase.sh {target}`
4. Check template files in `templates/` directory

**Prevention:** Run `--check-health` to verify report dependencies.
