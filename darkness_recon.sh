#!/bin/bash

# Darkness Recon: Ultimate Subdomain Enumeration, Reconnaissance, and Scanning Script
# Made by DarkLegende
# Requirements: Install tools (subfinder, assetfinder, amass, findomain, sublist3r, gobuster, waybackurls, waymore, gauplus, httpx, katana, dnsx, puredns, dnsrecon, altdns, shuffledns, haktrails, dnsgen, ctfr, knockpy, cero, bhedak, bbot, spiderfoot, gospider, hakrawler, paramspider, gf, ffuf, wafw00f, nuclei, subjack, subzy, nmap, masscan, naabu, dnsenum, sublert, dnsmap, aquatone, arjun, sdgo, cloud_enum, dirsearch, sslyze, commonspeak2, apiscope, whatweb, gitrob, dnsvalidator, trufflehog, ratelimitr, anew, unfurl, jq)
# Ensure SecLists wordlists and dnsvalidator resolvers are available
# Usage: ./darkness_recon.sh <domain> [--waf] [--nuclei] [--portscan] [--dirsearch] [--ssl] [--api] [--git] [--secrets]
# Example: ./darkness_recon.sh example.com --waf --nuclei --portscan --dirsearch --ssl --api --git --secrets

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain> [--waf] [--nuclei] [--portscan] [--dirsearch] [--ssl] [--api] [--git] [--secrets]"
    exit 1
fi

DOMAIN=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$DOMAIN/recon_$TIMESTAMP"
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
RESOLVERS="/path/to/resolvers.txt"  # Update with path to trusted resolvers
WEB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
CUSTOM_WORDLIST="$OUTPUT_DIR/fuzz/custom_wordlist.txt"
API_WORDLIST="/usr/share/seclists/Discovery/Web-Content/api/words.txt"
BASE_THREADS=150  # Base thread count; dynamically scaled
TIMEOUT=8         # Timeout for tools like amass (in minutes)
NMAP_SCRIPTS="/usr/share/nmap/scripts"  # Update with path to nmap scripts
MAX_RETRIES=2     # Retry count for flaky tools
RATE_LIMIT=1000   # Base rate limit for scans

# Parse optional flags
WAF_CHECK=false
NUCLEI_SCAN=false
PORT_SCAN=false
DIRSEARCH=false
SSL_CHECK=false
API_SCAN=false
GIT_SCAN=false
SECRETS_SCAN=false
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --waf) WAF_CHECK=true ;;
        --nuclei) NUCLEI_SCAN=true ;;
        --portscan) PORT_SCAN=true ;;
        --dirsearch) DIRSEARCH=true ;;
        --ssl) SSL_CHECK=true ;;
        --api) API_SCAN=true ;;
        --git) GIT_SCAN=true ;;
        --secrets) SECRETS_SCAN=true ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# Dynamic thread scaling based on CPU cores
CPU_CORES=$(nproc)
THREADS=$(( BASE_THREADS > CPU_CORES * 10 ? CPU_CORES * 10 : BASE_THREADS ))

# Create output directory structure
mkdir -p "$OUTPUT_DIR/subdomains" "$OUTPUT_DIR/live" "$OUTPUT_DIR/wayback" "$OUTPUT_DIR/js" "$OUTPUT_DIR/urls" "$OUTPUT_DIR/screenshots" "$OUTPUT_DIR/takeovers" "$OUTPUT_DIR/waf" "$OUTPUT_DIR/nuclei" "$OUTPUT_DIR/fuzz" "$OUTPUT_DIR/endpoints" "$OUTPUT_DIR/gf" "$OUTPUT_DIR/ports" "$OUTPUT_DIR/params" "$OUTPUT_DIR/dns" "$OUTPUT_DIR/cloud" "$OUTPUT_DIR/dirsearch" "$OUTPUT_DIR/ssl" "$OUTPUT_DIR/api" "$OUTPUT_DIR/git" "$OUTPUT_DIR/secrets"

# Initialize output files
SUBDOMAINS_FILE="$OUTPUT_DIR/subdomains/all_subdomains.txt"
LIVE_SUBDOMAINS_FILE="$OUTPUT_DIR/live/live_subdomains.txt"
WAYBACK_FILE="$OUTPUT_DIR/wayback/wayback_urls.txt"
JS_FILES="$OUTPUT_DIR/js/js_files.txt"
URLS_FILE="$OUTPUT_DIR/urls/all_urls.txt"
PARAMS_FILE="$OUTPUT_DIR/urls/params.txt"
PARAM_KEYS_FILE="$OUTPUT_DIR/urls/param_keys.txt"
ENDPOINTS_FILE="$OUTPUT_DIR/endpoints/endpoints.txt"
GF_PATTERNS_DIR="$OUTPUT_DIR/gf"
TAKEOVER_FILE="$OUTPUT_DIR/takeovers/potential_takeovers.txt"
WAF_FILE="$OUTPUT_DIR/waf/waf_results.txt"
NUCLEI_FILE="$OUTPUT_DIR/nuclei/nuclei_results.txt"
FUZZ_FILE="$OUTPUT_DIR/fuzz/ffuf_results.txt"
PORTSCAN_FILE="$OUTPUT_DIR/ports/portscan_results.txt"
ARJUN_FILE="$OUTPUT_DIR/params/arjun_params.txt"
DNS_RECORDS_FILE="$OUTPUT_DIR/dns/dns_records.txt"
CLOUD_ASSETS_FILE="$OUTPUT_DIR/cloud/cloud_assets.txt"
DIRSEARCH_FILE="$OUTPUT_DIR/dirsearch/dirsearch_results.txt"
SSL_FILE="$OUTPUT_DIR/ssl/sslyze_results.txt"
API_FILE="$OUTPUT_DIR/api/apiscope_results.txt"
GIT_FILE="$OUTPUT_DIR/git/gitrob_results.txt"
SECRETS_FILE="$OUTPUT_DIR/secrets/trufflehog_results.txt"
FINAL_OUTPUT="$OUTPUT_DIR/final_output.txt"

# Glowing signature
echo -e "\033[1;35m"
echo "===================================================================="
echo "          Darkness Recon - Made by DarkLegende                     "
echo "===================================================================="
echo -e "\033[0m"

# Log start
echo "[*] Starting Darkness Recon for $DOMAIN at $TIMESTAMP (Threads: $THREADS)"

# Function to check if a tool is available
check_tool() {
    command -v "$1" >/dev/null && return 0 || { echo "[!] $1 not found, skipping..."; return 1; }
}

# Function to update resolvers dynamically
update_resolvers() {
    if check_tool dnsvalidator; then
        echo "[*] Updating resolvers with dnsvalidator..."
        dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o "$RESOLVERS" >/dev/null 2>&1
        [ -s "$RESOLVERS" ] || { echo "[!] Resolver update failed, using default resolvers"; return 1; }
    else
        echo "[!] dnsvalidator not found, using existing resolvers"
    fi
}

# Step 1: Update Resolvers
update_resolvers

# Step 2: Generate Custom Wordlist with Commonspeak2
echo "[*] Generating custom wordlist with commonspeak2..."
check_tool commonspeak2 && commonspeak2 -t subdomains -o "$CUSTOM_WORDLIST" -d "$DOMAIN" -l 2000 -p
[ -s "$CUSTOM_WORDLIST" ] || cp "$WEB_WORDLIST" "$CUSTOM_WORDLIST"  # Fallback to default wordlist

# Step 3: Rate-Limit Detection
echo "[*] Detecting rate limits with ratelimitr..."
check_tool ratelimitr && {
    RATE_LIMIT=$(ratelimitr -u "https://$DOMAIN" -t "$THREADS" -o "$OUTPUT_DIR/ratelimit.txt" | grep -oE '[0-9]+' | head -n 1)
    [ -n "$RATE_LIMIT" ] && RATE_LIMIT=$(( RATE_LIMIT > 1000 ? 1000 : RATE_LIMIT )) || RATE_LIMIT=1000
    echo "[*] Adjusted rate limit: $RATE_LIMIT"
}

# Step 4: Subdomain Enumeration with Maximum Tools (Parallelized)
echo "[*] Enumerating subdomains with multiple tools..."
{
    check_tool subfinder && subfinder -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/subfinder.txt" -silent -all -t "$THREADS" -timeout 20 -recursive -nW -nC -es crtsh,wayback,alienvault,securitytrails -r "$RESOLVERS" -retry "$MAX_RETRIES" &
    check_tool assetfinder && assetfinder --subs-only "$DOMAIN" | grep -E "^[a-zA-Z0-9.-]+\.$DOMAIN$" > "$OUTPUT_DIR/subdomains/assetfinder.txt" &
    check_tool amass && amass enum -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/amass.txt" -timeout "$TIMEOUT" -no-alts -passive -brute -config /path/to/amass-config.ini -src -r "$RESOLVERS" -rf "$RESOLVERS" &
    check_tool findomain && findomain -t "$DOMAIN" --quiet -u "$OUTPUT_DIR/subdomains/findomain.txt" --threads "$THREADS" --resolvers "$RESOLVERS" &
    check_tool sublist3r && sublist3r -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/sublist3r.txt" -t "$THREADS" -n | sed 's/\x1B\[[0-9;]*[JKmsu]//g' &
    check_tool gobuster && gobuster dns -d "$DOMAIN" -w "$WORDLIST" -o "$OUTPUT_DIR/subdomains/gobuster.txt" --quiet -t "$THREADS" --delay 10ms --wildcard --resolvers "$RESOLVERS" &
    check_tool curl && curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | grep -E "^[a-zA-Z0-9.-]+\.$DOMAIN$" | sort -u > "$OUTPUT_DIR/subdomains/crtsh.txt" &
    check_tool dnsx && dnsx -d "$DOMAIN" -w "$WORDLIST" -r "$RESOLVERS" -o "$OUTPUT_DIR/subdomains/dnsx.txt" -silent -t "$THREADS" -resp -retry "$MAX_RETRIES" -rl "$RATE_LIMIT" &
    check_tool puredns && puredns bruteforce "$WORDLIST" "$DOMAIN" -r "$RESOLVERS" -w "$OUTPUT_DIR/subdomains/puredns.txt" --threads "$THREADS" --rate-limit "$RATE_LIMIT" --wildcard-batch 100000 --bin /usr/bin/dnsx &
    check_tool dnsrecon && dnsrecon -d "$DOMAIN" -t brt -D "$WORDLIST" -f --threads "$THREADS" --lifetime 20 --db "$OUTPUT_DIR/subdomains/dnsrecon.db" > "$OUTPUT_DIR/subdomains/dnsrecon.txt" &
    check_tool altdns && altdns -i "$DOMAIN" -w "$WORDLIST" -o "$OUTPUT_DIR/subdomains/altdns.txt" -t "$THREADS" -r -s "$OUTPUT_DIR/subdomains/altdns_resolved.txt" &
    check_tool shuffledns && shuffledns -d "$DOMAIN" -w "$WORDLIST" -r "$RESOLVERS" -o "$OUTPUT_DIR/subdomains/shuffledns.txt" -t "$THREADS" -mode bruteforce -retry "$MAX_RETRIES" -rl "$RATE_LIMIT" &
    check_tool haktrails && haktrails subdomains -d "$DOMAIN" -t "$THREADS" > "$OUTPUT_DIR/subdomains/haktrails.txt" &
    check_tool dnsgen && echo "$DOMAIN" | dnsgen -w "$WORDLIST" -t "$THREADS" -f > "$OUTPUT_DIR/subdomains/dnsgen.txt" &
    check_tool ctfr && ctfr -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/ctfr.txt" &
    check_tool knockpy && knockpy "$DOMAIN" --no-http -t "$THREADS" -r "$RESOLVERS" | jq -r '.[] | select(.type == "A") | .domain' > "$OUTPUT_DIR/subdomains/knockpy.txt" &
    check_tool cero && cero -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/cero.txt" -c "$THREADS" -r "$RESOLVERS" &
    check_tool bhedak && bhedak -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/bhedak.txt" -r "$RESOLVERS" &
    check_tool dnsenum && dnsenum --dnsserver "$(head -n 1 "$RESOLVERS")" --enum -f "$WORDLIST" --threads "$THREADS" "$DOMAIN" --noreverse --timeout 20 --res "$RESOLVERS" > "$OUTPUT_DIR/subdomains/dnsenum.txt" &
    check_tool sublert && sublert -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/sublert.txt" &
    check_tool dnsmap && dnsmap "$DOMAIN" -w "$WORDLIST" -r "$OUTPUT_DIR/subdomains/dnsmap.txt" --threads "$THREADS" --res "$RESOLVERS" &
    check_tool sdgo && sdgo -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/sdgo.txt" -t "$THREADS" -w "$WORDLIST" -r "$RESOLVERS" &
    wait
}
echo "[*] Subdomain enumeration completed"

# Combine and deduplicate subdomains
echo "[*] Combining and deduplicating subdomains..."
cat "$OUTPUT_DIR/subdomains/"*.txt | grep -vE '^$' | grep -E "^[a-zA-Z0-9.-]+\.$DOMAIN$" | sort -u | anew > "$SUBDOMAINS_FILE"
echo "[*] Total subdomains found: $(wc -l < "$SUBDOMAINS_FILE")"

# Step 5: AI-Powered Reconnaissance
echo "[*] Running AI-powered reconnaissance..."
{
    check_tool bbot && bbot -t "$DOMAIN" -f subdomain-enum -o "$OUTPUT_DIR/subdomains/bbot.txt" --no-interactive --force --quiet --output-module raw --config /path/to/bbot-config.yml --threads "$THREADS" &
    check_tool spiderfoot && spiderfoot -s "$DOMAIN" -m sfp_subdomains,sfp_dnsresolve,sfp_spider,sfp_portscan -o json > "$OUTPUT_DIR/subdomains/spiderfoot.json" && jq -r '.[] | select(.type == "DNS Name") | .data' "$OUTPUT_DIR/subdomains/spiderfoot.json" > "$OUTPUT_DIR/subdomains/spiderfoot.txt" &
    wait
}
cat "$OUTPUT_DIR/subdomains/bbot.txt" "$OUTPUT_DIR/subdomains/spiderfoot.txt" 2>/dev/null | grep -vE '^$' | grep -E "^[a-zA-Z0-9.-]+\.$DOMAIN$" | sort -u | anew "$SUBDOMAINS_FILE"
echo "[*] Updated total subdomains after AI recon: $(wc -l < "$SUBDOMAINS_FILE")"

# Step 6: DNS Record Analysis
echo "[*] Analyzing DNS records with dnsx..."
check_tool dnsx && cat "$SUBDOMAINS_FILE" | dnsx -silent -a -aaaa -cname -mx -ns -txt -srv -ptr -resp -o "$DNS_RECORDS_FILE" -t "$THREADS" -r "$RESOLVERS" -retry "$MAX_RETRIES" -rl "$RATE_LIMIT"
echo "[*] DNS records saved to $DNS_RECORDS_FILE"

# Step 7: Cloud Asset Detection
echo "[*] Detecting cloud assets with cloud_enum..."
check_tool cloud_enum && cloud_enum -k "$DOMAIN" -t "$THREADS" -o "$CLOUD_ASSETS_FILE" --disable-brute --quickscan --timeout 15
echo "[*] Cloud assets saved to $CLOUD_ASSETS_FILE"

# Step 8: Resolve and Find Live Subdomains
echo "[*] Checking for live subdomains with httpx..."
check_tool httpx && cat "$SUBDOMAINS_FILE" | httpx -silent -o "$LIVE_SUBDOMAINS_FILE" -sc -cl -ct -location -title -method -server -tech-detect -t "$THREADS" -timeout 10 -follow-redirects -ip -no-fallback -probe-all-ips -random-agent -include-response -retry "$MAX_RETRIES" -rl "$RATE_LIMIT"
echo "[*] Total live subdomains: $(wc -l < "$LIVE_SUBDOMAINS_FILE")"

# Step 9: Technology Fingerprinting with WhatWeb
echo "[*] Fingerprinting technologies with WhatWeb..."
check_tool whatweb && cat "$LIVE_SUBDOMAINS_FILE" | whatweb -a 3 --no-errors -t "$THREADS" --log-json "$OUTPUT_DIR/live/whatweb.json"
check_tool jq && jq -r '.[] | "\(.target) \(.plugins)"' "$OUTPUT_DIR/live/whatweb.json" 2>/dev/null > "$OUTPUT_DIR/live/whatweb.txt"
echo "[*] Technology fingerprinting results saved to $OUTPUT_DIR/live/whatweb.txt"

# Step 10: Port Scanning (Optional)
if [ "$PORT_SCAN" = true ]; then
    echo "[*] Performing port scanning with nmap, masscan, and naabu..."
    {
        # Prepare IP list
        check_tool httpx && cat "$LIVE_SUBDOMAINS_FILE" | httpx -silent -ip | awk '{print $NF}' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | sort -u > "$OUTPUT_DIR/ports/ips.txt"

        # Advanced nmap scan
        check_tool nmap && nmap -iL "$OUTPUT_DIR/ports/ips.txt" -T4 --top-ports 1000 -sV -sC --script "banner,http-title,vuln,http-headers,http-enum,http-auth-finder,ssl-cert,http-methods,dns-brute" -oN "$OUTPUT_DIR/ports/nmap.txt" -Pn --min-rate 2500 --open --defeat-rst-ratelimit --script-timeout 30s &

        # Masscan for ultra-fast port discovery
        check_tool masscan && masscan -iL "$OUTPUT_DIR/ports/ips.txt" -p1-65535 --rate 30000 --open-only -oG "$OUTPUT_DIR/ports/masscan.txt" --banners --wait 0 --max-rate "$RATE_LIMIT" &

        # Naabu for lightweight port scanning
        check_tool naabu && naabu -list "$OUTPUT_DIR/ports/ips.txt" -top-ports 1000 -silent -t "$THREADS" -o "$OUTPUT_DIR/ports/naabu.txt" -nmap-cli 'nmap -sV -sC --script vuln' -rate "$RATE_LIMIT" -retries "$MAX_RETRIES" &
        wait
    }
    cat "$OUTPUT_DIR/ports/nmap.txt" "$OUTPUT_DIR/ports/masscan.txt" "$OUTPUT_DIR/ports/naabu.txt" 2>/dev/null | grep -vE '^$' | sort -u > "$PORTSCAN_FILE"
    echo "[*] Port scan results saved to $PORTSCAN_FILE"
fi

# Step 11: Check for Subdomain Takeovers
echo "[*] Checking for subdomain takeovers with Subjack and Subzy..."
{
    check_tool subjack && subjack -w "$SUBDOMAINS_FILE" -a -o "$OUTPUT_DIR/takeovers/subjack.txt" -t "$THREADS" -timeout 15 -ssl -c /path/to/subjack-fingerprints.json -m -v &
    check_tool subzy && subzy run --targets "$SUBDOMAINS_FILE" --timeout 15 --concurrency "$THREADS" --hide_fails --verify_ssl --output "$OUTPUT_DIR/takeovers/subzy.txt" --retry "$MAX_RETRIES" &
    wait
}
cat "$OUTPUT_DIR/takeovers/subjack.txt" "$OUTPUT_DIR/takeovers/subzy.txt" 2>/dev/null | grep -vE '^$' | sort -u | anew > "$TAKEOVER_FILE"
echo "[*] Potential takeovers saved to $TAKEOVER_FILE"

# Step 12: Fetch Historical URLs
echo "[*] Fetching historical URLs..."
{
    check_tool waybackurls && cat "$SUBDOMAINS_FILE" | waybackurls > "$OUTPUT_DIR/wayback/waybackurls.txt" &
    check_tool waymore && waymore -i "$DOMAIN" -mode U -oU "$OUTPUT_DIR/wayback/waymore.txt" -t "$THREADS" -no-subs -timeout 15 -include-response -limit 20000 -filter-response 200,301,302 &
    check_tool gauplus && cat "$SUBDOMAINS_FILE" | gauplus --random-agent --subs --threads "$THREADS" --timeout 15 --blacklist png,jpg,gif,css,woff,ttf --retries "$MAX_RETRIES" > "$OUTPUT_DIR/wayback/gauplus.txt" &
    wait
}
cat "$OUTPUT_DIR/wayback/"*.txt | grep -vE '^$' | sort -u | anew > "$WAYBACK_FILE"
echo "[*] Total Wayback URLs: $(wc -l < "$WAYBACK_FILE")"

# Step 13: Extract JavaScript Files
echo "[*] Extracting JavaScript files..."
cat "$WAYBACK_FILE" | grep -E '\.js(\?.*)?$' | sort -u > "$JS_FILES"
check_tool httpx && cat "$JS_FILES" | httpx -silent -mc 200 -o "$OUTPUT_DIR/js/live_js_files.txt" -t "$THREADS" -timeout 10 -random-agent -include-response -fr -retry "$MAX_RETRIES" -rl "$RATE_LIMIT"
echo "[*] Total JS files found: $(wc -l < "$JS_FILES")"
echo "[*] Live JS files: $(wc -l < "$OUTPUT_DIR/js/live_js_files.txt")"

# Step 14: Extract URLs with Parameters
echo "[*] Extracting URLs with parameters..."
cat "$WAYBACK_FILE" | grep -E '\?.*=' | sort -u | anew > "$PARAMS_FILE"
check_tool unfurl && cat "$PARAMS_FILE" | unfurl -u keys | sort -u > "$PARAM_KEYS_FILE"
echo "[*] Total URLs with parameters: $(wc -l < "$PARAMS_FILE")"

# Step 15: Parameter Discovery with Arjun
echo "[*] Discovering parameters with Arjun..."
check_tool arjun && cat "$LIVE_SUBDOMAINS_FILE" | arjun -t "$THREADS" -o "$ARJUN_FILE" --stable -T 15 -m GET,POST,JSON -c 50 -w "$API_WORDLIST" --delay 0.5
echo "[*] Arjun parameter results saved to $ARJUN_FILE"

# Step 16: Crawl Live Subdomains for Endpoints
echo "[*] Crawling live subdomains for endpoints..."
{
    check_tool katana && katana -u "$LIVE_SUBDOMAINS_FILE" -o "$OUTPUT_DIR/endpoints/katana.txt" -js -d 6 -c "$THREADS" -timeout 15 -automatic-form-fill -ef json,css,png,jpg,gif,woff,ttf -silent -xhr -retry "$MAX_RETRIES" -rl "$RATE_LIMIT" &
    check_tool gospider && gospider -S "$LIVE_SUBDOMAINS_FILE" -o "$OUTPUT_DIR/endpoints/gospider" -t "$THREADS" --robots --sitemap --timeout 15 --depth 6 --random-agent --blacklist "\.(png|jpg|gif|css|woff|ttf)$" --include-subs &
    check_tool hakrawler && cat "$LIVE_SUBDOMAINS_FILE" | hakrawler -d 6 -t "$THREADS" -plain -usewayback -all > "$OUTPUT_DIR/endpoints/hakrawler.txt" &
    check_tool paramspider && paramspider -l "$LIVE_SUBDOMAINS_FILE" -o "$OUTPUT_DIR/endpoints/paramspider.txt" --timeout 15 --level high --exclude png,jpg,gif,css,woff,ttf --crawl &
    wait
}
cat "$OUTPUT_DIR/endpoints/"*.txt "$OUTPUT_DIR/endpoints/gospider/"*.txt 2>/dev/null | grep -vE '^$' | sort -u | anew > "$ENDPOINTS_FILE"
echo "[*] Total endpoints found: $(wc -l < "$ENDPOINTS_FILE")"

# Step 17: API Endpoint Discovery (Optional)
if [ "$API_SCAN" = true ]; then
    echo "[*] Discovering API endpoints with apiscope..."
    check_tool apiscope && cat "$LIVE_SUBDOMAINS_FILE" | apiscope -o "$API_FILE" -t "$THREADS" -w "$API_WORDLIST" --depth 5 --timeout 15 --random-agent --retry "$MAX_RETRIES"
    echo "[*] API endpoint results saved to $API_FILE"
fi

# Step 18: Fuzzing with ffuf
echo "[*] Fuzzing live subdomains with ffuf..."
check_tool ffuf && cat "$LIVE_SUBDOMAINS_FILE" | while read -r sub; do
    ffuf -u "$sub/FUZZ" -w "$CUSTOM_WORDLIST" -o "$OUTPUT_DIR/fuzz/ffuf_$(echo "$sub" | tr '/' '_').json" -t "$THREADS" -mc 200,301,302,403 -timeout 8 -silent -ac -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -recursion -recursion-depth 3 -rl "$RATE_LIMIT" -retry "$MAX_RETRIES"
done
check_tool jq && jq -r '.results[] | "\(.url) [\(.status)]"' "$OUTPUT_DIR/fuzz/"*.json 2>/dev/null | sort -u > "$FUZZ_FILE"
echo "[*] Fuzzing results saved to $FUZZ_FILE"

# Step 19: Directory Brute-Forcing with dirsearch (Optional)
if [ "$DIRSEARCH" = true ]; then
    echo "[*] Performing directory brute-forcing with dirsearch..."
    check_tool dirsearch && cat "$LIVE_SUBDOMAINS_FILE" | while read -r sub; do
        dirsearch -u "$sub" -e php,asp,aspx,js,html,py -w "$CUSTOM_WORDLIST" -t "$THREADS" -o "$OUTPUT_DIR/dirsearch/dirsearch_$(echo "$sub" | tr '/' '_').txt" --format plain -r -R 3 --timeout 10 --random-agent --exclude-status 429,503 --rl "$RATE_LIMIT"
    done
    cat "$OUTPUT_DIR/dirsearch/"*.txt 2>/dev/null | grep -vE '^$' | sort -u > "$DIRSEARCH_FILE"
    echo "[*] Dirsearch results saved to $DIRSEARCH_FILE"
fi

# Step 20: Git Repository Scanning (Optional)
if [ "$GIT_SCAN" = true ]; then
    echo "[*] Scanning for Git repositories with gitrob..."
    check_tool gitrob && gitrob -domain "$DOMAIN" -threads "$THREADS" -output "$GIT_FILE" --no-auth --timeout 15
    echo "[*] Git repository results saved to $GIT_FILE"
fi

# Step 21: Secret Scanning with TruffleHog (Optional)
if [ "$SECRETS_SCAN" = true ]; then
    echo "[*] Scanning for secrets with trufflehog..."
    check_tool trufflehog && {
        cat "$JS_FILES" "$ENDPOINTS_FILE" "$WAYBACK_FILE" | trufflehog --regex --entropy --json > "$SECRETS_FILE"
        echo "[*] Secret scanning results saved to $SECRETS_FILE"
    }
fi

# Step 22: Pattern Matching with gf
echo "[*] Running gf for pattern matching..."
check_tool gf && {
    mkdir -p "$GF_PATTERNS_DIR"
    for pattern in xss sqli lfi rce redirect secrets aws-keys firebase debug-pages cors ssrf oauth api-keys jwt; do
        cat "$ENDPOINTS_FILE" "$WAYBACK_FILE" "$PARAMS_FILE" "$API_FILE" 2>/dev/null | gf "$pattern" | sort -u > "$GF_PATTERNS_DIR/$pattern.txt"
        echo "[*] Found $(wc -l < "$GF_PATTERNS_DIR/$pattern.txt") $pattern patterns"
    done
}

# Step 23: Visual Recon with Aquatone
echo "[*] Capturing visual reconnaissance with Aquatone..."
check_tool aquatone && cat "$LIVE_SUBDOMAINS_FILE" | aquatone -out "$OUTPUT_DIR/screenshots/aquatone" -threads "$THREADS" -ports large -scan-timeout 8000 -http-timeout 10000 -screenshot-timeout 30000 -chrome-path /usr/bin/chromium
echo "[*] Aquatone screenshots saved to $OUTPUT_DIR/screenshots/aquatone"

# Step 24: Optional WAF Detection
if [ "$WAF_CHECK" = true ]; then
    echo "[*] Performing WAF detection with wafw00f..."
    check_tool wafw00f && wafw00f -i "$LIVE_SUBDOMAINS_FILE" -o "$WAF_FILE" -j -t "$THREADS" --format json --no-passive --retry "$MAX_RETRIES"
    echo "[*] WAF detection results saved to $WAF_FILE"
fi

# Step 25: Optional Nuclei Vulnerability Scan
if [ "$NUCLEI_SCAN" = true ]; then
    echo "[*] Running Nuclei vulnerability scan..."
    check_tool nuclei && nuclei -list "$LIVE_SUBDOMAINS_FILE" -o "$NUCLEI_FILE" -t "$THREADS" -severity critical,high,medium,low -silent -timeout 15 -concurrency "$THREADS" -bulk-size 100 -retries "$MAX_RETRIES" -rl "$RATE_LIMIT" -es info -fr -etags network,cloud
    echo "[*] Nuclei scan results saved to $NUCLEI_FILE"
fi

# Step 26: SSL/TLS Analysis (Optional)
if [ "$SSL_CHECK" = true ]; then
    echo "[*] Performing SSL/TLS analysis with sslyze..."
    check_tool sslyze && cat "$LIVE_SUBDOMAINS_FILE" | while read -r sub; do
        sslyze --regular --certinfo --compression --heartbleed --openssl_ccs --reneg --resum --http_headers --elliptic_curves --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 "$sub" --json_out "$OUTPUT_DIR/ssl/sslyze_$(echo "$sub" | tr '/' '_').json"
    done
    check_tool jq && jq -r '.' "$OUTPUT_DIR/ssl/"*.json 2>/dev/null > "$SSL_FILE"
    echo "[*] SSL/TLS results saved to $SSL_FILE"
fi

# Step 27: Capture Screenshots with EyeWitness
echo "[*] Capturing screenshots with EyeWitness..."
check_tool EyeWitness && EyeWitness -f "$LIVE_SUBDOMAINS_FILE" -d "$OUTPUT_DIR/screenshots/eyewitness" --web --threads "$THREADS" --timeout 15 --no-prompt --prepend-https --resolve
echo "[*] EyeWitness screenshots saved to $OUTPUT_DIR/screenshots/eyewitness"

# Step 28: Combine All URLs
echo "[*] Combining all URLs..."
cat "$WAYBACK_FILE" "$ENDPOINTS_FILE" "$FUZZ_FILE" "$DIRSEARCH_FILE" "$API_FILE" 2>/dev/null | grep -vE '^$' | sort -u | anew > "$URLS_FILE"
echo "[*] Total URLs found: $(wc -l < "$URLS_FILE")"

# Step 29: Combine All Results into Final Output
echo "[*] Creating final output file..."
{
    echo -e "\033[1;35m"
    echo "===================================================================="
    echo "          Darkness Recon - Made by DarkLegende                     "
    echo "===================================================================="
    echo -e "\033[0m"
    echo "[*] Reconnaissance Results for $DOMAIN"
    echo "Timestamp: $TIMESTAMP"
    echo "Total Subdomains: $(wc -l < "$SUBDOMAINS_FILE")"
    echo "Live Subdomains: $(wc -l < "$LIVE_SUBDOMAINS_FILE")"
    echo "JavaScript Files: $(wc -l < "$JS_FILES")"
    echo "Live JavaScript Files: $(wc -l < "$OUTPUT_DIR/js/live_js_files.txt")"
    echo "URLs with Parameters: $(wc -l < "$PARAMS_FILE")"
    echo "Endpoints: $(wc -l < "$ENDPOINTS_FILE")"
    echo "Fuzzing Results: $(wc -l < "$FUZZ_FILE")"
    [ "$DIRSEARCH" = true ] && echo "Dirsearch Results: $(wc -l < "$DIRSEARCH_FILE")"
    [ "$API_SCAN" = true ] && echo "API Endpoints: $(wc -l < "$API_FILE")"
    echo "Parameter Discovery (Arjun): $(wc -l < "$ARJUN_FILE")"
    echo "DNS Records: $(wc -l < "$DNS_RECORDS_FILE")"
    echo "Cloud Assets: $(wc -l < "$CLOUD_ASSETS_FILE")"
    echo "Technology Fingerprinting: $(wc -l < "$OUTPUT_DIR/live/whatweb.txt")"
    echo "Potential Takeovers: $(wc -l < "$TAKEOVER_FILE")"
    [ "$GIT_SCAN" = true ] && echo "Git Repositories: $(wc -l < "$GIT_FILE")"
    [ "$SECRETS_SCAN" = true ] && echo "Secrets Found: $(wc -l < "$SECRETS_FILE")"
    [ "$PORT_SCAN" = true ] && echo "Port Scan Results: $(wc -l < "$PORTSCAN_FILE")"
    [ "$WAF_CHECK" = true ] && echo "WAF Detection Results: $(wc -l < "$WAF_FILE")"
    [ "$NUCLEI_SCAN" = true ] && echo "Nuclei Scan Results: $(wc -l < "$NUCLEI_FILE")"
    [ "$SSL_CHECK" = true ] && echo "SSL/TLS Results: $(wc -l < "$SSL_FILE")"
    echo -e "\n[*] Live Subdomains:"
    cat "$LIVE_SUBDOMAINS_FILE"
    echo -e "\n[*] Technology Fingerprinting:"
    cat "$OUTPUT_DIR/live/whatweb.txt"
    echo -e "\n[*] DNS Records:"
    cat "$DNS_RECORDS_FILE"
    echo -e "\n[*] Cloud Assets:"
    cat "$CLOUD_ASSETS_FILE"
    echo -e "\n[*] JavaScript Files:"
    cat "$JS_FILES"
    echo -e "\n[*] Live JavaScript Files:"
    cat "$OUTPUT_DIR/js/live_js_files.txt" 2>/dev/null
    echo -e "\n[*] URLs with Parameters:"
    cat "$PARAMS_FILE"
    echo -e "\n[*] Parameter Keys:"
    cat "$PARAM_KEYS_FILE" 2>/dev/null
    echo -e "\n[*] Arjun Parameter Discovery:"
    cat "$ARJUN_FILE"
    echo -e "\n[*] Endpoints:"
    cat "$ENDPOINTS_FILE"
    [ "$API_SCAN" = true ] && { echo -e "\n[*] API Endpoints:"; cat "$API_FILE"; }
    echo -e "\n[*] Fuzzing Results:"
    cat "$FUZZ_FILE"
    [ "$DIRSEARCH" = true ] && { echo -e "\n[*] Dirsearch Results:"; cat "$DIRSEARCH_FILE"; }
    echo -e "\n[*] Potential Takeovers:"
    cat "$TAKEOVER_FILE"
    [ "$GIT_SCAN" = true ] && { echo -e "\n[*] Git Repositories:"; cat "$GIT_FILE"; }
    [ "$SECRETS_SCAN" = true ] && { echo -e "\n[*] Secrets Found:"; cat "$SECRETS_FILE"; }
    [ "$PORT_SCAN" = true ] && { echo -e "\n[*] Port Scan Results:"; cat "$PORTSCAN_FILE"; }
    [ -d "$GF_PATTERNS_DIR" ] && {
        echo -e "\n[*] GF Pattern Matches:"
        for pattern in "$GF_PATTERNS_DIR"/*.txt; do
            [ -f "$pattern" ] && {
                echo -e "\n[*] $(basename "$pattern" .txt):"
                cat "$pattern"
            }
        done
    }
    [ "$WAF_CHECK" = true ] && { echo -e "\n[*] WAF Detection Results:"; cat "$WAF_FILE"; }
    [ "$NUCLEI_SCAN" = true ] && { echo -e "\n[*] Nuclei Scan Results:"; cat "$NUCLEI_FILE"; }
    [ "$SSL_CHECK" = true ] && { echo -e "\n[*] SSL/TLS Results:"; cat "$SSL_FILE"; }
} > "$FINAL_OUTPUT"

echo "[*] Darkness Recon completed. Results saved in $OUTPUT_DIR"
echo "[*] Final output: $FINAL_OUTPUT"
echo "[*] Screenshots: $OUTPUT_DIR/screenshots"
echo "[*] GF Patterns: $GF_PATTERNS_DIR"
echo "[*] Port Scan Results: $PORTSCAN_FILE"
echo "[*] Dirsearch Results: $DIRSEARCH_FILE"
echo "[*] API Endpoints: $API_FILE"
echo "[*] Git Repositories: $GIT_FILE"
echo "[*] Secrets: $SECRETS_FILE"
echo "[*] SSL/TLS Results: $SSL_FILE"
echo -e "\033[1;35m"
echo "===================================================================="
echo "          Darkness Recon - Made by DarkLegende                     "
echo "===================================================================="
echo -e "\033[0m"
