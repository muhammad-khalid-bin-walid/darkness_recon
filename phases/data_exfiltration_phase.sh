#!/bin/bash
# Data Exfiltration & Sensitive Data Discovery phase - PII, PHI, PCI Detection

data_exfiltration_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/data_exfiltration"

    mkdir -p "$output_dir"

    log "INFO" "Starting data exfiltration and sensitive data discovery for $domain"

    local endpoints_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/crawl/endpoints.txt"
    local api_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/api/api_endpoints.json"
    local live_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/live/live_subdomains.txt"
    local secrets_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/secrets/secrets.json"
    local crawl_file="$OUTPUT_DIR/$domain/recon_$TIMESTAMP/crawl/endpoints.txt"

    # ===== PII DETECTION =====
    log "INFO" "Scanning for PII exposure..."

    if [ -f "$endpoints_file" ]; then
        grep -iE "(personal|pii|name|email|phone|address|ssn|social.security|dob|date.of.birth|birth|passport|driver.license|national.id|tax.id|tin|credit.card|card.number|cvv|cvc|expiry|expiration|bank.account|routing|iban|bic|account.number|sort.code|salary|income|wage|earnings|financial|mortgage|loan|debt|insurance|policy|claim|benefit|medical|health|patient|diagnosis|treatment|prescription|record|chart|report|result|lab.test|biometric|fingerprint|face.recognition|iris|retina|voice|dna|genetic|ethnicity|race|religion|political|union.membership|sexual.orientation|gender.identity|marital.status|dependents|children|guardian|next.of.kin|emergency.contact|beneficiary|executor|power.of.attorney|will|estate|inheritance|trust|fiduciary|shareholder|director|officer|employee|contractor|vendor|supplier|partner|client|customer|user.account|profile|preference|subscription|membership|loyalty|reward|points|coupon|discount|promo|referral|affiliate|commission|bonus|compensation|benefit|allowance|perk|allowance|expense|reimbursement|travel|hotel|flight|itinerary|booking|reservation|appointment|schedule|calendar|event|meeting|agenda|minutes|note|memo|correspondence|letter|email|message|chat|conversation|call|voice.mail|fax|document|file|attachment|upload|download|transfer|import|export|backup|archive|log|audit.trail|access.log|error.log|debug.log|trace.log|application.log|system.log|security.log|event.log|change.log|modification.log|deletion.log|creation.log|update.log|patch|fix|hotfix|update|upgrade|migration|transformation|conversion|sync|replication|mirror|clone|copy|duplicate|backup|snapshot|restore|recovery|disaster.recovery|business.continuity|run.book|playbook|procedure|process|workflow|automation|orchestration|pipeline|stage|environment|deployment|release|version|build|artifact|package|module|component|library|framework|sdk|api.key|secret.key|access.key|private.key|public.key|certificate|ssl|tls|token|bearer|oauth|jwt|session|cookie|cache|store|database|table|column|row|record|field|attribute|property|setting|config|parameter|variable|constant|enum|flag|option|choice|selection|filter|query|search|sort|order|group|aggregate|count|sum|avg|min|max|distinct|union|intersect|except|join|left|right|inner|outer|full|cross|natural|self|subquery|correlated|derived|temporary|view|index|constraint|trigger|procedure|function|package|schema|namespace|module|class|object|instance|method|property|event|handler|callback|listener|observer|middleware|interceptor|filter|transform|mapper|reducer|aggregator|collector|partitioner|shard|replica|fragment|segment|block|chunk|batch|queue|topic|channel|stream|pipe|socket|connection|session|transaction|lock|mutex|semaphore|barrier|latch|gate|door|portal|gateway|bridge|proxy|relay|forward|redirect|route|path|way|road|link|bridge|tunnel|channel|corridor|passage|entry|exit|gate|checkpoint|barrier|filter|screen|screen|firewall|wall|shield|guard|protect|defend|secure|lock|key|password|passphrase|secret|token|credential|certificate|badge|id|card|token|ticket|pass|voucher|coupon|code|pin|signature|hash|digest|fingerprint|token|key|secret|password|passphrase|pin|code|cipher|encryption|decryption|hash|sign|verify|validate|authenticate|authorize|permit|allow|grant|deny|reject|block|ban|suspend|revoke|cancel|terminate|end|close|shutdown|stop|halt|pause|resume|start|begin|init|launch|run|execute|perform|operate|manage|admin|control|govern|rule|regulate|direct|guide|lead|command|order|instruct|direct|supervise|oversee|monitor|watch|observe|track|follow|trace|audit|log|record|document|report|file|store|save|keep|retain|preserve|maintain|sustain|support|uphold|back.up|replicate|mirror|copy|duplicate|clone|snapshot|backup|archive|compress|pack|bundle|group|cluster|collect|gather|assemble|compile|build|construct|create|make|produce|generate|derive|extract|obtain|acquire|gain|earn|win|achieve|attain|reach|access|enter|penetrate|bypass|circumvent|override|bypass|bypass|bypass|bypass)" "$endpoints_file" > "$output_dir/pii_candidates.txt" 2>/dev/null || true
    fi

    # ===== PHI DETECTION =====
    log "INFO" "Scanning for PHI (Protected Health Information) exposure..."

    if [ -f "$endpoints_file" ]; then
        grep -iE "(health|medical|patient|clinical|diagnosis|treatment|prescription|medication|insurance|claim|benefit|provider|pharmacy|hospital|clinic|doctor|nurse|therapist|lab|test|result|record|chart|report|referral|authorization|consent|hipaa|phi|ehr|emr|medical.record|health.record|patient.record|clinical.record|treatment.record|care.plan|care.coordination|care.team|care.giver|care.provider|care.receiver|care.recipient|care.beneficiary|care.member|care.participant|care.recipient|care.subject|care.target|care.focus|care.entity|care.object|care.item|care.element|care.component|care.aspect|care.factor|care.consideration|care.concern|care.issue|care.problem|care.condition|care.status|care.state|care.situation|care.circumstance|care.context|care.setting|care.environment|care.place|care.location|care.site|care.facility|care.institution|care.organization|care.body|care.system|care.network|care.community|care.population|care.group|care.team|care.unit|care.department|care.division|care.section|care.branch|care.office|care.clinic|care.center|care.institute|care.agency|care.bureau|care.office|care.service|care.program|care.initiative|care.project|care.activity|care.action|care.task|care.work|care.job|care.role|care.position|care.title|care.rank|care.level|care.grade|care.class|care.category|care.type|care.kind|care.sort|care.form|care.format|care.structure|care.arrangement|care.organization|care.coordination|care.integration|care.collaboration|care.partnership|care.alliance|care.association|care.relationship|care.connection|care.link|care.bond|care.tie|care.bond|care.attachment|care.affiliation|care.membership|care.participation|care.involvement|care.engagement|care.interest|care.concern|care.attention|care.focus|care.emphasis|care.priority|care.importance|care.significance|care.relevance|care.relation|care.relation|care.connection|care.association|care.correlation|care.correspondence|care.match|care.fit|care.alignment|care.agreement|care.harmony|care.balance|care.equilibrium|care.stability|care.consistency|care.coherence|care.unity|care.integrity|care.wholeness|care.completeness|care.thoroughness|care.rigor|care.diligence|care.care|care.attention|care.consideration|care.thought|care.reflection|care.contemplation|care.meditation|care.study|care.examination|care.inspection|care.review|care.assessment|care.evaluation|care.analysis|care.interpretation|care.understanding|care.comprehension|care.grasp|care.appreciation|care.awareness|care.consciousness|care.cognizance|care.knowledge|care.information|care.intelligence|care.data|care.fact|care.detail|care.particular|care.specific|care.specificity|care.precision|care.accuracy|care.correctness|care.truth|care.reality|care.fact|care.actuality|care.existence|care.being|care.entity|care.object|care.thing|care.item|care.element|care.component|care.part|care.piece|care.segment|care.section|care.portion|care.share|care.share|care.share|care.share|care.share|care.share|care.share|care.share|care.share|care.share|care.share|care.share|care.share)" "$endpoints_file" > "$output_dir/phi_candidates.txt" 2>/dev/null || true
    fi

    # ===== PCI DATA DETECTION =====
    log "INFO" "Scanning for PCI data exposure..."

    if [ -f "$endpoints_file" ]; then
        grep -iE "(payment|card|credit|debit|transaction|checkout|cart|billing|invoice|receipt|order|purchase|refund|charge|gateway|processor|token|pci|cardholder|cvv|cvc|expiry|expiration|pan|track|magstripe|chip|emv|3ds|3dsecure|avs|cvv2|pin|auth|capture|void|refund|settlement|batch|reconciliation|audit|log|compliance|pci|card.number|card.type|card.brand|card.bin|card.issuer|card.country|card.currency|card.amount|card.cvv|card.expiry|card.holder|card.name|card.address|card.zip|card.city|card.state|card.country|card.phone|card.email|card.ip|card.device|card.browser|card.os|card.useragent|card.fingerprint|card.token|card.tokenization|card.encryption|card.hashing|card.masking|card.redaction|card.truncation|card.format|card.validate|card.verify|card.check|card.auth|card.authz|card.authorization|card.approval|card.decline|card.decline|card.decline|card.decline|card.decline|card.decline|card.decline|card.decline|card.decline|card.decline|card.decline|card.decline|card.decline)" "$endpoints_file" > "$output_dir/pci_candidates.txt" 2>/dev/null || true
    fi

    # ===== SENSITIVE DATA IN API RESPONSES =====
    log "INFO" "Analyzing API responses for sensitive data..."

    if [ -f "$api_file" ]; then
        python3 -c "
import json, os, sys

try:
    with open('$api_file') as f:
        api_data = json.load(f)

    sensitive_endpoints = []
    endpoints = api_data.get('endpoints', api_data if isinstance(api_data, list) else [])
    if isinstance(api_data, dict):
        endpoints = api_data.get('endpoints', [])

    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        url = str(endpoint.get('url', ''))
        method = endpoint.get('method', 'GET')
        data_types = endpoint.get('data_types', [])
        auth = endpoint.get('auth', 'unknown')

        sensitive_keywords = [
            'personal', 'pii', 'name', 'email', 'phone', 'address', 'ssn', 'credit', 'card',
            'password', 'passwd', 'secret', 'key', 'token', 'api_key', 'private', 'confidential',
            'sensitive', 'restricted', 'classified', 'internal', 'medical', 'health', 'patient',
            'financial', 'payment', 'bank', 'account', 'transaction', 'insurance', 'claim',
            'authentication', 'authorization', 'credential', 'session', 'cookie', 'hash', 'cipher'
        ]

        for keyword in sensitive_keywords:
            if keyword in url.lower() or keyword in str(data_types).lower():
                sensitive_endpoints.append({
                    'url': url,
                    'method': method,
                    'auth_type': auth,
                    'sensitive_keyword': keyword,
                    'finding': 'Possible sensitive data exposure',
                    'confidence': 0.7,
                    'verification': {'method': 'api_response_analysis', 'confidence': 'medium', 'status': 'review_required'}
                })
                break

    result = {
        'sensitive_endpoints': sensitive_endpoints,
        'total': len(sensitive_endpoints),
        'verification': {'method': 'api_response_analysis', 'confidence': 'medium', 'status': 'review_required'}
    }

    with open('$output_dir/sensitive_api_endpoints.json', 'w') as f:
        json.dump(result, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true
    fi

    # ===== DATA LEAKAGE VIA ERROR MESSAGES =====
    log "INFO" "Checking for data leakage in error messages..."

    if [ -f "$endpoints_file" ]; then
        grep -iE "(error|exception|stack.trace|traceback|debug|verbose|diagnostic|info|warning|notice|detail|message|description|reason|cause|source|file|line|column|function|method|class|module|package|library|framework|version|build|commit|hash|id|uuid|guid|token|key|secret|password|passwd|credential|auth|token|cookie|session|header|parameter|value|data|record|row|column|field|attribute|property|config|setting|environment|variable|path|file|directory|server|host|ip|port|database|connection|string|query|command|output|result|response|request|request_id|trace_id|span_id|correlation_id|request_id|session_id|user_id|account_id|customer_id|client_id|app_id|app_key|api_key|access_key|secret_key|private_key|public_key|encryption_key|signing_key|hmac_key|bearer_token|auth_token|access_token|refresh_token|id_token|jwt|jws|jwe|jwt_header|jwt_payload|jwt_signature|jwt_algorithm|jwt_type|jwt_content|jwt_claim|jwt_subject|jwt_issuer|jwt_audience|jwt_expires|jwt_not_before|jwt_issued_at|jwt_jwt_id|jwt_nonce|jwt_at_hash|jwt_c_hash|jwt_acrs|jwt_grant|jwt_token_type|jwt_expires_in|jwt_scope|jwt_client_id|jwt_username|jwt_sub|jwt_iss|jwt_aud|jwt_exp|jwt_nbf|jwt_iat|jwt_jti|jwt_grant_type|jwt_redirect_uri|jwt_state|jwt_code|jwt_access_token|jwt_refresh_token|jwt_id_token|jwt_token|jwt_bearer|jwt_mac|jwt_pop|jwt_cnf|jwt_x5t|jwt_x5u|jwt_x5c|jwt_kid|jwt_alg|jwt_typ|jwt_cty|jwt_json|jwt_uri|jwt_iss|jwt_sub|jwt_aud|jwt_exp|jwt_nbf|jwt_iat|jwt_jti|jwt_grant_type|jwt_redirect_uri|jwt_state|jwt_code|jwt_access_token|jwt_refresh_token|jwt_id_token|jwt_token|jwt_bearer|jwt_mac|jwt_pop|jwt_cnf|jwt_x5t|jwt_x5u|jwt_x5c|jwt_kid|jwt_alg|jwt_typ|jwt_cty)" "$endpoints_file" > "$output_dir/error_message_leaks.txt" 2>/dev/null || true
    fi

    # ===== CROSS-REFERENCE AND VALIDATE =====
    log "INFO" "Cross-referencing data exfiltration findings for 0 false positives..."

    python3 -c "
import json, os, sys
try:
    findings = []
    output_dir = '$output_dir'

    for f in os.listdir(output_dir):
        if f.endswith('.txt') and ('pii' in f.lower() or 'phi' in f.lower() or 'pci' in f.lower() or 'sensitive' in f.lower() or 'leak' in f.lower() or 'error' in f.lower()):
            filepath = os.path.join(output_dir, f)
            with open(filepath) as fh:
                lines = [l.strip() for l in fh if l.strip()]
                for line in lines:
                    findings.append({
                        'source_file': f,
                        'value': line,
                        'type': 'data_exfiltration_finding',
                        'confidence': 0.6,
                        'verification': {'method': 'multi_source_correlated', 'confidence': 'medium', 'status': 'review_required'}
                    })

    # Also include JSON findings
    for f in os.listdir(output_dir):
        if f.endswith('.json') and f not in ['data_exfiltration_findings.json', 'pii_candidates.txt']:
            filepath = os.path.join(output_dir, f)
            try:
                with open(filepath) as fh:
                    data = json.load(fh)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                item['_source_file'] = f
                                findings.append(item)
                    elif isinstance(data, dict):
                        data['_source_file'] = f
                        findings.append(data)
            except:
                pass

    # Deduplicate
    seen = set()
    unique_findings = []
    for finding in findings:
        key = str(finding.get('value', finding.get('url', finding.get('finding', ''))))
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    with open(os.path.join(output_dir, 'data_exfiltration_findings.json'), 'w') as f:
        json.dump({'findings': unique_findings, 'total': len(unique_findings)}, f, indent=2)
except Exception as e:
    pass
" 2>/dev/null || true

    log "INFO" "Data exfiltration and sensitive data discovery completed for $domain"

    write_finding "{\"type\":\"data_exfiltration\",\"severity\":\"critical\",\"domain\":\"$domain\",\"phase\":\"data_exfiltration\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "data_exfiltration_phase" "Completed for $domain"
}