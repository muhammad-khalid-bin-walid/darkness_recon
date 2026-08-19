$count = 0
# Map phase numbers to actual file names
$phaseMap = @{
    1 = "subdomain"; 2 = "live_host"; 3 = "tech_fingerprint"; 4 = "url_endpoint"
    5 = "parameter"; 6 = "fuzzing"; 7 = "waf"; 8 = "vuln_scanning"
    9 = "api_security"; 10 = "git_secret"; 11 = "cloud_infra"; 12 = "compliance"
    13 = "business_logic"; 14 = "advanced_exploitation"; 15 = "post_exploitation"
    16 = "threat_intel"; 17 = "osint"; 18 = "cache_encoding"; 19 = "rich_protocol"
    20 = "reporting_integration"
}

foreach ($entry in $phaseMap.GetEnumerator()) {
    $i = $entry.Key
    $name = $entry.Value
    $fname = "phases/${name}_phase.sh"
    if (Test-Path $fname) {
        $funcName = $name + "_phase"
        $content = Get-Content $fname
        if ($content -match [regex]::Escape($funcName) + "\(\)") {
            Write-Host ("OK Phase " + $i + ": " + $funcName + " defined") -ForegroundColor Green
            $count++
        } else {
            Write-Host ("MISSING Phase " + $i + ": " + $funcName + " not defined") -ForegroundColor Red
        }
    } else {
        Write-Host ("NOFILE Phase " + $i) -ForegroundColor Red
    }
}
Write-Host ("Total: " + $count + " / 20 phases have function definitions")