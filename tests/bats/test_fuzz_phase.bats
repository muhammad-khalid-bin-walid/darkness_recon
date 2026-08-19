#!/usr/bin/env bats
# tests/bats/test_fuzz_phase.bats — Tests for phases/fuzz_phase.sh

setup() {
    load 'setup.bash'
    source "${BATS_TEST_DIRNAME}/../../phases/fuzz_phase.sh"
    export OUTDIR="${OUTPUT_DIR}/${DOMAIN}/recon_${TIMESTAMP}"
    export WORDLIST="${CACHE_DIR}/wordlists/common.txt"
    mkdir -p "${OUTDIR}/live" "${OUTDIR}/fuzz"
}

teardown() {
    rm -rf "$OUTPUT_DIR" "$CACHE_DIR" "$LOGS_DIR"
}

@test "fuzz_phase skips when live subdomains file missing" {
    # live file does NOT exist
    rm -f "${OUTDIR}/live/live_subdomains.txt"
    run fuzz_phase "$DOMAIN"
    [ "$status" -eq 0 ]
    # count.txt written with 0
    [ -f "${OUTDIR}/fuzz/count.txt" ]
}

@test "fuzz_phase skips when wordlist missing" {
    # wordlist does NOT exist
    echo "https://sub.${DOMAIN}" > "${OUTDIR}/live/live_subdomains.txt"
    export WORDLIST="${CACHE_DIR}/wordlists/nonexistent.txt"
    run fuzz_phase "$DOMAIN"
    [ "$status" -eq 0 ]
    [ -f "${OUTDIR}/fuzz/count.txt" ]
}

@test "fuzz_phase creates output directories" {
    echo "https://sub.${DOMAIN}" > "${OUTDIR}/live/live_subdomains.txt"
    echo "test" > "${WORDLIST}"
    run fuzz_phase "$DOMAIN"
    [ "$status" -eq 0 ]
    [ -d "${OUTDIR}/fuzz" ]
}

@test "fuzz_phase writes count.txt on completion" {
    echo "https://sub.${DOMAIN}" > "${OUTDIR}/live/live_subdomains.txt"
    echo "test" > "${WORDLIST}"
    fuzz_phase "$DOMAIN"
    [ -f "${OUTDIR}/fuzz/count.txt" ]
}

@test "fuzz_phase is idempotent - skips if results exist" {
    mkdir -p "${OUTDIR}/fuzz"
    echo '[{"url":"https://sub.test.example.com/admin","status":200}]' \
        > "${OUTDIR}/fuzz/fuzz_results.json"

    # Track calls by checking count.txt isn't overwritten
    echo "99" > "${OUTDIR}/fuzz/count.txt"

    run fuzz_phase "$DOMAIN"
    [ "$status" -eq 0 ]
    # count.txt should still be 99 (we skipped)
    result=$(cat "${OUTDIR}/fuzz/count.txt")
    [ "$result" = "99" ]
}
