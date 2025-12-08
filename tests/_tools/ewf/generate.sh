#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TESTS_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly OUT_DIR="${TESTS_ROOT}/_data/ewf"

log()  { printf '[INFO] %s\n' "$*" >&2; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
error()  { printf '[ERROR] %s\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

require_tools() {
    local -a tools=(ewfacquirestream dd xxd)
    local missing=0

    for t in "${tools[@]}"; do
        if ! have "$t"; then
            error "Missing required tool: $t"
            missing=1
        fi
    done

    if (( missing != 0 )); then
        error "One or more required tools are missing. Aborting."
        exit 1
    fi
}

pattern() {
    local size="$1"

    stream() {
        while true; do
            for i in $(seq 0 255); do
                printf "`printf '%02x' "${i}"`%.0s" {0..4095}
            done
        done
    }

    stream | xxd -r -ps | head -c "${size}" || true

    # Add a final message to test unaligned sizes
    echo -n "kusjes van SRT<3"
}

generate() {
    local name="$1"
    local size="$2"
    local split="$3"
    local compression="$4"

    local outdir="${OUT_DIR}/${name}"
    mkdir -p "${outdir}"

    pattern "${size}" | ewfacquirestream \
        -t "${outdir}/image" \
        -S "${split}" \
        -c "${compression}" \
        >/dev/null 2>/dev/null

    log "Generated test case: ${outdir}"
}

main() {
    require_tools

    mkdir -p "${OUT_DIR}"

    generate "single" "$((4 * 1024 * 1024))" "256M" best
    generate "segmented" "$((4 * 1024 * 1024))" "1M" none

    log "All test cases generated under: ${OUT_DIR}"
}

main "$@"
