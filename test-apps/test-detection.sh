#!/usr/bin/env bash
# ============================================================
# Auto-ZAP Detection-Only Test
# Quick validation that auto-zap.sh correctly identifies each framework
# Does NOT run ZAP scan - just tests detection logic in isolation
# ============================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUTO_ZAP="$(cd "$SCRIPT_DIR/.." && pwd)/auto-zap.sh"
WSL_TMP="/tmp/auto-zap-detect-$$"
RESULTS_DIR="$SCRIPT_DIR/results"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test definitions: "folder|expected_detection_pattern|expected_port"
TESTS=(
    "node-express|Express|3000"
    "node-fastify|Fastify|3000"
    "node-hono|Hono|3000"
    "node-vite|Vite|5173"
    "node-nextjs|Next.js|3000"
    "node-nestjs|NestJS|3000"
    "node-generic|Node.js|3000"
    "python-flask|Flask|5000"
    "python-fastapi|FastAPI|8000"
    "python-django|Django|8000"
    "go-web|Go|8080"
    "java-spring|Spring Boot|8080"
    "docker-app|Docker|3000"
    "static-html|Static HTML|8080"
)

TOTAL=0
PASS=0
FAIL=0

cleanup() {
    rm -rf "$WSL_TMP" 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Auto-ZAP Framework Detection Test${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

mkdir -p "$WSL_TMP" "$RESULTS_DIR"

# We extract just the detection logic from auto-zap.sh by running it
# and letting it fail at the Docker check (since we only care about detection).
# Alternative: we source the detection section directly.

# Actually, we'll create a minimal wrapper that sources the detection part.
# The simplest approach: run auto-zap.sh and it will detect, then try to install/start
# and fail. We just need the "Detected:" line from output.

# Since auto-zap.sh does set -euo pipefail and has prereq checks, we need docker running.
# Let's just run it with a very short timeout and grep for the detection output.

for test_def in "${TESTS[@]}"; do
    IFS='|' read -r folder expected_fw expected_port <<< "$test_def"
    TOTAL=$((TOTAL + 1))

    test_dir="$WSL_TMP/$folder"
    rm -rf "$test_dir"
    mkdir -p "$test_dir"
    cp -r "$SCRIPT_DIR/$folder"/. "$test_dir"/

    log_file="$RESULTS_DIR/${folder}-detect.log"

    # Run auto-zap.sh with a 30s timeout - enough for detection + start of install
    # It will likely fail or timeout during install/start, which is fine
    cd "$test_dir" || return 1
    timeout 30 bash "$AUTO_ZAP" > "$log_file" 2>&1 || true
    cd "$SCRIPT_DIR" || return 1

    # Check detection
    detected=$(grep -o 'Detected: .*' "$log_file" 2>/dev/null | head -1 | sed 's/Detected: //')

    if echo "$detected" | grep -qi "$expected_fw" 2>/dev/null; then
        printf "  ${GREEN}PASS${NC}  %-16s -> %s\n" "$folder" "$detected"
        PASS=$((PASS + 1))
    elif [[ -n "$detected" ]]; then
        printf "  ${RED}FAIL${NC}  %-16s -> %s (expected: %s)\n" "$folder" "$detected" "$expected_fw"
        FAIL=$((FAIL + 1))
    else
        # Check for specific errors
        if grep -q "Missing required tools" "$log_file" 2>/dev/null; then
            printf "  ${YELLOW}SKIP${NC}  %-16s -> Missing prerequisites\n" "$folder"
        elif grep -q "Could not detect" "$log_file" 2>/dev/null; then
            printf "  ${RED}FAIL${NC}  %-16s -> No framework detected (expected: %s)\n" "$folder" "$expected_fw"
            FAIL=$((FAIL + 1))
        else
            printf "  ${RED}FAIL${NC}  %-16s -> No detection output (expected: %s)\n" "$folder" "$expected_fw"
            FAIL=$((FAIL + 1))
        fi
    fi

    # Kill any started processes on the expected port
    lsof -ti :"$expected_port" 2>/dev/null | xargs kill -9 2>/dev/null || true
done

echo ""
echo -e "${CYAN}Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC} (of $TOTAL)"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Some tests failed. Check logs in $RESULTS_DIR/${NC}"
    exit 1
else
    echo -e "${GREEN}All detection tests passed!${NC}"
    exit 0
fi
