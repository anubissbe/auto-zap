#!/usr/bin/env bash
# ============================================================
# Auto-ZAP Test Runner
# Runs auto-zap.sh against each test app and validates detection
# ============================================================
set -uo pipefail

# ---- Config ----
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUTO_ZAP="$(cd "$SCRIPT_DIR/.." && pwd)/auto-zap.sh"
RESULTS_DIR="$SCRIPT_DIR/results"
WSL_TMP="/tmp/auto-zap-tests-$$"
TIMEOUT=300  # 5 minutes per app

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---- Test definitions ----
# Format: "folder|expected_framework_pattern|expected_port"
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

# ---- State ----
TOTAL=0
DETECT_PASS=0
DETECT_FAIL=0
START_PASS=0
START_FAIL=0
SCAN_PASS=0
SCAN_FAIL=0
SKIPPED=0  # exported for summary display
export SKIPPED

declare -A RESULT_DETECT
declare -A RESULT_START
declare -A RESULT_SCAN
declare -A RESULT_NOTES

# ---- Cleanup ----
cleanup() {
    echo ""
    echo -e "${CYAN}[*] Cleaning up test environment...${NC}"

    # Kill any leftover app processes we may have started
    pkill -f "auto-zap-target" 2>/dev/null || true

    # Remove any auto-zap docker containers from tests
    docker ps -a --filter "name=auto-zap-" --format '{{.Names}}' 2>/dev/null | while read -r name; do
        docker rm -f "$name" 2>/dev/null || true
    done

    # Clean up tmp dirs
    rm -rf "$WSL_TMP" 2>/dev/null || true

    echo -e "${GREEN}[+] Cleanup done.${NC}"
}
trap cleanup EXIT

# ---- Helpers ----
log_header() {
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
}

# Kill all processes listening on a specific port
kill_port() {
    local port="$1"
    local pids
    pids=$(lsof -ti :"$port" 2>/dev/null) || true
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs kill -9 2>/dev/null || true
        sleep 1
    fi
}

# Run a single test app through auto-zap.sh's detection phase only (no ZAP scan)
# We test: (1) framework detection, (2) dependency install, (3) app starts
run_detection_test() {
    local folder="$1"
    local expected_fw="$2"
    local expected_port="$3"
    local test_dir="$WSL_TMP/$folder"
    local log_file="$RESULTS_DIR/${folder}.log"
    local src_dir="$SCRIPT_DIR/$folder"

    echo -e "${CYAN}[*] Testing: $folder${NC}"
    echo "    Expected: $expected_fw on port $expected_port"

    # Copy test app to WSL tmp
    rm -rf "$test_dir"
    mkdir -p "$test_dir"
    cp -r "$src_dir"/. "$test_dir"/

    # Initialize results
    RESULT_DETECT[$folder]="FAIL"
    RESULT_START[$folder]="SKIP"
    RESULT_SCAN[$folder]="SKIP"
    RESULT_NOTES[$folder]=""

    # ---- Phase 1: Detection test (dry run via timeout on the full script) ----
    # We run auto-zap.sh but kill it after detection + install + start attempt
    # by using a short overall timeout. The script will try to start ZAP Docker
    # which is where we let it run to test the full flow.

    cd "$test_dir" || { RESULT_NOTES[$folder]="cd failed"; return; }

    # Run auto-zap with timeout, capture output
    local exit_code=0
    timeout "$TIMEOUT" bash "$AUTO_ZAP" > "$log_file" 2>&1 || exit_code=$?

    # Go back to script dir
    cd "$SCRIPT_DIR" || true

    # ---- Analyze results ----

    # Check framework detection
    if grep -qi "Detected:.*${expected_fw}" "$log_file" 2>/dev/null; then
        RESULT_DETECT[$folder]="PASS"
        DETECT_PASS=$((DETECT_PASS + 1))
        echo -e "    ${GREEN}[+] Detection: PASS${NC} (found '$expected_fw')"
    else
        detected=$(grep -o 'Detected: .*' "$log_file" 2>/dev/null | head -1) || true
        if [[ -n "$detected" ]]; then
            RESULT_DETECT[$folder]="FAIL"
            RESULT_NOTES[$folder]="Got: $detected"
            echo -e "    ${RED}[-] Detection: FAIL${NC} (expected '$expected_fw', got: $detected)"
        else
            # Check if it failed to detect anything
            if grep -q "Could not detect" "$log_file" 2>/dev/null; then
                RESULT_DETECT[$folder]="FAIL"
                RESULT_NOTES[$folder]="No framework detected"
                echo -e "    ${RED}[-] Detection: FAIL${NC} (no framework detected)"
            else
                RESULT_DETECT[$folder]="FAIL"
                RESULT_NOTES[$folder]="Detection output missing"
                echo -e "    ${RED}[-] Detection: FAIL${NC} (no detection output found)"
            fi
        fi
        DETECT_FAIL=$((DETECT_FAIL + 1))
    fi

    # Check if app started (looked for "is ready" message)
    if grep -q "is ready" "$log_file" 2>/dev/null; then
        RESULT_START[$folder]="PASS"
        START_PASS=$((START_PASS + 1))
        echo -e "    ${GREEN}[+] App start: PASS${NC}"
    elif grep -q "failed to start" "$log_file" 2>/dev/null || grep -q "did not respond" "$log_file" 2>/dev/null; then
        RESULT_START[$folder]="FAIL"
        START_FAIL=$((START_FAIL + 1))
        echo -e "    ${RED}[-] App start: FAIL${NC}"
    else
        # Timeout or other - may have started but we killed it
        if [[ $exit_code -eq 124 ]]; then
            RESULT_START[$folder]="TIMEOUT"
            RESULT_NOTES[$folder]+=" (timeout after ${TIMEOUT}s)"
            echo -e "    ${YELLOW}[!] App start: TIMEOUT${NC}"
        else
            RESULT_START[$folder]="UNKNOWN"
            echo -e "    ${YELLOW}[!] App start: UNKNOWN${NC} (exit=$exit_code)"
        fi
    fi

    # Check for report generation
    if ls "$test_dir"/zap-report-*.html 1>/dev/null 2>&1; then
        RESULT_SCAN[$folder]="PASS"
        SCAN_PASS=$((SCAN_PASS + 1))
        echo -e "    ${GREEN}[+] ZAP scan: PASS${NC} (reports generated)"
        # Copy reports to results
        cp "$test_dir"/zap-report-*.html "$RESULTS_DIR/" 2>/dev/null || true
        cp "$test_dir"/zap-report-*.json "$RESULTS_DIR/" 2>/dev/null || true
    elif grep -q "Spider found" "$log_file" 2>/dev/null; then
        # ZAP ran but maybe reports failed
        RESULT_SCAN[$folder]="PARTIAL"
        SCAN_PASS=$((SCAN_PASS + 1))
        echo -e "    ${YELLOW}[!] ZAP scan: PARTIAL${NC} (ZAP ran but no report files)"
    else
        RESULT_SCAN[$folder]="SKIP"
        echo -e "    ${YELLOW}[!] ZAP scan: SKIPPED${NC} (app didn't reach scan phase)"
    fi

    # Kill any leftover processes on the expected port
    kill_port "$expected_port"

    TOTAL=$((TOTAL + 1))
    echo ""
}

# ============================================================
# MAIN
# ============================================================
log_header "Auto-ZAP Test Runner"

echo "Auto-ZAP script: $AUTO_ZAP"
echo "Test apps dir:   $SCRIPT_DIR"
echo "Results dir:     $RESULTS_DIR"
echo "WSL temp dir:    $WSL_TMP"
echo "Timeout per app: ${TIMEOUT}s"
echo ""

# Verify prerequisites
if [[ ! -f "$AUTO_ZAP" ]]; then
    echo -e "${RED}[-] auto-zap.sh not found at $AUTO_ZAP${NC}"
    exit 1
fi

if ! command -v docker &>/dev/null; then
    echo -e "${RED}[-] Docker is required but not installed.${NC}"
    exit 1
fi

if ! docker info &>/dev/null; then
    echo -e "${RED}[-] Docker daemon is not running.${NC}"
    exit 1
fi

# Clean results dir
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"
mkdir -p "$WSL_TMP"

# Run all tests sequentially (each one uses ports that need to be freed)
for test_def in "${TESTS[@]}"; do
    IFS='|' read -r folder expected_fw expected_port <<< "$test_def"
    run_detection_test "$folder" "$expected_fw" "$expected_port"
done

# ============================================================
# SUMMARY
# ============================================================
log_header "Test Results Summary"

# Print table header
printf "%-16s | %-10s | %-10s | %-10s | %s\n" "Test App" "Detection" "App Start" "ZAP Scan" "Notes"
printf "%-16s-+-%-10s-+-%-10s-+-%-10s-+-%s\n" "----------------" "----------" "----------" "----------" "-----"

for test_def in "${TESTS[@]}"; do
    IFS='|' read -r folder expected_fw expected_port <<< "$test_def"

    detect="${RESULT_DETECT[$folder]:-N/A}"
    start="${RESULT_START[$folder]:-N/A}"
    scan="${RESULT_SCAN[$folder]:-N/A}"
    notes="${RESULT_NOTES[$folder]:-}"

    # Colorize
    case "$detect" in
        PASS) detect_c="${GREEN}PASS${NC}" ;;
        FAIL) detect_c="${RED}FAIL${NC}" ;;
        *)    detect_c="${YELLOW}${detect}${NC}" ;;
    esac
    case "$start" in
        PASS) start_c="${GREEN}PASS${NC}" ;;
        FAIL) start_c="${RED}FAIL${NC}" ;;
        *)    start_c="${YELLOW}${start}${NC}" ;;
    esac
    case "$scan" in
        PASS) scan_c="${GREEN}PASS${NC}" ;;
        FAIL) scan_c="${RED}FAIL${NC}" ;;
        *)    scan_c="${YELLOW}${scan}${NC}" ;;
    esac

    printf "%-16s | %-21s | %-21s | %-21s | %s\n" "$folder" "$detect_c" "$start_c" "$scan_c" "$notes"
done

echo ""
echo -e "${CYAN}Totals:${NC}"
echo "  Detection: $DETECT_PASS passed, $DETECT_FAIL failed (of $TOTAL)"
echo "  App Start: $START_PASS passed, $START_FAIL failed"
echo "  ZAP Scan:  $SCAN_PASS passed, $SCAN_FAIL failed"
echo ""

# Write machine-readable summary
{
    echo "timestamp=$(date -Iseconds)"
    echo "total=$TOTAL"
    echo "detect_pass=$DETECT_PASS"
    echo "detect_fail=$DETECT_FAIL"
    echo "start_pass=$START_PASS"
    echo "start_fail=$START_FAIL"
    echo "scan_pass=$SCAN_PASS"
    echo "scan_fail=$SCAN_FAIL"
    for test_def in "${TESTS[@]}"; do
        IFS='|' read -r folder expected_fw expected_port <<< "$test_def"
        echo "${folder}_detect=${RESULT_DETECT[$folder]:-N/A}"
        echo "${folder}_start=${RESULT_START[$folder]:-N/A}"
        echo "${folder}_scan=${RESULT_SCAN[$folder]:-N/A}"
    done
} > "$RESULTS_DIR/summary.txt"

echo "Detailed logs: $RESULTS_DIR/"
echo "Summary file:  $RESULTS_DIR/summary.txt"
echo ""

if [[ $DETECT_FAIL -gt 0 ]]; then
    echo -e "${RED}Some detection tests FAILED. Check logs for details.${NC}"
    exit 1
else
    echo -e "${GREEN}All detection tests PASSED!${NC}"
    exit 0
fi
