#!/usr/bin/env bash
# ============================================================
# Auto-ZAP Comprehensive Test Runner
# Tests framework detection + dry-run for ALL supported frameworks
# ============================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUTO_ZAP="$(cd "$SCRIPT_DIR/.." && pwd)/auto-zap.sh"
TMP_DIR="/tmp/auto-zap-tests-$$"
RESULTS_DIR="$SCRIPT_DIR/results"

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ---- Test mode ----
MODE="${1:---detection}"  # --detection (default), --dry-run, or --full-scan

# ============================================================
# Test definitions: "folder|expected_framework|expected_port"
# ============================================================
TESTS=(
    # --- Node.js frameworks ---
    "node-nextjs|Next.js|3000"
    "node-nuxt|Nuxt|3000"
    "node-remix|Remix|3000"
    "node-nestjs|NestJS|3000"
    "node-sveltekit|SvelteKit|5173"
    "node-astro|Astro|4321"
    "node-angular|Angular|4200"
    "node-gatsby|Gatsby|8000"
    "node-vite|Vite|5173"
    "node-adonisjs|AdonisJS|3333"
    "node-fastify|Fastify|3000"
    "node-hono|Hono|3000"
    "node-express|Express|3000"
    "node-generic|Node.js|3000"

    # --- Python frameworks ---
    "python-django|Django|8000"
    "python-fastapi|FastAPI|8000"
    "python-flask|Flask|5000"
    "python-generic|Python|8000"

    # --- .NET ---
    "dotnet-aspnet|ASP.NET|5000"

    # --- Java ---
    "java-spring-maven|Spring Boot|8080"
    "java-spring-gradle|Spring Boot|8080"

    # --- PHP frameworks ---
    "php-wordpress|WordPress|8080"
    "php-laravel|Laravel|8000"
    "php-symfony|Symfony|8000"
    "php-generic|PHP|8080"

    # --- Ruby ---
    "ruby-rails|Rails|3000"

    # --- Go ---
    "go-web|Go|8080"

    # --- Rust ---
    "rust-web|Rust|8080"

    # --- Elixir ---
    "elixir-phoenix|Phoenix|4000"
    "elixir-generic|Elixir|4000"

    # --- Deno ---
    "deno-web|Deno|8000"

    # --- Other ---
    "docker-app|Docker|3000"
    "static-html|Static HTML|8080"
)

TOTAL=0
PASS=0
FAIL=0
SKIP=0

cleanup() {
    rm -rf "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Auto-ZAP Comprehensive Test Runner${NC}"
echo -e "${CYAN}  Mode: $MODE | Projects: ${#TESTS[@]}${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

mkdir -p "$TMP_DIR" "$RESULTS_DIR"

# ============================================================
# Check prerequisites
# ============================================================
if [[ "$MODE" == "--full-scan" ]]; then
    if ! command -v docker &>/dev/null; then
        echo -e "${RED}Full scan mode requires Docker. Install Docker and retry.${NC}"
        exit 1
    fi
    if ! docker info &>/dev/null; then
        echo -e "${RED}Docker is not running. Start Docker and retry.${NC}"
        exit 1
    fi
fi

# Verify auto-zap.sh exists and has valid syntax
if [[ ! -f "$AUTO_ZAP" ]]; then
    echo -e "${RED}auto-zap.sh not found at: $AUTO_ZAP${NC}"
    exit 1
fi
if ! bash -n "$AUTO_ZAP" 2>/dev/null; then
    echo -e "${RED}auto-zap.sh has syntax errors${NC}"
    exit 1
fi
echo -e "${GREEN}  auto-zap.sh syntax: OK${NC}"
echo ""

# ============================================================
# Run tests
# ============================================================
for test_def in "${TESTS[@]}"; do
    IFS='|' read -r folder expected_fw expected_port <<< "$test_def"
    TOTAL=$((TOTAL + 1))

    # Prepare test directory
    test_dir="$TMP_DIR/$folder"
    rm -rf "$test_dir"
    mkdir -p "$test_dir"

    # Check if test project exists
    if [[ ! -d "$SCRIPT_DIR/$folder" ]]; then
        printf "  ${YELLOW}SKIP${NC}  %-22s -> Test project not found\n" "$folder"
        SKIP=$((SKIP + 1))
        continue
    fi

    cp -r "$SCRIPT_DIR/$folder"/. "$test_dir"/
    log_file="$RESULTS_DIR/${folder}.log"

    case "$MODE" in
        --detection)
            # Run auto-zap.sh and capture detection output (will fail at install/start, that's OK)
            cd "$test_dir" || continue
            timeout 30 bash "$AUTO_ZAP" > "$log_file" 2>&1 || true
            cd "$SCRIPT_DIR" || continue

            detected=$(grep -o 'Detected: .*' "$log_file" 2>/dev/null | head -1 | sed 's/Detected: //')
            detected_port=$(grep -o 'Port: [0-9]*' "$log_file" 2>/dev/null | head -1 | sed 's/Port: //')

            if echo "$detected" | grep -qi "$expected_fw" 2>/dev/null; then
                if [[ -n "$detected_port" && "$detected_port" == "$expected_port" ]]; then
                    printf "  ${GREEN}PASS${NC}  %-22s -> %s (port %s)\n" "$folder" "$detected" "$detected_port"
                else
                    printf "  ${GREEN}PASS${NC}  %-22s -> %s (port: %s, expected %s)\n" "$folder" "$detected" "${detected_port:-?}" "$expected_port"
                fi
                PASS=$((PASS + 1))
            elif [[ -n "$detected" ]]; then
                printf "  ${RED}FAIL${NC}  %-22s -> %s (expected: %s)\n" "$folder" "$detected" "$expected_fw"
                FAIL=$((FAIL + 1))
            else
                if grep -q "Missing required tools" "$log_file" 2>/dev/null; then
                    printf "  ${YELLOW}SKIP${NC}  %-22s -> Missing prerequisites (docker/curl/jq)\n" "$folder"
                    SKIP=$((SKIP + 1))
                    TOTAL=$((TOTAL - 1))  # Don't count as a real test
                elif grep -q "Could not detect" "$log_file" 2>/dev/null; then
                    printf "  ${RED}FAIL${NC}  %-22s -> Not detected (expected: %s)\n" "$folder" "$expected_fw"
                    FAIL=$((FAIL + 1))
                else
                    printf "  ${RED}FAIL${NC}  %-22s -> No output (expected: %s)\n" "$folder" "$expected_fw"
                    FAIL=$((FAIL + 1))
                fi
            fi
            ;;

        --dry-run)
            # Run with --dry-run flag — should exit 0 with summary
            cd "$test_dir" || continue
            timeout 30 bash "$AUTO_ZAP" --dry-run > "$log_file" 2>&1
            EXIT_CODE=$?
            cd "$SCRIPT_DIR" || continue

            if [[ $EXIT_CODE -eq 0 ]] && grep -q "Dry run complete" "$log_file" 2>/dev/null; then
                detected=$(grep -o 'Detected: .*' "$log_file" 2>/dev/null | head -1 | sed 's/Detected: //')
                printf "  ${GREEN}PASS${NC}  %-22s -> Dry-run OK (%s)\n" "$folder" "${detected:-detected}"
                PASS=$((PASS + 1))
            elif grep -q "Missing required tools" "$log_file" 2>/dev/null; then
                printf "  ${YELLOW}SKIP${NC}  %-22s -> Missing prerequisites\n" "$folder"
                SKIP=$((SKIP + 1))
                TOTAL=$((TOTAL - 1))
            else
                printf "  ${RED}FAIL${NC}  %-22s -> Dry-run failed (exit: %s)\n" "$folder" "$EXIT_CODE"
                FAIL=$((FAIL + 1))
            fi
            ;;

        --full-scan)
            # Full scan mode: start app, scan with ZAP, generate reports
            cd "$test_dir" || continue
            timeout 600 bash "$AUTO_ZAP" > "$log_file" 2>&1
            EXIT_CODE=$?
            cd "$SCRIPT_DIR" || continue

            if [[ $EXIT_CODE -eq 0 ]]; then
                printf "  ${GREEN}PASS${NC}  %-22s -> Scan complete (exit 0)\n" "$folder"
                PASS=$((PASS + 1))
            elif [[ $EXIT_CODE -eq 1 ]] && grep -q "high severity" "$log_file" 2>/dev/null; then
                printf "  ${GREEN}PASS${NC}  %-22s -> Scan complete (HIGH vulns found, exit 1)\n" "$folder"
                PASS=$((PASS + 1))  # Exit 1 for HIGH vulns is expected behavior
            else
                printf "  ${RED}FAIL${NC}  %-22s -> Scan failed (exit: %s)\n" "$folder" "$EXIT_CODE"
                FAIL=$((FAIL + 1))
            fi
            ;;
    esac

    # Cleanup any lingering processes on the expected port
    lsof -ti :"$expected_port" 2>/dev/null | xargs kill -9 2>/dev/null || true
done

# ============================================================
# Summary
# ============================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${WHITE}  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC} (of $TOTAL)"
echo -e "${CYAN}============================================================${NC}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Some tests failed. Check logs in $RESULTS_DIR/${NC}"
    exit 1
elif [[ $PASS -eq 0 ]]; then
    echo -e "${YELLOW}No tests passed. Are prerequisites (docker, curl, jq) available?${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
