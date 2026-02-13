#!/usr/bin/env bash
# ============================================================
# Auto-ZAP - Automated OWASP ZAP Security Scanner (Linux/macOS)
# Uses Docker-based ZAP for scanning web applications
# ============================================================
set -euo pipefail

# ---- Configuration ----
ZAP_API_PORT=8090
ZAP_API_KEY=$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' || uuidgen 2>/dev/null | tr -d '-' || openssl rand -hex 16 2>/dev/null || { echo "FATAL: No cryptographic random source for ZAP API key" >&2; exit 1; })
ZAP_DOCKER_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
ZAP_CONTAINER_NAME="auto-zap-$$"
ORIGINAL_DIR=$(pwd)
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")

# ---- Defaults ----
URL=""
PORT=""
PORT_FROM_CLI=false
REPORT_PATH=""
FULL_SCAN=false
KEEP_DOCKER=false
SKIP_INSTALL=false
AUTH_USER=""
AUTH_PASSWORD=""
AUTH_URL=""
AUTH_TOKEN=""
AUTH_TYPE=""
AUTO_AUTH=false
SARIF=false
USE_DOCKER_ZAP=true  # Bash version always uses Docker ZAP
DRY_RUN=false
VERBOSE_LOG=false
SCAN_MODE="auto"

# ---- State ----
APP_PID=""
DB_CONTAINER=""
REDIS_CONTAINER=""
COMPOSE_STARTED=false
FRAMEWORK=""
RUNTIME=""
APP_PORT=3000
START_COMMAND=""
SCAN_POLICY_NAME=""
MONOREPO_ROOT=""
INSTALL_DIR=""
SERVICE_PIDS=()
CONFIG_FILE=""
AUTO_AUTH_CREATED=false

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
WHITE='\033[1;37m'
NC='\033[0m'

log_step()   { echo -e "${CYAN}[*] $1${NC}"; }
log_ok()     { echo -e "${GREEN}[+] $1${NC}"; }
log_warn()   { echo -e "${YELLOW}[!] $1${NC}"; }
log_err()    { echo -e "${RED}[-] $1${NC}"; }
log_detail() { echo -e "${GRAY}    $1${NC}"; }
log_verbose() { [[ "$VERBOSE_LOG" == "true" ]] && echo -e "${GRAY}[V] $1${NC}" || true; }
log_dryrun()  { [[ "$DRY_RUN" == "true" ]] && echo -e "\033[0;35m[DRY-RUN] $1${NC}" || true; }

# ---- Parse arguments ----
while [[ $# -gt 0 ]]; do
    # shellcheck disable=SC2034
    case $1 in
        --url|-u)           URL="$2"; shift 2 ;;
        --port|-p)          PORT="$2"; PORT_FROM_CLI=true; shift 2 ;;
        --report-path|-r)   REPORT_PATH="$2"; shift 2 ;;
        --full-scan|-f)     FULL_SCAN=true; shift ;;
        --keep-docker|-k)   KEEP_DOCKER=true; shift ;;
        --skip-install|-s)  SKIP_INSTALL=true; shift ;;
        --auth-user)        AUTH_USER="$2"; shift 2 ;;
        --auth-password)    AUTH_PASSWORD="$2"; shift 2 ;;
        --auth-url)         AUTH_URL="$2"; shift 2 ;;
        --auth-token)       AUTH_TOKEN="$2"; shift 2 ;;
        --auth-type)        AUTH_TYPE="$2"; shift 2 ;;
        --auto-auth|-a)     AUTO_AUTH=true; shift ;;
        --sarif)            SARIF=true; shift ;;
        --use-docker-zap)   USE_DOCKER_ZAP=true; shift ;;
        --dry-run)          DRY_RUN=true; shift ;;
        --verbose|-v)       VERBOSE_LOG=true; shift ;;
        --scan-mode)        SCAN_MODE="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: auto-zap.sh [options]"
            echo ""
            echo "Options:"
            echo "  --url, -u URL          Target URL (skip auto-detection)"
            echo "  --port, -p PORT        Override detected port"
            echo "  --report-path, -r PATH Custom report path"
            echo "  --full-scan, -f        Thorough active scan (slower)"
            echo "  --keep-docker, -k      Don't stop Docker containers after scan"
            echo "  --skip-install, -s     Skip dependency installation"
            echo "  --auth-user USER       Username for authenticated scanning"
            echo "  --auth-password PASS   Password for authenticated scanning"
            echo "  --auth-url URL         Login endpoint"
            echo "  --auth-token TOKEN     Pre-obtained Bearer token"
            echo "  --auth-type TYPE       form, json, or bearer"
            echo "  --auto-auth, -a        Auto-create temp user for authenticated scanning"
            echo "  --sarif                Generate SARIF report for GitHub Code Scanning"
            echo "  --use-docker-zap       Use Docker-based ZAP (default, always enabled on Linux)"
            echo "  --dry-run              Show what would happen without executing"
            echo "  --verbose, -v          Enable verbose debug logging"
            echo "  --scan-mode MODE       Scan mode: auto, webapp, api, static"
            echo "  --help, -h             Show this help"
            exit 0
            ;;
        *) log_err "Unknown option: $1"; exit 1 ;;
    esac
done

# ---- Cleanup trap ----
cleanup() {
    echo ""
    log_step "Cleaning up..."

    # Stop background service processes
    for svc_pid in ${SERVICE_PIDS[@]+"${SERVICE_PIDS[@]}"}; do
        if [[ -n "$svc_pid" ]] && kill -0 "$svc_pid" 2>/dev/null; then
            log_detail "Stopping background service (PID $svc_pid)..."
            pkill -P "$svc_pid" 2>/dev/null || true
            kill "$svc_pid" 2>/dev/null || true
            wait "$svc_pid" 2>/dev/null || true
        fi
    done

    # Stop app process tree
    if [[ -n "$APP_PID" ]] && kill -0 "$APP_PID" 2>/dev/null; then
        log_detail "Stopping application (PID $APP_PID)..."
        pkill -P "$APP_PID" 2>/dev/null || true
        kill "$APP_PID" 2>/dev/null || true
        wait "$APP_PID" 2>/dev/null || true
    fi

    # Shutdown ZAP via API first, then force-remove container
    if docker ps -q -f "name=$ZAP_CONTAINER_NAME" 2>/dev/null | grep -q .; then
        log_detail "Shutting down ZAP..."
        curl -sf "http://localhost:$ZAP_API_PORT/JSON/core/action/shutdown/?apikey=$ZAP_API_KEY" >/dev/null 2>&1 || true
        sleep 2
        docker rm -f "$ZAP_CONTAINER_NAME" >/dev/null 2>&1 || true
    fi

    # Stop database containers
    if [[ "$KEEP_DOCKER" != "true" ]]; then
        if [[ -n "$DB_CONTAINER" ]]; then
            log_detail "Stopping database container ($DB_CONTAINER)..."
            docker rm -f "$DB_CONTAINER" >/dev/null 2>&1 || true
        fi
        if [[ -n "$REDIS_CONTAINER" ]]; then
            log_detail "Stopping Redis container ($REDIS_CONTAINER)..."
            docker rm -f "$REDIS_CONTAINER" >/dev/null 2>&1 || true
        fi
        if [[ "$COMPOSE_STARTED" == "true" ]]; then
            log_detail "Stopping Docker Compose services..."
            docker compose down >/dev/null 2>&1 || docker-compose down >/dev/null 2>&1 || true
        fi
    fi

    # Remove auto-auth temp user if we created one
    remove_temp_user

    log_ok "Cleanup complete."
}
trap cleanup EXIT INT TERM

# ---- Helper: ZAP API call ----
zap_api() {
    local endpoint="$1"
    local url="http://localhost:$ZAP_API_PORT$endpoint"
    if [[ "$url" == *"?"* ]]; then
        url="${url}&apikey=$ZAP_API_KEY"
    else
        url="${url}?apikey=$ZAP_API_KEY"
    fi
    curl -sf --max-time 120 "$url"
}

# ---- Helper: Wait for URL ----
wait_for_url() {
    local url="$1"
    local timeout="${2:-120}"
    local label="${3:-service}"
    local elapsed=0

    log_detail "Waiting for $label at $url (timeout: ${timeout}s)..."
    while [[ $elapsed -lt $timeout ]]; do
        if curl -sf -o /dev/null --max-time 5 "$url" 2>/dev/null; then
            log_ok "$label is ready."
            return 0
        fi
        sleep 3
        elapsed=$((elapsed + 3))
        if [[ $((elapsed % 15)) -eq 0 ]]; then
            log_detail "Still waiting... (${elapsed}s / ${timeout}s)"
        fi
    done
    log_err "$label did not respond within $timeout seconds."
    return 1
}

# ---- Helper: Wait for TCP port ----
wait_for_tcp() {
    local host="$1"
    local port="$2"
    local timeout="${3:-60}"
    local label="${4:-service}"
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if nc -z "$host" "$port" 2>/dev/null || (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; then
            log_ok "$label is accepting connections on port $port."
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    log_err "$label not reachable on $host:$port within $timeout seconds."
    return 1
}

# ---- Helper: URL-encode ----
urlencode() {
    local string="$1"
    # Use jq first (always available since it's a prerequisite), safe against injection
    printf '%s' "$string" | jq -sRr @uri 2>/dev/null \
        || python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=''))" <<< "$string" 2>/dev/null \
        || printf '%s' "$string"
}

# ---- Auto-Auth: Generate random string ----
random_string() {
    local length="${1:-8}"
    cat /dev/urandom 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c "$length" 2>/dev/null \
        || python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range($length)))" 2>/dev/null \
        || openssl rand -hex $(( (length + 1) / 2 )) 2>/dev/null | head -c "$length" \
        || { echo "FATAL: No cryptographic random source available" >&2; return 1; }
}

# ---- Auto-Auth: Detect if app requires authentication ----
detect_auth_requirement() {
    local target_url="$1"
    local project_dir="$2"

    AUTH_DETECTED=false
    AUTH_HINT=""
    AUTH_REG_ENDPOINTS=()
    AUTH_LOGIN_ENDPOINTS=()
    AUTH_SUGGESTED_TYPE="json"

    # 1. File-based detection
    log_detail "Checking dependencies for authentication libraries..."

    # Node.js
    if [[ -f "$project_dir/package.json" ]]; then
        local pkg_text
        pkg_text=$(cat "$project_dir/package.json" 2>/dev/null)
        for lib in '"passport"' '"bcrypt"' '"bcryptjs"' '"argon2"' '"next-auth"' '"@auth/core"' '"better-auth"' '"lucia"' '"jsonwebtoken"' '"express-session"'; do
            if echo "$pkg_text" | grep -q "$lib"; then
                AUTH_DETECTED=true
                log_detail "Auth library detected: $lib"
            fi
        done
        if echo "$pkg_text" | grep -q '"better-auth"'; then AUTH_HINT="better-auth"; fi
    fi

    # Python - Django
    if [[ -f "$project_dir/manage.py" ]]; then
        local settings_file
        settings_file=$(find "$project_dir" -name "settings.py" -maxdepth 3 2>/dev/null | head -1)
        if [[ -n "$settings_file" ]] && grep -q "django.contrib.auth" "$settings_file" 2>/dev/null; then
            AUTH_DETECTED=true
            AUTH_HINT="django"
            log_detail "Django auth detected."
        fi
    fi

    # Python - generic
    for req_file in requirements.txt Pipfile pyproject.toml; do
        if [[ -f "$project_dir/$req_file" ]]; then
            for lib in flask-login flask-security fastapi-users passlib bcrypt PyJWT python-jose; do
                if grep -qi "$lib" "$project_dir/$req_file" 2>/dev/null; then
                    AUTH_DETECTED=true
                    log_detail "Auth library detected: $lib"
                fi
            done
        fi
    done

    # Java Spring Security
    for build_file in pom.xml build.gradle build.gradle.kts; do
        if [[ -f "$project_dir/$build_file" ]] && grep -q "spring-boot-starter-security" "$project_dir/$build_file" 2>/dev/null; then
            AUTH_DETECTED=true
            AUTH_HINT="spring-boot"
            log_detail "Spring Security detected."
        fi
    done

    # PHP Laravel
    if [[ -f "$project_dir/composer.json" ]]; then
        for lib in '"laravel/sanctum"' '"laravel/passport"' '"laravel/breeze"' '"laravel/jetstream"'; do
            if grep -q "$lib" "$project_dir/composer.json" 2>/dev/null; then
                AUTH_DETECTED=true
                AUTH_HINT="laravel"
                log_detail "Laravel auth detected."
            fi
        done
    fi

    # Ruby Devise
    if [[ -f "$project_dir/Gemfile" ]] && grep -q "devise" "$project_dir/Gemfile" 2>/dev/null; then
        AUTH_DETECTED=true
        AUTH_HINT="rails-devise"
        log_detail "Rails/Devise detected."
    fi

    # WordPress
    if [[ -f "$project_dir/wp-config.php" ]]; then
        AUTH_DETECTED=true
        AUTH_HINT="wordpress"
        AUTH_SUGGESTED_TYPE="form"
        log_detail "WordPress detected."
    fi

    # .NET Identity
    local csproj_file
    csproj_file=$(find "$project_dir" -name "*.csproj" -maxdepth 2 2>/dev/null | head -1)
    if [[ -n "$csproj_file" ]] && grep -q "Microsoft.AspNetCore.Identity" "$csproj_file" 2>/dev/null; then
        AUTH_DETECTED=true
        AUTH_HINT="aspnet"
        log_detail "ASP.NET Identity detected."
    fi

    # .env auth secrets
    for env_file in .env .env.local .env.development; do
        if [[ -f "$project_dir/$env_file" ]] && grep -qE "AUTH_SECRET|JWT_SECRET|SESSION_SECRET|NEXTAUTH_SECRET|BETTER_AUTH_SECRET" "$project_dir/$env_file" 2>/dev/null; then
            AUTH_DETECTED=true
            log_detail "Auth secret found in $env_file"
        fi
    done

    # 2. Runtime probing
    if [[ -n "$target_url" ]]; then
        local http_code
        http_code=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 5 "$target_url" 2>/dev/null || echo "000")
        if [[ "$http_code" == "401" || "$http_code" == "403" ]]; then
            AUTH_DETECTED=true
            log_detail "App returns HTTP $http_code — auth required."
        elif [[ "$http_code" == "301" || "$http_code" == "302" || "$http_code" == "307" || "$http_code" == "308" ]]; then
            local redirect_url
            redirect_url=$(curl -sf -o /dev/null -w "%{redirect_url}" --max-time 5 "$target_url" 2>/dev/null || echo "")
            if echo "$redirect_url" | grep -qiE "login|signin|sign-in|auth|accounts"; then
                AUTH_DETECTED=true
                log_detail "App redirects to login ($redirect_url) — auth required."
            fi
        elif [[ "$http_code" == "200" ]]; then
            local body
            body=$(curl -sf --max-time 5 "$target_url" 2>/dev/null || echo "")
            if echo "$body" | grep -q 'type=.password.'; then
                AUTH_DETECTED=true
                log_detail "Main page contains password field — auth required."
            fi
        fi
    fi

    # 3. Probe registration endpoints
    if [[ "$AUTH_DETECTED" == "true" && -n "$target_url" ]]; then
        for ep in /api/auth/register /api/auth/signup /api/auth/sign-up /api/auth/sign-up/email /api/register /api/signup /register /signup /api/v1/auth/register /auth/register /auth/signup; do
            local sc
            sc=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 3 "${target_url}${ep}" 2>/dev/null || echo "404")
            if [[ "$sc" != "404" ]]; then
                AUTH_REG_ENDPOINTS+=("$ep")
            fi
        done
        if [[ ${#AUTH_REG_ENDPOINTS[@]} -gt 0 ]]; then
            log_detail "Registration endpoints found: ${AUTH_REG_ENDPOINTS[*]}"
        fi

        # Probe login endpoints
        for ep in /api/auth/login /api/auth/signin /api/login /auth/login /login /signin /accounts/login/ /wp-login.php /users/sign_in /admin/login/ /Identity/Account/Login /users/log_in; do
            local sc
            sc=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 3 "${target_url}${ep}" 2>/dev/null || echo "404")
            if [[ "$sc" != "404" ]]; then
                AUTH_LOGIN_ENDPOINTS+=("$ep")
            fi
        done
        if [[ ${#AUTH_LOGIN_ENDPOINTS[@]} -gt 0 ]]; then
            log_detail "Login endpoints found: ${AUTH_LOGIN_ENDPOINTS[*]}"
        fi
    fi

    # Adjust auth type based on framework hint
    if [[ "$AUTH_HINT" == "django" ]]; then
        for ep in "${AUTH_LOGIN_ENDPOINTS[@]}"; do
            [[ "$ep" == "/admin/login/" ]] && AUTH_SUGGESTED_TYPE="form"
        done
    elif [[ "$AUTH_HINT" == "wordpress" || "$AUTH_HINT" == "rails-devise" ]]; then
        AUTH_SUGGESTED_TYPE="form"
    fi
}

# ---- Auto-Auth: Provision temporary test user ----
provision_temp_user() {
    local target_url="$1"
    local project_dir="$2"

    local rand
    rand=$(random_string 8)
    AUTO_AUTH_USER="zapuser-$rand"
    AUTO_AUTH_EMAIL="zapuser-${rand}@test.local"
    AUTO_AUTH_PASS="ZapTest-${rand}!1"
    AUTO_AUTH_CREATED=false
    AUTO_AUTH_CLEANUP_METHOD=""
    AUTO_AUTH_CLEANUP_DIR=""
    AUTO_AUTH_CLEANUP_ID=""
    AUTO_AUTH_CLEANUP_EXTRA=""
    AUTO_AUTH_LOGIN_URL=""
    AUTO_AUTH_LOGIN_TYPE="$AUTH_SUGGESTED_TYPE"

    log_step "Provisioning temporary test user ($AUTO_AUTH_USER)..."

    # Strategy 1: Framework-specific CLI commands

    # Django
    if [[ "$AUTH_HINT" == "django" || -f "$project_dir/manage.py" ]]; then
        log_detail "Attempting Django createsuperuser..."
        local py_cmd="python3"
        command -v python3 &>/dev/null || py_cmd="python"
        if DJANGO_SUPERUSER_USERNAME="$AUTO_AUTH_USER" \
           DJANGO_SUPERUSER_EMAIL="$AUTO_AUTH_EMAIL" \
           DJANGO_SUPERUSER_PASSWORD="$AUTO_AUTH_PASS" \
           $py_cmd "$project_dir/manage.py" createsuperuser --noinput 2>&1; then
            log_ok "Django superuser created: $AUTO_AUTH_USER"
            AUTO_AUTH_CREATED=true
            AUTO_AUTH_CLEANUP_METHOD="django"
            AUTO_AUTH_CLEANUP_DIR="$project_dir"
            AUTO_AUTH_CLEANUP_ID="$AUTO_AUTH_USER"
            AUTO_AUTH_CLEANUP_EXTRA="$py_cmd"
            # Find best login URL
            for ep in "${AUTH_LOGIN_ENDPOINTS[@]}"; do
                [[ "$ep" == "/admin/login/" ]] && AUTO_AUTH_LOGIN_URL="${target_url}/admin/login/" && AUTO_AUTH_LOGIN_TYPE="form" && break
            done
            [[ -z "$AUTO_AUTH_LOGIN_URL" && ${#AUTH_LOGIN_ENDPOINTS[@]} -gt 0 ]] && AUTO_AUTH_LOGIN_URL="${target_url}${AUTH_LOGIN_ENDPOINTS[0]}"
        fi
        [[ "$AUTO_AUTH_CREATED" == "true" ]] && return 0
    fi

    # Laravel
    if [[ "$AUTH_HINT" == "laravel" || -f "$project_dir/artisan" ]]; then
        log_detail "Attempting Laravel user creation via artisan tinker..."
        export AUTO_ZAP_USER="$AUTO_AUTH_USER"
        export AUTO_ZAP_EMAIL="$AUTO_AUTH_EMAIL"
        export AUTO_ZAP_PASS="$AUTO_AUTH_PASS"
        local tinker_code='\\App\\Models\\User::create(["name"=>env("AUTO_ZAP_USER"),"email"=>env("AUTO_ZAP_EMAIL"),"password"=>bcrypt(env("AUTO_ZAP_PASS"))]); echo "OK";'
        local output
        output=$(php "$project_dir/artisan" tinker --execute="$tinker_code" 2>&1) || true
        if echo "$output" | grep -q "OK"; then
            log_ok "Laravel user created: $AUTO_AUTH_USER"
            AUTO_AUTH_CREATED=true
            AUTO_AUTH_USER="$AUTO_AUTH_EMAIL"  # Laravel uses email for login
            AUTO_AUTH_CLEANUP_METHOD="laravel"
            AUTO_AUTH_CLEANUP_DIR="$project_dir"
            AUTO_AUTH_CLEANUP_ID="$AUTO_AUTH_EMAIL"
            [[ ${#AUTH_LOGIN_ENDPOINTS[@]} -gt 0 ]] && AUTO_AUTH_LOGIN_URL="${target_url}${AUTH_LOGIN_ENDPOINTS[0]}"
        fi
        unset AUTO_ZAP_USER AUTO_ZAP_EMAIL AUTO_ZAP_PASS
        [[ "$AUTO_AUTH_CREATED" == "true" ]] && return 0
    fi

    # WordPress
    if [[ "$AUTH_HINT" == "wordpress" || -f "$project_dir/wp-config.php" ]]; then
        log_detail "Attempting WordPress user creation via WP-CLI..."
        if wp user create "$AUTO_AUTH_USER" "$AUTO_AUTH_EMAIL" --user_pass="$AUTO_AUTH_PASS" --role=administrator --path="$project_dir" 2>&1; then
            log_ok "WordPress user created: $AUTO_AUTH_USER"
            AUTO_AUTH_CREATED=true
            AUTO_AUTH_CLEANUP_METHOD="wordpress"
            AUTO_AUTH_CLEANUP_DIR="$project_dir"
            AUTO_AUTH_CLEANUP_ID="$AUTO_AUTH_USER"
            AUTO_AUTH_LOGIN_URL="${target_url}/wp-login.php"
            AUTO_AUTH_LOGIN_TYPE="form"
        fi
        [[ "$AUTO_AUTH_CREATED" == "true" ]] && return 0
    fi

    # Rails/Devise
    if [[ "$AUTH_HINT" == "rails-devise" ]]; then
        log_detail "Attempting Rails/Devise user creation..."
        export AUTO_ZAP_EMAIL="$AUTO_AUTH_EMAIL"
        export AUTO_ZAP_PASS="$AUTO_AUTH_PASS"
        local ruby_code='User.create!(email: ENV["AUTO_ZAP_EMAIL"], password: ENV["AUTO_ZAP_PASS"], password_confirmation: ENV["AUTO_ZAP_PASS"])'
        if (cd "$project_dir" && bundle exec rails runner "$ruby_code" 2>&1); then
            log_ok "Rails/Devise user created: $AUTO_AUTH_EMAIL"
            AUTO_AUTH_CREATED=true
            AUTO_AUTH_USER="$AUTO_AUTH_EMAIL"
            AUTO_AUTH_CLEANUP_METHOD="rails"
            AUTO_AUTH_CLEANUP_DIR="$project_dir"
            AUTO_AUTH_CLEANUP_ID="$AUTO_AUTH_EMAIL"
            for ep in "${AUTH_LOGIN_ENDPOINTS[@]}"; do
                [[ "$ep" == "/users/sign_in" ]] && AUTO_AUTH_LOGIN_URL="${target_url}/users/sign_in" && AUTO_AUTH_LOGIN_TYPE="form" && break
            done
            [[ -z "$AUTO_AUTH_LOGIN_URL" && ${#AUTH_LOGIN_ENDPOINTS[@]} -gt 0 ]] && AUTO_AUTH_LOGIN_URL="${target_url}${AUTH_LOGIN_ENDPOINTS[0]}"
        fi
        unset AUTO_ZAP_EMAIL AUTO_ZAP_PASS
        [[ "$AUTO_AUTH_CREATED" == "true" ]] && return 0
    fi

    # Strategy 2: Registration endpoint probing
    if [[ ${#AUTH_REG_ENDPOINTS[@]} -gt 0 ]]; then
        log_detail "Attempting user registration via API endpoints..."
        for ep in "${AUTH_REG_ENDPOINTS[@]}"; do
            local reg_url="${target_url}${ep}"

            # Try JSON registrations with different field combinations
            for json_body in \
                "{\"username\":\"$AUTO_AUTH_USER\",\"email\":\"$AUTO_AUTH_EMAIL\",\"password\":\"$AUTO_AUTH_PASS\"}" \
                "{\"email\":\"$AUTO_AUTH_EMAIL\",\"password\":\"$AUTO_AUTH_PASS\",\"name\":\"$AUTO_AUTH_USER\"}" \
                "{\"email\":\"$AUTO_AUTH_EMAIL\",\"password\":\"$AUTO_AUTH_PASS\",\"password_confirmation\":\"$AUTO_AUTH_PASS\"}" \
                "{\"username\":\"$AUTO_AUTH_USER\",\"email\":\"$AUTO_AUTH_EMAIL\",\"password\":\"$AUTO_AUTH_PASS\",\"confirmPassword\":\"$AUTO_AUTH_PASS\"}"; do

                local http_code
                local response
                response=$(curl -sf -w "\n%{http_code}" --max-time 10 -X POST \
                    -H "Content-Type: application/json" \
                    -d "$json_body" \
                    "$reg_url" 2>/dev/null) || true
                http_code=$(echo "$response" | tail -1)
                local body
                body=$(echo "$response" | sed '$d')

                if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
                    # Determine which field was the login identifier
                    if echo "$json_body" | jq -e '.username' &>/dev/null && echo "$json_body" | jq -e '.email' &>/dev/null; then
                        # Has both — prefer email if email field was primary
                        if echo "$json_body" | grep -q '"email".*"password"'; then
                            AUTO_AUTH_USER="$AUTO_AUTH_EMAIL"
                        fi
                    elif echo "$json_body" | jq -e '.email' &>/dev/null; then
                        AUTO_AUTH_USER="$AUTO_AUTH_EMAIL"
                    fi

                    log_ok "User registered via $ep (HTTP $http_code)"
                    AUTO_AUTH_CREATED=true
                    AUTO_AUTH_LOGIN_TYPE="json"
                    AUTO_AUTH_CLEANUP_METHOD="api"
                    AUTO_AUTH_CLEANUP_DIR="$target_url"
                    AUTO_AUTH_CLEANUP_ID="$AUTO_AUTH_USER"

                    # Try to extract token for later cleanup
                    local token
                    token=$(echo "$body" | jq -r '.token // .access_token // .accessToken // empty' 2>/dev/null || echo "")
                    [[ -n "$token" ]] && AUTO_AUTH_CLEANUP_EXTRA="$token"

                    [[ ${#AUTH_LOGIN_ENDPOINTS[@]} -gt 0 ]] && AUTO_AUTH_LOGIN_URL="${target_url}${AUTH_LOGIN_ENDPOINTS[0]}"
                    return 0
                fi
            done

            # Try form-based registration
            local form_body
            form_body="username=$(urlencode "$AUTO_AUTH_USER")&email=$(urlencode "$AUTO_AUTH_EMAIL")&password=$(urlencode "$AUTO_AUTH_PASS")"
            local http_code
            http_code=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 -X POST \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "$form_body" \
                "$reg_url" 2>/dev/null) || true
            if [[ "$http_code" =~ ^[23][0-9][0-9]$ ]]; then
                log_ok "User registered via $ep (form, HTTP $http_code)"
                AUTO_AUTH_CREATED=true
                AUTO_AUTH_USER="$AUTO_AUTH_EMAIL"
                AUTO_AUTH_LOGIN_TYPE="form"
                AUTO_AUTH_CLEANUP_METHOD="api"
                AUTO_AUTH_CLEANUP_DIR="$target_url"
                AUTO_AUTH_CLEANUP_ID="$AUTO_AUTH_EMAIL"
                [[ ${#AUTH_LOGIN_ENDPOINTS[@]} -gt 0 ]] && AUTO_AUTH_LOGIN_URL="${target_url}${AUTH_LOGIN_ENDPOINTS[0]}"
                return 0
            fi
        done
    fi

    log_warn "Could not provision a temporary user automatically."
    log_warn "Tip: Use --auth-user/--auth-password to provide existing credentials."
    return 1
}

# ---- Auto-Auth: Remove temporary test user ----
remove_temp_user() {
    if [[ "$AUTO_AUTH_CREATED" != "true" || -z "$AUTO_AUTH_CLEANUP_METHOD" ]]; then return; fi

    log_step "Removing temporary test user..."

    local method="$AUTO_AUTH_CLEANUP_METHOD"
    local project_dir="$AUTO_AUTH_CLEANUP_DIR"
    local identifier="$AUTO_AUTH_CLEANUP_ID"
    local extra="$AUTO_AUTH_CLEANUP_EXTRA"

    case "$method" in
        django)
            local py_cmd="$extra"
            [[ -z "$py_cmd" ]] && py_cmd="python3"
            export AUTO_ZAP_DEL_USER="$identifier"
            local del_code="import os; from django.contrib.auth.models import User; User.objects.filter(username=os.environ['AUTO_ZAP_DEL_USER']).delete(); print('deleted')"
            local output
            output=$($py_cmd "$project_dir/manage.py" shell -c "$del_code" 2>&1) || true
            if echo "$output" | grep -q "deleted"; then
                log_ok "Django temp user removed."
            else
                log_warn "Django user cleanup may have failed."
            fi
            unset AUTO_ZAP_DEL_USER
            ;;
        laravel)
            export AUTO_ZAP_DEL_EMAIL="$identifier"
            local del_code='\\App\\Models\\User::where("email",env("AUTO_ZAP_DEL_EMAIL"))->delete(); echo "deleted";'
            local output
            output=$(php "$project_dir/artisan" tinker --execute="$del_code" 2>&1) || true
            if echo "$output" | grep -q "deleted"; then
                log_ok "Laravel temp user removed."
            else
                log_warn "Laravel user cleanup may have failed."
            fi
            unset AUTO_ZAP_DEL_EMAIL
            ;;
        wordpress)
            wp user delete "$identifier" --yes --path="$project_dir" 2>&1 || log_warn "WordPress user cleanup may have failed."
            log_ok "WordPress temp user removed."
            ;;
        rails)
            (cd "$project_dir" && AUTO_ZAP_DEL_EMAIL="$identifier" bundle exec rails runner 'User.find_by(email: ENV["AUTO_ZAP_DEL_EMAIL"])&.destroy!' 2>&1) || log_warn "Rails user cleanup may have failed."
            log_ok "Rails temp user removed."
            ;;
        api)
            local token="$extra"
            if [[ -n "$token" ]]; then
                for ep in /api/auth/user /api/user /api/users/me /api/auth/account; do
                    if curl -sf -X DELETE -H "Authorization: Bearer $token" --max-time 5 "${project_dir}${ep}" >/dev/null 2>&1; then
                        log_ok "API temp user removed via DELETE $ep"
                        return
                    fi
                done
            fi
            log_warn "Could not remove API-created temp user automatically."
            ;;
    esac
}

# ---- Helper: Load .env file ----
load_env_file() {
    local envfile="$1"
    if [[ -f "$envfile" ]]; then
        local count=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Strip comments and leading/trailing whitespace (without xargs to avoid quote issues)
            line="${line%%#*}"
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            if [[ -n "$line" && "$line" == *"="* ]]; then
                local key="${line%%=*}"
                local value="${line#*=}"
                value=$(echo "$value" | sed "s/^['\"]//;s/['\"]$//")
                if [[ -z "${!key:-}" ]]; then
                    export "$key=$value"
                    count=$((count + 1))
                fi
            fi
        done < "$envfile"
        if [[ $count -gt 0 ]]; then
            log_detail "Loaded $count variables from $(basename "$envfile")"
        fi
    fi
}

# ============================================================
# BANNER
# ============================================================
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  Auto-ZAP - Automated OWASP ZAP Security Scanner (Linux)${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# ============================================================
# STEP 0: Prerequisites
# ============================================================
log_step "STEP 0: Checking prerequisites..."

missing=()
command -v docker &>/dev/null || missing+=("docker")
command -v curl &>/dev/null   || missing+=("curl")
command -v jq &>/dev/null     || missing+=("jq")

if [[ ${#missing[@]} -gt 0 ]]; then
    log_err "Missing required tools: ${missing[*]}"
    log_detail "Install with: sudo apt install ${missing[*]}"
    exit 1
fi

# Check Docker is running
if ! docker info &>/dev/null; then
    log_err "Docker daemon is not running. Start it with: sudo systemctl start docker"
    exit 1
fi

log_ok "Prerequisites OK (docker, curl, jq)"
echo ""

# ============================================================
# STEP 0b: Load .auto-zap.json config (if present)
# ============================================================
load_config_file() {
    local config_path=".auto-zap.json"
    if [[ ! -f "$config_path" ]]; then
        return
    fi
    if ! jq empty "$config_path" 2>/dev/null; then
        log_err "Failed to parse .auto-zap.json - invalid JSON."
        log_detail "Fix: Validate your JSON at https://jsonlint.com"
        exit 1
    fi
    CONFIG_FILE="$config_path"
    log_ok "Loaded config from .auto-zap.json"

    # Apply config values (CLI flags take precedence)
    if [[ -z "$URL" ]]; then
        local cfg_url
        cfg_url=$(jq -r '.url // empty' "$config_path" 2>/dev/null)
        [[ -n "$cfg_url" ]] && URL="$cfg_url"
    fi
    if [[ "$PORT_FROM_CLI" != "true" ]]; then
        local cfg_port
        cfg_port=$(jq -r '.port // empty' "$config_path" 2>/dev/null)
        [[ -n "$cfg_port" ]] && PORT="$cfg_port"
    fi

    # Inject env vars from config
    local env_keys
    env_keys=$(jq -r '.env // {} | keys[]' "$config_path" 2>/dev/null)
    if [[ -n "$env_keys" ]]; then
        while IFS= read -r key; do
            if [[ -z "${!key:-}" ]]; then
                local val
                val=$(jq -r ".env[\"$key\"]" "$config_path" 2>/dev/null)
                export "$key=$val"
            fi
        done <<< "$env_keys"
        log_detail "Injected env vars from .auto-zap.json"
    fi
}
load_config_file

# ---- Validate scan mode ----
case "$SCAN_MODE" in
    auto|webapp|api|static) ;;
    *) log_err "Invalid --scan-mode: $SCAN_MODE (must be: auto, webapp, api, static)"; exit 1 ;;
esac
log_verbose "ScanMode: $SCAN_MODE | DryRun: $DRY_RUN | VerboseLog: $VERBOSE_LOG"

# ============================================================
# STEP 1: Detect framework (or use provided URL)
# ============================================================
if [[ -n "$URL" ]]; then
    log_step "STEPS 1-5: Skipped (using provided URL)"
    APP_PORT="${PORT:-${URL##*:}}"
    APP_PORT="${APP_PORT%%/*}"
    [[ "$APP_PORT" =~ ^[0-9]+$ ]] || APP_PORT=80
    log_ok "Target: $URL"
    echo ""

    # Verify target is reachable
    wait_for_url "$URL" 15 "target" || exit 1
    echo ""
else
    log_step "STEP 1: Detecting web app framework..."

    # Load .env files
    for envfile in .env.development.local .env.local .env.development .env; do
        load_env_file "$envfile"
    done

    # --- Monorepo detection ---
    detect_monorepo() {
        local is_monorepo=false
        local monorepo_type=""

        if [[ -f "turbo.json" ]]; then
            is_monorepo=true; monorepo_type="Turborepo"
        elif [[ -f "nx.json" ]]; then
            is_monorepo=true; monorepo_type="Nx"
        elif [[ -f "pnpm-workspace.yaml" ]]; then
            is_monorepo=true; monorepo_type="pnpm workspace"
        elif [[ -f "package.json" ]] && jq -e '.workspaces' package.json &>/dev/null; then
            is_monorepo=true; monorepo_type="npm/yarn workspace"
        fi

        if [[ "$is_monorepo" != "true" ]]; then
            return
        fi

        log_warn "Monorepo detected ($monorepo_type). Looking for web app subdirectory..."
        MONOREPO_ROOT=$(pwd)

        # Strategy 1: Config override via webAppDir
        if [[ -n "$CONFIG_FILE" ]]; then
            local web_app_dir
            web_app_dir=$(jq -r '.webAppDir // empty' "$CONFIG_FILE" 2>/dev/null)
            if [[ -n "$web_app_dir" && -d "$web_app_dir" ]]; then
                log_ok "Found web app at $web_app_dir (from .auto-zap.json)"
                cd "$web_app_dir" || exit 1
                return
            elif [[ -n "$web_app_dir" ]]; then
                log_err "webAppDir '$web_app_dir' specified in .auto-zap.json does not exist."
                exit 1
            fi
        fi

        # Strategy 2: Smart scan - find package.json files with web framework deps
        local web_keywords=("next" "nuxt" "@remix-run/react" "express" "fastify" "hono"
            "@nestjs/core" "@angular/core" "vue" "svelte" "@sveltejs/kit" "astro" "gatsby")
        local found_dir=""

        for candidate_dir in apps/*/package.json packages/*/package.json */package.json; do
            [[ -f "$candidate_dir" ]] || continue
            local pkg_dir
            pkg_dir=$(dirname "$candidate_dir")
            [[ "$pkg_dir" == "node_modules"* ]] && continue
            local pkg_content
            pkg_content=$(cat "$candidate_dir" 2>/dev/null) || continue
            for keyword in "${web_keywords[@]}"; do
                if echo "$pkg_content" | grep -q "\"$keyword\"" 2>/dev/null; then
                    found_dir="$pkg_dir"
                    break 2
                fi
            done
        done

        if [[ -n "$found_dir" ]]; then
            log_ok "Found web app at $found_dir (smart scan)"
            cd "$found_dir" || exit 1
            return
        fi

        # Strategy 3: Fallback to hardcoded list
        for sub_dir in apps/web apps/frontend apps/client apps/site packages/web packages/app; do
            if [[ -d "$sub_dir" && -f "$sub_dir/package.json" ]]; then
                log_ok "Found web app at $sub_dir"
                cd "$sub_dir" || exit 1
                return
            fi
        done

        log_err "Monorepo detected ($monorepo_type) but could not find a web application."
        log_detail "Fix: Create .auto-zap.json with \"webAppDir\": \"path/to/your/web/app\""
        log_detail "     Or cd into the web app directory and re-run."
        exit 1
    }
    detect_monorepo

    # --- Handle installDir from config ---
    if [[ -n "$CONFIG_FILE" ]]; then
        INSTALL_DIR=$(jq -r '.installDir // empty' "$CONFIG_FILE" 2>/dev/null)
    fi

    detect_pm() {
        if [[ -f "bun.lockb" ]]; then echo "bun"
        elif [[ -f "pnpm-lock.yaml" ]]; then echo "pnpm"
        elif [[ -f "yarn.lock" ]]; then echo "yarn"
        else echo "npm"
        fi
    }

    # --- Node.js ---
    if [[ -f "package.json" ]]; then
        PM=$(detect_pm)
        PKG=$(cat package.json)

        RUNTIME="Node.js"
        if echo "$PKG" | jq -e '.dependencies["next"] // .devDependencies["next"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Next.js"; APP_PORT=3000; START_COMMAND="$PM run dev"
        elif echo "$PKG" | jq -e '.dependencies["nuxt"] // .devDependencies["nuxt"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Nuxt"; APP_PORT=3000; START_COMMAND="$PM run dev"
        elif echo "$PKG" | jq -e '.dependencies["@remix-run/react"] // .devDependencies["@remix-run/react"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Remix"; APP_PORT=3000; START_COMMAND="$PM run dev"
        elif echo "$PKG" | jq -e '.dependencies["@nestjs/core"] // .devDependencies["@nestjs/core"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - NestJS"; APP_PORT=3000; START_COMMAND="$PM run start:dev"
        elif echo "$PKG" | jq -e '.dependencies["@sveltejs/kit"] // .devDependencies["@sveltejs/kit"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - SvelteKit"; APP_PORT=5173; START_COMMAND="$PM run dev"
        elif echo "$PKG" | jq -e '.dependencies["astro"] // .devDependencies["astro"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Astro"; APP_PORT=4321; START_COMMAND="$PM run dev"
        elif echo "$PKG" | jq -e '.dependencies["@angular/core"] // .devDependencies["@angular/core"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Angular"; APP_PORT=4200; START_COMMAND="$PM run start"
        elif echo "$PKG" | jq -e '.dependencies["gatsby"] // .devDependencies["gatsby"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Gatsby"; APP_PORT=8000; START_COMMAND="$PM run develop"
        elif echo "$PKG" | jq -e '.dependencies["vite"] // .devDependencies["vite"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Vite"; APP_PORT=5173; START_COMMAND="$PM run dev"
            # Parse port from vite.config
            for vconf in vite.config.ts vite.config.js vite.config.mts; do
                if [[ -f "$vconf" ]]; then
                    vite_port=$(sed -n 's/.*port\s*:\s*\([0-9]\+\).*/\1/p' "$vconf" 2>/dev/null | head -1) || true
                    [[ -n "${vite_port:-}" ]] && APP_PORT="$vite_port"
                    break
                fi
            done
        elif echo "$PKG" | jq -e '.dependencies["@adonisjs/core"] // .devDependencies["@adonisjs/core"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - AdonisJS"; APP_PORT=3333; START_COMMAND="node ace serve --watch"
        elif echo "$PKG" | jq -e '.dependencies["fastify"] // .devDependencies["fastify"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Fastify"; APP_PORT=3000; START_COMMAND="$PM start"
        elif echo "$PKG" | jq -e '.dependencies["hono"] // .devDependencies["hono"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Hono"; APP_PORT=3000; START_COMMAND="$PM start"
        elif echo "$PKG" | jq -e '.dependencies["express"] // .devDependencies["express"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Express"; APP_PORT=3000; START_COMMAND="$PM start"
        else
            FRAMEWORK="Node.js ($PM)"; APP_PORT=3000; START_COMMAND="$PM start"
        fi

        # Smart port detection from npm scripts
        if [[ "$PORT_FROM_CLI" != "true" ]]; then
            dev_script=$(echo "$PKG" | jq -r '.scripts.dev // .scripts.start // empty' 2>/dev/null) || true
            if [[ -n "${dev_script:-}" ]]; then
                script_port=$(echo "$dev_script" | sed -n 's/.*\(-p\|--port\)\s\+\([0-9]\+\).*/\2/p; s/.*PORT=\([0-9]\+\).*/\1/p' 2>/dev/null | head -1) || true
                [[ -n "${script_port:-}" ]] && APP_PORT="$script_port"
            fi
        fi

    # --- AdonisJS (standalone detection) ---
    elif [[ -f ".adonisrc.ts" ]] || [[ -f ".adonisrc.json" ]]; then
        FRAMEWORK="Node.js - AdonisJS"; RUNTIME="Node.js"; APP_PORT=3333; START_COMMAND="node ace serve --watch"

    # --- Python ---
    elif [[ -f "manage.py" ]]; then
        FRAMEWORK="Python - Django"; RUNTIME="Python"; APP_PORT=8000
        if command -v python3 &>/dev/null; then
            START_COMMAND="python3 manage.py runserver 0.0.0.0:8000"
        else
            START_COMMAND="python manage.py runserver 0.0.0.0:8000"
        fi
    elif [[ -f "pyproject.toml" ]] && grep -q "fastapi" pyproject.toml 2>/dev/null; then
        FRAMEWORK="Python - FastAPI"; RUNTIME="Python"; APP_PORT=8000; START_COMMAND="uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
    elif [[ -f "requirements.txt" ]] && grep -qi "fastapi" requirements.txt 2>/dev/null; then
        FRAMEWORK="Python - FastAPI"; RUNTIME="Python"; APP_PORT=8000; START_COMMAND="uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
    elif [[ -f "requirements.txt" ]] && grep -qi "flask" requirements.txt 2>/dev/null; then
        FRAMEWORK="Python - Flask"; RUNTIME="Python"; APP_PORT=5000; START_COMMAND="flask run --host 0.0.0.0"
    elif [[ -f "requirements.txt" ]] || [[ -f "pyproject.toml" ]]; then
        FRAMEWORK="Python"; RUNTIME="Python"; APP_PORT=8000
        if command -v python3 &>/dev/null; then
            START_COMMAND="python3 app.py"
        else
            START_COMMAND="python app.py"
        fi

    # --- .NET ---
    elif ls ./*.csproj &>/dev/null 2>&1; then
        FRAMEWORK=".NET - ASP.NET Core"; RUNTIME=".NET"; APP_PORT=5000; START_COMMAND="dotnet run --urls http://0.0.0.0:5000"

    # --- Java ---
    elif [[ -f "pom.xml" ]]; then
        RUNTIME="Java"; APP_PORT=8080
        if [[ -f "mvnw" ]]; then
            FRAMEWORK="Java - Spring Boot (Maven)"; START_COMMAND="./mvnw spring-boot:run"
        else
            FRAMEWORK="Java - Spring Boot (Maven)"; START_COMMAND="mvn spring-boot:run"
        fi
        # Parse Spring Boot port from application.properties / application.yml
        if [[ -f "src/main/resources/application.properties" ]]; then
            spring_port=$(sed -n 's/^server\.port\s*=\s*\([0-9]\+\).*/\1/p' src/main/resources/application.properties 2>/dev/null | head -1) || true
            [[ -n "${spring_port:-}" ]] && APP_PORT="$spring_port"
        fi
        if [[ -f "src/main/resources/application.yml" ]]; then
            spring_port=$(sed -n 's/.*port\s*:\s*\([0-9]\+\).*/\1/p' src/main/resources/application.yml 2>/dev/null | head -1) || true
            [[ -n "${spring_port:-}" ]] && APP_PORT="$spring_port"
        fi
    elif [[ -f "build.gradle" ]] || [[ -f "build.gradle.kts" ]]; then
        RUNTIME="Java"; APP_PORT=8080
        if [[ -f "gradlew" ]]; then
            FRAMEWORK="Java - Spring Boot (Gradle)"; START_COMMAND="./gradlew bootRun"
        else
            FRAMEWORK="Java - Spring Boot (Gradle)"; START_COMMAND="gradle bootRun"
        fi
        if [[ -f "src/main/resources/application.properties" ]]; then
            spring_port=$(sed -n 's/^server\.port\s*=\s*\([0-9]\+\).*/\1/p' src/main/resources/application.properties 2>/dev/null | head -1) || true
            [[ -n "${spring_port:-}" ]] && APP_PORT="$spring_port"
        fi
        if [[ -f "src/main/resources/application.yml" ]]; then
            spring_port=$(sed -n 's/.*port\s*:\s*\([0-9]\+\).*/\1/p' src/main/resources/application.yml 2>/dev/null | head -1) || true
            [[ -n "${spring_port:-}" ]] && APP_PORT="$spring_port"
        fi

    # --- PHP ---
    elif [[ -f "artisan" ]]; then
        FRAMEWORK="PHP - Laravel"; RUNTIME="PHP"; APP_PORT=8000; START_COMMAND="php artisan serve --host=0.0.0.0"
    elif [[ -f "symfony.lock" ]]; then
        FRAMEWORK="PHP - Symfony"; RUNTIME="PHP"; APP_PORT=8000; START_COMMAND="symfony server:start --port=8000"
    elif [[ -f "composer.json" ]]; then
        FRAMEWORK="PHP"; RUNTIME="PHP"; APP_PORT=8080; START_COMMAND="php -S 0.0.0.0:8080"

    # --- Ruby ---
    elif [[ -f "Gemfile" ]]; then
        FRAMEWORK="Ruby - Rails"; RUNTIME="Ruby"; APP_PORT=3000; START_COMMAND="bundle exec rails server -b 0.0.0.0"

    # --- Go ---
    elif [[ -f "go.mod" ]]; then
        FRAMEWORK="Go"; RUNTIME="Go"; APP_PORT=8080; START_COMMAND="go run ."

    # --- Rust ---
    elif [[ -f "Cargo.toml" ]]; then
        FRAMEWORK="Rust"; RUNTIME="Rust"; APP_PORT=8080; START_COMMAND="cargo run"

    # --- Elixir ---
    elif [[ -f "mix.exs" ]]; then
        RUNTIME="Elixir"
        if grep -q ":phoenix" mix.exs 2>/dev/null; then
            FRAMEWORK="Elixir - Phoenix"; APP_PORT=4000; START_COMMAND="mix phx.server"
        else
            FRAMEWORK="Elixir"; APP_PORT=4000; START_COMMAND="mix run --no-halt"
        fi

    # --- Deno ---
    elif [[ -f "deno.json" ]] || [[ -f "deno.jsonc" ]]; then
        FRAMEWORK="Deno"; RUNTIME="Deno"; APP_PORT=8000; START_COMMAND="deno task start"

    # --- Docker fallback ---
    elif [[ -f "Dockerfile" ]]; then
        APP_PORT=3000
        if grep -q "EXPOSE" Dockerfile 2>/dev/null; then
            APP_PORT=$(sed -n 's/^EXPOSE\s\+\([0-9]\+\).*/\1/p' Dockerfile 2>/dev/null | head -1) || true
            [[ -z "$APP_PORT" ]] && APP_PORT=3000
        fi
        FRAMEWORK="Docker"; RUNTIME="Docker"; START_COMMAND="docker build -t auto-zap-target . && docker run --rm -p $APP_PORT:$APP_PORT auto-zap-target"

    # --- Static ---
    elif [[ -f "index.html" ]]; then
        FRAMEWORK="Static HTML"; RUNTIME="Static"; APP_PORT=8080
        if command -v python3 &>/dev/null; then
            START_COMMAND="python3 -m http.server $APP_PORT"
        elif command -v npx &>/dev/null; then
            START_COMMAND="npx serve -l $APP_PORT"
        fi

    else
        log_err "Could not detect a web application framework."
        log_detail "Checked: package.json, manage.py, requirements.txt, pyproject.toml,"
        log_detail "  *.csproj, pom.xml, build.gradle, Gemfile, go.mod, Cargo.toml,"
        log_detail "  mix.exs, deno.json, bunfig.toml, Dockerfile, index.html"
        log_detail ""
        log_detail "Use --url to scan an already-running app."
        exit 1
    fi

    # Override port if specified via CLI, config, or .env
    if [[ -n "$PORT" && "$PORT" =~ ^[0-9]+$ ]]; then
        APP_PORT="$PORT"
        if [[ "$PORT_FROM_CLI" == "true" ]]; then
            log_detail "PORT=$APP_PORT from CLI"
        else
            log_detail "PORT=$APP_PORT from environment/config"
        fi
    fi

    # Override start command from config
    if [[ -n "$CONFIG_FILE" ]]; then
        cfg_command=$(jq -r '.command // empty' "$CONFIG_FILE" 2>/dev/null)
        [[ -n "${cfg_command:-}" ]] && START_COMMAND="$cfg_command" && log_detail "Using custom command from .auto-zap.json"
    fi

    URL="http://localhost:$APP_PORT"
    log_ok "Detected: $FRAMEWORK"
    log_detail "Port: $APP_PORT"
    log_detail "Command: $START_COMMAND"
    echo ""

    # ============================================================
    # STEP 2: Database
    # ============================================================
    DB_URL="${DATABASE_URL:-}"

    if [[ -n "$DB_URL" ]]; then
        log_step "STEP 2: Starting database..."

        if [[ "$DB_URL" == postgres://* ]] || [[ "$DB_URL" == postgresql://* ]]; then
            # Check if already running
            if nc -z localhost 5432 2>/dev/null || (echo >/dev/tcp/localhost/5432) 2>/dev/null; then
                log_ok "PostgreSQL already running on port 5432."
            elif [[ -f "docker-compose.yml" ]] || [[ -f "docker-compose.yaml" ]] || [[ -f "compose.yml" ]] || [[ -f "compose.yaml" ]]; then
                log_detail "Starting via Docker Compose..."
                docker compose up -d db postgres postgresql 2>/dev/null || docker-compose up -d db postgres postgresql 2>/dev/null || true
                COMPOSE_STARTED=true
                wait_for_tcp localhost 5432 60 "PostgreSQL"
            else
                log_detail "Starting standalone PostgreSQL container..."
                DB_CONTAINER="auto-zap-postgres-$$"
                docker run -d --name "$DB_CONTAINER" \
                    -e POSTGRES_USER=postgres \
                    -e POSTGRES_PASSWORD=postgres \
                    -e POSTGRES_DB=app \
                    -p 5432:5432 \
                    postgres:17-alpine >/dev/null
                wait_for_tcp localhost 5432 60 "PostgreSQL"
            fi

        elif [[ "$DB_URL" == mysql://* ]]; then
            if nc -z localhost 3306 2>/dev/null; then
                log_ok "MySQL already running on port 3306."
            else
                DB_CONTAINER="auto-zap-mysql-$$"
                docker run -d --name "$DB_CONTAINER" \
                    -e MYSQL_ROOT_PASSWORD=root \
                    -e MYSQL_DATABASE=app \
                    -p 3306:3306 \
                    mysql:8 >/dev/null
                wait_for_tcp localhost 3306 60 "MySQL"
            fi

        elif [[ "$DB_URL" == mongodb://* ]] || [[ "$DB_URL" == mongodb+srv://* ]]; then
            if nc -z localhost 27017 2>/dev/null; then
                log_ok "MongoDB already running on port 27017."
            else
                DB_CONTAINER="auto-zap-mongo-$$"
                docker run -d --name "$DB_CONTAINER" \
                    -p 27017:27017 \
                    mongo:7 >/dev/null
                wait_for_tcp localhost 27017 60 "MongoDB"
            fi
        fi
        echo ""
    else
        # Check for compose file with db service
        for cf in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
            if [[ -f "$cf" ]] && grep -qE '^\s+(db|postgres|mysql|mongo|redis):' "$cf" 2>/dev/null; then
                log_step "STEP 2: Starting Docker Compose services..."
                docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null || true
                COMPOSE_STARTED=true
                sleep 5
                log_ok "Docker Compose services started."
                echo ""
                break
            fi
        done
    fi

    # Redis check
    if [[ -n "${REDIS_URL:-}" ]] || grep -rq "redis" .env* 2>/dev/null; then
        if ! nc -z localhost 6379 2>/dev/null; then
            log_detail "Starting Redis container..."
            REDIS_CONTAINER="auto-zap-redis-$$"
            docker run -d --name "$REDIS_CONTAINER" -p 6379:6379 redis:7-alpine >/dev/null
            wait_for_tcp localhost 6379 30 "Redis"
        fi
    fi

    # ============================================================
    # STEP 3: Install dependencies
    # ============================================================
    if [[ "$SKIP_INSTALL" != "true" && -n "$FRAMEWORK" ]]; then
        log_step "STEP 3: Installing dependencies..."

        # Handle installDir from config (monorepo: install from root)
        install_cwd=""
        if [[ -n "$INSTALL_DIR" && -d "$INSTALL_DIR" ]]; then
            install_cwd=$(pwd)
            cd "$INSTALL_DIR" || true
            log_detail "Installing from $INSTALL_DIR"
        fi

        if [[ -f "package.json" ]]; then
            PM=$(detect_pm)
            if ! $PM install 2>&1; then
                log_warn "Dependency installation had errors (continuing anyway)."
            fi
        elif [[ -f "requirements.txt" ]]; then
            # Use venv if not already in one (avoids PEP 668 externally-managed-environment)
            if [[ -z "${VIRTUAL_ENV:-}" && ! -d ".venv" ]]; then
                log_detail "Creating Python virtual environment..."
                python3 -m venv .venv 2>&1 || log_warn "Failed to create venv."
            fi
            if [[ -d ".venv" && -z "${VIRTUAL_ENV:-}" ]]; then
                # shellcheck disable=SC1091
                source .venv/bin/activate 2>/dev/null || source .venv/Scripts/activate 2>/dev/null || true
                log_detail "Activated venv at .venv"
            fi
            pip install -r requirements.txt -q 2>&1 || log_warn "pip install had errors."
        elif [[ -f "pyproject.toml" ]]; then
            if command -v poetry &>/dev/null; then
                poetry install -q 2>&1 || log_warn "poetry install had errors."
            elif command -v uv &>/dev/null; then
                uv sync 2>&1 || log_warn "uv sync had errors."
            else
                # Use venv if not already in one
                if [[ -z "${VIRTUAL_ENV:-}" && ! -d ".venv" ]]; then
                    log_detail "Creating Python virtual environment..."
                    python3 -m venv .venv 2>&1 || log_warn "Failed to create venv."
                fi
                if [[ -d ".venv" && -z "${VIRTUAL_ENV:-}" ]]; then
                    # shellcheck disable=SC1091
                    source .venv/bin/activate 2>/dev/null || source .venv/Scripts/activate 2>/dev/null || true
                fi
                pip install -e . -q 2>&1 || log_warn "pip install had errors."
            fi
        elif ls ./*.csproj &>/dev/null 2>&1; then
            dotnet restore 2>&1 || log_warn "dotnet restore had errors."
        elif [[ -f "Gemfile" ]]; then
            bundle install 2>&1 || log_warn "bundle install had errors."
        elif [[ -f "composer.json" ]]; then
            composer install 2>&1 || log_warn "composer install had errors."
        elif [[ -f "go.mod" ]]; then
            go mod download 2>&1 || log_warn "go mod download had errors."
        fi

        # Return to app dir if we cd'd for installDir
        if [[ -n "$install_cwd" ]]; then
            cd "$install_cwd" || true
        fi

        log_ok "Dependencies installed."
        echo ""
    fi

    # ============================================================
    # STEP 4: Migrations
    # ============================================================
    MIGRATIONS_RAN=false

    if [[ -d "prisma" ]] && [[ -f "prisma/schema.prisma" ]]; then
        log_step "STEP 4: Running Prisma migrations..."
        PM=$(detect_pm 2>/dev/null || echo "npx")
        [[ "$PM" == "npx" ]] || PM="$PM exec"
        $PM prisma generate 2>&1 || log_warn "prisma generate had errors."
        $PM prisma db push --accept-data-loss 2>&1 || $PM prisma migrate deploy 2>&1 || log_warn "Prisma migration had errors."
        MIGRATIONS_RAN=true
    fi
    if [[ -f "drizzle.config.ts" ]] || [[ -f "drizzle.config.js" ]]; then
        log_step "STEP 4: Running Drizzle migrations..."
        npx drizzle-kit push 2>&1 || log_warn "Drizzle push had errors."
        MIGRATIONS_RAN=true
    fi
    if [[ -f "package.json" ]]; then
        PKG_TEXT=$(cat package.json 2>/dev/null)
        if echo "$PKG_TEXT" | grep -q '"typeorm"' 2>/dev/null; then
            log_step "STEP 4: Running TypeORM migrations..."
            npx typeorm migration:run -d ./data-source.ts 2>&1 || npx typeorm migration:run 2>&1 || log_warn "TypeORM migration had errors."
            MIGRATIONS_RAN=true
        fi
        if echo "$PKG_TEXT" | grep -q '"sequelize-cli"' 2>/dev/null || echo "$PKG_TEXT" | grep -q '"sequelize"' 2>/dev/null; then
            log_step "STEP 4: Running Sequelize migrations..."
            npx sequelize-cli db:migrate 2>&1 || log_warn "Sequelize migration had errors."
            MIGRATIONS_RAN=true
        fi
        if echo "$PKG_TEXT" | grep -q '"knex"' 2>/dev/null; then
            log_step "STEP 4: Running Knex migrations..."
            npx knex migrate:latest 2>&1 || log_warn "Knex migration had errors."
            MIGRATIONS_RAN=true
        fi
    fi
    if [[ -f "manage.py" ]]; then
        log_step "STEP 4: Running Django migrations..."
        python manage.py migrate 2>&1 || log_warn "Django migrate had errors."
        MIGRATIONS_RAN=true
    elif [[ -f "symfony.lock" ]] && [[ -f "bin/console" ]]; then
        log_step "STEP 4: Running Doctrine migrations..."
        php bin/console doctrine:migrations:migrate --no-interaction 2>&1 || log_warn "Doctrine migration had errors."
        MIGRATIONS_RAN=true
    elif ls ./*.csproj &>/dev/null 2>&1 && grep -q "EntityFrameworkCore" ./*.csproj 2>/dev/null; then
        log_step "STEP 4: Running EF Core migrations..."
        dotnet ef database update 2>&1 || log_warn "EF Core migration had errors."
        MIGRATIONS_RAN=true
    elif [[ -f "Gemfile" ]] && [[ -d "db/migrate" ]]; then
        log_step "STEP 4: Running Rails migrations..."
        bundle exec rails db:migrate 2>&1 || log_warn "Rails migration had errors."
        MIGRATIONS_RAN=true
    elif [[ -f "mix.exs" ]] && grep -q ":ecto" mix.exs 2>/dev/null; then
        log_step "STEP 4: Running Ecto migrations..."
        mix ecto.setup 2>&1 || log_warn "Ecto setup had errors."
        MIGRATIONS_RAN=true
    fi

    if [[ "$MIGRATIONS_RAN" == "true" ]]; then
        log_ok "Migrations complete."
        echo ""
    fi

    # ============================================================
    # STEP 4b: Start background services from config
    # ============================================================
    if [[ -n "$CONFIG_FILE" ]]; then
        svc_count=$(jq -r '.services // [] | length' "$CONFIG_FILE" 2>/dev/null)
        if [[ "${svc_count:-0}" -gt 0 ]]; then
            log_step "STEP 4b: Starting background services..."
            for i in $(seq 0 $((svc_count - 1))); do
                svc_cmd=$(jq -r ".services[$i].command" "$CONFIG_FILE" 2>/dev/null)
                svc_label=$(jq -r ".services[$i].label // .services[$i].command" "$CONFIG_FILE" 2>/dev/null)
                svc_wait=$(jq -r ".services[$i].waitFor // empty" "$CONFIG_FILE" 2>/dev/null)

                log_detail "Starting: $svc_label"
                eval "$svc_cmd" &>/dev/null &
                SERVICE_PIDS+=($!)

                if [[ -n "$svc_wait" ]]; then
                    svc_timeout=$(jq -r ".services[$i].timeout // 120" "$CONFIG_FILE" 2>/dev/null)
                    wait_for_url "$svc_wait" "$svc_timeout" "$svc_label" || log_warn "Service '$svc_label' did not become ready."
                fi
            done
            log_ok "Background services started."
            echo ""
        fi
    fi

    # ============================================================
    # STEP 5: Start application
    # ============================================================
    log_step "STEP 5: Starting web application..."
    log_detail "Command: $START_COMMAND"

    eval "$START_COMMAND" &>/dev/null &
    APP_PID=$!

    if ! wait_for_url "$URL" 180 "$FRAMEWORK"; then
        log_err "Application failed to start."
        log_detail "Check your start command: $START_COMMAND"
        exit 1
    fi
    echo ""
fi

# ---- Dry-run exit point ----
if [[ "$DRY_RUN" == "true" ]]; then
    echo ""
    log_dryrun "=== DRY RUN SUMMARY ==="
    log_dryrun "Framework       : ${FRAMEWORK:-None}"
    log_dryrun "Runtime         : ${RUNTIME:-None}"
    log_dryrun "Scan mode       : $SCAN_MODE"
    log_dryrun "Start command   : ${START_COMMAND:-N/A}"
    log_dryrun "Target URL      : ${URL:-http://localhost:$APP_PORT}"
    log_dryrun "ZAP mode        : Docker"
    log_dryrun "Auth            : $(if [[ -n "$AUTH_USER" || -n "$AUTH_TOKEN" ]]; then echo 'Yes'; elif [[ "$AUTO_AUTH" == "true" ]]; then echo 'Auto'; else echo 'None'; fi)"
    log_dryrun "Full scan       : $FULL_SCAN"
    log_dryrun ""
    log_dryrun "Would execute:"
    log_dryrun "  1. Start app: ${START_COMMAND:-N/A}"
    log_dryrun "  2. Start ZAP on port $ZAP_API_PORT"
    log_dryrun "  3. Configure context + technology filter"
    log_dryrun "  4. Import API specs (if found)"
    log_dryrun "  5. Run spider + active vulnerability scan"
    log_dryrun "  6. Generate reports"
    log_dryrun "  7. Cleanup all processes"
    log_ok "Dry run complete. No scanning performed."
    exit 0
fi

# ============================================================
# STEP 6: Start OWASP ZAP via Docker
# ============================================================
log_step "STEP 6: Starting OWASP ZAP via Docker on port $ZAP_API_PORT..."

# Check if ZAP port is available
if nc -z localhost "$ZAP_API_PORT" 2>/dev/null || (echo >/dev/tcp/localhost/"$ZAP_API_PORT") 2>/dev/null; then
    log_warn "Port $ZAP_API_PORT is in use. Finding a free port..."
    # Find a free port
    ZAP_API_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()" 2>/dev/null || echo $((ZAP_API_PORT + 1)))
    log_detail "Using port $ZAP_API_PORT"
fi

# Remove any existing container
docker rm -f "$ZAP_CONTAINER_NAME" >/dev/null 2>&1 || true

# Pull image
log_detail "Pulling ZAP Docker image (if needed)..."
docker pull "$ZAP_DOCKER_IMAGE" 2>&1 | tail -1

# Start ZAP container with host networking
log_detail "Starting ZAP container..."
docker run -d \
    --name "$ZAP_CONTAINER_NAME" \
    --network host \
    -v "$ORIGINAL_DIR:/zap/wrk:rw" \
    "$ZAP_DOCKER_IMAGE" \
    zap.sh -daemon -port "$ZAP_API_PORT" \
    -config api.key="$ZAP_API_KEY" \
    -config api.addrs.addr.name=.* \
    -config api.addrs.addr.regex=true \
    -config connection.timeoutInSecs=120 >/dev/null || {
    log_err "Failed to start ZAP Docker container."
    exit 1
}

wait_for_url "http://localhost:$ZAP_API_PORT" 120 "ZAP API" || exit 1
log_ok "ZAP is running on port $ZAP_API_PORT."
echo ""

# ============================================================
# STEP 7: Configure ZAP context
# ============================================================
log_step "STEP 7: Configuring ZAP context..."

CONTEXT_NAME="auto-zap-context"
CONTEXT_RESP=$(zap_api "/JSON/context/action/newContext/?contextName=$CONTEXT_NAME" 2>/dev/null) || true
CONTEXT_ID=$(echo "${CONTEXT_RESP:-}" | jq -r '.contextId' 2>/dev/null) || true

if [[ -z "$CONTEXT_ID" || "$CONTEXT_ID" == "null" ]]; then
    log_err "Failed to create ZAP context. Response: $CONTEXT_RESP"
    exit 1
fi

# Include target in context
INCLUDE_REGEX=$(urlencode "${URL}.*")
zap_api "/JSON/context/action/includeInContext/?contextName=$CONTEXT_NAME&regex=$INCLUDE_REGEX" >/dev/null

# Exclude common non-app paths (static assets)
for exclude in ".*\\.js$" ".*\\.css$" ".*\\.png$" ".*\\.jpg$" ".*\\.gif$" ".*\\.svg$" ".*\\.woff2?$" ".*\\.ico$" \
    ".*\\.webp$" ".*\\.avif$" ".*\\.mp4$" ".*\\.webm$" ".*\\.ttf$" ".*\\.otf$" ".*\\.eot$" ".*\\.map$" ".*\\.wasm$"; do
    ENCODED_EXCLUDE=$(urlencode "$exclude")
    zap_api "/JSON/context/action/excludeFromContext/?contextName=$CONTEXT_NAME&regex=$ENCODED_EXCLUDE" >/dev/null 2>&1 || true
done

# Exclude custom patterns from config
if [[ -n "$CONFIG_FILE" ]]; then
    excl_count=$(jq -r '.exclude // [] | length' "$CONFIG_FILE" 2>/dev/null)
    if [[ "${excl_count:-0}" -gt 0 ]]; then
        for i in $(seq 0 $((excl_count - 1))); do
            excl_pattern=$(jq -r ".exclude[$i]" "$CONFIG_FILE" 2>/dev/null)
            ENCODED_EXCLUDE=$(urlencode "$excl_pattern")
            zap_api "/JSON/context/action/excludeFromContext/?contextName=$CONTEXT_NAME&regex=$ENCODED_EXCLUDE" >/dev/null 2>&1 || true
        done
        log_detail "Applied $excl_count custom exclusion patterns from config."
    fi
fi

# Register anti-CSRF token names
for csrf_token in _csrf csrf_token _token authenticity_token csrfmiddlewaretoken __RequestVerificationToken X-CSRF-TOKEN _csrf_token; do
    ENCODED_TOKEN=$(urlencode "$csrf_token")
    zap_api "/JSON/acsrf/action/addOptionToken/?String=$ENCODED_TOKEN" >/dev/null 2>&1 || true
done
zap_api "/JSON/ascan/action/setOptionHandleAntiCSRFTokens/?Boolean=true" >/dev/null 2>&1 || true

log_ok "ZAP context configured (ID: $CONTEXT_ID)."
echo ""

# ============================================================
# STEP 8: Import API specs (if found)
# ============================================================
log_step "STEP 8: Checking for API specifications..."

API_SPEC_FOUND=false
for spec_path in "swagger.json" "swagger.yaml" "openapi.json" "openapi.yaml" "api-docs.json"; do
    SPEC_URL="$URL/$spec_path"
    if curl -sf -o /dev/null "$SPEC_URL" 2>/dev/null; then
        log_detail "Found OpenAPI spec at $SPEC_URL"
        ENCODED_SPEC=$(urlencode "$SPEC_URL")
        if zap_api "/JSON/openapi/action/importUrl/?url=$ENCODED_SPEC&contextId=$CONTEXT_ID" >/dev/null 2>&1; then
            API_SPEC_FOUND=true
            log_ok "OpenAPI spec imported."
        else
            log_warn "Found OpenAPI spec but failed to import it into ZAP."
        fi
        break
    fi
done

if [[ "$API_SPEC_FOUND" != "true" ]]; then
    log_detail "No API spec found (checked swagger.json, openapi.json, etc.)"
fi
echo ""

# ============================================================
# STEP 9a: Auto-Auth (detect, provision temp user)
# ============================================================
if [[ "$AUTO_AUTH" == "true" && -z "$AUTH_USER" && -z "$AUTH_TOKEN" ]]; then
    log_step "STEP 9a: Auto-auth — detecting authentication requirements..."
    detect_auth_requirement "$URL" "$ORIGINAL_DIR"

    if [[ "$AUTH_DETECTED" == "true" ]]; then
        log_ok "Authentication required — attempting to provision temp user..."
        if provision_temp_user "$URL" "$ORIGINAL_DIR"; then
            AUTH_USER="$AUTO_AUTH_USER"
            AUTH_PASSWORD="$AUTO_AUTH_PASS"
            AUTH_TYPE="$AUTO_AUTH_LOGIN_TYPE"
            [[ -n "$AUTO_AUTH_LOGIN_URL" ]] && AUTH_URL="$AUTO_AUTH_LOGIN_URL"
            log_ok "Auto-auth: temp user ready ($AUTH_USER) — proceeding with authenticated scan."
        else
            log_warn "Auto-auth: could not create temp user. Falling back to unauthenticated scan."
        fi
    else
        log_ok "Auto-auth: app does not appear to require authentication. Scanning unauthenticated."
    fi
    echo ""
fi

# ============================================================
# STEP 9b: Authentication (ZAP configuration)
# ============================================================
ZAP_USER_ID=""

if [[ -n "$AUTH_TOKEN" ]]; then
    log_step "STEP 9: Configuring Bearer token authentication..."
    if zap_api "/JSON/replacer/action/addRule/?description=AuthToken&enabled=true&matchType=REQ_HEADER&matchRegex=false&matchString=Authorization&replacement=Bearer%20$AUTH_TOKEN" >/dev/null 2>&1; then
        log_ok "Bearer token configured."
    else
        log_warn "Failed to configure Bearer token via replacer rule."
    fi
    echo ""
elif [[ -n "$AUTH_USER" && -n "$AUTH_PASSWORD" ]]; then
    log_step "STEP 9: Configuring form/JSON authentication..."
    log_detail "Auth user: $AUTH_USER"

    # Determine auth method
    AUTH_METHOD="${AUTH_TYPE:-json}"
    if [[ "$AUTH_METHOD" != "json" && "$AUTH_METHOD" != "form" ]]; then
        AUTH_METHOD="json"
    fi

    # Determine login URL
    LOGIN_URL="$AUTH_URL"
    if [[ -z "$LOGIN_URL" ]]; then
        # Auto-detect common login endpoints
        for login_path in /api/auth/login /api/login /auth/login /login /api/auth/signin /signin; do
            if curl -sf -o /dev/null --max-time 5 "${URL}${login_path}" 2>/dev/null; then
                LOGIN_URL="${URL}${login_path}"
                log_detail "Auto-detected login URL: $LOGIN_URL"
                break
            fi
        done
        if [[ -z "$LOGIN_URL" ]]; then
            LOGIN_URL="${URL}/api/auth/login"
            log_detail "Using default login URL: $LOGIN_URL"
        fi
    fi

    ENCODED_LOGIN_URL=$(urlencode "$LOGIN_URL")

    if [[ "$AUTH_METHOD" == "json" ]]; then
        LOGIN_BODY=$(urlencode '{"username":"{%username%}","password":"{%password%}"}')
        AUTH_CONFIG="loginUrl=${ENCODED_LOGIN_URL}&loginRequestData=${LOGIN_BODY}"
        zap_api "/JSON/authentication/action/setAuthenticationMethod/?contextId=$CONTEXT_ID&authMethodName=jsonBasedAuthentication&authMethodConfigParams=$AUTH_CONFIG" >/dev/null 2>&1 || log_warn "Failed to set JSON auth method."
    else
        LOGIN_BODY=$(urlencode "username={%username%}&password={%password%}")
        AUTH_CONFIG="loginUrl=${ENCODED_LOGIN_URL}&loginRequestData=${LOGIN_BODY}"
        zap_api "/JSON/authentication/action/setAuthenticationMethod/?contextId=$CONTEXT_ID&authMethodName=formBasedAuthentication&authMethodConfigParams=$AUTH_CONFIG" >/dev/null 2>&1 || log_warn "Failed to set form auth method."
    fi

    # Set logged-in / logged-out indicators
    LOGGED_IN_REGEX=$(urlencode '(?:dashboard|logout|signout|profile|account|welcome)')
    LOGGED_OUT_REGEX=$(urlencode '(?:login|signin|sign-in|unauthorized|401)')
    zap_api "/JSON/authentication/action/setLoggedInIndicator/?contextId=$CONTEXT_ID&loggedInIndicatorRegex=$LOGGED_IN_REGEX" >/dev/null 2>&1 || true
    zap_api "/JSON/authentication/action/setLoggedOutIndicator/?contextId=$CONTEXT_ID&loggedOutIndicatorRegex=$LOGGED_OUT_REGEX" >/dev/null 2>&1 || true

    # Create user in ZAP context
    USER_RESP=$(zap_api "/JSON/users/action/newUser/?contextId=$CONTEXT_ID&name=scanner-user" 2>/dev/null)
    ZAP_USER_ID=$(echo "$USER_RESP" | jq -r '.userId' 2>/dev/null)

    if [[ -n "$ZAP_USER_ID" && "$ZAP_USER_ID" != "null" ]]; then
        # Set credentials
        ENCODED_USER=$(urlencode "$AUTH_USER")
        ENCODED_PASS=$(urlencode "$AUTH_PASSWORD")
        CREDS="username=${ENCODED_USER}&password=${ENCODED_PASS}"
        zap_api "/JSON/users/action/setAuthenticationCredentials/?contextId=$CONTEXT_ID&userId=$ZAP_USER_ID&authCredentialsConfigParams=$CREDS" >/dev/null 2>&1 || true
        zap_api "/JSON/users/action/setUserEnabled/?contextId=$CONTEXT_ID&userId=$ZAP_USER_ID&enabled=true" >/dev/null 2>&1 || true

        # Enable forced user mode
        zap_api "/JSON/forcedUser/action/setForcedUser/?contextId=$CONTEXT_ID&userId=$ZAP_USER_ID" >/dev/null 2>&1 || true
        zap_api "/JSON/forcedUser/action/setForcedUserModeEnabled/?boolean=true" >/dev/null 2>&1 || true

        log_ok "Authentication configured: $AUTH_METHOD-based login at $LOGIN_URL"
    else
        log_warn "Failed to create ZAP user. Continuing with unauthenticated scanning."
    fi
    echo ""
else
    log_step "STEP 9: No authentication configured. Skipping."
    echo ""
fi

# ============================================================
# STEP 10: Configure scan policy
# ============================================================
log_step "STEP 10: Configuring scan policy..."

SCAN_POLICY_NAME="auto-zap-policy"

# Remove stale policy from prior run
zap_api "/JSON/ascan/action/removeScanPolicy/?scanPolicyName=$SCAN_POLICY_NAME" >/dev/null 2>&1 || true

# Create custom scan policy
POLICY_RESP=$(zap_api "/JSON/ascan/action/addScanPolicy/?scanPolicyName=$SCAN_POLICY_NAME" 2>/dev/null) || true
if [[ -n "$POLICY_RESP" ]] && echo "$POLICY_RESP" | jq -e '.Result == "OK"' &>/dev/null; then
    # Disable irrelevant scanners based on framework runtime
    DISABLE_IDS=""
    case "$RUNTIME" in
        Node.js|Deno|Python|PHP|Ruby|Go|Rust|Elixir)
            # Disable Java Spring rules (40042, 40045) and .NET rules (40028, 40029)
            DISABLE_IDS="40042,40045,40028,40029"
            ;;
        .NET)
            # Disable Java Spring rules
            DISABLE_IDS="40042,40045"
            ;;
        Java)
            # Disable .NET rules
            DISABLE_IDS="40028,40029"
            ;;
    esac

    if [[ -n "$DISABLE_IDS" ]]; then
        zap_api "/JSON/ascan/action/disableScanners/?ids=$DISABLE_IDS&scanPolicyName=$SCAN_POLICY_NAME" >/dev/null 2>&1 || true
        log_detail "Disabled irrelevant scan rules for $RUNTIME."
    fi

    # Set attack strength and alert threshold
    if [[ "$FULL_SCAN" == "true" ]]; then
        STRENGTH="HIGH"; THRESHOLD="LOW"; THREADS=5
    else
        STRENGTH="MEDIUM"; THRESHOLD="MEDIUM"; THREADS=2
    fi

    zap_api "/JSON/ascan/action/setOptionAttackStrength/?String=$STRENGTH" >/dev/null 2>&1 || true
    zap_api "/JSON/ascan/action/setOptionAlertThreshold/?String=$THRESHOLD" >/dev/null 2>&1 || true
    zap_api "/JSON/ascan/action/setOptionThreadPerHost/?Integer=$THREADS" >/dev/null 2>&1 || true

    log_ok "Scan policy configured: strength=$STRENGTH, threshold=$THRESHOLD, threads=$THREADS"
else
    log_warn "Could not create custom scan policy. Using ZAP default."
    SCAN_POLICY_NAME=""
fi
echo ""

# ============================================================
# PRE-SCAN SUMMARY
# ============================================================
echo -e "${WHITE}    Pre-Scan Configuration Summary${NC}"
echo "    --------------------------------------------------"
echo -e "    Framework    : ${WHITE}${FRAMEWORK:-Unknown}${NC}"
echo -e "    Target URL   : ${WHITE}$URL${NC}"
echo -e "    Port         : ${WHITE}$APP_PORT${NC}"
echo -e "    ZAP Source   : ${WHITE}Docker ($ZAP_DOCKER_IMAGE)${NC}"
[[ "$ZAP_API_PORT" -ne 8090 ]] && echo -e "    ZAP Port     : ${YELLOW}$ZAP_API_PORT (dynamic)${NC}"
echo -e "    Scan Mode    : ${WHITE}$(if [[ "$FULL_SCAN" == "true" ]]; then echo "Full (thorough)"; else echo "Baseline (quick)"; fi)${NC}"
[[ -n "$SCAN_POLICY_NAME" ]] && echo -e "    Scan Policy  : ${WHITE}$SCAN_POLICY_NAME${NC}"
[[ "$API_SPEC_FOUND" == "true" ]] && echo -e "    API Spec     : ${WHITE}Imported${NC}"
[[ -n "$AUTH_TOKEN" ]] && echo -e "    Auth         : ${WHITE}Bearer token${NC}"
[[ -n "$ZAP_USER_ID" && "$ZAP_USER_ID" != "null" ]] && echo -e "    Auth         : ${WHITE}${AUTH_TYPE:-json}-based ($AUTH_USER)${NC}"
[[ -n "$CONFIG_FILE" ]] && echo -e "    Config       : ${WHITE}.auto-zap.json${NC}"
[[ -n "$MONOREPO_ROOT" ]] && echo -e "    Monorepo     : ${WHITE}$MONOREPO_ROOT${NC}"
echo "    --------------------------------------------------"
echo ""

# ============================================================
# SCANNING
# ============================================================
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}     SCANNING: $URL${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# ---- Phase 1: Spider ----
log_step "Phase 1/3: Spidering (crawling the application)..."
SPIDER_URL=$(urlencode "$URL")
SPIDER_RESP=$(zap_api "/JSON/spider/action/scan/?url=$SPIDER_URL&maxChildren=0&recurse=true&subtreeOnly=false&contextName=$CONTEXT_NAME" 2>/dev/null) || true
SPIDER_ID=$(echo "${SPIDER_RESP:-}" | jq -r '.scan' 2>/dev/null) || true
if [[ -z "$SPIDER_ID" || "$SPIDER_ID" == "null" ]]; then
    log_err "Failed to start spider. ZAP may not be responding."
    exit 1
fi

SPIDER_TIMEOUT=$( [[ "$FULL_SCAN" == "true" ]] && echo 600 || echo 180 )
SPIDER_ELAPSED=0
while true; do
    SPIDER_STATUS=$(zap_api "/JSON/spider/view/status/?scanId=$SPIDER_ID" 2>/dev/null | jq -r '.status' 2>/dev/null) || true
    [[ -z "$SPIDER_STATUS" || "$SPIDER_STATUS" == "null" ]] && SPIDER_STATUS="0"
    printf "\r    Spider progress: %3s%%" "$SPIDER_STATUS"
    [[ "$SPIDER_STATUS" == "100" ]] && break
    sleep 3
    SPIDER_ELAPSED=$((SPIDER_ELAPSED + 3))
    if [[ $SPIDER_ELAPSED -ge $SPIDER_TIMEOUT ]]; then
        log_warn "Spider timed out after ${SPIDER_TIMEOUT}s. Continuing..."
        zap_api "/JSON/spider/action/stop/?scanId=$SPIDER_ID" >/dev/null 2>&1 || true
        break
    fi
done
echo ""
SPIDER_RESULTS=$(zap_api "/JSON/spider/view/results/?scanId=$SPIDER_ID" 2>/dev/null | jq '.results | length' 2>/dev/null) || SPIDER_RESULTS=0
log_ok "Spider found $SPIDER_RESULTS URLs."
echo ""

# ---- Phase 2: Ajax Spider ----
log_step "Phase 2/3: Ajax spider (JavaScript-rendered content)..."
AJAX_RESP=$(zap_api "/JSON/ajaxSpider/action/scan/?url=$SPIDER_URL&contextName=$CONTEXT_NAME" 2>/dev/null) || true

if [[ -n "$AJAX_RESP" ]]; then
    AJAX_TIMEOUT=$( [[ "$FULL_SCAN" == "true" ]] && echo 300 || echo 120 )
    AJAX_ELAPSED=0
    while true; do
        AJAX_STATUS=$(zap_api "/JSON/ajaxSpider/view/status/" 2>/dev/null | jq -r '.status' 2>/dev/null) || AJAX_STATUS="stopped"
        printf "\r    Ajax spider: %s" "$AJAX_STATUS"
        [[ "$AJAX_STATUS" == "stopped" ]] && break
        sleep 5
        AJAX_ELAPSED=$((AJAX_ELAPSED + 5))
        if [[ $AJAX_ELAPSED -ge $AJAX_TIMEOUT ]]; then
            zap_api "/JSON/ajaxSpider/action/stop/" >/dev/null 2>&1 || true
            break
        fi
    done
    echo ""
    AJAX_RESULTS=$(zap_api "/JSON/ajaxSpider/view/numberOfResults/" 2>/dev/null | jq -r '.numberOfResults' 2>/dev/null) || AJAX_RESULTS=0
    log_ok "Ajax spider found $AJAX_RESULTS additional resources."
else
    log_detail "Ajax spider not available (browser add-on may be missing)."
fi
echo ""

# ---- Phase 3: Active Scan ----
log_step "Phase 3/3: Active vulnerability scan..."
SCAN_PARAMS="url=$SPIDER_URL&recurse=true&inScopeOnly=false&contextId=$CONTEXT_ID"
[[ -n "$SCAN_POLICY_NAME" ]] && SCAN_PARAMS="${SCAN_PARAMS}&scanPolicyName=$SCAN_POLICY_NAME"
SCAN_RESP=$(zap_api "/JSON/ascan/action/scan/?$SCAN_PARAMS" 2>/dev/null) || true
SCAN_ID=$(echo "${SCAN_RESP:-}" | jq -r '.scan' 2>/dev/null) || true
if [[ -z "$SCAN_ID" || "$SCAN_ID" == "null" ]]; then
    log_err "Failed to start active scan. ZAP may not be responding."
    exit 1
fi

SCAN_TIMEOUT=$( [[ "$FULL_SCAN" == "true" ]] && echo 3600 || echo 1800 )
SCAN_ELAPSED=0
STALL_COUNT=0
LAST_PROGRESS=-1

while true; do
    SCAN_STATUS=$(zap_api "/JSON/ascan/view/status/?scanId=$SCAN_ID" 2>/dev/null | jq -r '.status' 2>/dev/null) || true
    [[ -z "$SCAN_STATUS" || "$SCAN_STATUS" == "null" ]] && SCAN_STATUS="0"
    printf "\r    Active scan: %3s%%" "$SCAN_STATUS"
    [[ "$SCAN_STATUS" == "100" ]] && break

    # Stall detection
    if [[ "$SCAN_STATUS" == "$LAST_PROGRESS" ]]; then
        STALL_COUNT=$((STALL_COUNT + 1))
        if [[ $STALL_COUNT -ge 60 ]]; then  # 5 minutes with no progress
            log_warn "Scan stalled at ${SCAN_STATUS}%. Stopping..."
            zap_api "/JSON/ascan/action/stop/?scanId=$SCAN_ID" >/dev/null 2>&1 || true
            break
        fi
    else
        STALL_COUNT=0
        LAST_PROGRESS="$SCAN_STATUS"
    fi

    sleep 5
    SCAN_ELAPSED=$((SCAN_ELAPSED + 5))
    if [[ $SCAN_ELAPSED -ge $SCAN_TIMEOUT ]]; then
        log_warn "Active scan timed out after ${SCAN_TIMEOUT}s."
        zap_api "/JSON/ascan/action/stop/?scanId=$SCAN_ID" >/dev/null 2>&1 || true
        break
    fi
done
echo ""
log_ok "Active scan complete."
echo ""

# ============================================================
# RESULTS
# ============================================================
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}     RESULTS${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# Set report paths
REPORT_PATH="${REPORT_PATH:-zap-report-$TIMESTAMP.html}"
JSON_PATH="${REPORT_PATH%.html}.json"
SARIF_PATH="${REPORT_PATH%.html}.sarif"

# Generate HTML report
log_step "Generating reports..."
zap_api "/OTHER/core/other/htmlreport/" > "$REPORT_PATH" 2>/dev/null
if [[ ! -s "$REPORT_PATH" ]]; then
    log_warn "HTML report is empty - ZAP may not have generated results."
else
    log_ok "HTML report: $REPORT_PATH"
fi

# Generate JSON alerts
ALERTS_JSON=$(zap_api "/JSON/alert/view/alerts/?start=0&count=9999" 2>/dev/null)
if [[ -z "$ALERTS_JSON" ]]; then
    log_warn "Failed to retrieve alerts from ZAP."
    ALERTS_JSON='{"alerts":[]}'
fi
echo "$ALERTS_JSON" | jq '.' > "$JSON_PATH" 2>/dev/null
if [[ ! -s "$JSON_PATH" ]]; then
    log_warn "JSON report is empty."
else
    log_ok "JSON report: $JSON_PATH"
fi

# Parse vulnerability counts (with error handling)
HIGH=$(echo "$ALERTS_JSON" | jq '[.alerts[] | select(.risk=="3" or .risk=="High")] | length' 2>/dev/null || echo "0")
MEDIUM=$(echo "$ALERTS_JSON" | jq '[.alerts[] | select(.risk=="2" or .risk=="Medium")] | length' 2>/dev/null || echo "0")
LOW=$(echo "$ALERTS_JSON" | jq '[.alerts[] | select(.risk=="1" or .risk=="Low")] | length' 2>/dev/null || echo "0")
INFO=$(echo "$ALERTS_JSON" | jq '[.alerts[] | select(.risk=="0" or .risk=="Informational")] | length' 2>/dev/null || echo "0")

# Ensure counts are numeric
[[ "$HIGH" =~ ^[0-9]+$ ]] || HIGH=0
[[ "$MEDIUM" =~ ^[0-9]+$ ]] || MEDIUM=0
[[ "$LOW" =~ ^[0-9]+$ ]] || LOW=0
[[ "$INFO" =~ ^[0-9]+$ ]] || INFO=0

# Generate SARIF report (if requested)
if [[ "$SARIF" == "true" ]]; then
    log_step "Generating SARIF report..."
    # Build SARIF JSON from ZAP alerts
    SARIF_JSON=$(echo "$ALERTS_JSON" | jq --arg target_url "$URL" '{
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OWASP ZAP",
                    "informationUri": "https://www.zaproxy.org/",
                    "rules": [(.alerts // []) | group_by(.pluginId // "unknown")[] | .[0] | {
                        "id": ((.pluginId // .alertRef // "unknown") | tostring),
                        "name": (.name // "Unknown"),
                        "shortDescription": {"text": (.name // "Unknown")},
                        "fullDescription": {"text": (.description // .name // "No description")},
                        "helpUri": ((.reference // "" | split("\n") | .[0] | gsub("^\\s+|\\s+$"; "")) | if . == "" then "https://www.zaproxy.org/" else . end)
                    }]
                }
            },
            "results": [(.alerts // [])[] | {
                "ruleId": ((.pluginId // .alertRef // "unknown") | tostring),
                "level": (if .risk == "High" or .risk == "3" then "error"
                         elif .risk == "Medium" or .risk == "2" then "warning"
                         else "note" end),
                "message": {"text": (.description // .name // "No description")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": (.url // $target_url)
                        }
                    }
                }]
            }]
        }]
    }' 2>/dev/null)

    if [[ -n "$SARIF_JSON" ]]; then
        echo "$SARIF_JSON" > "$SARIF_PATH"
        log_ok "SARIF report: $SARIF_PATH"
    else
        log_warn "Failed to generate SARIF report."
    fi
fi

echo ""
echo -e "${WHITE}    Vulnerability Summary${NC}"
echo "    --------------------------------------------------"
if [[ "$HIGH" -gt 0 ]]; then
    echo -e "    ${RED}HIGH:          $HIGH${NC}"
else
    echo -e "    HIGH:          $HIGH"
fi
if [[ "$MEDIUM" -gt 0 ]]; then
    echo -e "    ${YELLOW}MEDIUM:        $MEDIUM${NC}"
else
    echo -e "    MEDIUM:        $MEDIUM"
fi
echo "    LOW:           $LOW"
echo "    INFORMATIONAL: $INFO"
echo "    --------------------------------------------------"
echo ""
echo -e "    HTML Report  : ${WHITE}$REPORT_PATH${NC}"
echo -e "    JSON Report  : ${WHITE}$JSON_PATH${NC}"
[[ "$SARIF" == "true" && -s "$SARIF_PATH" ]] && echo -e "    SARIF Report : ${WHITE}$SARIF_PATH${NC}"
echo ""

# ============================================================
# EXIT CODE
# ============================================================
if [[ "$HIGH" -gt 0 ]]; then
    log_err "FAIL: Found $HIGH high severity vulnerabilities."
    exit 1
else
    log_ok "PASS: No high severity vulnerabilities found."
    exit 0
fi
