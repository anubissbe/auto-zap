#!/usr/bin/env bash
# ============================================================
# Auto-ZAP - Automated OWASP ZAP Security Scanner (Linux/macOS)
# Uses Docker-based ZAP for scanning web applications
# ============================================================
set -euo pipefail

# ---- Configuration ----
ZAP_API_PORT=8090
ZAP_API_KEY=$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' || uuidgen 2>/dev/null | tr -d '-' || echo "auto-zap-$(date +%s)")
ZAP_DOCKER_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
ZAP_CONTAINER_NAME="auto-zap-$$"
ORIGINAL_DIR=$(pwd)
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")

# ---- Defaults ----
URL=""
PORT=""
REPORT_PATH=""
FULL_SCAN=false
KEEP_DOCKER=false
SKIP_INSTALL=false
AUTH_USER=""
AUTH_PASSWORD=""
AUTH_URL=""
AUTH_TOKEN=""
AUTH_TYPE=""

# ---- State ----
APP_PID=""
DB_CONTAINER=""
REDIS_CONTAINER=""
COMPOSE_STARTED=false
FRAMEWORK=""
APP_PORT=3000
START_COMMAND=""

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

# ---- Parse arguments ----
while [[ $# -gt 0 ]]; do
    case $1 in
        --url|-u)           URL="$2"; shift 2 ;;
        --port|-p)          PORT="$2"; shift 2 ;;
        --report-path|-r)   REPORT_PATH="$2"; shift 2 ;;
        --full-scan|-f)     FULL_SCAN=true; shift ;;
        --keep-docker|-k)   KEEP_DOCKER=true; shift ;;
        --skip-install|-s)  SKIP_INSTALL=true; shift ;;
        --auth-user)        AUTH_USER="$2"; shift 2 ;;
        --auth-password)    AUTH_PASSWORD="$2"; shift 2 ;;
        --auth-url)         AUTH_URL="$2"; shift 2 ;;
        --auth-token)       AUTH_TOKEN="$2"; shift 2 ;;
        --auth-type)        AUTH_TYPE="$2"; shift 2 ;;
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
    python3 -c "import urllib.parse; print(urllib.parse.quote('$string', safe=''))" 2>/dev/null \
        || printf '%s' "$string" | jq -sRr @uri 2>/dev/null \
        || printf '%s' "$string"
}

# ---- Helper: Load .env file ----
load_env_file() {
    local envfile="$1"
    if [[ -f "$envfile" ]]; then
        local count=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            line=$(echo "$line" | sed 's/#.*$//' | xargs)
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
        elif echo "$PKG" | jq -e '.dependencies["fastify"] // .devDependencies["fastify"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Fastify"; APP_PORT=3000; START_COMMAND="$PM start"
        elif echo "$PKG" | jq -e '.dependencies["hono"] // .devDependencies["hono"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Hono"; APP_PORT=3000; START_COMMAND="$PM start"
        elif echo "$PKG" | jq -e '.dependencies["express"] // .devDependencies["express"]' &>/dev/null; then
            FRAMEWORK="Node.js ($PM) - Express"; APP_PORT=3000; START_COMMAND="$PM start"
        else
            FRAMEWORK="Node.js ($PM)"; APP_PORT=3000; START_COMMAND="$PM start"
        fi

    # --- Python ---
    elif [[ -f "manage.py" ]]; then
        FRAMEWORK="Python - Django"; APP_PORT=8000; START_COMMAND="python manage.py runserver 0.0.0.0:8000"
    elif [[ -f "pyproject.toml" ]] && grep -q "fastapi" pyproject.toml 2>/dev/null; then
        FRAMEWORK="Python - FastAPI"; APP_PORT=8000; START_COMMAND="uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
    elif [[ -f "requirements.txt" ]] && grep -qi "fastapi" requirements.txt 2>/dev/null; then
        FRAMEWORK="Python - FastAPI"; APP_PORT=8000; START_COMMAND="uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
    elif [[ -f "requirements.txt" ]] && grep -qi "flask" requirements.txt 2>/dev/null; then
        FRAMEWORK="Python - Flask"; APP_PORT=5000; START_COMMAND="flask run --host 0.0.0.0"
    elif [[ -f "requirements.txt" ]] || [[ -f "pyproject.toml" ]]; then
        FRAMEWORK="Python"; APP_PORT=8000; START_COMMAND="python app.py"

    # --- .NET ---
    elif ls ./*.csproj &>/dev/null 2>&1; then
        FRAMEWORK=".NET - ASP.NET Core"; APP_PORT=5000; START_COMMAND="dotnet run --urls http://0.0.0.0:5000"

    # --- Java ---
    elif [[ -f "pom.xml" ]]; then
        if [[ -f "mvnw" ]]; then
            FRAMEWORK="Java - Spring Boot (Maven)"; APP_PORT=8080; START_COMMAND="./mvnw spring-boot:run"
        else
            FRAMEWORK="Java - Spring Boot (Maven)"; APP_PORT=8080; START_COMMAND="mvn spring-boot:run"
        fi
    elif [[ -f "build.gradle" ]] || [[ -f "build.gradle.kts" ]]; then
        if [[ -f "gradlew" ]]; then
            FRAMEWORK="Java - Spring Boot (Gradle)"; APP_PORT=8080; START_COMMAND="./gradlew bootRun"
        else
            FRAMEWORK="Java - Spring Boot (Gradle)"; APP_PORT=8080; START_COMMAND="gradle bootRun"
        fi

    # --- PHP ---
    elif [[ -f "artisan" ]]; then
        FRAMEWORK="PHP - Laravel"; APP_PORT=8000; START_COMMAND="php artisan serve --host=0.0.0.0"
    elif [[ -f "symfony.lock" ]]; then
        FRAMEWORK="PHP - Symfony"; APP_PORT=8000; START_COMMAND="symfony server:start --port=8000"
    elif [[ -f "composer.json" ]]; then
        FRAMEWORK="PHP"; APP_PORT=8080; START_COMMAND="php -S 0.0.0.0:8080"

    # --- Ruby ---
    elif [[ -f "Gemfile" ]]; then
        FRAMEWORK="Ruby - Rails"; APP_PORT=3000; START_COMMAND="bundle exec rails server -b 0.0.0.0"

    # --- Go ---
    elif [[ -f "go.mod" ]]; then
        FRAMEWORK="Go"; APP_PORT=8080; START_COMMAND="go run ."

    # --- Rust ---
    elif [[ -f "Cargo.toml" ]]; then
        FRAMEWORK="Rust"; APP_PORT=8080; START_COMMAND="cargo run"

    # --- Elixir ---
    elif [[ -f "mix.exs" ]]; then
        if grep -q ":phoenix" mix.exs 2>/dev/null; then
            FRAMEWORK="Elixir - Phoenix"; APP_PORT=4000; START_COMMAND="mix phx.server"
        else
            FRAMEWORK="Elixir"; APP_PORT=4000; START_COMMAND="mix run --no-halt"
        fi

    # --- Deno ---
    elif [[ -f "deno.json" ]] || [[ -f "deno.jsonc" ]]; then
        FRAMEWORK="Deno"; APP_PORT=8000; START_COMMAND="deno task start"

    # --- Docker fallback ---
    elif [[ -f "Dockerfile" ]]; then
        APP_PORT=3000
        if grep -q "EXPOSE" Dockerfile 2>/dev/null; then
            APP_PORT=$(grep -oP 'EXPOSE\s+\K\d+' Dockerfile | head -1)
        fi
        FRAMEWORK="Docker"; START_COMMAND="docker build -t auto-zap-target . && docker run --rm -p $APP_PORT:$APP_PORT auto-zap-target"

    # --- Static ---
    elif [[ -f "index.html" ]]; then
        FRAMEWORK="Static HTML"; APP_PORT=8080
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

    # Override port if specified
    [[ -n "$PORT" ]] && APP_PORT="$PORT"

    # Check PORT env var from .env
    if [[ -z "$PORT" && -n "${PORT_ENV:-}" ]]; then
        APP_PORT="$PORT_ENV"
        log_detail "PORT=$APP_PORT from environment"
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

        if [[ -f "package.json" ]]; then
            PM=$(detect_pm)
            $PM install 2>&1 | tail -3
        elif [[ -f "requirements.txt" ]]; then
            pip install -r requirements.txt -q 2>&1 | tail -3
        elif [[ -f "pyproject.toml" ]]; then
            if command -v poetry &>/dev/null; then
                poetry install -q 2>&1 | tail -3
            elif command -v uv &>/dev/null; then
                uv sync 2>&1 | tail -3
            else
                pip install -e . -q 2>&1 | tail -3
            fi
        elif ls ./*.csproj &>/dev/null 2>&1; then
            dotnet restore 2>&1 | tail -3
        elif [[ -f "Gemfile" ]]; then
            bundle install 2>&1 | tail -3
        elif [[ -f "composer.json" ]]; then
            composer install 2>&1 | tail -3
        elif [[ -f "go.mod" ]]; then
            go mod download 2>&1 | tail -3
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
        $PM prisma generate 2>&1 | tail -3
        $PM prisma db push --accept-data-loss 2>&1 | tail -3 || $PM prisma migrate deploy 2>&1 | tail -3 || true
        MIGRATIONS_RAN=true
    elif [[ -f "drizzle.config.ts" ]] || [[ -f "drizzle.config.js" ]]; then
        log_step "STEP 4: Running Drizzle migrations..."
        npx drizzle-kit push 2>&1 | tail -3 || true
        MIGRATIONS_RAN=true
    elif [[ -f "manage.py" ]]; then
        log_step "STEP 4: Running Django migrations..."
        python manage.py migrate 2>&1 | tail -3 || true
        MIGRATIONS_RAN=true
    elif ls ./*.csproj &>/dev/null 2>&1 && grep -q "EntityFrameworkCore" ./*.csproj 2>/dev/null; then
        log_step "STEP 4: Running EF Core migrations..."
        dotnet ef database update 2>&1 | tail -3 || true
        MIGRATIONS_RAN=true
    elif [[ -f "Gemfile" ]] && [[ -d "db/migrate" ]]; then
        log_step "STEP 4: Running Rails migrations..."
        bundle exec rails db:migrate 2>&1 | tail -3 || true
        MIGRATIONS_RAN=true
    elif [[ -f "mix.exs" ]] && grep -q ":ecto" mix.exs 2>/dev/null; then
        log_step "STEP 4: Running Ecto migrations..."
        mix ecto.setup 2>&1 | tail -3 || true
        MIGRATIONS_RAN=true
    fi

    if [[ "$MIGRATIONS_RAN" == "true" ]]; then
        log_ok "Migrations complete."
        echo ""
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
    -config connection.timeoutInSecs=120 >/dev/null

if [[ $? -ne 0 ]]; then
    log_err "Failed to start ZAP Docker container."
    exit 1
fi

wait_for_url "http://localhost:$ZAP_API_PORT" 120 "ZAP API" || exit 1
log_ok "ZAP is running on port $ZAP_API_PORT."
echo ""

# ============================================================
# STEP 7: Configure ZAP context
# ============================================================
log_step "STEP 7: Configuring ZAP context..."

CONTEXT_NAME="auto-zap-context"
CONTEXT_RESP=$(zap_api "/JSON/context/action/newContext/?contextName=$CONTEXT_NAME")
CONTEXT_ID=$(echo "$CONTEXT_RESP" | jq -r '.contextId')

# Include target in context
ENCODED_URL=$(urlencode "$URL")
INCLUDE_REGEX=$(urlencode "${URL}.*")
zap_api "/JSON/context/action/includeInContext/?contextName=$CONTEXT_NAME&regex=$INCLUDE_REGEX" >/dev/null

# Exclude common non-app paths
for exclude in ".*\\.js$" ".*\\.css$" ".*\\.png$" ".*\\.jpg$" ".*\\.gif$" ".*\\.svg$" ".*\\.woff2?$" ".*\\.ico$"; do
    ENCODED_EXCLUDE=$(urlencode "$exclude")
    zap_api "/JSON/context/action/excludeFromContext/?contextName=$CONTEXT_NAME&regex=$ENCODED_EXCLUDE" >/dev/null 2>&1 || true
done

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
        zap_api "/JSON/openapi/action/importUrl/?url=$ENCODED_SPEC&contextId=$CONTEXT_ID" >/dev/null 2>&1 || true
        API_SPEC_FOUND=true
        log_ok "OpenAPI spec imported."
        break
    fi
done

if [[ "$API_SPEC_FOUND" != "true" ]]; then
    log_detail "No API spec found (checked swagger.json, openapi.json, etc.)"
fi
echo ""

# ============================================================
# STEP 9: Authentication (if provided)
# ============================================================
if [[ -n "$AUTH_TOKEN" ]]; then
    log_step "STEP 9: Configuring Bearer token authentication..."
    HEADER_ENCODED=$(urlencode "Authorization: Bearer $AUTH_TOKEN")
    zap_api "/JSON/replacer/action/addRule/?description=AuthToken&enabled=true&matchType=REQ_HEADER&matchRegex=false&matchString=Authorization&replacement=Bearer%20$AUTH_TOKEN" >/dev/null 2>&1 || true
    log_ok "Bearer token configured."
    echo ""
elif [[ -n "$AUTH_USER" && -n "$AUTH_PASSWORD" ]]; then
    log_step "STEP 9: Configuring authentication..."
    log_detail "Auth user: $AUTH_USER"
    # Note: Full form/JSON auth requires ZAP script authentication configuration
    # For CI use, Bearer token is recommended
    log_warn "Form/JSON auth requires manual ZAP script configuration. Use --auth-token for CI."
    echo ""
else
    log_step "STEP 9: No authentication configured. Skipping."
    echo ""
fi

# ============================================================
# PRE-SCAN SUMMARY
# ============================================================
echo -e "${WHITE}    Pre-Scan Configuration Summary${NC}"
echo "    --------------------------------------------------"
echo -e "    Framework    : ${WHITE}$FRAMEWORK${NC}"
echo -e "    Target URL   : ${WHITE}$URL${NC}"
echo -e "    Port         : ${WHITE}$APP_PORT${NC}"
echo -e "    ZAP Source   : ${WHITE}Docker ($ZAP_DOCKER_IMAGE)${NC}"
[[ "$ZAP_API_PORT" -ne 8090 ]] && echo -e "    ZAP Port     : ${YELLOW}$ZAP_API_PORT (dynamic)${NC}"
echo -e "    Scan Mode    : ${WHITE}$(if [[ "$FULL_SCAN" == "true" ]]; then echo "Full (thorough)"; else echo "Baseline (quick)"; fi)${NC}"
[[ "$API_SPEC_FOUND" == "true" ]] && echo -e "    API Spec     : ${WHITE}Imported${NC}"
[[ -n "$AUTH_TOKEN" ]] && echo -e "    Auth         : ${WHITE}Bearer token${NC}"
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
SPIDER_RESP=$(zap_api "/JSON/spider/action/scan/?url=$SPIDER_URL&maxChildren=0&recurse=true&subtreeOnly=false&contextName=$CONTEXT_NAME")
SPIDER_ID=$(echo "$SPIDER_RESP" | jq -r '.scan')

SPIDER_TIMEOUT=$((FULL_SCAN == true ? 600 : 180))
SPIDER_ELAPSED=0
while true; do
    SPIDER_STATUS=$(zap_api "/JSON/spider/view/status/?scanId=$SPIDER_ID" | jq -r '.status')
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
SPIDER_RESULTS=$(zap_api "/JSON/spider/view/results/?scanId=$SPIDER_ID" | jq '.results | length')
log_ok "Spider found $SPIDER_RESULTS URLs."
echo ""

# ---- Phase 2: Ajax Spider ----
log_step "Phase 2/3: Ajax spider (JavaScript-rendered content)..."
AJAX_RESP=$(zap_api "/JSON/ajaxSpider/action/scan/?url=$SPIDER_URL&contextName=$CONTEXT_NAME" 2>/dev/null) || true

if [[ -n "$AJAX_RESP" ]]; then
    AJAX_TIMEOUT=$((FULL_SCAN == true ? 300 : 120))
    AJAX_ELAPSED=0
    while true; do
        AJAX_STATUS=$(zap_api "/JSON/ajaxSpider/view/status/" | jq -r '.status')
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
    AJAX_RESULTS=$(zap_api "/JSON/ajaxSpider/view/numberOfResults/" | jq -r '.numberOfResults')
    log_ok "Ajax spider found $AJAX_RESULTS additional resources."
else
    log_detail "Ajax spider not available (browser add-on may be missing)."
fi
echo ""

# ---- Phase 3: Active Scan ----
log_step "Phase 3/3: Active vulnerability scan..."
SCAN_RESP=$(zap_api "/JSON/ascan/action/scan/?url=$SPIDER_URL&recurse=true&inScopeOnly=false&contextId=$CONTEXT_ID")
SCAN_ID=$(echo "$SCAN_RESP" | jq -r '.scan')

SCAN_TIMEOUT=$((FULL_SCAN == true ? 3600 : 1800))
SCAN_ELAPSED=0
STALL_COUNT=0
LAST_PROGRESS=-1

while true; do
    SCAN_STATUS=$(zap_api "/JSON/ascan/view/status/?scanId=$SCAN_ID" | jq -r '.status')
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

# Generate HTML report
log_step "Generating reports..."
zap_api "/OTHER/core/other/htmlreport/" > "$REPORT_PATH" 2>/dev/null
log_ok "HTML report: $REPORT_PATH"

# Generate JSON alerts
ALERTS_JSON=$(zap_api "/JSON/alert/view/alerts/?start=0&count=9999")
echo "$ALERTS_JSON" | jq '.' > "$JSON_PATH" 2>/dev/null
log_ok "JSON report: $JSON_PATH"

# Parse vulnerability counts
HIGH=$(echo "$ALERTS_JSON" | jq '[.alerts[] | select(.risk=="3" or .risk=="High")] | length')
MEDIUM=$(echo "$ALERTS_JSON" | jq '[.alerts[] | select(.risk=="2" or .risk=="Medium")] | length')
LOW=$(echo "$ALERTS_JSON" | jq '[.alerts[] | select(.risk=="1" or .risk=="Low")] | length')
INFO=$(echo "$ALERTS_JSON" | jq '[.alerts[] | select(.risk=="0" or .risk=="Informational")] | length')

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
