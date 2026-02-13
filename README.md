# Auto-ZAP

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Auto--ZAP-blue?logo=github)](https://github.com/marketplace/actions/auto-zap-security-scanner)
[![CI Pipeline](https://github.com/anubissbe/auto-zap/actions/workflows/ci.yml/badge.svg)](https://github.com/anubissbe/auto-zap/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Fully automated OWASP ZAP security scanner for web applications.**

Drop it into any project, and Auto-ZAP detects your framework, starts your database, installs dependencies, launches your app, runs OWASP ZAP, and generates vulnerability reports. No configuration required.

## Features

- **Zero-config** - Detects 13 runtimes and 30+ frameworks automatically
- **Cross-platform** - Windows (PowerShell), Linux/macOS (Bash) with local ZAP or Docker
- **GitHub Action** - Use as `anubissbe/auto-zap@v1` in any workflow
- **Full pipeline** - Database provisioning, dependency install, migrations, app startup, scan, reports
- **Authenticated scanning** - Form, JSON, or Bearer token auth with auto-detection
- **Auto-auth** - Automatically creates temp test users for authenticated scanning (`--auto-auth`)
- **Multiple reports** - HTML, JSON, and SARIF output formats
- **CI-ready** - Exit code 1 on HIGH severity findings, artifact-ready reports

---

## Quick Start

### GitHub Actions

```yaml
- uses: anubissbe/auto-zap@v1
```

That's it. Auto-ZAP detects your framework, starts your app, scans it, and outputs vulnerability counts. Add options as needed:

```yaml
- uses: anubissbe/auto-zap@v1
  id: scan
  with:
    full-scan: true
    auth-token: ${{ secrets.AUTH_TOKEN }}

- run: echo "Found ${{ steps.scan.outputs.high-count }} HIGH severity issues"
```

### Linux / macOS

```bash
chmod +x auto-zap.sh
./auto-zap.sh                                    # Auto-detect everything
./auto-zap.sh --url http://localhost:3000         # Scan a specific URL
./auto-zap.sh --full-scan --auth-token "eyJ..."   # Full scan with auth
./auto-zap.sh --auto-auth                         # Auto-create temp user + scan
```

Requires curl and jq. ZAP runs locally (Java) or via Docker — auto-detected.

### Windows

```powershell
.\auto-zap.ps1                                           # Auto-detect everything
.\auto-zap.ps1 -Url http://localhost:3000                 # Scan a specific URL
.\auto-zap.ps1 -FullScan -AuthUser admin -AuthPassword p  # Full scan with auth
.\auto-zap.ps1 -AutoAuth                                    # Auto-create temp user + scan
.\auto-zap.ps1 -UseDockerZap                              # Use Docker-based ZAP
```

---

## How It Works

Auto-ZAP performs a complete security scan pipeline in 11 steps:

| Step | What happens |
|------|-------------|
| **0** | Checks prerequisites (ZAP, Java, Docker) |
| **1** | Detects your web framework and configuration |
| **2** | Starts database containers (PostgreSQL, MySQL, MongoDB, MSSQL, Redis) |
| **3** | Installs dependencies (npm, yarn, pnpm, bun, pip, poetry, uv, composer, etc.) |
| **4** | Runs database migrations (Prisma, Drizzle, Django, TypeORM, Knex, Sequelize, EF Core) |
| **5** | Starts your web application |
| **6** | Launches OWASP ZAP (local or Docker) |
| **7** | Configures ZAP context, technology stack, and exclusions |
| **8** | Imports OpenAPI/Swagger/GraphQL specs automatically |
| **9** | Configures authenticated scanning (form, JSON, or bearer token) |
| **10** | Runs spider + Ajax spider + active vulnerability scan |
| **11** | Generates reports and cleans up everything |

---

## Supported Frameworks

Auto-ZAP detects **13 runtimes** and **30+ frameworks** automatically:

### Node.js
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Next.js | 3000 | `"next"` in package.json |
| Nuxt | 3000 | `"nuxt"` in package.json |
| Remix | 3000 | `"@remix-run"` in package.json |
| NestJS | 3000 | `"@nestjs/core"` in package.json |
| AdonisJS | 3333 | `.adonisrc.ts` file |
| Express | 3000 | `"express"` in package.json |
| Fastify | 3000 | `"fastify"` in package.json |
| Hono | 3000 | `"hono"` in package.json |
| Vite | 5173 | `"vite"` in package.json (reads port from vite.config) |
| SvelteKit | 5173 | `"@sveltejs/kit"` in package.json |
| Astro | 4321 | `"astro"` in package.json |
| Gatsby | 8000 | `"gatsby"` in package.json |
| Angular | 4200 | `"@angular"` in package.json |

**Package managers:** npm, yarn, pnpm, bun (auto-detected from lockfiles)
**ORMs:** Prisma, Drizzle, TypeORM, Knex, Sequelize (migrations auto-detected)

### Python
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Django | 8000 | `manage.py` file |
| FastAPI | 8000 | `fastapi` or `uvicorn` in requirements |
| Flask | 5000 | `flask` in requirements |

**Package managers:** pip, Poetry, pipenv, UV (auto-detected from lockfiles)

### .NET
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| ASP.NET Core | 5000 | `*.csproj` file (reads port from launchSettings.json) |

**ORM:** Entity Framework Core (migrations auto-detected)

### Java
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Spring Boot (Maven) | 8080 | `pom.xml` (reads port from application.properties/yml) |
| Spring Boot (Gradle) | 8080 | `build.gradle` / `build.gradle.kts` |

### PHP
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Laravel | 8000 | `artisan` file |
| Symfony | 8000 | `symfony.lock` file |
| WordPress | 8080 | `wp-config.php` file |
| Generic PHP | 8080 | `composer.json` or `*.php` files |

### Ruby
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Rails | 3000 | `Gemfile` (migrations auto-detected) |

### Go
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Generic (gin, echo, fiber, chi) | 8080 | `go.mod` file |

### Rust
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Generic (Actix, Rocket, Axum) | 8080 | `Cargo.toml` file |

### Elixir
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Phoenix | 4000 | `mix.exs` with `:phoenix` dependency |

**ORM:** Ecto (migrations auto-detected via `mix ecto.setup`)

### Deno
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Generic | 8000 | `deno.json` / `deno.jsonc` (reads tasks) |

### Others
| Type | Default Port | Detection |
|------|-------------|-----------|
| Bun native | 3000 | `bunfig.toml` without `package.json` |
| Docker | From EXPOSE | `Dockerfile` (fallback when no other framework detected) |
| Static HTML | 8080 | `index.html` (served via Python or npx serve) |

---

## GitHub Actions

### Basic Usage

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anubissbe/auto-zap@v1
```

### With Options

```yaml
- name: Run security scan
  id: scan
  uses: anubissbe/auto-zap@v1
  with:
    url: 'http://localhost:3000'
    full-scan: true
    auth-token: ${{ secrets.AUTH_TOKEN }}
    working-directory: './apps/web'

- name: Check results
  run: |
    echo "High: ${{ steps.scan.outputs.high-count }}"
    echo "Medium: ${{ steps.scan.outputs.medium-count }}"
    echo "Report: ${{ steps.scan.outputs.report-path }}"
```

### Upload Reports as Artifacts

```yaml
- uses: anubissbe/auto-zap@v1
  id: scan

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: security-report
    path: |
      zap-report-*.html
      zap-report-*.json
```

### Scheduled Scans

```yaml
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2 AM

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anubissbe/auto-zap@v1
        with:
          full-scan: true
```

### Fail on Vulnerabilities

```yaml
- uses: anubissbe/auto-zap@v1
  id: scan

- name: Fail if HIGH vulnerabilities found
  if: steps.scan.outputs.high-count > 0
  run: |
    echo "::error::Found ${{ steps.scan.outputs.high-count }} HIGH severity vulnerabilities"
    exit 1
```

### Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `url` | No | auto-detect | Target URL to scan |
| `port` | No | auto-detect | Override app port |
| `report-path` | No | `zap-report-<timestamp>.html` | Report path |
| `full-scan` | No | `false` | Thorough scan mode |
| `keep-docker` | No | `false` | Keep containers after scan |
| `skip-install` | No | `false` | Skip dependency install |
| `auth-user` | No | | Username for auth |
| `auth-password` | No | | Password for auth |
| `auth-url` | No | | Login endpoint URL |
| `auth-token` | No | | Bearer token |
| `auth-type` | No | auto | `form`, `json`, or `bearer` |
| `auto-auth` | No | `false` | Auto-create temp user for authenticated scan |
| `working-directory` | No | `.` | Working directory |

### Action Outputs

| Output | Description |
|--------|-------------|
| `report-path` | Path to HTML report |
| `json-path` | Path to JSON report |
| `high-count` | Number of HIGH severity vulnerabilities |
| `medium-count` | Number of MEDIUM severity vulnerabilities |
| `low-count` | Number of LOW severity vulnerabilities |

### Platform Notes

| Runner | ZAP Method | Notes |
|--------|-----------|-------|
| `ubuntu-latest` | Local (Java) or Docker | Local preferred; Docker as fallback |
| `windows-latest` | Local PowerShell | Docker containers not supported on Windows runners |

---

## Linux / macOS

Auto-ZAP includes a native bash script (`auto-zap.sh`) for Linux and macOS. It supports both local ZAP (Java) and Docker-based ZAP with automatic fallback.

### ZAP Mode (auto-detected)

The script determines how to run ZAP using this priority chain:

1. **`--use-docker-zap` flag** — forces Docker mode
2. **Local ZAP found** — searches `/usr/share/zaproxy/`, `/opt/zaproxy/`, `/snap/zaproxy/current/`, `$HOME/.ZAP/`, `$HOME/.auto-zap/zap/`, `$ZAP_HOME` env, and `zap.sh` on PATH
3. **Auto-install** — if Java is available, downloads the latest ZAP from GitHub to `$HOME/.auto-zap/zap/`
4. **Docker fallback** — uses `ghcr.io/zaproxy/zaproxy:stable` if Docker is available
5. **Error** — exits with clear instructions if none of the above work

### Requirements

- **curl** and **jq** (pre-installed on most systems)
- **One of:** Java 11+ (for local ZAP) **or** Docker (for container-based ZAP)
- **Docker** (optional, for database containers)

### CLI Parameters

```
./auto-zap.sh [options]

Options:
  --url, -u URL          Target URL (skip auto-detection)
  --port, -p PORT        Override detected port
  --report-path, -r PATH Custom report path
  --full-scan, -f        Thorough active scan (slower)
  --keep-docker, -k      Don't stop Docker containers after scan
  --skip-install, -s     Skip dependency installation
  --auth-user USER       Username for authenticated scanning
  --auth-password PASS   Password for authenticated scanning
  --auth-url URL         Login endpoint URL
  --auth-token TOKEN     Pre-obtained Bearer token
  --auth-type TYPE       form, json, or bearer
  --auto-auth, -a        Auto-create temp user for authenticated scanning
  --scan-mode MODE       Scan mode: auto, webapp, api, static
  --use-docker-zap       Force Docker-based ZAP (skip local detection)
  --sarif                Generate SARIF report for GitHub Code Scanning
  --dry-run              Show what would happen without executing
  --verbose, -v          Enable verbose debug logging
  --help, -h             Show help
```

### Platform Comparison

| Feature | Windows (`auto-zap.ps1`) | Linux (`auto-zap.sh`) |
|---------|--------------------------|----------------------|
| ZAP method | Local JAR or Docker | Local JAR or Docker |
| Java required | Yes (for local ZAP) | Yes (for local ZAP) |
| Process management | `Win32_Process` | `pkill`, `kill` |
| Port detection | `Get-NetTCPConnection` | `nc -z` |
| Frameworks | 13 runtimes, 30+ frameworks | Same coverage |
| Reports | HTML + JSON + SARIF | HTML + JSON + SARIF |

---

## Windows

### Installation

#### Windows Installer (recommended)

Download from the [GitHub Releases](https://github.com/anubissbe/auto-zap/releases/latest) page:

| Download | Description |
|----------|-------------|
| [Auto-ZAP-Setup.exe](https://github.com/anubissbe/auto-zap/releases/latest/download/Auto-ZAP-Setup.exe) | Full installer (~112 MB) with bundled ZAP + Java |
| [auto-zap.ps1](https://github.com/anubissbe/auto-zap/releases/latest/download/auto-zap.ps1) | Standalone script (requires ZAP + Java separately) |

The installer bundles:
- `auto-zap.ps1` - The scanner script
- **OWASP ZAP 2.16.1** - Vulnerability scanner
- **Eclipse Temurin JRE 17** - Java runtime

After installation, `auto-zap.cmd` is available from any directory (added to system PATH).

#### Manual Installation

```powershell
git clone https://github.com/anubissbe/auto-zap.git
cd auto-zap

# Install ZAP and Java separately
winget install ZAP.ZAP
winget install EclipseAdoptium.Temurin.17.JRE

.\auto-zap.ps1
```

#### Building the Installer from Source

```powershell
cd build
.\build.ps1                  # Downloads ZAP + JRE, builds & signs installer
.\build.ps1 -SkipDownload    # Rebuild using cached downloads
.\build.ps1 -SkipSign        # Build without code signing
```

### PowerShell Parameters

```powershell
.\auto-zap.ps1
    [-Url <string>]           # Skip detection, scan this URL directly
    [-Port <int>]             # Override the detected port
    [-ReportPath <string>]    # Custom report path
    [-FullScan]               # Thorough active scan (slower, 60 min timeout)
    [-KeepDocker]             # Don't stop Docker containers after scan
    [-SkipInstall]            # Skip dependency installation
    [-AuthUser <string>]      # Username for authenticated scanning
    [-AuthPassword <string>]  # Password for authenticated scanning
    [-AuthUrl <string>]       # Login endpoint (auto-detected if not provided)
    [-AuthToken <string>]     # Pre-obtained Bearer token
    [-AuthType <string>]      # "form", "json", or "bearer" (auto-detected)
    [-AutoAuth]               # Auto-create temp user for authenticated scanning
    [-UseDockerZap]           # Force Docker-based ZAP
```

### Examples

```powershell
.\auto-zap.ps1                                                # Auto-detect everything
.\auto-zap.ps1 -Url http://localhost:3000                     # Scan a running app
.\auto-zap.ps1 -FullScan -KeepDocker                          # Full scan, keep containers
.\auto-zap.ps1 -AuthUser admin -AuthPassword secret123         # Authenticated scan
.\auto-zap.ps1 -AuthToken "eyJhbGciOiJIUzI1NiIs..."           # Bearer token auth
.\auto-zap.ps1 -AutoAuth                                       # Auto-detect + create temp user
.\auto-zap.ps1 -UseDockerZap -ReportPath C:\reports\scan.html  # Docker ZAP, custom report
```

### Prerequisites

> **Easiest option:** Use the [Windows installer](#windows-installer-recommended) - it bundles ZAP and Java.

**Required (one of):**
- **Auto-ZAP Installer** - Includes everything
- **OWASP ZAP** + **Java 17+** (`winget install ZAP.ZAP && winget install EclipseAdoptium.Temurin.17.JRE`)
- **Docker** (`winget install Docker.DockerDesktop`)

**Optional:**
- Docker (for database containers)
- Your app's runtime (Node.js, Python, .NET, Java, PHP, Ruby, Go, Rust, Elixir, Deno, Bun)

---

## Configuration File

Create `.auto-zap.json` in your project root for advanced control:

```json
{
  "command": "npm run dev",
  "port": 3000,
  "install": "npm ci",
  "installDir": ".",
  "webAppDir": "apps/web",
  "healthCheckUrl": "/api/health",
  "authUser": "admin",
  "authPassword": "password123",
  "authUrl": "/api/auth/login",
  "authType": "json",
  "autoAuth": true,
  "exclude": [".*\\/api\\/webhook.*"],
  "migrations": ["npx prisma db push"],
  "preStart": ["npm run build"],
  "env": {
    "NODE_ENV": "development",
    "DATABASE_URL": "postgresql://user:pass@localhost:5432/mydb"
  },
  "services": [
    {
      "label": "API Server",
      "command": "npm run api",
      "dir": "apps/api",
      "waitFor": "http://localhost:4000/health"
    }
  ],
  "compose": {
    "file": "docker-compose.yml",
    "services": ["db", "redis"]
  }
}
```

All fields are optional. CLI parameters override config values. Config values override auto-detection.

| Field | Type | Description |
|-------|------|-------------|
| `command` | string | Start command (overrides detected command) |
| `port` | number | App port (overrides detected port) |
| `install` | string | Install command |
| `installDir` | string | Directory to run install in |
| `webAppDir` | string | Web app subdirectory in a monorepo |
| `healthCheckUrl` | string | Custom health check path |
| `authUser` | string | Username for authenticated scanning |
| `authPassword` | string | Password |
| `authUrl` | string | Login endpoint URL |
| `authType` | string | `"form"`, `"json"`, or `"bearer"` |
| `autoAuth` | boolean | Auto-create temp user for authenticated scanning |
| `exclude` | string[] | Regex patterns to exclude from scanning |
| `migrations` | string[] | Migration commands to run before the app |
| `preStart` | string[] | Commands to run after migrations |
| `env` | object | Environment variables |
| `services` | array | Background services to start |
| `compose` | object | Docker Compose services to start |

---

## Authentication

Auto-ZAP supports three authentication modes:

### Form-based
```powershell
.\auto-zap.ps1 -AuthUser admin -AuthPassword secret123
```
Detects the login page, submits credentials via HTML form, and maintains the session.

### JSON API
```powershell
.\auto-zap.ps1 -AuthUser admin -AuthPassword secret123 -AuthType json
```
Posts `{"username": "admin", "password": "secret123"}` to the detected login endpoint.

### Bearer Token
```powershell
.\auto-zap.ps1 -AuthToken "eyJhbGciOiJIUzI1NiIs..."
```
Adds `Authorization: Bearer <token>` header to all ZAP requests.

### Auto-detection
If you provide credentials without specifying the type, Auto-ZAP will:
1. Check `.env` files for `ADMIN_USER`, `TEST_USER`, `AUTH_USER` variables
2. Search for login endpoints at common paths
3. Determine the auth type from the endpoint response

### Auto-Auth (zero-config authenticated scanning)

```powershell
.\auto-zap.ps1 -AutoAuth
```
```bash
./auto-zap.sh --auto-auth
```

When `--auto-auth` / `-AutoAuth` is enabled, Auto-ZAP will:

1. **Detect** whether the app requires authentication (dependency scan + endpoint probing)
2. **Create** a temporary test user using framework-specific strategies
3. **Configure** ZAP with the temp credentials for an authenticated scan
4. **Clean up** the temp user after the scan completes

**Supported frameworks for automatic user creation:**

| Framework | Method | User type |
|-----------|--------|-----------|
| **Django** | `manage.py createsuperuser --noinput` | Superuser |
| **Laravel** | `php artisan tinker` | User model |
| **WordPress** | `wp user create` (WP-CLI) | Administrator |
| **Rails/Devise** | `rails runner "User.create!(...)"` | User |
| **Any (generic)** | POST to `/register`, `/signup`, `/api/auth/register` | Standard user |

For frameworks without a CLI user creation method (Express, FastAPI, NestJS, Spring Boot, Go, etc.), Auto-ZAP probes common registration endpoints with multiple field combinations.

**GitHub Actions:**
```yaml
- uses: anubissbe/auto-zap@v1
  with:
    auto-auth: true
```

---

## Reports

Auto-ZAP generates reports in multiple formats:

| Format | File | Purpose |
|--------|------|---------|
| **HTML** | `zap-report-<timestamp>.html` | Human-readable vulnerability report |
| **JSON** | `zap-report-<timestamp>.json` | Machine-readable for CI/CD pipelines |
| **SARIF** | `zap-report-<timestamp>.sarif` | GitHub Advanced Security / Code scanning |

The script exits with code `1` if HIGH severity vulnerabilities are found, `0` otherwise.

---

## Architecture

### Discovery Manifest

Auto-ZAP builds a discovery manifest that centralizes all detection results:

```
Pre-Scan Configuration Summary
--------------------------------------------------
Config       : .auto-zap.json
Framework    : Node.js (pnpm) - Next.js
Target URL   : http://localhost:3000
Port         : 3000
Database     : PostgreSQL
ZAP Source   : Local
ZAP Port     : 8091 (dynamic)
Monorepo     : Yes (root: myapp)
Redis        : localhost:6379
Compose      : docker-compose.yml
Auth         : JSON login (admin)
API Spec     : OpenAPI 3.0 (swagger.json)
--------------------------------------------------
```

### Database Strategy

When a database is needed, Auto-ZAP tries three strategies in order:

1. **Already running** - Checks if the database is reachable on the configured port
2. **Docker Compose** - Looks for `docker-compose.yml` and starts the database service
3. **Standalone container** - Starts a fresh Docker container with the correct image

Supported: PostgreSQL, MySQL, MongoDB, MSSQL, SQLite (no server needed), Redis.

### ZAP Execution Modes

| Mode | How | When |
|------|-----|------|
| **Local** | Java process with `zap-*.jar` | ZAP installed locally + Java available (both platforms) |
| **Docker** | `ghcr.io/zaproxy/zaproxy:stable` | `--use-docker-zap` / `-UseDockerZap` flag, or no local ZAP + no Java |

### Dynamic Port Allocation

Auto-ZAP uses port 8090 for the ZAP API by default. If that port is occupied, it dynamically allocates a free port. This enables running multiple scans in parallel.

### Process Cleanup

All processes are cleaned up on exit (including Ctrl+C via trap handler):
- Web app process tree
- Background service processes
- ZAP (via API shutdown + force kill)
- Docker containers (unless `-KeepDocker`)
- Database and Redis containers started by Auto-ZAP

---

## Monorepo Support

Auto-ZAP detects monorepos automatically:

| Tool | Detection |
|------|-----------|
| Turborepo | `turbo.json` |
| Nx | `nx.json` |
| pnpm workspaces | `pnpm-workspace.yaml` |
| npm/yarn workspaces | `workspaces` in `package.json` |

In a monorepo, Auto-ZAP finds the web app by:
1. **Config override**: `"webAppDir": "apps/web"` in `.auto-zap.json`
2. **Smart scan**: Searches for web framework dependencies, preferring `apps/` and names like `web`, `frontend`, `client`
3. **Fallback**: Common paths like `apps/web`, `apps/frontend`

---

## CI Pipeline

The project includes a comprehensive CI pipeline (`.github/workflows/ci.yml`) with 8 jobs:

| Job | What it checks |
|-----|---------------|
| **Lint & Syntax** | ShellCheck, PSScriptAnalyzer, PowerShell syntax, YAML, NSIS |
| **Test Linux** (2x) | Help flag behavior + missing target error handling |
| **Test Windows** | PowerShell syntax validation + parameter checks |
| **Test Action** | Full integration test with local ZAP against a test app |
| **Documentation** | README completeness, download links, input/output cross-references |
| **Feature Parity** | Compares framework detection, CLI params, and ZAP API usage between `.ps1` and `.sh` |
| **Security** | Scans for hardcoded secrets and dangerous patterns |
| **CI Summary** | Aggregates all results, fails if any required job failed |

---

## Troubleshooting

### "Could not detect a web application"

Auto-ZAP looks for: `package.json`, `requirements.txt`, `pyproject.toml`, `*.csproj`, `pom.xml`, `build.gradle`, `Gemfile`, `go.mod`, `Cargo.toml`, `mix.exs`, `deno.json`, `bunfig.toml`, `Dockerfile`, `index.html`.

**Fixes:**
- Ensure you're in the correct directory
- Create `.auto-zap.json` with `"command"` and `"port"`
- Use `-Url` to scan an already-running app

### "Database required but not reachable"

**Fixes:**
- Start the database manually
- Install Docker: `winget install Docker.DockerDesktop`
- Update `DATABASE_URL` in `.env`

### "ZAP failed to start"

**Fixes:**
- Check Java: `java -version` (requires Java 11+)
- Use Docker: `--use-docker-zap` (Linux) or `-UseDockerZap` (Windows)
- Install ZAP manually: https://www.zaproxy.org/download/

### "Port XXXX is in use"

Auto-ZAP handles ZAP API port conflicts automatically. For the app port, use `-Port` to specify a different one, or set `PORT` in your `.env` file.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Auto-ZAP-Presentation.pptx](https://github.com/anubissbe/auto-zap/releases/latest/download/Auto-ZAP-Presentation.pptx) | Project overview slide deck (10 slides) |
| [Auto-ZAP-Technical-Specification.docx](https://github.com/anubissbe/auto-zap/releases/latest/download/Auto-ZAP-Technical-Specification.docx) | Technical specification document |

---

## License

MIT License - see [LICENSE](LICENSE).

This project bundles [OWASP ZAP](https://www.zaproxy.org/) (Apache 2.0) and [Eclipse Temurin JRE 17](https://adoptium.net/) (GPLv2 with Classpath Exception) in the installer.

Use responsibly and only on applications you have permission to test.
