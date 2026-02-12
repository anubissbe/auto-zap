# Auto-ZAP

**Fully automated OWASP ZAP security scanner for web applications.**

Drop into any web app directory, run `.\auto-zap.ps1`, and get a complete vulnerability report. No configuration required - it detects your framework, starts your database, installs dependencies, launches your app, runs OWASP ZAP, and generates HTML/JSON/SARIF reports.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [What It Does](#what-it-does)
- [Supported Frameworks](#supported-frameworks)
- [Parameters](#parameters)
- [Configuration File](#configuration-file)
- [Authentication](#authentication)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Reports](#reports)
- [Monorepo Support](#monorepo-support)
- [Parallel Scans](#parallel-scans)
- [Prerequisites](#prerequisites)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Windows Installer (recommended)

Download the latest installer from the [GitHub Releases](https://github.com/bert-euraika/auto-zap/releases/latest) page:

**[Download Auto-ZAP-Setup.exe (v1.0.0)](https://github.com/bert-euraika/auto-zap/releases/download/v1.0.0/Auto-ZAP-Setup.exe)** (~112 MB)

The installer bundles everything you need:
- `auto-zap.ps1` - The scanner script
- **OWASP ZAP 2.16.1** - Vulnerability scanner
- **Eclipse Temurin JRE 17** - Java runtime

Run the installer as Administrator. After installation, `auto-zap.cmd` is available from any directory (added to system PATH).

> **Note:** The installer is signed with a self-signed certificate. Windows may show "Unknown publisher" - click "Run anyway" to proceed.

### Manual Installation

If you prefer not to use the installer:

```powershell
# Clone the repo
git clone https://github.com/bert-euraika/auto-zap.git
cd auto-zap

# Install ZAP and Java separately
winget install ZAP.ZAP
winget install EclipseAdoptium.Temurin.17.JRE

# Run from the repo directory
.\auto-zap.ps1
```

### Building the Installer from Source

```powershell
# Prerequisites: NSIS (winget install NSIS.NSIS)
cd build
.\build.ps1                  # Downloads ZAP + JRE, builds & signs installer
.\build.ps1 -SkipDownload    # Rebuild using cached downloads
.\build.ps1 -SkipSign        # Build without code signing
```

The installer will be output to `dist/Auto-ZAP-Setup.exe`.

---

## Quick Start

```powershell
# Scan the current directory (auto-detects everything)
.\auto-zap.ps1

# Scan a specific URL (skip framework detection)
.\auto-zap.ps1 -Url http://localhost:8080

# Full scan with authentication
.\auto-zap.ps1 -FullScan -AuthUser admin -AuthPassword secret123

# Use Docker-based ZAP (no local Java needed)
.\auto-zap.ps1 -UseDockerZap
```

That's it. Auto-ZAP handles everything else.

---

## What It Does

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
| Generic Elixir | 4000 | `mix.exs` file |

**ORM:** Ecto (migrations auto-detected via `mix ecto.setup`)

### Deno
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Generic | 8000 | `deno.json` / `deno.jsonc` (reads tasks) |

### Bun (native)
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Bun native | 3000 | `bunfig.toml` without `package.json` |

### Docker (fallback)
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Dockerfile | From EXPOSE | `Dockerfile` (parsed when no other framework detected) |

### Static Sites
| Framework | Default Port | Detection |
|-----------|-------------|-----------|
| Static HTML | 8080 | `index.html` (served via Python or npx serve) |

### PORT Environment Variable

After loading `.env` files, Auto-ZAP checks for a `PORT` environment variable and uses it to override the detected port. This handles apps that set `PORT=xxxx` in their `.env` (common in Node.js, Python, and Heroku-style deployments).

---

## Parameters

```powershell
.\auto-zap.ps1
    [-Url <string>]           # Skip detection, scan this URL directly
    [-Port <int>]             # Override the detected port
    [-ReportPath <string>]    # Custom report path (default: zap-report-<timestamp>.html)
    [-FullScan]               # Thorough active scan (slower, 60 min timeout)
    [-KeepDocker]             # Don't stop Docker containers after scan
    [-SkipInstall]            # Skip dependency installation
    [-AuthUser <string>]      # Username for authenticated scanning
    [-AuthPassword <string>]  # Password for authenticated scanning
    [-AuthUrl <string>]       # Login endpoint (auto-detected if not provided)
    [-AuthToken <string>]     # Pre-obtained Bearer token
    [-AuthType <string>]      # "form", "json", or "bearer" (auto-detected)
    [-UseDockerZap]           # Force Docker-based ZAP
```

### Examples

```powershell
# Basic scan (auto-detect everything)
.\auto-zap.ps1

# Scan a running app
.\auto-zap.ps1 -Url http://localhost:3000

# Full scan, keep Docker running for re-scans
.\auto-zap.ps1 -FullScan -KeepDocker

# Authenticated scan with credentials
.\auto-zap.ps1 -AuthUser admin -AuthPassword secret123

# Authenticated scan with pre-obtained token
.\auto-zap.ps1 -AuthToken "eyJhbGciOiJIUzI1NiIs..."

# Docker-based ZAP, custom report location
.\auto-zap.ps1 -UseDockerZap -ReportPath C:\reports\scan.html

# Override detected port
.\auto-zap.ps1 -Port 4000

# Skip install (deps already up to date)
.\auto-zap.ps1 -SkipInstall
```

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
  "exclude": [
    ".*\\/api\\/webhook.*",
    ".*\\/admin\\/dangerous.*"
  ],
  "migrations": [
    "npx prisma db push",
    "npx prisma db seed"
  ],
  "preStart": [
    "npm run build"
  ],
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
    "services": ["db", "redis", "elasticsearch"]
  }
}
```

All fields are optional. CLI parameters override config values. Config values override auto-detection.

### Config Fields

| Field | Type | Description |
|-------|------|-------------|
| `command` | string | Start command (overrides detected command) |
| `port` | number | App port (overrides detected port) |
| `install` | string | Install command (overrides detected command) |
| `installDir` | string | Directory to run install in (relative to project root) |
| `webAppDir` | string | Web app subdirectory in a monorepo |
| `healthCheckUrl` | string | Custom health check path (e.g., `/api/health`) |
| `authUser` | string | Default username for authenticated scanning |
| `authPassword` | string | Default password for authenticated scanning |
| `authUrl` | string | Login endpoint URL |
| `authType` | string | `"form"`, `"json"`, or `"bearer"` |
| `exclude` | string[] | Regex patterns to exclude from scanning |
| `migrations` | string[] | Migration commands to run before starting the app |
| `preStart` | string[] | Commands to run after migrations, before starting the app |
| `env` | object | Environment variables to set |
| `services` | array | Background services to start (with optional `waitFor` URL) |
| `compose` | object | Docker Compose services to start |

---

## Authentication

Auto-ZAP supports three authentication modes:

### 1. Form-based authentication
```powershell
.\auto-zap.ps1 -AuthUser admin -AuthPassword secret123
```
Auto-ZAP will detect the login page, submit credentials via HTML form, and configure ZAP to maintain the session.

### 2. JSON API authentication
```powershell
.\auto-zap.ps1 -AuthUser admin -AuthPassword secret123 -AuthType json
```
Posts `{"username": "admin", "password": "secret123"}` to the detected login endpoint.

### 3. Bearer token authentication
```powershell
.\auto-zap.ps1 -AuthToken "eyJhbGciOiJIUzI1NiIs..."
```
Adds the token as an `Authorization: Bearer <token>` header to all ZAP requests.

### Auto-detection
If you provide credentials without specifying `-AuthType`, Auto-ZAP will:
1. Check `.env` files for `ADMIN_USER`, `TEST_USER`, `AUTH_USER` variables
2. Search for login endpoints at common paths (`/api/auth/login`, `/login`, `/api/login`, etc.)
3. Determine the auth type from the endpoint response (HTML form vs JSON API)

---

## How It Works

### Detection Pipeline

```
                     +-----------------+
                     |  cd /your/app   |
                     +--------+--------+
                              |
                     +--------v--------+
                     | Monorepo check  |  turbo.json, nx.json,
                     | (if applicable) |  pnpm-workspace.yaml
                     +--------+--------+
                              |
                     +--------v--------+
                     | Framework detect|  package.json, manage.py,
                     | (13 runtimes)   |  *.csproj, pom.xml, etc.
                     +--------+--------+
                              |
                +-------------+-------------+
                |                           |
       +--------v--------+        +--------v--------+
       | Load .env files |        | Port detection  |  config files,
       | (4 priority lvls)|        | (PORT env var) |  dev scripts
       +--------+--------+        +--------+--------+
                |                           |
                +-------------+-------------+
                              |
                     +--------v--------+
                     | Build manifest  |  Aggregates all
                     | (discovery)     |  detection results
                     +--------+--------+
                              |
              +---------------+---------------+
              |               |               |
     +--------v------+ +-----v------+ +------v-------+
     | Start database| | Install    | | Run          |
     | (Docker/      | | deps       | | migrations   |
     | compose/local)| | (auto PM)  | | (auto ORM)   |
     +---------------+ +------------+ +--------------+
              |               |               |
              +---------------+---------------+
                              |
                     +--------v--------+
                     |  Start web app  |
                     |  + health check |
                     +--------+--------+
                              |
                     +--------v--------+
                     |  Launch ZAP     |  Local (Java) or
                     |  (dynamic port) |  Docker container
                     +--------+--------+
                              |
              +---------------+---------------+
              |               |               |
     +--------v------+ +-----v------+ +------v-------+
     | Configure     | | Import API | | Configure    |
     | context &     | | specs      | | auth         |
     | technology    | | (OpenAPI/  | | (form/JSON/  |
     |               | |  GraphQL)  | |  bearer)     |
     +---------------+ +------------+ +--------------+
              |               |               |
              +---------------+---------------+
                              |
              +---------------+---------------+
              |               |               |
     +--------v------+ +-----v------+ +------v-------+
     | Spider crawl  | | Ajax       | | Active scan  |
     | (discover     | | spider     | | (test for    |
     |  URLs)        | | (JS apps)  | |  vulns)      |
     +---------------+ +------------+ +--------------+
                              |
                     +--------v--------+
                     | Generate reports|  HTML + JSON + SARIF
                     | + cleanup       |
                     +-----------------+
```

### Database Strategy

When a database is needed, Auto-ZAP tries three strategies in order:

1. **Already running** - Checks if the database is reachable on the configured port
2. **Docker Compose** - Looks for `docker-compose.yml` and starts the database service
3. **Standalone container** - Starts a fresh Docker container with the correct image

Supported databases: PostgreSQL, MySQL, MongoDB, MSSQL, SQLite (no server needed), Redis.

### ZAP Execution Modes

| Mode | How | When |
|------|-----|------|
| **Local** | Java process with `zap-*.jar` | ZAP installed locally + Java available |
| **Docker** | `ghcr.io/zaproxy/zaproxy:stable` container | `-UseDockerZap` flag or no local ZAP found |

### Dynamic Port Allocation

Auto-ZAP uses port 8090 for the ZAP API by default. If that port is occupied:
1. If held by a stale ZAP/Java process, it kills it
2. If held by another process, it dynamically allocates a free port using `TcpListener`
3. This enables running multiple scans in parallel

### Scan Policy

Auto-ZAP configures an optimized scan policy based on the detected framework:
- **Default scan**: Tests for the most impactful vulnerabilities (~30 min timeout)
- **Full scan** (`-FullScan`): Tests all vulnerability categories (~60 min timeout)
- **Stall detection**: Automatically stops the scan if no progress for 5 minutes

---

## Architecture

### Discovery Manifest

Auto-ZAP builds a discovery manifest that centralizes all detection results:

```powershell
$manifest = @{
    ProjectRoot    = "C:\projects\myapp"
    AppDir         = "C:\projects\myapp\apps\web"    # may differ in monorepos
    MonorepoRoot   = "C:\projects\myapp"
    Framework      = @{ Name = "Node.js (pnpm) - Next.js"; Port = 3000; ... }
    Database       = @{ Type = "PostgreSQL"; Host = "localhost"; Port = 5432 }
    Redis          = @{ Host = "localhost"; Port = 6379 }
    ComposeFile    = "C:\projects\myapp\docker-compose.yml"
    EnvFilesLoaded = 12
    ZapPort        = 8090
    ZapMode        = "local"
}
```

The manifest is re-synchronized after database/compose startup via `Sync-Manifest` to ensure display accuracy.

### Pre-Scan Summary

Before scanning, Auto-ZAP displays a configuration summary:

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
    Technology   : JavaScript, Node, PostgreSQL
    Scan Policy  : auto-zap-policy (42 rules active)
    Health Check : OK (15234 bytes)
    --------------------------------------------------
```

### Process Cleanup

All processes are cleaned up on exit (including Ctrl+C via trap handler):
- Web app process tree
- Background service processes
- ZAP (via API shutdown + force kill)
- Docker containers (unless `-KeepDocker`)
- Database containers started by Auto-ZAP
- Redis containers started by Auto-ZAP
- Docker Compose services started by Auto-ZAP

---

## Reports

Auto-ZAP generates three report formats:

| Format | File | Purpose |
|--------|------|---------|
| **HTML** | `zap-report-<timestamp>.html` | Human-readable vulnerability report |
| **JSON** | `zap-report-<timestamp>.json` | Machine-readable for CI/CD pipelines |
| **SARIF** | `zap-report-<timestamp>.sarif` | GitHub Advanced Security / Code scanning |

### CI/CD Integration

The script exits with code `1` if HIGH severity vulnerabilities are found, `0` otherwise. Use this in your CI pipeline:

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    powershell -File auto-zap.ps1 -UseDockerZap -Url http://localhost:3000
  continue-on-error: false
```

---

## Monorepo Support

Auto-ZAP detects monorepos automatically:

| Monorepo Tool | Detection |
|--------------|-----------|
| Turborepo | `turbo.json` |
| Nx | `nx.json` |
| pnpm workspaces | `pnpm-workspace.yaml` |
| npm/yarn workspaces | `workspaces` field in `package.json` |

### Web App Resolution

In a monorepo, Auto-ZAP finds the web app using three strategies:

1. **Config override**: Set `"webAppDir": "apps/web"` in `.auto-zap.json`
2. **Smart scan**: Searches `package.json` files for web framework dependencies, preferring `apps/` over `packages/` and names containing `web`, `frontend`, `client`, `site`
3. **Fallback**: Checks common paths like `apps/web`, `apps/frontend`, `apps/client`

### Example Monorepo Structure

```
my-monorepo/
  turbo.json
  docker-compose.yml       <-- found by Auto-ZAP
  .env                     <-- loaded first
  apps/
    web/                   <-- auto-detected as the scan target
      package.json         <-- has "next" dependency
      .env.local           <-- loaded second (overrides root)
    api/
      package.json
  packages/
    shared/
```

---

## Parallel Scans

You can run multiple Auto-ZAP instances simultaneously. Each instance:

1. Checks if port 8090 is available
2. If occupied by a stale ZAP process, kills it
3. If occupied by another process, automatically picks a free port
4. Reports the dynamic port in the pre-scan summary

```powershell
# Terminal 1
cd C:\projects\app1
.\auto-zap.ps1

# Terminal 2 (simultaneously)
cd C:\projects\app2
.\auto-zap.ps1   # Automatically uses a different ZAP port
```

---

## Prerequisites

> **Easiest option:** Use the [Windows installer](#installation) - it bundles ZAP and Java, no separate installs needed.

### Required (one of)
- **Auto-ZAP Installer** - Includes everything ([download](https://github.com/bert-euraika/auto-zap/releases/latest))
- **OWASP ZAP** (local install) + **Java 17+**
  ```
  winget install ZAP.ZAP
  winget install EclipseAdoptium.Temurin.17.JRE
  ```
- **Docker** (ZAP runs as a container)
  ```
  winget install Docker.DockerDesktop
  ```

### Optional
- **Docker** - For database containers (PostgreSQL, MySQL, etc.)
- **Runtime** - The runtime for your app (Node.js, Python, .NET, Java, PHP, Ruby, Go, Rust, Elixir, Deno, Bun)

### Java Auto-Discovery

Auto-ZAP searches for Java in this order:
1. `JAVA_HOME` environment variable
2. `java.exe` in PATH
3. Common install locations: Eclipse Adoptium, Oracle Java, Microsoft JDK, Zulu, BellSoft, Amazon Corretto

### ZAP Auto-Discovery

Auto-ZAP searches for ZAP in:
1. `C:\Program Files\ZAP\Zed Attack Proxy`
2. `C:\Program Files\OWASP\Zed Attack Proxy`
3. `%LOCALAPPDATA%\Programs\ZAP`
4. `%USERPROFILE%\ZAP`
5. Any ZAP-related directory in Program Files

---

## Troubleshooting

### "Could not detect a web application"

Auto-ZAP checks for: `package.json`, `requirements.txt`, `pyproject.toml`, `*.csproj`, `pom.xml`, `build.gradle`, `Gemfile`, `go.mod`, `Cargo.toml`, `mix.exs`, `deno.json`, `bunfig.toml`, `Dockerfile`, `index.html`.

**Fixes:**
- Ensure you're in the correct directory
- Create `.auto-zap.json` with `"command"` and `"port"` for unsupported frameworks
- Use `-Url` to scan an already-running app

### "Database required but not reachable"

**Fixes:**
- Start the database manually
- Install Docker: `winget install Docker.DockerDesktop`
- Update `DATABASE_URL` in `.env` to point to a running database

### "ZAP failed to start"

**Fixes:**
- Check Java: `java -version` (requires Java 17+)
- Install Java: `winget install EclipseAdoptium.Temurin.17.JRE`
- Use Docker instead: `.\auto-zap.ps1 -UseDockerZap`

### "Port XXXX is in use"

Auto-ZAP automatically handles port conflicts for the ZAP API port. For the app port:
- Use `-Port` to specify a different port
- Set `PORT` in your `.env` file
- Set `"port"` in `.auto-zap.json`

### Wrong port detected

If your app starts on a different port than detected:
1. Set `PORT=xxxx` in your `.env` file
2. Or use `-Port xxxx` on the command line
3. Or set `"port": xxxx` in `.auto-zap.json`

### Monorepo: "could not find a web application"

**Fixes:**
- Create `.auto-zap.json` with `"webAppDir": "apps/your-web-app"`
- Or `cd` directly into the web app subdirectory

---

## How It Was Built

Auto-ZAP is a single PowerShell script (~3,140 lines) with zero external dependencies beyond ZAP itself. It was built with these design principles:

1. **Zero-config by default** - Everything is auto-detected. Config is opt-in for edge cases.
2. **Full cleanup guaranteed** - Trap handler ensures all processes are stopped, even on Ctrl+C.
3. **Progressive fallbacks** - Local ZAP -> Docker ZAP. Local DB -> Compose -> Standalone container.
4. **Defensive port management** - Dynamic port allocation prevents conflicts in parallel scans.
5. **Monorepo-aware** - Searches both app directory and monorepo root for `.env` files, compose files, and dependencies.

### Key Internal Components

| Component | Purpose |
|-----------|---------|
| `Detect-AppFramework` | Identifies runtime, framework, port, install/migration commands |
| `Build-ScanManifest` | Aggregates all discovery results into a single manifest |
| `Sync-Manifest` | Re-synchronizes manifest after database/compose startup |
| `Get-FreePort` | Dynamic port allocation using TcpListener bind test |
| `Import-EnvFiles` | Loads `.env` files with precedence (`.env.development.local` > `.env.local` > `.env.development` > `.env`) |
| `Ensure-Database` | Three-strategy database startup (check/compose/standalone) |
| `Configure-ZapContext` | Sets up ZAP scan context, technology stack, and exclusions |
| `Configure-ZapAuth` | Auto-detects and configures authentication |
| `Import-ApiSpec` | Finds and imports OpenAPI/Swagger/GraphQL specs |
| `Configure-ScanPolicy` | Builds optimized scan policy per framework |
| `New-SarifReport` | Generates SARIF report for GitHub Advanced Security |

---

## License

MIT License - see [LICENSE.txt](LICENSE.txt).

This project bundles [OWASP ZAP](https://www.zaproxy.org/) (Apache 2.0) and [Eclipse Temurin JRE 17](https://adoptium.net/) (GPLv2 with Classpath Exception) in the installer.

Use responsibly and only on applications you have permission to test.
