#Requires -Version 5.1
<#
.SYNOPSIS
    Fully automated OWASP ZAP security scan for web applications.
.DESCRIPTION
    This script handles EVERYTHING needed to scan a web app:
      1. Checks prerequisites (ZAP, runtime, Docker)
      2. Starts database containers (Docker/PostgreSQL/MySQL/MongoDB/MSSQL/Redis)
      3. Installs dependencies (npm/yarn/pnpm/bun/pip/poetry/uv/etc.)
      4. Runs database migrations (Prisma/Drizzle/Django/etc.)
      5. Starts the web application
      6. Launches OWASP ZAP (local or Docker) and configures context/technology
      7. Imports OpenAPI/Swagger/GraphQL specs automatically
      8. Configures authenticated scanning (form, JSON, or bearer token)
      9. Runs spider + active scan with optimized scan policy
     10. Generates HTML + JSON + SARIF vulnerability reports
     11. Cleans up all processes (app, ZAP, optionally Docker)

    Run this script from the root of any web application directory.
.PARAMETER Url
    Skip auto-detection and scan a URL directly (e.g. http://localhost:3000)
.PARAMETER Port
    Override the default port for the detected app
.PARAMETER ReportPath
    Path for the HTML report (default: zap-report-<timestamp>.html)
.PARAMETER FullScan
    Run a more thorough active scan (slower)
.PARAMETER KeepDocker
    Don't stop Docker containers after the scan (useful for re-runs)
.PARAMETER SkipInstall
    Skip dependency installation (if you know deps are up to date)
.PARAMETER AuthUser
    Username for authenticated scanning
.PARAMETER AuthPassword
    Password for authenticated scanning
.PARAMETER AuthUrl
    Login endpoint URL (auto-detected if not provided)
.PARAMETER AuthToken
    Pre-obtained Bearer token (skip login flow)
.PARAMETER AuthType
    Authentication type: "form", "json", or "bearer" (auto-detected if not provided)
.PARAMETER UseDockerZap
    Force using Docker-based ZAP even if local install exists
.EXAMPLE
    .\auto-zap.ps1
    .\auto-zap.ps1 -Url http://localhost:8080
    .\auto-zap.ps1 -FullScan -KeepDocker
    .\auto-zap.ps1 -AuthToken "eyJhbGciOi..."
    .\auto-zap.ps1 -AuthUser admin -AuthPassword secret123
    .\auto-zap.ps1 -UseDockerZap
#>
param(
    [string]$Url,
    [int]$Port,
    [string]$ReportPath,
    [switch]$FullScan,
    [switch]$KeepDocker,
    [switch]$SkipInstall,
    [string]$AuthUser,
    [string]$AuthPassword,
    [string]$AuthUrl,
    [string]$AuthToken,
    [ValidateSet("form", "json", "bearer", "")]
    [string]$AuthType,
    [switch]$UseDockerZap
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Find and configure Java ---
$javaExe = $null

# Check JAVA_HOME first
if ($env:JAVA_HOME -and (Test-Path (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
    $javaExe = Join-Path $env:JAVA_HOME "bin\java.exe"
}

# Check PATH
if (-not $javaExe) {
    $javaInPath = Get-Command "java.exe" -ErrorAction SilentlyContinue
    if ($javaInPath) { $javaExe = $javaInPath.Source }
}

# Search common install locations
if (-not $javaExe) {
    $javaSearchPaths = @(
        "C:\Program Files\Eclipse Adoptium",
        "C:\Program Files\Java",
        "C:\Program Files\Microsoft\jdk-*",
        "C:\Program Files\Zulu",
        "C:\Program Files\Eclipse Foundation",
        "C:\Program Files\BellSoft",
        "C:\Program Files\Amazon Corretto"
    )
    foreach ($searchPath in $javaSearchPaths) {
        $found = Get-ChildItem -Path $searchPath -Filter "java.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            $javaExe = $found.FullName
            break
        }
    }
}

if ($javaExe) {
    $javaBin = Split-Path $javaExe -Parent
    $env:JAVA_HOME = Split-Path $javaBin -Parent
    if ($env:PATH -notlike "*$javaBin*") {
        $env:PATH = "$javaBin;$env:PATH"
    }
}

# --- Find ZAP installation dynamically ---
$ZapPath = $null
$zapSearchDirs = @(
    "C:\Program Files\ZAP\Zed Attack Proxy",
    "C:\Program Files\OWASP\Zed Attack Proxy",
    "C:\Program Files (x86)\ZAP\Zed Attack Proxy",
    "C:\Program Files (x86)\OWASP\Zed Attack Proxy",
    "$env:LOCALAPPDATA\Programs\ZAP",
    "$env:USERPROFILE\ZAP"
)
foreach ($searchDir in $zapSearchDirs) {
    if (Test-Path $searchDir) {
        $jar = Get-ChildItem -Path $searchDir -Filter "zap-*.jar" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($jar) { $ZapPath = $searchDir; break }
    }
}

# Fallback: search Program Files for any ZAP-related directory
if (-not $ZapPath) {
    foreach ($root in @("C:\Program Files", "C:\Program Files (x86)")) {
        if (-not (Test-Path $root)) { continue }
        $zapDir = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "ZAP|Zed Attack" } | Select-Object -First 1
        if ($zapDir) {
            $jar = Get-ChildItem -Path $zapDir.FullName -Filter "zap-*.jar" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($jar) { $ZapPath = $jar.DirectoryName; break }
        }
    }
}

# --- Configuration ---
$ZapApiPort = 8090
$ZapApiKey = [guid]::NewGuid().ToString("N")
$MaxWaitSeconds = 180
$script:AppProcess = $null
$script:ZapProcess = $null
$script:DockerStartedByUs = $false
$script:DbContainerStartedByUs = $false
$script:DbContainerName = $null
$script:DbStartedViaCompose = $false
$script:ComposeFile = $null
$script:OriginalDir = (Get-Location).Path
$script:ProjectRoot = (Get-Location).Path
$script:MonorepoRoot = $null
$script:UsingDockerZap = $false
$script:ZapDockerContainer = "zap-scanner"
$script:ZapContextId = $null
$script:ZapContextName = "scan-context"
$script:ZapUserId = -1
$script:AuthResult = $null
$script:ApiSpecSource = $null
$script:GraphqlDetected = $false
$script:DetectedDbType = $null
$script:ScanPolicyName = $null
$script:RedisContainerName = "zap-scan-redis"
$script:RedisContainerStartedByUs = $false
$script:TechList = @()
$script:ActiveRuleCount = $null
$script:HealthCheckResult = $null
$script:Config = $null
$script:ServiceProcesses = @()
$script:ComposeServicesStartedByUs = $false
$script:ComposeConfigFile = $null
$script:ComposeConfigServices = @()
$script:Manifest = $null

# Default report name with timestamp
if (-not $ReportPath) {
    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $ReportPath = "zap-report-$timestamp.html"
}

# --- Load .auto-zap.json config ---
function Import-AutoZapConfig {
    $configPath = Join-Path $script:OriginalDir ".auto-zap.json"
    if (-not (Test-Path $configPath)) {
        $script:Config = $null
        return
    }
    try {
        $raw = Get-Content $configPath -Raw -ErrorAction Stop
        $script:Config = $raw | ConvertFrom-Json -ErrorAction Stop
        Write-Ok "Loaded config from .auto-zap.json"
    } catch {
        Write-Err "Failed to parse .auto-zap.json: $($_.Exception.Message)"
        Write-Err "    Fix: Validate your JSON at https://jsonlint.com or check for trailing commas."
        exit 1
    }
}

# --- Start background services from config ---
function Start-BackgroundService {
    if (-not $script:Config -or -not $script:Config.services) { return }

    Write-Step "STEP 4c: Starting background services..."
    $projectRoot = if ($script:MonorepoRoot) { $script:MonorepoRoot } else { $script:OriginalDir }

    foreach ($svc in $script:Config.services) {
        $label = if ($svc.label) { $svc.label } else { $svc.command }
        $svcDir = $projectRoot
        if ($svc.dir -and $svc.dir -ne ".") {
            $svcDir = Join-Path $projectRoot $svc.dir
        }

        Write-Step "Starting background service: $label"
        Write-Detail "Command: $($svc.command)"
        Write-Detail "Directory: $svcDir"

        try {
            $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $($svc.command)" -WorkingDirectory $svcDir -PassThru -WindowStyle Minimized
            $script:ServiceProcesses += $proc
            Write-Ok "Service '$label' started (PID $($proc.Id))."
        } catch {
            Write-Err "Background service '$label' failed to start: $($svc.command)"
            Write-Err "    Fix: Run the command manually to see the error."
            Write-Err "         Check the `"services`" section in .auto-zap.json."
            Cleanup
            exit 1
        }

        if ($svc.waitFor) {
            if (-not (Wait-ForUrl $svc.waitFor -TimeoutSec 120 -Label $label)) {
                Write-Err "Background service '$label' did not become ready at $($svc.waitFor) within 120 seconds."
                Write-Err "    Fix: Increase the timeout, check the service logs, or verify the waitFor URL is correct."
                Write-Err "         Check the `"services`" section in .auto-zap.json."
                Cleanup
                exit 1
            }
        }
    }
    Write-Ok "All background services started."
}

# --- Start Docker Compose services from config ---
function Start-ComposeService {
    if (-not $script:Config -or -not $script:Config.compose) { return $false }

    $compose = $script:Config.compose
    $projectRoot = if ($script:MonorepoRoot) { $script:MonorepoRoot } else { $script:OriginalDir }

    # Resolve compose file
    $composeFilePath = $null
    if ($compose.file) {
        $composeFilePath = Join-Path $projectRoot $compose.file
    } else {
        foreach ($name in @("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")) {
            $candidate = Join-Path $projectRoot $name
            if (Test-Path $candidate) { $composeFilePath = $candidate; break }
        }
    }

    if (-not $composeFilePath -or -not (Test-Path $composeFilePath)) {
        Write-Warn "Compose file not found. Skipping compose services."
        return $false
    }

    $services = @()
    if ($compose.services) { $services = @($compose.services) }

    if ($services.Count -eq 0) {
        Write-Warn "No compose services specified. Skipping."
        return $false
    }

    if (-not (Test-DockerRunning)) {
        Write-Err "Docker Compose failed to start services: $($services -join ', ')"
        Write-Err "    Fix: Run 'docker compose -f $composeFilePath up -d $($services -join ' ')' manually to see the error."
        Write-Err "         Check the `"compose`" section in .auto-zap.json."
        return $false
    }

    Write-Step "Starting Docker Compose services: $($services -join ', ')..."
    $svcArgs = $services -join " "
    $result = docker compose -f $composeFilePath up -d $svcArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Docker Compose failed to start services: $($services -join ', ')"
        Write-Err "    Output: $result"
        Write-Err "    Fix: Run 'docker compose -f $composeFilePath up -d $svcArgs' manually to see the error."
        Write-Err "         Check the `"compose`" section in .auto-zap.json."
        return $false
    }

    $script:ComposeServicesStartedByUs = $true
    $script:ComposeConfigFile = $composeFilePath
    $script:ComposeConfigServices = $services

    # Wait for services to be ready
    Start-Sleep -Seconds 10
    Write-Ok "Docker Compose services started: $($services -join ', ')"
    return $true
}

# --- Helpers ---
function Write-Step($msg)    { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)      { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg)    { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg)     { Write-Host "[-] $msg" -ForegroundColor Red }
function Write-Detail($msg)  { Write-Host "    $msg" -ForegroundColor DarkGray }

function Stop-ProcessTree([int]$ParentPid) {
    try {
        $children = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ParentProcessId -eq $ParentPid }
        foreach ($child in $children) {
            Stop-ProcessTree $child.ProcessId
        }
    } catch { $null = $_ }
    Stop-Process -Id $ParentPid -Force -ErrorAction SilentlyContinue
}

function Cleanup {
    Write-Host ""
    Write-Step "Cleaning up..."

    # Stop background service processes
    foreach ($svcProc in $script:ServiceProcesses) {
        if ($svcProc -and !$svcProc.HasExited) {
            Write-Detail "Stopping background service (PID $($svcProc.Id))..."
            Stop-ProcessTree $svcProc.Id
        }
    }

    # Stop web app (full process tree)
    if ($script:AppProcess -and !$script:AppProcess.HasExited) {
        Write-Detail "Stopping web app (PID $($script:AppProcess.Id))..."
        Stop-ProcessTree $script:AppProcess.Id
    }

    # Stop ZAP
    if ($script:UsingDockerZap) {
        Write-Detail "Stopping ZAP Docker container..."
        try {
            Invoke-RestMethod "http://localhost:$ZapApiPort/JSON/core/action/shutdown/?apikey=$ZapApiKey" -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 3
        } catch { $null = $_ }
        docker stop $script:ZapDockerContainer 2>$null | Out-Null
        docker rm $script:ZapDockerContainer 2>$null | Out-Null
    } elseif ($script:ZapProcess -and !$script:ZapProcess.HasExited) {
        Write-Detail "Stopping ZAP (PID $($script:ZapProcess.Id))..."
        try {
            Invoke-RestMethod "http://localhost:$ZapApiPort/JSON/core/action/shutdown/?apikey=$ZapApiKey" -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Seconds 3
        } catch { $null = $_ }
        if (!$script:ZapProcess.HasExited) {
            Stop-ProcessTree $script:ZapProcess.Id
        }
    }

    # Stop Docker containers we started (unless -KeepDocker)
    if ($script:DbContainerStartedByUs -and -not $KeepDocker -and $script:DbContainerName) {
        Write-Detail "Stopping database container..."
        if ($script:DbStartedViaCompose -and $script:ComposeFile) {
            docker compose -f $script:ComposeFile stop $script:DbContainerName 2>$null | Out-Null
        } else {
            docker stop $script:DbContainerName 2>$null | Out-Null
        }
    }

    # Stop Docker Compose services if we started them
    if ($script:ComposeServicesStartedByUs -and -not $KeepDocker -and $script:ComposeConfigFile) {
        Write-Detail "Stopping Docker Compose services..."
        $svcArgs = $script:ComposeConfigServices -join " "
        docker compose -f $script:ComposeConfigFile stop $svcArgs 2>$null | Out-Null
    }

    # Stop Redis container if we started it
    if ($script:RedisContainerStartedByUs -and -not $KeepDocker) {
        Write-Detail "Stopping Redis container..."
        docker stop $script:RedisContainerName 2>$null | Out-Null
    }

    Write-Ok "Cleanup complete."
}

trap { Cleanup; break }

function Test-Command([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-FreePort {
    param([int]$PreferredPort = 8090)
    # Test if preferred port is free
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $PreferredPort)
        $listener.Start()
        $listener.Stop()
        return $PreferredPort
    } catch { $null = $_ }
    # Preferred port occupied - let OS assign a free one
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $freePort = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $freePort
}

function Wait-ForUrl([string]$TestUrl, [int]$TimeoutSec = 60, [string]$Label = "service") {
    Write-Step "Waiting for $Label at $TestUrl ..."
    $elapsed = 0
    while ($elapsed -lt $TimeoutSec) {
        try {
            $resp = Invoke-WebRequest -Uri $TestUrl -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            Write-Ok "$Label is ready (HTTP $($resp.StatusCode))."
            return $true
        } catch {
            # Accept any HTTP response as "the server is up" (even 401, 404, 500)
            if ($_.Exception.Response) {
                $httpCode = [int]$_.Exception.Response.StatusCode
                if ($httpCode -ge 500) {
                    Write-Warn "$Label responded with HTTP $httpCode - server may not be fully healthy."
                }
                Write-Ok "$Label is ready (HTTP $httpCode)."
                return $true
            }
            Start-Sleep -Seconds 2
            $elapsed += 2
            if ($elapsed % 10 -eq 0) { Write-Detail "Still waiting... ($elapsed`s / $TimeoutSec`s)" }
        }
    }
    Write-Err "$Label did not start within $TimeoutSec seconds."
    return $false
}

function Wait-ForTcp([string]$TargetHost, [int]$TcpPort, [int]$TimeoutSec = 60, [string]$Label = "service") {
    Write-Step "Waiting for $Label on ${TargetHost}:$TcpPort ..."
    $elapsed = 0
    while ($elapsed -lt $TimeoutSec) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect($TargetHost, $TcpPort)
            $tcp.Close()
            Write-Ok "$Label is accepting connections."
            return $true
        } catch {
            Start-Sleep -Seconds 2
            $elapsed += 2
        }
    }
    Write-Err "$Label not reachable on port $TcpPort within $TimeoutSec seconds."
    return $false
}

function Invoke-ZapApi([string]$Endpoint) {
    $uri = "http://localhost:$ZapApiPort$Endpoint"
    if ($uri -match "\?") { $uri += "&apikey=$ZapApiKey" } else { $uri += "?apikey=$ZapApiKey" }
    return (Invoke-RestMethod -Uri $uri -TimeoutSec 60)
}

# --- Load .env files into process environment ---
function Import-EnvFile {
    # Most specific first - "don't override" semantics means first writer wins
    $envFiles = @(".env.development.local", ".env.local", ".env.development", ".env")
    # Monorepo root first so app-dir values override root values
    $searchDirs = @()
    if ($script:MonorepoRoot -and $script:MonorepoRoot -ne $script:OriginalDir) {
        $searchDirs += $script:MonorepoRoot
    }
    $searchDirs += $script:OriginalDir
    $loaded = 0
    # Load in order: root first, then app dir; earlier files don't override later ones
    foreach ($searchDir in $searchDirs) {
        foreach ($f in $envFiles) {
            $envPath = Join-Path $searchDir $f
            if (Test-Path $envPath) {
                $lines = Get-Content $envPath -ErrorAction SilentlyContinue
                foreach ($line in $lines) {
                    $line = $line.Trim()
                    if ($line -eq "" -or $line.StartsWith("#")) { continue }
                    if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
                        $varName = $Matches[1]
                        $varValue = $Matches[2].Trim()
                        # Strip surrounding quotes
                        if (($varValue.StartsWith('"') -and $varValue.EndsWith('"')) -or
                            ($varValue.StartsWith("'") -and $varValue.EndsWith("'"))) {
                            $varValue = $varValue.Substring(1, $varValue.Length - 2)
                        }
                        # Only set if not already defined (don't override existing env vars)
                        if (-not [System.Environment]::GetEnvironmentVariable($varName, "Process")) {
                            [System.Environment]::SetEnvironmentVariable($varName, $varValue, "Process")
                            $loaded++
                        }
                    }
                }
            }
        }
    }
    if ($loaded -gt 0) {
        Write-Detail "Loaded $loaded environment variables from .env files."
    }
    return $loaded
}

function Build-ScanManifest {
    param([hashtable]$Framework)

    $manifest = @{
        ProjectRoot    = $script:ProjectRoot
        AppDir         = $script:OriginalDir
        MonorepoRoot   = $script:MonorepoRoot
        Framework      = $Framework
        Database       = $null
        Redis          = $null
        ComposeFile    = $null
        EnvFilesLoaded = 0
        ZapPort        = $ZapApiPort
        ZapMode        = if ($script:UsingDockerZap) { "docker" } else { "local" }
    }

    # Discover database config
    if ($Framework -and $Framework.NeedsDb) {
        $manifest.Database = Get-DatabaseConfig
    }

    # Discover Redis config
    $manifest.Redis = Get-RedisConfig

    # Discover compose file
    $composeDirs = @($script:OriginalDir)
    if ($script:MonorepoRoot -and $script:MonorepoRoot -ne $script:OriginalDir) {
        $composeDirs += $script:MonorepoRoot
    }
    foreach ($searchDir in $composeDirs) {
        foreach ($name in @("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")) {
            $cpath = Join-Path $searchDir $name
            if (Test-Path $cpath) { $manifest.ComposeFile = $cpath; break }
        }
        if ($manifest.ComposeFile) { break }
    }

    $script:Manifest = $manifest
}

function Sync-Manifest {
    if (-not $script:Manifest) { return }
    # Re-sync fields that may have been updated by later steps (Initialize-Database, Initialize-RedisCache, etc.)
    if ($script:ComposeFile -and -not $script:Manifest.ComposeFile) {
        $script:Manifest.ComposeFile = $script:ComposeFile
    }
    if ($script:DetectedDbType) {
        $script:Manifest.DetectedDbType = $script:DetectedDbType
    }
    if ($script:RedisContainerStartedByUs -and -not $script:Manifest.Redis) {
        $script:Manifest.Redis = @{ Host = "localhost"; Port = 6379; Source = "docker" }
    }
    $script:Manifest.ZapPort = $ZapApiPort
}

# --- Parse DATABASE_URL from .env files ---
function Get-DatabaseConfig {
    $envFiles = @(".env.local", ".env", ".env.development", ".env.development.local")
    # Search both app dir and monorepo root for .env files
    $searchDirs = @($script:OriginalDir)
    if ($script:MonorepoRoot -and $script:MonorepoRoot -ne $script:OriginalDir) {
        $searchDirs += $script:MonorepoRoot
    }
    foreach ($searchDir in $searchDirs) {
    foreach ($f in $envFiles) {
        $envPath = Join-Path $searchDir $f
        if (Test-Path $envPath) {
            $content = Get-Content $envPath -Raw

            # PostgreSQL: postgresql:// or postgres://
            if ($content -match 'DATABASE_URL\s*=\s*"?(?:postgresql|postgres)://([^:]+):([^@]+)@([^:/]+):(\d+)/([^"?\s]+)') {
                return @{
                    Type     = "PostgreSQL"
                    User     = $Matches[1]
                    Password = $Matches[2]
                    Host     = $Matches[3]
                    Port     = [int]$Matches[4]
                    Database = $Matches[5]
                    File     = $f
                }
            }

            # MySQL: mysql://
            if ($content -match 'DATABASE_URL\s*=\s*"?mysql://([^:]+):([^@]+)@([^:/]+):(\d+)/([^"?\s]+)') {
                return @{
                    Type     = "MySQL"
                    User     = $Matches[1]
                    Password = $Matches[2]
                    Host     = $Matches[3]
                    Port     = [int]$Matches[4]
                    Database = $Matches[5]
                    File     = $f
                }
            }

            # MongoDB: mongodb:// or mongodb+srv://
            if ($content -match '(?:DATABASE_URL|MONGODB_URI|MONGO_URL)\s*=\s*"?(mongodb(?:\+srv)?://[^"?\s]+)') {
                $mongoUrl = $Matches[1]
                $mongoHost = "localhost"
                $mongoPort = 27017
                if ($mongoUrl -match '@([^:/]+):(\d+)') {
                    $mongoHost = $Matches[1]
                    $mongoPort = [int]$Matches[2]
                } elseif ($mongoUrl -match '@([^:/]+)') {
                    $mongoHost = $Matches[1]
                }
                return @{
                    Type     = "MongoDB"
                    Host     = $mongoHost
                    Port     = $mongoPort
                    Url      = $mongoUrl
                    File     = $f
                }
            }

            # MSSQL: mssql:// or sqlserver://
            if ($content -match 'DATABASE_URL\s*=\s*"?(?:mssql|sqlserver)://([^:]+):([^@]+)@([^:/]+):(\d+)/([^"?\s]+)') {
                return @{
                    Type     = "MSSQL"
                    User     = $Matches[1]
                    Password = $Matches[2]
                    Host     = $Matches[3]
                    Port     = [int]$Matches[4]
                    Database = $Matches[5]
                    File     = $f
                }
            }

            # SQLite: file: or sqlite:
            if ($content -match 'DATABASE_URL\s*=\s*"?(?:file:|sqlite:)') {
                return @{
                    Type     = "SQLite"
                    Host     = "localhost"
                    Port     = 0
                    File     = $f
                }
            }
        }
    }
    }
    return $null
}

# --- Detect Redis from .env files ---
function Get-RedisConfig {
    $envFiles = @(".env.local", ".env", ".env.development", ".env.development.local")
    $searchDirs = @($script:OriginalDir)
    if ($script:MonorepoRoot -and $script:MonorepoRoot -ne $script:OriginalDir) {
        $searchDirs += $script:MonorepoRoot
    }
    foreach ($searchDir in $searchDirs) {
    foreach ($f in $envFiles) {
        $envPath = Join-Path $searchDir $f
        if (Test-Path $envPath) {
            $content = Get-Content $envPath -Raw
            if ($content -match '(?:REDIS_URL|REDIS_URI)\s*=\s*"?redis://([^:/]*):?(\d*)') {
                $redisHost = if ($Matches[1]) { $Matches[1] } else { "localhost" }
                $redisPort = if ($Matches[2]) { [int]$Matches[2] } else { 6379 }
                return @{ Host = $redisHost; Port = $redisPort; File = $f }
            }
        }
    }
    }
    return $null
}

# --- Find Docker Desktop executable ---
function Find-DockerDesktop {
    $paths = @(
        "C:\Program Files\Docker\Docker\Docker Desktop.exe",
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { return $p }
    }
    $found = Get-ChildItem -Path "C:\Program Files" -Filter "Docker Desktop.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

# --- Ensure Docker daemon is running ---
function Test-DockerRunning {
    if (-not (Test-Command "docker")) {
        return $false
    }
    $null = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Step "Docker daemon is not running. Starting Docker Desktop..."
        $dockerDesktopPath = Find-DockerDesktop
        if ($dockerDesktopPath) {
            Start-Process $dockerDesktopPath -ErrorAction SilentlyContinue
        } else {
            Write-Err "Cannot find Docker Desktop executable. Start it manually."
            return $false
        }
        $dockerWait = 0
        while ($dockerWait -lt 120) {
            Start-Sleep -Seconds 5
            $dockerWait += 5
            docker info 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Docker is ready."
                $script:DockerStartedByUs = $true
                return $true
            }
            Write-Detail "Waiting for Docker... ($dockerWait`s)"
        }
        Write-Err "Docker failed to start within 120 seconds."
        return $false
    }
    return $true
}

# --- Detect and ensure Docker + database ---
function Initialize-Database {
    $dbConfig = Get-DatabaseConfig
    if (-not $dbConfig) {
        Write-Warn "No DATABASE_URL found in .env files. Skipping database setup."
        return $true
    }

    $script:DetectedDbType = $dbConfig.Type

    # SQLite needs no server
    if ($dbConfig.Type -eq "SQLite") {
        Write-Ok "SQLite database detected. No server needed."
        return $true
    }

    Write-Step "Found $($dbConfig.Type) config in $($dbConfig.File): $($dbConfig.Host):$($dbConfig.Port)"

    # Check if the database is already reachable
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($dbConfig.Host, $dbConfig.Port)
        $tcp.Close()
        Write-Ok "Database is already running on port $($dbConfig.Port)."
        return $true
    } catch {
        Write-Detail "Database not reachable. Will attempt to start via Docker..."
    }

    # Need Docker
    if (-not (Test-DockerRunning)) {
        Write-Err "Database ($($dbConfig.Type)) required but not reachable on port $($dbConfig.Port), and Docker is not available."
        Write-Err "    Fix: Start the database manually, or install Docker: winget install Docker.DockerDesktop"
        Write-Err "         Or update DATABASE_URL in .env to point to a running database."
        return $false
    }

    # Strategy 1: Check for an existing stopped container for this database
    $existingContainers = docker ps -a --filter "publish=$($dbConfig.Port)" --format "{{.Names}} {{.Status}}" 2>&1
    if ($existingContainers -and $LASTEXITCODE -eq 0) {
        foreach ($line in $existingContainers -split "`n") {
            $line = $line.Trim()
            if (-not $line) { continue }
            if ($line -match "^(\S+)\s+Exited") {
                $containerName = $Matches[1]
                Write-Step "Found stopped container '$containerName'. Restarting..."
                docker start $containerName | Out-Null
                $script:DbContainerName = $containerName
                $script:DbContainerStartedByUs = $true

                if (Wait-ForTcp $dbConfig.Host $dbConfig.Port -TimeoutSec 30 -Label $dbConfig.Type) {
                    return $true
                }
            } elseif ($line -match "^(\S+)\s+Up") {
                Write-Ok "Container is already running."
                return $true
            }
        }
    }

    # Strategy 2: Use docker-compose if available
    $composeFile = $null
    $composeDir = $null
    $composeDirs = @($script:OriginalDir)
    if ($script:MonorepoRoot -and $script:MonorepoRoot -ne $script:OriginalDir) {
        $composeDirs += $script:MonorepoRoot
    }
    foreach ($searchDir in $composeDirs) {
        foreach ($name in @("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")) {
            $cpath = Join-Path $searchDir $name
            if (Test-Path $cpath) { $composeFile = $name; $composeDir = $searchDir; break }
        }
        if ($composeFile) { break }
    }
    if ($composeFile) {
        Write-Step "Starting database via docker compose ($composeFile)..."
        $dbServiceStarted = $false
        foreach ($svcName in @("db", "database", "postgres", "postgresql", "mysql", "mariadb", "mongo", "mongodb", "mssql", "sqlserver")) {
            $null = docker compose -f (Join-Path $composeDir $composeFile) up -d $svcName 2>&1
            if ($LASTEXITCODE -eq 0) {
                $script:DbContainerName = $svcName
                $script:DbContainerStartedByUs = $true
                $script:DbStartedViaCompose = $true
                $script:ComposeFile = Join-Path $composeDir $composeFile
                $dbServiceStarted = $true
                break
            }
        }
        if (-not $dbServiceStarted) {
            docker compose -f (Join-Path $composeDir $composeFile) up -d 2>&1 | Out-Null
            $script:DbContainerStartedByUs = $true
            $script:DbStartedViaCompose = $true
            $script:ComposeFile = Join-Path $composeDir $composeFile
        }

        if (Wait-ForTcp $dbConfig.Host $dbConfig.Port -TimeoutSec 60 -Label "$($dbConfig.Type) (compose)") {
            return $true
        }
    }

    # Strategy 3: Start a standalone container
    $containerName = "zap-scan-$($dbConfig.Type.ToLower())"
    docker rm -f $containerName 2>$null | Out-Null

    if ($dbConfig.Type -eq "PostgreSQL") {
        Write-Step "Starting standalone PostgreSQL container..."
        docker run -d `
            --name $containerName `
            -e "POSTGRES_USER=$($dbConfig.User)" `
            -e "POSTGRES_PASSWORD=$($dbConfig.Password)" `
            -e "POSTGRES_DB=$($dbConfig.Database)" `
            -p "$($dbConfig.Port):5432" `
            postgres:17 2>&1 | Out-Null
    } elseif ($dbConfig.Type -eq "MySQL") {
        Write-Step "Starting standalone MySQL container..."
        docker run -d `
            --name $containerName `
            -e "MYSQL_ROOT_PASSWORD=$($dbConfig.Password)" `
            -e "MYSQL_DATABASE=$($dbConfig.Database)" `
            -e "MYSQL_USER=$($dbConfig.User)" `
            -e "MYSQL_PASSWORD=$($dbConfig.Password)" `
            -p "$($dbConfig.Port):3306" `
            mysql:8 2>&1 | Out-Null
    } elseif ($dbConfig.Type -eq "MongoDB") {
        Write-Step "Starting standalone MongoDB container..."
        docker run -d `
            --name $containerName `
            -p "$($dbConfig.Port):27017" `
            mongo:7 2>&1 | Out-Null
    } elseif ($dbConfig.Type -eq "MSSQL") {
        Write-Step "Starting standalone MSSQL container..."
        $saPassword = if ($dbConfig.Password) { $dbConfig.Password } else { "ZapScan_P@ss1" }
        docker run -d `
            --name $containerName `
            -e "ACCEPT_EULA=Y" `
            -e "SA_PASSWORD=$saPassword" `
            -p "$($dbConfig.Port):1433" `
            "mcr.microsoft.com/mssql/server:2022-latest" 2>&1 | Out-Null
    } else {
        Write-Err "Unsupported database type for standalone container: $($dbConfig.Type)"
        return $false
    }

    $script:DbContainerName = $containerName
    $script:DbContainerStartedByUs = $true

    if (Wait-ForTcp $dbConfig.Host $dbConfig.Port -TimeoutSec 60 -Label "$($dbConfig.Type) (standalone)") {
        return $true
    }

    Write-Err "Failed to start database."
    return $false
}

# --- Ensure Redis if needed ---
function Initialize-RedisCache {
    $redisConfig = Get-RedisConfig
    if (-not $redisConfig) { return }

    Write-Step "Redis configuration detected in $($redisConfig.File)"

    # Check if already reachable
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($redisConfig.Host, $redisConfig.Port)
        $tcp.Close()
        Write-Ok "Redis is already running on port $($redisConfig.Port)."
        return
    } catch {
        Write-Detail "Redis not reachable. Will attempt to start via Docker..."
    }

    if (-not (Test-DockerRunning)) {
        Write-Warn "Docker not available. Cannot start Redis. Continuing without it."
        return
    }

    docker rm -f $script:RedisContainerName 2>$null | Out-Null
    Write-Step "Starting standalone Redis container..."
    docker run -d `
        --name $script:RedisContainerName `
        -p "$($redisConfig.Port):6379" `
        redis:7 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        $script:RedisContainerStartedByUs = $true
        Wait-ForTcp $redisConfig.Host $redisConfig.Port -TimeoutSec 30 -Label "Redis" | Out-Null
    } else {
        Write-Warn "Failed to start Redis container. Continuing without it."
    }
}

# --- Detect Node.js package manager ---
function Get-NodePackageManager {
    # In a monorepo, check the root for lock files first
    $checkDirs = @($script:OriginalDir)
    if ($script:MonorepoRoot -and $script:MonorepoRoot -ne $script:OriginalDir) {
        $checkDirs = @($script:MonorepoRoot) + $checkDirs
    }
    foreach ($dir in $checkDirs) {
        if (Test-Path (Join-Path $dir "bun.lockb"))      { return @{ Name = "bun";  Install = "bun install";  Run = "bun run";  Root = $dir } }
        if (Test-Path (Join-Path $dir "pnpm-lock.yaml"))  { return @{ Name = "pnpm"; Install = "pnpm install"; Run = "pnpm run"; Root = $dir } }
        if (Test-Path (Join-Path $dir "yarn.lock"))       { return @{ Name = "yarn"; Install = "yarn install"; Run = "yarn";     Root = $dir } }
    }
    # Also check for packageManager field in root package.json
    $rootDir = if ($script:MonorepoRoot) { $script:MonorepoRoot } else { $script:OriginalDir }
    $rootPkgPath = Join-Path $rootDir "package.json"
    if (Test-Path $rootPkgPath) {
        $rootPkgText = Get-Content $rootPkgPath -Raw -ErrorAction SilentlyContinue
        if ($rootPkgText -match '"packageManager"\s*:\s*"(pnpm|yarn|bun)@') {
            $pmName = $Matches[1]
            switch ($pmName) {
                "pnpm" { return @{ Name = "pnpm"; Install = "pnpm install"; Run = "pnpm run"; Root = $rootDir } }
                "yarn" { return @{ Name = "yarn"; Install = "yarn install"; Run = "yarn";     Root = $rootDir } }
                "bun"  { return @{ Name = "bun";  Install = "bun install";  Run = "bun run";  Root = $rootDir } }
            }
        }
    }
    return @{ Name = "npm"; Install = "npm install"; Run = "npm run"; Root = $script:OriginalDir }
}

# --- Ensure package manager is installed ---
function Test-PackageManager([string]$Name) {
    if ($Name -eq "npm") { return $true }

    # Check if already available
    if (Test-Command $Name) { return $true }

    Write-Warn "$Name is not installed. Attempting to install..."

    # Strategy 1: corepack enable (built into Node.js 16.13+)
    if (Test-Command "corepack") {
        Write-Step "Enabling $Name via corepack..."
        $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c corepack enable 2>nul" -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -eq 0 -and (Test-Command $Name)) {
            Write-Ok "$Name enabled via corepack."
            return $true
        }
        # corepack enable might need a specific prepare for the version
        $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c corepack prepare $Name@latest --activate 2>nul" -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -eq 0 -and (Test-Command $Name)) {
            Write-Ok "$Name installed via corepack prepare."
            return $true
        }
    }

    # Strategy 2: npm install -g
    if (Test-Command "npm") {
        Write-Step "Installing $Name globally via npm..."
        $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c npm install -g $Name" -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            # Refresh PATH so the new command is found
            $npmRoot = & cmd.exe /c "npm root -g" 2>$null
            if ($npmRoot) {
                $npmBin = Split-Path $npmRoot -Parent
                if ($env:PATH -notlike "*$npmBin*") {
                    $env:PATH = "$npmBin;$env:PATH"
                }
            }
            if (Test-Command $Name) {
                Write-Ok "$Name installed globally via npm."
                return $true
            }
        }
    }

    Write-Err "$Name could not be installed automatically."
    Write-Err "    Fix: Install it manually: npm install -g $Name"
    Write-Err "         Or enable corepack: corepack enable"
    return $false
}

# --- Detect web app framework ---
function Get-AppFramework {
    $dir = $script:OriginalDir

    # --- Monorepo detection ---
    $isMonorepo = $false
    $monorepoType = $null
    if (Test-Path (Join-Path $dir "turbo.json"))          { $isMonorepo = $true; $monorepoType = "Turborepo" }
    elseif (Test-Path (Join-Path $dir "nx.json"))         { $isMonorepo = $true; $monorepoType = "Nx" }
    elseif (Test-Path (Join-Path $dir "pnpm-workspace.yaml")) { $isMonorepo = $true; $monorepoType = "pnpm workspace" }
    elseif (Test-Path (Join-Path $dir "package.json")) {
        try {
            $rootPkg = Get-Content (Join-Path $dir "package.json") -Raw | ConvertFrom-Json
            if ($rootPkg.workspaces) { $isMonorepo = $true; $monorepoType = "npm/yarn workspace" }
        } catch { $null = $_ }
    }

    if ($isMonorepo) {
        Write-Warn "Monorepo detected ($monorepoType). Looking for web app subdirectory..."
        $script:MonorepoRoot = $dir

        $foundWebApp = $false

        # Strategy 1: Config override via webAppDir
        if ($script:Config -and $script:Config.webAppDir) {
            $configWebDir = Join-Path $dir $script:Config.webAppDir
            if (Test-Path $configWebDir) {
                Write-Ok "Found web app at $($script:Config.webAppDir) (from .auto-zap.json)"
                $script:OriginalDir = $configWebDir
                $dir = $configWebDir
                $foundWebApp = $true
            } else {
                # List available directories for the error message
                $availDirs = @()
                foreach ($candidate in @("apps", "packages")) {
                    $candidatePath = Join-Path $dir $candidate
                    if (Test-Path $candidatePath) {
                        $subDirs = Get-ChildItem -Path $candidatePath -Directory -ErrorAction SilentlyContinue
                        foreach ($sd in $subDirs) {
                            $availDirs += "$candidate/$($sd.Name)"
                        }
                    }
                }
                Write-Err "webAppDir '$($script:Config.webAppDir)' specified in .auto-zap.json does not exist."
                Write-Err "    Fix: Check the path is relative to the project root and the directory exists."
                if ($availDirs.Count -gt 0) {
                    Write-Err "    Available directories: $($availDirs -join ', ')"
                }
                exit 1
            }
        }

        # Strategy 2: Smart scan - find package.json files with web framework deps
        if (-not $foundWebApp) {
            $excludeDirs = @("node_modules", ".next", "dist", "build", ".git", ".turbo", ".nx")
            $packageJsonFiles = @()

            # Recursively find package.json files up to depth 3
            for ($depth = 1; $depth -le 3; $depth++) {
                $candidates = Get-ChildItem -Path $dir -Filter "package.json" -Recurse -Depth $depth -ErrorAction SilentlyContinue
                foreach ($candidate in $candidates) {
                    $relPath = $candidate.DirectoryName.Substring($dir.Length).TrimStart('\', '/')
                    $skip = $false
                    foreach ($excl in $excludeDirs) {
                        if ($relPath -match "(^|[\\/])$([regex]::Escape($excl))([\\/]|$)") {
                            $skip = $true
                            break
                        }
                    }
                    if (-not $skip -and $relPath -ne "") {
                        $alreadyAdded = $packageJsonFiles | Where-Object { $_.FullName -eq $candidate.FullName }
                        if (-not $alreadyAdded) {
                            $packageJsonFiles += $candidate
                        }
                    }
                }
                if ($packageJsonFiles.Count -gt 0) { break }
            }

            $webFrameworkKeywords = @("next", "nuxt", "@remix-run/react", "express", "fastify", "hono",
                "@nestjs/core", "@angular/core", "vue", "svelte", "@sveltejs/kit", "astro", "gatsby", "remix")

            $matchedApps = @()
            foreach ($pkgFile in $packageJsonFiles) {
                try {
                    $pkgContent = Get-Content $pkgFile.FullName -Raw -ErrorAction SilentlyContinue
                    if (-not $pkgContent) { continue }
                    $hasWebFramework = $false
                    foreach ($keyword in $webFrameworkKeywords) {
                        if ($pkgContent -match [regex]::Escape("`"$keyword`"")) {
                            $hasWebFramework = $true
                            break
                        }
                    }
                    if ($hasWebFramework) {
                        $relPath = $pkgFile.DirectoryName.Substring($dir.Length).TrimStart('\', '/')
                        $matchedApps += @{ Path = $pkgFile.DirectoryName; RelPath = $relPath }
                    }
                } catch { $null = $_ }
            }

            if ($matchedApps.Count -gt 0) {
                # Prefer apps/ directories over packages/
                $appsDir = @($matchedApps | Where-Object { $_.RelPath -match "^apps[\\/]" })
                $chosen = $null
                if ($appsDir.Count -gt 0) {
                    # Among apps/, prefer names containing web, frontend, client, site
                    $preferred = @($appsDir | Where-Object { $_.RelPath -match "(web|frontend|client|site)" })
                    $chosen = if ($preferred.Count -gt 0) { $preferred[0] } else { $appsDir[0] }
                } else {
                    $chosen = $matchedApps[0]
                }
                Write-Ok "Found web app at $($chosen.RelPath) (smart scan)"
                $script:OriginalDir = $chosen.Path
                $dir = $chosen.Path
                $foundWebApp = $true
            }
        }

        # Strategy 3: Fallback to hardcoded list
        if (-not $foundWebApp) {
            $webAppDirs = @("apps/web", "apps/frontend", "apps/client", "apps/site", "packages/web", "packages/app")
            foreach ($subDir in $webAppDirs) {
                $subPath = Join-Path $dir $subDir
                if ((Test-Path $subPath) -and (Test-Path (Join-Path $subPath "package.json"))) {
                    Write-Ok "Found web app at $subDir"
                    $script:OriginalDir = $subPath
                    $dir = $subPath
                    $foundWebApp = $true
                    break
                }
            }
        }

        # Nothing found
        if (-not $foundWebApp) {
            $scannedCount = $packageJsonFiles.Count
            Write-Err "Monorepo detected ($monorepoType) but could not find a web application."
            Write-Err "    Scanned $scannedCount package.json files but none contained a web framework dependency."
            Write-Err "    Fix: Create .auto-zap.json with `"webAppDir`": `"path/to/your/web/app`""
            Write-Err "         Or cd into the web app directory and re-run."
            exit 1
        }
    }

    # --- Node.js ---
    if (Test-Path (Join-Path $dir "package.json")) {
        $pkg = Get-Content (Join-Path $dir "package.json") -Raw | ConvertFrom-Json
        $pm = Get-NodePackageManager
        $startCmd = $null
        $defaultPort = 3000
        $migrations = @()
        $subFramework = $null

        if ($pkg.scripts) {
            if ($pkg.scripts.dev)       { $startCmd = "$($pm.Run) dev" }
            elseif ($pkg.scripts.start) { $startCmd = "$($pm.Name) start" }
        }
        if (-not $startCmd) { $startCmd = "$($pm.Name) start" }

        # Detect port from frameworks and config files
        $pkgText = Get-Content (Join-Path $dir "package.json") -Raw

        # Detect sub-framework for technology mapping
        if ($pkgText -match '"next"')                                              { $defaultPort = 3000; $subFramework = "Next.js" }
        elseif ($pkgText -match '"nuxt"')                                          { $defaultPort = 3000; $subFramework = "Nuxt" }
        elseif ($pkgText -match '"remix"' -or $pkgText -match '"@remix-run"')      { $defaultPort = 3000; $subFramework = "Remix" }
        elseif ($pkgText -match '"@nestjs/core"' -or (Test-Path (Join-Path $dir "nest-cli.json"))) {
            $defaultPort = 3000
            $subFramework = "NestJS"
        }
        elseif (Test-Path (Join-Path $dir ".adonisrc.ts")) {
            $defaultPort = 3333
            $subFramework = "AdonisJS"
        }
        elseif ($pkgText -match '"express"')                                       { $defaultPort = 3000; $subFramework = "Express" }
        elseif ($pkgText -match '"hono"')                                          { $defaultPort = 3000; $subFramework = "Hono" }
        elseif ($pkgText -match '"fastify"')                                       { $defaultPort = 3000; $subFramework = "Fastify" }
        elseif ($pkgText -match '"vite"' -or $pkgText -match '"@vitejs"') {
            $defaultPort = 5173
            $subFramework = "Vite"
            foreach ($configFile in @("vite.config.ts", "vite.config.js", "vite.config.mts")) {
                $configPath = Join-Path $dir $configFile
                if (Test-Path $configPath) {
                    $viteConfig = Get-Content $configPath -Raw -ErrorAction SilentlyContinue
                    if ($viteConfig -match 'port\s*:\s*(\d+)') {
                        $defaultPort = [int]$Matches[1]
                    }
                    break
                }
            }
        }
        elseif ($pkgText -match '"svelte"' -or $pkgText -match '"@sveltejs"')      { $defaultPort = 5173; $subFramework = "SvelteKit" }
        elseif ($pkgText -match '"astro"')                                         { $defaultPort = 4321; $subFramework = "Astro" }
        elseif ($pkgText -match '"gatsby"')                                        { $defaultPort = 8000; $subFramework = "Gatsby" }
        elseif ($pkgText -match '"@angular"')                                      { $defaultPort = 4200; $subFramework = "Angular" }

        # Check for explicit port in dev script
        if ($pkg.scripts -and $pkg.scripts.dev) {
            $devScript = $pkg.scripts.dev
            if ($devScript -match '-p\s+(\d+)|--port\s+(\d+)|PORT=(\d+)') {
                $portMatch = $Matches[1]
                if (-not $portMatch) { $portMatch = $Matches[2] }
                if (-not $portMatch) { $portMatch = $Matches[3] }
                if ($portMatch) { $defaultPort = [int]$portMatch }
            }
        }

        # Detect ORM migrations (check both app dir and monorepo root)
        $ormPkgTexts = @($pkgText)
        $ormDirsToCheck = @($dir)
        if ($script:MonorepoRoot -and $script:MonorepoRoot -ne $dir) {
            $ormDirsToCheck += $script:MonorepoRoot
            $rootPkgPath = Join-Path $script:MonorepoRoot "package.json"
            if (Test-Path $rootPkgPath) {
                $ormPkgTexts += (Get-Content $rootPkgPath -Raw -ErrorAction SilentlyContinue)
            }
        }
        $hasPrisma = $false; $hasDrizzle = $false; $hasTypeorm = $false; $hasKnex = $false; $hasSequelize = $false
        foreach ($txt in $ormPkgTexts) {
            if ($txt -match '"prisma"')       { $hasPrisma = $true }
            if ($txt -match '"drizzle-kit"')  { $hasDrizzle = $true }
            if ($txt -match '"typeorm"')      { $hasTypeorm = $true }
            if ($txt -match '"knex"')         { $hasKnex = $true }
            if ($txt -match '"sequelize"')    { $hasSequelize = $true }
        }
        foreach ($checkDir in $ormDirsToCheck) {
            if (Test-Path (Join-Path $checkDir "prisma")) { $hasPrisma = $true }
        }
        if ($hasPrisma) {
            $migrations += "npx prisma generate"
            $migrations += "npx prisma db push"
        }
        if ($hasDrizzle) {
            $migrations += "npx drizzle-kit push"
        }
        if ($hasTypeorm) {
            $migrations += "npx typeorm migration:run"
        }
        if ($hasKnex) {
            $migrations += "npx knex migrate:latest"
        }
        if ($hasSequelize) {
            $migrations += "npx sequelize-cli db:migrate"
        }

        # Detect GraphQL
        if ($pkgText -match '"graphql"' -or $pkgText -match '"@apollo/server"' -or $pkgText -match '"type-graphql"' -or $pkgText -match '"@graphql-yoga"') {
            $script:GraphqlDetected = $true
        }

        $frameworkLabel = "Node.js ($($pm.Name))"
        if ($subFramework) { $frameworkLabel += " - $subFramework" }

        return @{
            Name         = $frameworkLabel
            Runtime      = "Node.js"
            SubFramework = $subFramework
            Command      = $startCmd
            Port         = $defaultPort
            Install      = $pm.Install
            InstallDir   = $pm.Root
            Migrations   = $migrations
            NeedsDb      = ($migrations.Count -gt 0)
        }
    }

    # --- Python (Django / Flask / FastAPI) ---
    $hasPyProject    = Test-Path (Join-Path $dir "pyproject.toml")
    $hasRequirements = Test-Path (Join-Path $dir "requirements.txt")
    $hasPipfile      = Test-Path (Join-Path $dir "Pipfile")
    $hasPoetryLock   = Test-Path (Join-Path $dir "poetry.lock")
    $hasUvLock       = Test-Path (Join-Path $dir "uv.lock")

    if ($hasRequirements -or $hasPipfile -or $hasPyProject -or $hasPoetryLock -or $hasUvLock) {
        $defaultPort = 8000
        $startCmd = $null
        $migrations = @()
        $installCmd = $null
        $subFramework = $null
        $runPrefix = ""

        # Determine install command and run prefix
        if ($hasUvLock) {
            $installCmd = "uv sync"
            $runPrefix = "uv run "
        } elseif ($hasPoetryLock) {
            $installCmd = "poetry install"
            $runPrefix = "poetry run "
        } elseif ($hasPipfile) {
            $installCmd = "pipenv install"
            $runPrefix = "pipenv run "
        } elseif ($hasRequirements) {
            $installCmd = "pip install -r requirements.txt"
        } elseif ($hasPyProject) {
            $installCmd = "pip install -e ."
        }

        # Detect Django by manage.py
        if (Test-Path (Join-Path $dir "manage.py")) {
            $subFramework = "Django"
            $startCmd = "${runPrefix}python manage.py runserver 0.0.0.0:$defaultPort"
            $migrations += "${runPrefix}python manage.py migrate"

            # Try to detect Django settings module
            $managePy = Get-Content (Join-Path $dir "manage.py") -Raw -ErrorAction SilentlyContinue
            if ($managePy -match "DJANGO_SETTINGS_MODULE.*?['""]([^'""]+)['""]") {
                Write-Detail "Django settings: $($Matches[1])"
            }
        }

        # Check requirements/pyproject for framework hints
        $pyFiles = @("requirements.txt", "Pipfile", "pyproject.toml") | Where-Object { Test-Path (Join-Path $dir $_) }
        foreach ($f in $pyFiles) {
            $content = Get-Content (Join-Path $dir $f) -Raw -ErrorAction SilentlyContinue
            if (-not $content) { continue }
            if ($content -match "fastapi|uvicorn" -and -not $startCmd) {
                $subFramework = "FastAPI"
                # Check if fastapi CLI is available
                if ($content -match '"fastapi\[') {
                    $startCmd = "${runPrefix}fastapi dev --host 0.0.0.0 --port $defaultPort"
                } else {
                    $startCmd = "${runPrefix}uvicorn main:app --host 0.0.0.0 --port $defaultPort"
                }
                break
            }
            if ($content -match "flask" -and -not $startCmd) {
                $subFramework = "Flask"
                $defaultPort = 5000
                $startCmd = "${runPrefix}flask run --host=0.0.0.0 --port $defaultPort"
                break
            }
            if ($content -match "django" -and -not $startCmd) {
                $subFramework = "Django"
                $startCmd = "${runPrefix}python manage.py runserver 0.0.0.0:$defaultPort"
                break
            }
            # Detect GraphQL for Python
            if ($content -match "graphene|strawberry-graphql|ariadne") {
                $script:GraphqlDetected = $true
            }
        }

        if (-not $startCmd) {
            if (Test-Path (Join-Path $dir "app.py"))  { $startCmd = "${runPrefix}python app.py"; $defaultPort = 5000 }
            elseif (Test-Path (Join-Path $dir "main.py")) { $startCmd = "${runPrefix}python main.py" }
            else { $startCmd = "${runPrefix}python app.py" }
        }

        $frameworkLabel = "Python"
        if ($subFramework) { $frameworkLabel += " - $subFramework" }

        return @{
            Name         = $frameworkLabel
            Runtime      = "Python"
            SubFramework = $subFramework
            Command      = $startCmd
            Port         = $defaultPort
            Install      = $installCmd
            Migrations   = $migrations
            NeedsDb      = ($migrations.Count -gt 0)
        }
    }

    # --- .NET ---
    $csproj = Get-ChildItem -Path $dir -Filter "*.csproj" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($csproj) {
        $dotnetPort = 5000
        $launchSettings = Join-Path $dir "Properties\launchSettings.json"
        if (Test-Path $launchSettings) {
            $lsContent = Get-Content $launchSettings -Raw -ErrorAction SilentlyContinue
            if ($lsContent -match '"applicationUrl"\s*:\s*"[^"]*http://[^:]+:(\d+)') {
                $dotnetPort = [int]$Matches[1]
            }
        }
        $migrations = @()
        $csprojContent = Get-Content $csproj.FullName -Raw -ErrorAction SilentlyContinue
        if ($csprojContent -match "Microsoft\.EntityFrameworkCore") {
            $migrations += "dotnet ef database update"
        }
        return @{
            Name         = ".NET"
            Runtime      = ".NET"
            SubFramework = $null
            Command      = "dotnet run --urls=http://localhost:$dotnetPort"
            Port         = $dotnetPort
            Install      = "dotnet restore"
            Migrations   = $migrations
            NeedsDb      = ($migrations.Count -gt 0)
        }
    }

    # --- Java (Maven) ---
    if (Test-Path (Join-Path $dir "pom.xml")) {
        $javaPort = 8080
        $mavenCmd = "mvn"

        # Check for Maven wrapper
        if (Test-Path (Join-Path $dir "mvnw.cmd")) { $mavenCmd = ".\mvnw.cmd" }
        elseif (Test-Path (Join-Path $dir "mvnw"))  { $mavenCmd = ".\mvnw" }

        # Parse Spring Boot application.properties for port
        $appProps = Join-Path $dir "src\main\resources\application.properties"
        if (Test-Path $appProps) {
            $propsContent = Get-Content $appProps -Raw -ErrorAction SilentlyContinue
            if ($propsContent -match 'server\.port\s*=\s*(\d+)') {
                $javaPort = [int]$Matches[1]
            }
        }

        # Parse application.yml for port
        $appYml = Join-Path $dir "src\main\resources\application.yml"
        if (Test-Path $appYml) {
            $ymlContent = Get-Content $appYml -Raw -ErrorAction SilentlyContinue
            if ($ymlContent -match 'port\s*:\s*(\d+)') {
                $javaPort = [int]$Matches[1]
            }
        }

        return @{
            Name         = "Java/Maven"
            Runtime      = "Java"
            SubFramework = "Spring Boot"
            Command      = "$mavenCmd spring-boot:run"
            Port         = $javaPort
            Install      = "$mavenCmd install -DskipTests"
            Migrations   = @()
            NeedsDb      = $false
        }
    }

    # --- Java (Gradle) ---
    if (Test-Path (Join-Path $dir "build.gradle") -or (Test-Path (Join-Path $dir "build.gradle.kts"))) {
        $javaPort = 8080
        $gradleCmd = ".\gradlew"
        if (-not (Test-Path (Join-Path $dir "gradlew")) -and -not (Test-Path (Join-Path $dir "gradlew.bat"))) {
            $gradleCmd = "gradle"
        }

        # Parse Spring Boot application.properties for port
        $appProps = Join-Path $dir "src\main\resources\application.properties"
        if (Test-Path $appProps) {
            $propsContent = Get-Content $appProps -Raw -ErrorAction SilentlyContinue
            if ($propsContent -match 'server\.port\s*=\s*(\d+)') {
                $javaPort = [int]$Matches[1]
            }
        }

        $appYml = Join-Path $dir "src\main\resources\application.yml"
        if (Test-Path $appYml) {
            $ymlContent = Get-Content $appYml -Raw -ErrorAction SilentlyContinue
            if ($ymlContent -match 'port\s*:\s*(\d+)') {
                $javaPort = [int]$Matches[1]
            }
        }

        return @{
            Name         = "Java/Gradle"
            Runtime      = "Java"
            SubFramework = "Spring Boot"
            Command      = "$gradleCmd bootRun"
            Port         = $javaPort
            Install      = "$gradleCmd build -x test"
            Migrations   = @()
            NeedsDb      = $false
        }
    }

    # --- PHP (Laravel) ---
    if (Test-Path (Join-Path $dir "artisan")) {
        return @{
            Name         = "PHP/Laravel"
            Runtime      = "PHP"
            SubFramework = "Laravel"
            Command      = "php artisan serve --port=8000"
            Port         = 8000
            Install      = "composer install"
            Migrations   = @("php artisan migrate --force")
            NeedsDb      = $true
        }
    }

    # --- PHP (Symfony) ---
    if (Test-Path (Join-Path $dir "symfony.lock")) {
        $sfCmd = "php -S localhost:8000 -t public/"
        if (Test-Command "symfony") { $sfCmd = "symfony serve --port=8000" }
        return @{
            Name         = "PHP/Symfony"
            Runtime      = "PHP"
            SubFramework = "Symfony"
            Command      = $sfCmd
            Port         = 8000
            Install      = "composer install"
            Migrations   = @("php bin/console doctrine:migrations:migrate --no-interaction")
            NeedsDb      = $true
        }
    }

    # --- PHP (WordPress) ---
    if (Test-Path (Join-Path $dir "wp-config.php")) {
        Write-Warn "WordPress detected. WordPress requires Apache/Nginx + MySQL."
        Write-Warn "Use -Url to scan a running WordPress instance."
        return @{
            Name         = "PHP/WordPress"
            Runtime      = "PHP"
            SubFramework = "WordPress"
            Command      = "php -S localhost:8080 -t ."
            Port         = 8080
            Install      = $null
            Migrations   = @()
            NeedsDb      = $true
        }
    }

    # --- PHP (generic) ---
    if (Test-Path (Join-Path $dir "composer.json") -or (Get-ChildItem -Path $dir -Filter "*.php" -ErrorAction SilentlyContinue | Select-Object -First 1)) {
        return @{
            Name         = "PHP"
            Runtime      = "PHP"
            SubFramework = $null
            Command      = "php -S localhost:8080 -t ."
            Port         = 8080
            Install      = $null
            Migrations   = @()
            NeedsDb      = $false
        }
    }

    # --- Ruby on Rails ---
    if (Test-Path (Join-Path $dir "Gemfile")) {
        $startCmd = if (Test-Path (Join-Path $dir "bin\rails")) { "ruby bin\rails server -p 3000" } else { "bundle exec rails server -p 3000" }
        return @{
            Name         = "Ruby/Rails"
            Runtime      = "Ruby"
            SubFramework = "Rails"
            Command      = $startCmd
            Port         = 3000
            Install      = "bundle install"
            Migrations   = @("bundle exec rails db:migrate")
            NeedsDb      = $true
        }
    }

    # --- Go ---
    if (Test-Path (Join-Path $dir "go.mod")) {
        return @{
            Name         = "Go"
            Runtime      = "Go"
            SubFramework = $null
            Command      = "go run ."
            Port         = 8080
            Install      = "go mod download"
            Migrations   = @()
            NeedsDb      = $false
        }
    }

    # --- Rust (Actix / Rocket / Axum) ---
    if (Test-Path (Join-Path $dir "Cargo.toml")) {
        return @{
            Name         = "Rust"
            Runtime      = "Rust"
            SubFramework = $null
            Command      = "cargo run"
            Port         = 8080
            Install      = $null
            Migrations   = @()
            NeedsDb      = $false
        }
    }

    # --- Elixir/Phoenix ---
    if (Test-Path (Join-Path $dir "mix.exs")) {
        $mixContent = Get-Content (Join-Path $dir "mix.exs") -Raw -ErrorAction SilentlyContinue
        $isPhoenix = $mixContent -and ($mixContent -match ':phoenix')
        $elixirPort = if ($isPhoenix) { 4000 } else { 4000 }
        $startCmd = if ($isPhoenix) { "mix phx.server" } else { "mix run --no-halt" }
        $migrations = @()
        if ($isPhoenix -and $mixContent -match ':ecto') {
            $migrations += "mix ecto.setup"
        }
        $frameworkLabel = if ($isPhoenix) { "Elixir - Phoenix" } else { "Elixir" }
        return @{
            Name         = $frameworkLabel
            Runtime      = "Elixir"
            SubFramework = if ($isPhoenix) { "Phoenix" } else { $null }
            Command      = $startCmd
            Port         = $elixirPort
            Install      = "mix deps.get"
            Migrations   = $migrations
            NeedsDb      = ($migrations.Count -gt 0)
        }
    }

    # --- Deno ---
    if (Test-Path (Join-Path $dir "deno.json") -or Test-Path (Join-Path $dir "deno.jsonc")) {
        $startCmd = "deno task dev"
        $denoConfig = $null
        foreach ($name in @("deno.json", "deno.jsonc")) {
            $dpath = Join-Path $dir $name
            if (Test-Path $dpath) {
                try { $denoConfig = Get-Content $dpath -Raw | ConvertFrom-Json } catch { $null = $_ }
                break
            }
        }
        if ($denoConfig -and $denoConfig.tasks) {
            if ($denoConfig.tasks.dev) { $startCmd = "deno task dev" }
            elseif ($denoConfig.tasks.start) { $startCmd = "deno task start" }
        }
        return @{
            Name         = "Deno"
            Runtime      = "Deno"
            SubFramework = $null
            Command      = $startCmd
            Port         = 8000
            Install      = $null
            Migrations   = @()
            NeedsDb      = $false
        }
    }

    # --- Bun-native (bunfig.toml without package.json) ---
    if ((Test-Path (Join-Path $dir "bunfig.toml")) -and -not (Test-Path (Join-Path $dir "package.json"))) {
        $startCmd = "bun run index.ts"
        if (Test-Path (Join-Path $dir "src\index.ts"))   { $startCmd = "bun run src/index.ts" }
        elseif (Test-Path (Join-Path $dir "index.ts"))    { $startCmd = "bun run index.ts" }
        elseif (Test-Path (Join-Path $dir "src\index.js")){ $startCmd = "bun run src/index.js" }
        elseif (Test-Path (Join-Path $dir "index.js"))    { $startCmd = "bun run index.js" }
        return @{
            Name         = "Bun (native)"
            Runtime      = "Bun"
            SubFramework = $null
            Command      = $startCmd
            Port         = 3000
            Install      = "bun install"
            Migrations   = @()
            NeedsDb      = $false
        }
    }

    # --- Static site (index.html) ---
    if (Test-Path (Join-Path $dir "index.html")) {
        if (Test-Command "python") {
            return @{ Name = "Static (Python server)"; Runtime = "Static"; SubFramework = $null; Command = "python -m http.server 8080"; Port = 8080; Install = $null; Migrations = @(); NeedsDb = $false }
        } elseif (Test-Command "npx") {
            return @{ Name = "Static (serve)"; Runtime = "Static"; SubFramework = $null; Command = "npx serve -l 8080"; Port = 8080; Install = $null; Migrations = @(); NeedsDb = $false }
        }
    }

    # --- Dockerfile fallback (no framework detected, but Dockerfile exists) ---
    if (Test-Path (Join-Path $dir "Dockerfile")) {
        $dockerfileContent = Get-Content (Join-Path $dir "Dockerfile") -Raw -ErrorAction SilentlyContinue
        if ($dockerfileContent) {
            $dockerPort = 3000
            # Parse EXPOSE directive for port
            $exposeMatches = [regex]::Matches($dockerfileContent, 'EXPOSE\s+(\d+)')
            if ($exposeMatches.Count -gt 0) {
                # Use the first EXPOSE port (usually the main app port)
                $dockerPort = [int]$exposeMatches[0].Groups[1].Value
            }

            # Check if Docker is available
            if (Test-Command "docker") {
                $containerName = "zap-scan-target"
                $buildCmd = "docker build -t $containerName `"$dir`" && docker run -d --name $containerName -p ${dockerPort}:${dockerPort} $containerName"
                Write-Warn "No framework detected but Dockerfile found. Will build and run via Docker."
                Write-Detail "EXPOSE port: $dockerPort"
                return @{
                    Name         = "Docker (Dockerfile)"
                    Runtime      = "Docker"
                    SubFramework = $null
                    Command      = $buildCmd
                    Port         = $dockerPort
                    Install      = $null
                    Migrations   = @()
                    NeedsDb      = $false
                }
            } else {
                Write-Warn "Dockerfile found but Docker is not available. Cannot auto-start."
            }
        }
    }

    return $null
}

function Invoke-ProjectCommand([string]$Label, [string]$Command, [string]$WorkDir) {
    if (-not $WorkDir) { $WorkDir = $script:OriginalDir }
    Write-Step "$Label`: $Command"
    Write-Detail "Working directory: $WorkDir"
    $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $Command" -WorkingDirectory $WorkDir -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Warn "$Label exited with code $($proc.ExitCode)"
        return $false
    }
    Write-Ok "$Label complete."
    return $true
}

# =============================================================
# PHASE 1: ZAP Context & Technology Configuration
# =============================================================
function Set-ZapContext {
    param(
        [string]$TargetUrl,
        [hashtable]$Framework
    )

    Write-Step "Configuring ZAP scan context..."

    # Create context
    try {
        $resp = Invoke-ZapApi "/JSON/context/action/newContext/?contextName=$($script:ZapContextName)"
        $script:ZapContextId = $resp.contextId
    } catch {
        Write-Warn "Failed to create ZAP context: $($_.Exception.Message)"
        return
    }

    # Parse target URL for port pattern
    $uri = [uri]$TargetUrl
    $hostPort = "$($uri.Scheme)://$($uri.Host):$($uri.Port)"
    $includeRegex = [uri]::EscapeDataString("${hostPort}.*")

    # Include target URL pattern
    try {
        Invoke-ZapApi "/JSON/context/action/includeInContext/?contextName=$($script:ZapContextName)&regex=$includeRegex" | Out-Null
    } catch {
        Write-Warn "Failed to include URL pattern in context."
    }

    # Exclude common noise patterns
    $excludePatterns = @(
        '.*\.(css|js|png|jpg|jpeg|gif|svg|woff2?|ttf|eot|ico|map)(\?.*)?$',
        '.*logout.*',
        '.*signout.*',
        '.*google-analytics.*',
        '.*cdn\..*',
        '.*fonts\.googleapis\.com.*'
    )
    foreach ($pattern in $excludePatterns) {
        try {
            $escaped = [uri]::EscapeDataString($pattern)
            Invoke-ZapApi "/JSON/context/action/excludeFromContext/?contextName=$($script:ZapContextName)&regex=$escaped" | Out-Null
        } catch { $null = $_ }
    }

    # Add config-defined exclude patterns
    if ($script:Config -and $script:Config.exclude) {
        foreach ($pattern in $script:Config.exclude) {
            try {
                $escaped = [uri]::EscapeDataString($pattern)
                Invoke-ZapApi "/JSON/context/action/excludeFromContext/?contextName=$($script:ZapContextName)&regex=$escaped" | Out-Null
                Write-Detail "Excluded pattern (config): $pattern"
            } catch { $null = $_ }
        }
    }

    # --- Technology stack mapping ---
    if ($Framework) {
        $runtime = $Framework.Runtime

        # Query ZAP for the actual supported technology names
        $availableTechs = @()
        try {
            $techListResp = Invoke-ZapApi "/JSON/context/view/technologyList/"
            if ($techListResp.technologyList) {
                $availableTechs = @($techListResp.technologyList)
            }
        } catch {
            Write-Detail "Could not query ZAP technology list."
        }

        # Build a list of keywords to match against ZAP's technology list
        $wantedKeywords = @()
        switch -Wildcard ($runtime) {
            "Node.js" { $wantedKeywords = @("JavaScript", "Node") }
            "Deno"    { $wantedKeywords = @("JavaScript") }
            "Python"  { $wantedKeywords = @("Python") }
            ".NET"    { $wantedKeywords = @("ASP", "C#", ".NET") }
            "Java"    { $wantedKeywords = @("Java", "JSP", "Servlet", "Spring", "Tomcat") }
            "PHP"     { $wantedKeywords = @("PHP") }
            "Ruby"    { $wantedKeywords = @("Ruby") }
            "Go"      { $wantedKeywords = @() }
            "Rust"    { $wantedKeywords = @() }
        }

        # Add database keywords
        $dbConfig = Get-DatabaseConfig
        if ($dbConfig) {
            switch ($dbConfig.Type) {
                "PostgreSQL" { $wantedKeywords += "PostgreSQL" }
                "MySQL"      { $wantedKeywords += "MySQL" }
                "MongoDB"    { $wantedKeywords += "MongoDB" }
                "MSSQL"      { $wantedKeywords += @("SQL Server", "MSSQL") }
                "SQLite"     { $wantedKeywords += "SQLite" }
            }
        }

        # Always include OS and common infrastructure
        $wantedKeywords += @("Windows", "Linux")

        if ($availableTechs.Count -gt 0 -and $wantedKeywords.Count -gt 0) {
            # Match wanted keywords against actual ZAP technology names
            $matchedTechs = @()
            foreach ($tech in $availableTechs) {
                foreach ($keyword in $wantedKeywords) {
                    if ($tech -match [regex]::Escape($keyword)) {
                        $matchedTechs += $tech
                        break
                    }
                }
            }

            if ($matchedTechs.Count -gt 0) {
                try {
                    Invoke-ZapApi "/JSON/context/action/excludeAllContextTechnologies/?contextName=$($script:ZapContextName)" | Out-Null
                    $techString = [uri]::EscapeDataString(($matchedTechs -join ","))
                    Invoke-ZapApi "/JSON/context/action/includeContextTechnologies/?contextName=$($script:ZapContextName)&technologyNames=$techString" | Out-Null
                    $script:TechList = $matchedTechs
                    Write-Ok "Technology filter applied: $($matchedTechs -join ', ')"
                } catch {
                    Write-Warn "Failed to set technology filter: $($_.Exception.Message)"
                    try {
                        Invoke-ZapApi "/JSON/context/action/includeAllContextTechnologies/?contextName=$($script:ZapContextName)" | Out-Null
                    } catch { $null = $_ }
                }
            } else {
                Write-Detail "No matching technologies found in ZAP. Using all technologies."
            }
        } elseif ($wantedKeywords.Count -gt 0) {
            Write-Detail "Could not query ZAP tech list. Skipping technology filter."
        }
    }

    # --- Configure anti-CSRF token names ---
    $csrfTokens = @('_csrf', 'csrf_token', '_token', 'authenticity_token', 'csrfmiddlewaretoken', '__RequestVerificationToken', 'X-CSRF-TOKEN')
    foreach ($token in $csrfTokens) {
        try {
            Invoke-ZapApi "/JSON/acsrf/action/addOptionToken/?String=$([uri]::EscapeDataString($token))" | Out-Null
        } catch { $null = $_ }
    }
    try {
        Invoke-ZapApi "/JSON/ascan/action/setOptionHandleAntiCSRFTokens/?Boolean=true" | Out-Null
    } catch { $null = $_ }

    Write-Ok "ZAP context configured (ID: $($script:ZapContextId))."
}

# =============================================================
# PHASE 2: OpenAPI / Swagger / GraphQL Import
# =============================================================
function Import-ApiSpec {
    param(
        [string]$TargetUrl,
        [string]$ProjectDir
    )

    Write-Step "Searching for API specifications..."

    $contextParam = ""
    if ($script:ZapContextId) { $contextParam = "&contextId=$($script:ZapContextId)" }

    # --- Strategy 1: Search for spec files in the project directory ---
    $specFileNames = @(
        "openapi.json", "openapi.yaml", "openapi.yml",
        "swagger.json", "swagger.yaml", "swagger.yml",
        "api-docs.json", "api-docs.yaml"
    )
    $searchDirs = @("", "docs", "api", "public", "static", "src")

    foreach ($subDir in $searchDirs) {
        foreach ($specFile in $specFileNames) {
            $specPath = if ($subDir) { Join-Path (Join-Path $ProjectDir $subDir) $specFile } else { Join-Path $ProjectDir $specFile }
            if (Test-Path $specPath) {
                Write-Detail "Found spec file: $specPath"
                if (-not $script:UsingDockerZap) {
                    try {
                        $escapedPath = [uri]::EscapeDataString($specPath)
                        $escapedTarget = [uri]::EscapeDataString($TargetUrl)
                        Invoke-ZapApi "/JSON/openapi/action/importFile/?file=$escapedPath&target=$escapedTarget$contextParam" | Out-Null
                        $script:ApiSpecSource = "File: $specPath"
                        Write-Ok "Imported API spec from file: $specPath"
                        return
                    } catch {
                        Write-Warn "Failed to import spec file: $($_.Exception.Message)"
                    }
                } else {
                    Write-Detail "Skipping file import (Docker ZAP cannot access host files directly)."
                }
            }
        }
    }

    # --- Strategy 2: Probe well-known runtime spec URLs ---
    $specUrls = @(
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/api-docs",
        "/v3/api-docs",
        "/openapi.json",
        "/api/openapi.json",
        "/docs/openapi.json"
    )

    foreach ($specUrl in $specUrls) {
        try {
            $fullUrl = "${TargetUrl}${specUrl}"
            $resp = Invoke-WebRequest -Uri $fullUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            if ($resp.StatusCode -eq 200 -and $resp.Content.Length -gt 20) {
                # Verify it looks like JSON or YAML
                $contentStart = $resp.Content.Substring(0, [Math]::Min(50, $resp.Content.Length)).Trim()
                if ($contentStart.StartsWith("{") -or $contentStart.StartsWith("openapi") -or $contentStart.StartsWith("swagger")) {
                    Write-Detail "Found API spec at: $fullUrl"
                    $zapTargetForImport = if ($script:UsingDockerZap) { $fullUrl -replace "localhost", "host.docker.internal" } else { $fullUrl }
                    try {
                        $escapedUrl = [uri]::EscapeDataString($zapTargetForImport)
                        Invoke-ZapApi "/JSON/openapi/action/importUrl/?url=$escapedUrl$contextParam" | Out-Null
                        $script:ApiSpecSource = "URL: $specUrl"
                        Write-Ok "Imported API spec from: $specUrl"
                        return
                    } catch {
                        Write-Warn "ZAP failed to import spec from URL: $($_.Exception.Message)"
                    }
                }
            }
        } catch { $null = $_ }
    }

    Write-Detail "No OpenAPI/Swagger specification found."
}

function Import-GraphqlSchema {
    param(
        [string]$TargetUrl
    )

    if (-not $script:GraphqlDetected) { return }

    Write-Step "GraphQL detected. Attempting schema import..."

    $graphqlEndpoints = @("/graphql", "/api/graphql", "/graphql/v1")
    $contextParam = ""
    if ($script:ZapContextId) { $contextParam = "&contextId=$($script:ZapContextId)" }

    foreach ($ep in $graphqlEndpoints) {
        try {
            # Test if the endpoint responds
            $testUrl = "${TargetUrl}${ep}"
            $body = '{"query":"{ __typename }"}'
            $resp = Invoke-WebRequest -Uri $testUrl -Method POST -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) {
                Write-Detail "GraphQL endpoint found at: $ep"
                $zapUrl = if ($script:UsingDockerZap) { $testUrl -replace "localhost", "host.docker.internal" } else { $testUrl }
                try {
                    $escapedUrl = [uri]::EscapeDataString($zapUrl)
                    Invoke-ZapApi "/JSON/graphql/action/importUrl/?url=$escapedUrl&endpointUrl=$escapedUrl$contextParam" | Out-Null
                    Write-Ok "Imported GraphQL schema from: $ep"
                    return
                } catch {
                    Write-Warn "ZAP failed to import GraphQL schema: $($_.Exception.Message)"
                }
            }
        } catch { $null = $_ }
    }

    Write-Detail "Could not import GraphQL schema automatically."
}

# =============================================================
# PHASE 3: Authenticated Scanning
# =============================================================
function Set-ZapAuth {
    param(
        [string]$TargetUrl,
        [string]$ProjectDir
    )

    # If AuthToken provided, use header-based auth (simplest)
    if ($AuthToken) {
        Write-Step "Configuring bearer token authentication..."
        try {
            $tokenValue = if ($AuthToken -match "^Bearer ") { $AuthToken } else { "Bearer $AuthToken" }
            $escapedToken = [uri]::EscapeDataString($tokenValue)
            Invoke-ZapApi "/JSON/replacer/action/addRule/?description=AuthHeader&enabled=true&matchType=REQ_HEADER&matchRegex=false&matchString=Authorization&replacement=$escapedToken&initiators=" | Out-Null
            $script:AuthResult = @{ Type = "bearer"; Description = "Bearer token (header injection)" }
            Write-Ok "Bearer token authentication configured."
        } catch {
            Write-Warn "Failed to configure bearer auth: $($_.Exception.Message)"
        }
        return
    }

    # --- Auto-detect credentials from .env files ---
    $detectedUser = $AuthUser
    $detectedPass = $AuthPassword

    if (-not $detectedUser -or -not $detectedPass) {
        $envFiles = @(".env.local", ".env", ".env.development", ".env.development.local")
        foreach ($f in $envFiles) {
            $envPath = Join-Path $ProjectDir $f
            if (-not (Test-Path $envPath)) { continue }
            $content = Get-Content $envPath -Raw

            foreach ($prefix in @("TEST_", "AUTH_", "ADMIN_", "BETTER_AUTH_", "")) {
                if (-not $detectedUser -and $content -match "(?m)^${prefix}(?:USER|USERNAME|EMAIL)\s*=\s*`"?([^`"\r\n]+)") {
                    $detectedUser = $Matches[1].Trim()
                }
                if (-not $detectedPass -and $content -match "(?m)^${prefix}(?:PASS|PASSWORD)\s*=\s*`"?([^`"\r\n]+)") {
                    $detectedPass = $Matches[1].Trim()
                }
                if ($detectedUser -and $detectedPass) { break }
            }
            if ($detectedUser -and $detectedPass) { break }
        }
    }

    if (-not $detectedUser -or -not $detectedPass) {
        Write-Detail "No authentication credentials found. Scanning as unauthenticated user."
        return
    }

    Write-Step "Configuring authenticated scanning (user: $detectedUser)..."

    # --- Auto-detect login endpoint ---
    $loginUrl = $AuthUrl
    if (-not $loginUrl) {
        $loginEndpoints = @(
            "/api/auth/login", "/api/auth/signin", "/api/auth/sign-in",
            "/api/login", "/auth/login", "/auth/signin",
            "/login", "/accounts/login/"
        )
        foreach ($ep in $loginEndpoints) {
            try {
                $testUrl = "${TargetUrl}${ep}"
                $null = Invoke-WebRequest -Uri $testUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                $loginUrl = $testUrl
                Write-Detail "Login endpoint found at: $ep"
                break
            } catch {
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    # 405 Method Not Allowed means the endpoint exists but needs POST
                    # 200 or 302 means login page exists
                    if ($statusCode -ne 404) {
                        $loginUrl = $testUrl
                        Write-Detail "Login endpoint found at: $ep (HTTP $statusCode)"
                        break
                    }
                }
            }
        }
    }

    if (-not $loginUrl) {
        Write-Warn "Could not detect login endpoint. Use -AuthUrl to specify it."
        Write-Warn "Continuing with unauthenticated scanning."
        return
    }

    # --- Determine auth type ---
    $authMethod = $AuthType
    if (-not $authMethod) {
        # Default to JSON for modern frameworks
        $authMethod = "json"
    }

    if (-not $script:ZapContextId) {
        Write-Warn "No ZAP context available. Skipping authentication configuration."
        return
    }

    try {
        # Configure authentication method
        $zapLoginUrl = if ($script:UsingDockerZap) { $loginUrl -replace "localhost", "host.docker.internal" } else { $loginUrl }

        if ($authMethod -eq "json") {
            $loginBody = [uri]::EscapeDataString('{"username":"{%username%}","password":"{%password%}"}')
            $authConfig = "loginUrl=$([uri]::EscapeDataString($zapLoginUrl))&loginRequestData=$loginBody"
            Invoke-ZapApi "/JSON/authentication/action/setAuthenticationMethod/?contextId=$($script:ZapContextId)&authMethodName=jsonBasedAuthentication&authMethodConfigParams=$authConfig" | Out-Null
        } else {
            $loginBody = [uri]::EscapeDataString("username={%username%}&password={%password%}")
            $authConfig = "loginUrl=$([uri]::EscapeDataString($zapLoginUrl))&loginRequestData=$loginBody"
            Invoke-ZapApi "/JSON/authentication/action/setAuthenticationMethod/?contextId=$($script:ZapContextId)&authMethodName=formBasedAuthentication&authMethodConfigParams=$authConfig" | Out-Null
        }

        # Set logged-in / logged-out indicators
        $loggedInRegex = [uri]::EscapeDataString('(?:dashboard|logout|signout|profile|account|welcome)')
        $loggedOutRegex = [uri]::EscapeDataString('(?:login|signin|sign-in|unauthorized|401)')
        Invoke-ZapApi "/JSON/authentication/action/setLoggedInIndicator/?contextId=$($script:ZapContextId)&loggedInIndicatorRegex=$loggedInRegex" | Out-Null
        Invoke-ZapApi "/JSON/authentication/action/setLoggedOutIndicator/?contextId=$($script:ZapContextId)&loggedOutIndicatorRegex=$loggedOutRegex" | Out-Null

        # Create user
        $userResp = Invoke-ZapApi "/JSON/users/action/newUser/?contextId=$($script:ZapContextId)&name=scanner-user"
        $script:ZapUserId = $userResp.userId

        # Set credentials
        $creds = "username=$([uri]::EscapeDataString($detectedUser))&password=$([uri]::EscapeDataString($detectedPass))"
        Invoke-ZapApi "/JSON/users/action/setAuthenticationCredentials/?contextId=$($script:ZapContextId)&userId=$($script:ZapUserId)&authCredentialsConfigParams=$creds" | Out-Null
        Invoke-ZapApi "/JSON/users/action/setUserEnabled/?contextId=$($script:ZapContextId)&userId=$($script:ZapUserId)&enabled=true" | Out-Null

        # Set forced user mode
        Invoke-ZapApi "/JSON/forcedUser/action/setForcedUser/?contextId=$($script:ZapContextId)&userId=$($script:ZapUserId)" | Out-Null
        Invoke-ZapApi "/JSON/forcedUser/action/setForcedUserModeEnabled/?boolean=true" | Out-Null

        $script:AuthResult = @{
            Type        = $authMethod
            User        = $detectedUser
            LoginUrl    = $loginUrl
            Description = "$authMethod-based ($detectedUser @ $loginUrl)"
        }
        Write-Ok "Authentication configured: $authMethod-based login at $loginUrl"
    } catch {
        Write-Warn "Failed to configure authentication: $($_.Exception.Message)"
        Write-Warn "Continuing with unauthenticated scanning."
    }
}

# =============================================================
# PHASE 4: Scan Policy Configuration
# =============================================================
function Set-ScanPolicy {
    param(
        [hashtable]$Framework,
        [bool]$IsFullScan
    )

    $policyName = "zap-scan-policy"
    Write-Step "Configuring scan policy..."

    # Remove stale policy from prior run (ignore errors if it doesn't exist)
    try { Invoke-ZapApi "/JSON/ascan/action/removeScanPolicy/?scanPolicyName=$policyName" | Out-Null } catch { $null = $_ }
    try {
        Invoke-ZapApi "/JSON/ascan/action/addScanPolicy/?scanPolicyName=$policyName" | Out-Null
    } catch {
        Write-Warn "Could not create custom scan policy. Using ZAP default."
        return $null
    }

    # Determine rules to disable based on framework
    $disableIds = @()
    if ($Framework) {
        $runtime = $Framework.Runtime
        switch -Wildcard ($runtime) {
            "Node.js" {
                # Disable Java Spring rules, .NET rules
                $disableIds += @(40042, 40045, 40028, 40029)
            }
            "Deno" {
                $disableIds += @(40042, 40045, 40028, 40029)
            }
            "Python" {
                # Disable Java, .NET rules
                $disableIds += @(40042, 40045, 40028, 40029)
            }
            ".NET" {
                # Disable Java Spring rules
                $disableIds += @(40042, 40045)
            }
            "Java" {
                # Disable .NET rules
                $disableIds += @(40028, 40029)
            }
            "PHP" {
                # Disable Java, .NET rules
                $disableIds += @(40042, 40045, 40028, 40029)
            }
            "Ruby" {
                $disableIds += @(40042, 40045, 40028, 40029)
            }
            "Go" {
                $disableIds += @(40042, 40045, 40028, 40029)
            }
            "Rust" {
                $disableIds += @(40042, 40045, 40028, 40029)
            }
        }
    }

    if ($disableIds.Count -gt 0) {
        try {
            $idsString = $disableIds -join ","
            Invoke-ZapApi "/JSON/ascan/action/disableScanners/?ids=$idsString&scanPolicyName=$policyName" | Out-Null
            Write-Detail "Disabled $($disableIds.Count) irrelevant scan rules for $($Framework.Runtime)."
        } catch {
            Write-Detail "Could not disable framework-specific rules."
        }
    }

    # Set attack strength and threshold
    $strength = if ($IsFullScan) { "HIGH" } else { "MEDIUM" }
    $threshold = if ($IsFullScan) { "LOW" } else { "MEDIUM" }

    try {
        Invoke-ZapApi "/JSON/ascan/action/setOptionAttackStrength/?String=$strength" | Out-Null
        Invoke-ZapApi "/JSON/ascan/action/setOptionAlertThreshold/?String=$threshold" | Out-Null
    } catch {
        Write-Detail "Could not set attack strength/threshold."
    }

    # Configure threading
    $threads = if ($IsFullScan) { 5 } else { 2 }
    try {
        Invoke-ZapApi "/JSON/ascan/action/setOptionThreadPerHost/?Integer=$threads" | Out-Null
    } catch { $null = $_ }

    # Count active rules
    try {
        $scanners = Invoke-ZapApi "/JSON/ascan/view/scanners/?scanPolicyName=$policyName&policyId="
        $enabledCount = ($scanners.scanners | Where-Object { $_.enabled -eq "true" }).Count
        $script:ActiveRuleCount = $enabledCount
    } catch { $null = $_ }

    $script:ScanPolicyName = $policyName
    Write-Ok "Scan policy configured: strength=$strength, threshold=$threshold, threads=$threads"
    return $policyName
}

# =============================================================
# PHASE 7: SARIF Report Generation
# =============================================================
function New-SarifReport {
    param(
        [string]$OutputPath,
        [string]$TargetUrl,
        [object]$Alerts
    )

    Write-Step "Generating SARIF report..."

    # First try ZAP's built-in SARIF generation
    try {
        $reportDir = [uri]::EscapeDataString((Split-Path $OutputPath -Parent))
        $reportName = [uri]::EscapeDataString([System.IO.Path]::GetFileNameWithoutExtension($OutputPath))
        $escapedSites = [uri]::EscapeDataString($TargetUrl)
        Invoke-ZapApi "/JSON/reports/action/generate/?title=ZAP+Security+Scan&template=sarif-json&sites=$escapedSites&reportDir=$reportDir&reportFileName=$reportName" | Out-Null
        if (Test-Path $OutputPath) {
            Write-Ok "SARIF report saved: $OutputPath"
            return
        }
    } catch {
        Write-Detail "ZAP SARIF template not available. Generating manually..."
    }

    # Fallback: construct SARIF manually from alert data
    try {
        $rules = @{}
        $results = @()

        if ($Alerts -and $Alerts.alerts) {
            foreach ($alert in $Alerts.alerts) {
                $ruleId = $alert.pluginId
                if (-not $ruleId) { $ruleId = $alert.alertRef }
                if (-not $ruleId) { $ruleId = "unknown" }

                # Collect unique rules
                if (-not $rules.ContainsKey($ruleId)) {
                    $rules[$ruleId] = @{
                        id               = [string]$ruleId
                        name             = $alert.name
                        shortDescription = @{ text = $alert.name }
                        fullDescription  = @{ text = if ($alert.description) { $alert.description } else { $alert.name } }
                        helpUri          = if ($alert.reference) { ($alert.reference -split "`n" | Select-Object -First 1).Trim() } else { "https://www.zaproxy.org/" }
                        properties       = @{
                            confidence = if ($alert.confidence) { $alert.confidence } else { "Medium" }
                        }
                    }
                    if ($alert.cweid -and $alert.cweid -ne "-1") {
                        $rules[$ruleId].properties["cwe"] = "CWE-$($alert.cweid)"
                    }
                }

                # Map ZAP risk to SARIF level
                $level = switch ($alert.risk) {
                    "High"          { "error" }
                    "Medium"        { "warning" }
                    "Low"           { "note" }
                    "Informational" { "note" }
                    default         { "note" }
                }

                $result = @{
                    ruleId    = [string]$ruleId
                    level     = $level
                    message   = @{ text = if ($alert.description) { $alert.description } else { $alert.name } }
                    locations = @(
                        @{
                            physicalLocation = @{
                                artifactLocation = @{
                                    uri = if ($alert.url) { $alert.url } else { $TargetUrl }
                                }
                            }
                        }
                    )
                }

                if ($alert.solution) {
                    $result["fixes"] = @(@{
                        description = @{ text = $alert.solution }
                    })
                }

                $results += $result
            }
        }

        $sarif = @{
            '$schema' = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
            version   = "2.1.0"
            runs      = @(
                @{
                    tool = @{
                        driver = @{
                            name           = "OWASP ZAP"
                            informationUri = "https://www.zaproxy.org/"
                            rules          = @($rules.Values)
                        }
                    }
                    results = $results
                }
            )
        }

        $sarif | ConvertTo-Json -Depth 15 | Out-File -FilePath $OutputPath -Encoding utf8
        Write-Ok "SARIF report saved: $OutputPath"
    } catch {
        Write-Warn "Failed to generate SARIF report: $($_.Exception.Message)"
    }
}

# =============================================================
# PHASE 9: Pre-Scan Validation & Health Check
# =============================================================
function Test-AppHealth {
    param(
        [string]$TestUrl
    )

    # Use custom health check URL from config if set
    if ($script:Config -and $script:Config.healthCheckUrl) {
        $baseUri = [uri]$TestUrl
        $healthPath = $script:Config.healthCheckUrl
        $TestUrl = "$($baseUri.Scheme)://$($baseUri.Host):$($baseUri.Port)$healthPath"
        Write-Step "Performing pre-scan health check at $TestUrl (from config)..."
    } else {
        Write-Step "Performing pre-scan health check..."
    }

    try {
        $resp = Invoke-WebRequest -Uri $TestUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop -MaximumRedirection 0
        $bodyLength = if ($resp.Content) { $resp.Content.Length } else { 0 }

        if ($bodyLength -lt 100) {
            Write-Warn "Response body is very short ($bodyLength bytes). The app may not be serving content."
        } else {
            Write-Ok "Health check passed ($bodyLength bytes received)."
        }

        $script:HealthCheckResult = "OK ($bodyLength bytes)"
    } catch {
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            if ($statusCode -eq 301 -or $statusCode -eq 302 -or $statusCode -eq 307 -or $statusCode -eq 308) {
                $location = $_.Exception.Response.Headers.Location
                if ($location -and $location -match "(?:login|signin|auth)") {
                    Write-Warn "App redirects to login page ($location). Authenticated scanning is recommended."
                    Write-Warn "Use -AuthUser/-AuthPassword or -AuthToken for better coverage."
                    $script:HealthCheckResult = "Redirect to login"
                } else {
                    $script:HealthCheckResult = "Redirect ($statusCode)"
                    Write-Ok "Health check: redirect ($statusCode)."
                }
            } else {
                $script:HealthCheckResult = "HTTP $statusCode"
                Write-Ok "Health check: HTTP $statusCode."
            }
        } else {
            $script:HealthCheckResult = "Error"
            Write-Warn "Health check failed: $($_.Exception.Message)"
        }
    }
    if ($script:Manifest) { $script:Manifest.HealthCheck = $script:HealthCheckResult }
}

function Write-ScanSummary {
    param(
        [hashtable]$Framework,
        [string]$TargetUrl,
        [int]$AppPort
    )

    Write-Host ""
    Write-Host "    Pre-Scan Configuration Summary" -ForegroundColor White
    Write-Host "    $('-' * 50)" -ForegroundColor DarkGray

    if ($script:Config) {
        Write-Host "    Config       : .auto-zap.json" -ForegroundColor White
    }
    if ($Framework) {
        Write-Host "    Framework    : $($Framework.Name)" -ForegroundColor White
    }
    Write-Host "    Target URL   : $TargetUrl" -ForegroundColor White
    if ($AppPort -gt 0) {
        Write-Host "    Port         : $AppPort" -ForegroundColor White
    }

    if ($script:ComposeServicesStartedByUs -and $script:ComposeConfigServices.Count -gt 0) {
        Write-Host "    Compose      : $($script:ComposeConfigServices -join ', ')" -ForegroundColor White
    }

    if ($script:DetectedDbType) {
        Write-Host "    Database     : $($script:DetectedDbType)" -ForegroundColor White
    }

    if ($script:ServiceProcesses.Count -gt 0) {
        $svcLabels = @()
        if ($script:Config -and $script:Config.services) {
            foreach ($svc in $script:Config.services) {
                $svcLabels += if ($svc.label) { $svc.label } else { $svc.command }
            }
        }
        if ($svcLabels.Count -gt 0) {
            Write-Host "    Services     : $($svcLabels -join ', ')" -ForegroundColor White
        }
    }

    if ($script:AuthResult) {
        Write-Host "    Auth         : $($script:AuthResult.Description)" -ForegroundColor White
    } else {
        Write-Host "    Auth         : None (unauthenticated)" -ForegroundColor DarkGray
    }

    if ($script:ApiSpecSource) {
        Write-Host "    API Spec     : $($script:ApiSpecSource)" -ForegroundColor White
    }

    if ($script:GraphqlDetected) {
        Write-Host "    GraphQL      : Detected" -ForegroundColor White
    }

    if ($script:TechList.Count -gt 0) {
        Write-Host "    Technology   : $($script:TechList -join ', ')" -ForegroundColor White
    }

    if ($script:ScanPolicyName) {
        $ruleInfo = if ($script:ActiveRuleCount) { " ($($script:ActiveRuleCount) rules active)" } else { "" }
        Write-Host "    Scan Policy  : $($script:ScanPolicyName)$ruleInfo" -ForegroundColor White
    }

    $zapSource = if ($script:UsingDockerZap) { "Docker" } else { "Local" }
    Write-Host "    ZAP Source   : $zapSource" -ForegroundColor White

    if ($ZapApiPort -ne 8090) {
        Write-Host "    ZAP Port     : $ZapApiPort (dynamic)" -ForegroundColor Yellow
    }
    if ($script:Manifest -and $script:Manifest.MonorepoRoot) {
        Write-Host "    Monorepo     : Yes (root: $(Split-Path $script:Manifest.MonorepoRoot -Leaf))" -ForegroundColor White
    }
    if ($script:Manifest -and $script:Manifest.Redis) {
        Write-Host "    Redis        : $($script:Manifest.Redis.Host):$($script:Manifest.Redis.Port)" -ForegroundColor White
    }
    if ($script:Manifest -and $script:Manifest.ComposeFile) {
        Write-Host "    Compose      : $(Split-Path $script:Manifest.ComposeFile -Leaf)" -ForegroundColor White
    }

    if ($script:HealthCheckResult) {
        Write-Host "    Health Check : $($script:HealthCheckResult)" -ForegroundColor White
    }

    Write-Host "    $('-' * 50)" -ForegroundColor DarkGray
    Write-Host ""
}

# =============================================================
# MAIN
# =============================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Magenta
Write-Host "     OWASP ZAP - Fully Automated Web Application Scanner       " -ForegroundColor Magenta
Write-Host "================================================================" -ForegroundColor Magenta
Write-Host ""

# --- Step 0: Check prerequisites ---
Write-Step "STEP 0: Checking prerequisites..."

$canRunLocal = ($null -ne $ZapPath)

# Determine ZAP execution mode
if ($UseDockerZap) {
    $script:UsingDockerZap = $true
    $canRunLocal = $false  # Force Docker even if local exists
}

if (-not $canRunLocal -and -not $script:UsingDockerZap) {
    # No local ZAP found, check if Docker is available as fallback
    if (Test-Command "docker") {
        Write-Warn "Local ZAP not found. Checking Docker as fallback..."
        $null = docker info 2>&1
        if ($LASTEXITCODE -eq 0) {
            $script:UsingDockerZap = $true
            Write-Ok "Docker available. Will use Docker-based ZAP."
        }
    }
}

if (-not $canRunLocal -and -not $script:UsingDockerZap) {
    Write-Err "OWASP ZAP is not installed and Docker is not available."
    Write-Err "    Auto-ZAP needs either a local ZAP installation or Docker to run ZAP in a container."
    Write-Err "    Fix: Install ZAP with: winget install ZAP.ZAP"
    Write-Err "         Or install Docker: winget install Docker.DockerDesktop"
    Write-Err "         Or use -Url to scan a running app with an external ZAP instance."
    exit 1
}

# Load .auto-zap.json config
Import-AutoZapConfig

# Dynamic ZAP port allocation
$zapPortInUse = Get-NetTCPConnection -LocalPort $ZapApiPort -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq "Listen" } |
    Select-Object -ExpandProperty OwningProcess -Unique
if ($zapPortInUse) {
    # If it's a stale ZAP/Java process, kill it
    $killed = $false
    foreach ($stalePid in $zapPortInUse) {
        $proc = Get-Process -Id $stalePid -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -match "java|zap") {
            Write-Warn "Port $ZapApiPort held by stale ZAP process (PID $stalePid). Killing..."
            Stop-ProcessTree $stalePid
            $killed = $true
        }
    }
    if ($killed) { Start-Sleep -Seconds 2 }
    # Re-check: if still occupied (non-ZAP process), pick a new port
    $stillInUse = Get-NetTCPConnection -LocalPort $ZapApiPort -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq "Listen" }
    if ($stillInUse) {
        $oldPort = $ZapApiPort
        $ZapApiPort = Get-FreePort -PreferredPort ($ZapApiPort + 1)
        Write-Warn "Port $oldPort is in use by another process. Using port $ZapApiPort for ZAP."
    }
}

Write-Ok "Prerequisites OK."
Write-Host ""

$TargetUrl = $Url
$framework = $null
$appPort = 0

if (-not $TargetUrl) {
    # --- Step 1: Detect framework ---
    Write-Step "STEP 1: Detecting web app framework..."
    $framework = Get-AppFramework

    if (-not $framework) {
        Write-Err "Could not detect a web application in $($script:OriginalDir)"
        Write-Err "    Auto-ZAP checks for: package.json, requirements.txt, pyproject.toml, *.csproj, pom.xml, build.gradle,"
        Write-Err "                        Gemfile, go.mod, Cargo.toml, mix.exs, deno.json, bunfig.toml, Dockerfile, index.html"
        Write-Err "    Fix: Create .auto-zap.json with `"command`" and `"port`" to configure manually."
        Write-Err "         Or use -Url to scan an already-running app: .\auto-zap.ps1 -Url http://localhost:8080"
        exit 1
    }

    # Apply config overrides (config > auto-detection, CLI params > config)
    if ($script:Config) {
        if ($script:Config.command -and -not $Port) {
            $framework.Command = $script:Config.command
            Write-Detail "Start command overridden by config: $($script:Config.command)"
        }
        if ($script:Config.port -and -not $Port) {
            $framework.Port = [int]$script:Config.port
            Write-Detail "Port overridden by config: $($script:Config.port)"
        }
        if ($script:Config.install) {
            $framework.Install = $script:Config.install
            Write-Detail "Install command overridden by config: $($script:Config.install)"
        }
        if ($script:Config.installDir) {
            $projectRoot = if ($script:MonorepoRoot) { $script:MonorepoRoot } else { $script:OriginalDir }
            $framework.InstallDir = Join-Path $projectRoot $script:Config.installDir
            Write-Detail "Install directory overridden by config: $($script:Config.installDir)"
        }
        if ($script:Config.migrations) {
            $framework.Migrations = @($script:Config.migrations)
            if ($framework.Migrations.Count -gt 0) { $framework.NeedsDb = $true }
            Write-Detail "Migrations overridden by config"
        }
    }

    # CLI params override everything
    if ($script:Config -and $script:Config.port -and $Port) {
        Write-Detail "CLI -Port overrides config port"
    }

    $appPort = if ($Port -gt 0) { $Port } else { $framework.Port }
    $TargetUrl = "http://localhost:$appPort"

    # Apply auth config overrides (config values used as defaults, CLI params override)
    if ($script:Config) {
        if ($script:Config.authUser -and -not $AuthUser)         { $AuthUser = $script:Config.authUser }
        if ($script:Config.authPassword -and -not $AuthPassword) { $AuthPassword = $script:Config.authPassword }
        if ($script:Config.authUrl -and -not $AuthUrl)           { $AuthUrl = $script:Config.authUrl }
        if ($script:Config.authType -and -not $AuthType)         { $AuthType = $script:Config.authType }
    }

    Write-Ok "Detected: $($framework.Name)"
    Write-Detail "Start command : $($framework.Command)"
    Write-Detail "Target URL    : $TargetUrl"
    Write-Detail "Needs database: $($framework.NeedsDb)"
    Write-Host ""

    # Load .env files into process environment so tools like Prisma can find DATABASE_URL etc.
    $envCount = Import-EnvFile

    # Check for PORT env var (many apps respect this, especially Node.js and Python)
    if (-not $Port) {
        $envPort = [System.Environment]::GetEnvironmentVariable("PORT", "Process")
        if ($envPort -and $envPort -match '^\d+$') {
            $envPortInt = [int]$envPort
            if ($envPortInt -ne $appPort) {
                Write-Detail "PORT=$envPortInt found in environment. Overriding detected port ($appPort)."
                $appPort = $envPortInt
                $TargetUrl = "http://localhost:$appPort"
            }
        }
    }

    Build-ScanManifest -Framework $framework
    if ($envCount) { $script:Manifest.EnvFilesLoaded = $envCount }

    # --- Step 2: Start database / compose services ---
    # Start Docker Compose services from config first (handles DB + other infra)
    $composeHandledDb = $false
    if ($script:Config -and $script:Config.compose) {
        Write-Step "STEP 2: Starting Docker Compose services..."
        $composeHandledDb = Start-ComposeService
    }

    if ($framework.NeedsDb -and -not $composeHandledDb) {
        Write-Step "STEP 2: Ensuring database is running..."
        $dbConfig = Get-DatabaseConfig
        if (-not (Initialize-Database)) {
            $dbType = if ($dbConfig) { $dbConfig.Type } else { "unknown" }
            $dbPort = if ($dbConfig) { $dbConfig.Port } else { "unknown" }
            Write-Err "Database ($dbType) required but not reachable on port $dbPort, and Docker is not available."
            Write-Err "    Fix: Start the database manually, or install Docker: winget install Docker.DockerDesktop"
            Write-Err "         Or update DATABASE_URL in .env to point to a running database."
            Cleanup
            exit 1
        }
        # Also check for Redis
        Initialize-RedisCache
        # Give DB a moment to accept queries after TCP is open
        Start-Sleep -Seconds 3
    } elseif (-not $composeHandledDb) {
        Write-Step "STEP 2: No database needed. Skipping."
        # Still check for Redis (some apps use it for caching/sessions)
        Initialize-RedisCache
    }
    Sync-Manifest
    Write-Host ""

    # --- Step 3: Install dependencies ---
    # Ensure the package manager is available before installing
    if ($framework.Runtime -eq "Node.js") {
        $pm = Get-NodePackageManager
        if (-not (Test-PackageManager $pm.Name)) {
            Cleanup
            exit 1
        }
    }

    if (-not $SkipInstall -and $framework.Install) {
        Write-Step "STEP 3: Installing dependencies..."
        $installDir = if ($framework.InstallDir) { $framework.InstallDir } else { $script:OriginalDir }
        $installResult = Invoke-ProjectCommand "Install" $framework.Install $installDir
        if (-not $installResult) {
            Write-Err "Dependency installation failed: $($framework.Install)"
            Write-Err "    Fix: Run '$($framework.Install)' manually to see the full error."
            Write-Err "         Common causes: wrong Node.js version, missing native build tools, network issues."
            if ($script:MonorepoRoot) {
                Write-Err "         If using a monorepo, ensure `"installDir`" in .auto-zap.json points to the monorepo root."
            }
            Write-Err "         Use -SkipInstall if dependencies are already installed."
            Cleanup
            exit 1
        }
    } else {
        Write-Step "STEP 3: Skipping dependency install."
    }
    Write-Host ""

    # --- Step 4: Run migrations ---
    if ($framework.Migrations -and $framework.Migrations.Count -gt 0) {
        Write-Step "STEP 4: Running database migrations..."
        foreach ($migration in $framework.Migrations) {
            $migResult = Invoke-ProjectCommand "Migration" $migration
            if (-not $migResult) {
                Write-Err "Migration failed: $migration"
                Write-Err "    Fix: Run '$migration' manually to debug."
                Write-Err "         Ensure the database is running and DATABASE_URL is correct."
                Write-Err "         If migrations are not needed, set `"migrations`": [] in .auto-zap.json."
                Cleanup
                exit 1
            }
        }
    } else {
        Write-Step "STEP 4: No migrations needed. Skipping."
    }
    Write-Host ""

    # --- Step 4b: Run pre-start hooks ---
    if ($script:Config -and $script:Config.preStart -and $script:Config.preStart.Count -gt 0) {
        Write-Step "STEP 4b: Running pre-start hooks..."
        foreach ($hook in $script:Config.preStart) {
            Write-Step "Pre-start: $hook"
            $hookResult = Invoke-ProjectCommand "Pre-start" $hook
            if (-not $hookResult) {
                Write-Err "Pre-start hook failed: $hook"
                Write-Err "    Fix: Run '$hook' manually to debug."
                Write-Err "         Pre-start hooks are defined in .auto-zap.json under `"preStart`"."
                Cleanup
                exit 1
            }
            Write-Ok "Pre-start complete."
        }
    }
    Write-Host ""

    # --- Step 4c: Start background services ---
    Start-BackgroundService
    Write-Host ""

    # --- Step 5: Start the web app ---
    Write-Step "STEP 5: Starting web application..."

    # Apply environment variables from config
    if ($script:Config -and $script:Config.env) {
        Write-Detail "Setting environment variables from config..."
        $envProps = $script:Config.env | Get-Member -MemberType NoteProperty
        foreach ($prop in $envProps) {
            $envName = $prop.Name
            $envValue = $script:Config.env.$envName
            [System.Environment]::SetEnvironmentVariable($envName, $envValue, "Process")
            Write-Detail "  $envName = $envValue"
        }
    }

    # Kill any stale process on the target port
    $staleProcs = Get-NetTCPConnection -LocalPort $appPort -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq "Listen" } |
        Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($stalePid in $staleProcs) {
        Write-Warn "Killing stale process (PID $stalePid) on port $appPort..."
        Stop-ProcessTree $stalePid
        Start-Sleep -Seconds 2
    }

    Write-Detail "Working directory: $($script:OriginalDir)"
    Write-Detail "Launch command: cmd.exe /c $($framework.Command)"
    $script:AppProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $($framework.Command)" -WorkingDirectory $script:OriginalDir -PassThru -WindowStyle Minimized

    if (-not (Wait-ForUrl $TargetUrl -TimeoutSec 180 -Label $framework.Name)) {
        Write-Err "Application did not start within 180 seconds at $TargetUrl."
        Write-Err "    Check the application's console window for error messages."
        Write-Err "    Fix: Run '$($framework.Command)' manually to debug."
        Write-Err "         Common causes: missing environment variables, port already in use, build errors."
        Write-Err "         If the app needs env vars, add them to `"env`" in .auto-zap.json."
        Write-Err "         If the app needs a different start command, set `"command`" in .auto-zap.json."
        Cleanup
        exit 1
    }
} else {
    if ($TargetUrl -notmatch "^https?://") { $TargetUrl = "http://$TargetUrl" }
    Write-Step "STEPS 1-5: Skipped (using provided URL)"
    Write-Ok "Target: $TargetUrl"

    if (-not (Wait-ForUrl $TargetUrl -TimeoutSec 15 -Label "target")) {
        Write-Err "Cannot reach $TargetUrl. Make sure the app is running."
        exit 1
    }

    # Try to detect framework for configuration even with -Url
    try { $framework = Get-AppFramework } catch { $null = $_ }

    # Parse port from URL
    try { $appPort = ([uri]$TargetUrl).Port } catch { $null = $_ }
}
Write-Host ""

# --- Health check ---
Test-AppHealth -TestUrl $TargetUrl
Write-Host ""

# --- Step 6: Start ZAP ---
# Determine the target URL as ZAP will see it
$ZapTargetUrl = $TargetUrl
if ($script:UsingDockerZap) {
    $ZapTargetUrl = $TargetUrl -replace "localhost", "host.docker.internal" -replace "127\.0\.0\.1", "host.docker.internal"
}

if ($script:UsingDockerZap) {
    Write-Step "STEP 6: Starting OWASP ZAP via Docker on port $ZapApiPort ..."

    # Ensure Docker is running
    if (-not (Test-DockerRunning)) {
        Write-Err "Docker is not available. Cannot start ZAP."
        Cleanup
        exit 1
    }

    # Remove any existing container
    docker rm -f $script:ZapDockerContainer 2>$null | Out-Null

    # Pull image if needed
    Write-Detail "Pulling ZAP Docker image (if needed)..."
    docker pull ghcr.io/zaproxy/zaproxy:stable 2>&1 | Out-Null

    # Start ZAP container
    $reportAbsDir = if ([System.IO.Path]::IsPathRooted($ReportPath)) {
        Split-Path $ReportPath -Parent
    } else {
        $script:OriginalDir
    }

    Write-Detail "Starting ZAP container..."
    docker run -d `
        --name $script:ZapDockerContainer `
        -p "${ZapApiPort}:${ZapApiPort}" `
        -v "${reportAbsDir}:/zap/wrk:rw" `
        ghcr.io/zaproxy/zaproxy:stable `
        zap.sh -daemon -port $ZapApiPort `
        -config api.key=$ZapApiKey `
        -config api.addrs.addr.name=.* `
        -config api.addrs.addr.regex=true `
        -config connection.timeoutInSecs=120 2>&1 | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to start ZAP Docker container."
        Cleanup
        exit 1
    }
} else {
    Write-Step "STEP 6: Starting OWASP ZAP daemon on port $ZapApiPort ..."

    # Find the ZAP jar dynamically
    $zapJar = Get-ChildItem -Path $ZapPath -Filter "zap-*.jar" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    if (-not $zapJar) {
        Write-Err "Cannot find ZAP jar in $ZapPath"
        Cleanup
        exit 1
    }

    if ($javaExe -and (Test-Path $javaExe)) {
        Write-Detail "Using Java: $javaExe"
        Write-Detail "Using ZAP jar: $zapJar"
        $script:ZapProcess = Start-Process -FilePath $javaExe -ArgumentList "-Xmx512m -jar `"$zapJar`" -daemon -port $ZapApiPort -config api.key=$ZapApiKey -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config connection.timeoutInSecs=120" -WorkingDirectory $ZapPath -PassThru -WindowStyle Hidden
    } else {
        $ZapBat = Join-Path $ZapPath "zap.bat"
        if (Test-Path $ZapBat) {
            Write-Detail "Using zap.bat (Java must be in PATH)"
            $zapArgs = "/c `"$ZapBat`" -daemon -port $ZapApiPort -config api.key=$ZapApiKey -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config connection.timeoutInSecs=120"
            $script:ZapProcess = Start-Process -FilePath "cmd.exe" -ArgumentList $zapArgs -PassThru -WindowStyle Hidden
        } else {
            Write-Err "Cannot find zap.bat and no Java found. Install Java or add it to PATH."
            Cleanup
            exit 1
        }
    }
}

if (-not (Wait-ForUrl "http://localhost:$ZapApiPort" -TimeoutSec $MaxWaitSeconds -Label "ZAP API")) {
    Write-Err "ZAP failed to start within $MaxWaitSeconds seconds."
    Write-Err "    Fix: Check Java installation: java -version (requires Java 17+)"
    Write-Err "         Install Java: winget install EclipseAdoptium.Temurin.17.JRE"
    Write-Err "         Or use -UseDockerZap to run ZAP via Docker."
    Cleanup
    exit 1
}
Write-Host ""

# --- Step 7: Configure ZAP context & technology ---
Write-Step "STEP 7: Configuring ZAP context and technology..."
Set-ZapContext -TargetUrl $ZapTargetUrl -Framework $framework
Write-Host ""

# --- Step 8: Import API specs ---
Write-Step "STEP 8: Importing API specifications..."
Import-ApiSpec -TargetUrl $TargetUrl -ProjectDir $script:OriginalDir
Import-GraphqlSchema -TargetUrl $TargetUrl
Write-Host ""

# --- Step 9: Configure authentication ---
Write-Step "STEP 9: Configuring authentication..."
Set-ZapAuth -TargetUrl $TargetUrl -ProjectDir $script:OriginalDir
Write-Host ""

# --- Step 10: Configure scan policy ---
Write-Step "STEP 10: Configuring scan policy..."
Set-ScanPolicy -Framework $framework -IsFullScan $FullScan.IsPresent
Write-Host ""

# --- Pre-scan summary ---
Write-ScanSummary -Framework $framework -TargetUrl $TargetUrl -AppPort $appPort

# =============================================================
# SCANNING
# =============================================================
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "     SCANNING: $TargetUrl" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""

# Build context and user parameters for scan API calls
$contextParam = ""
$userParam = ""
if ($script:ZapContextName) { $contextParam = "&contextName=$([uri]::EscapeDataString($script:ZapContextName))" }
if ($script:ZapUserId -ge 0 -and $script:AuthResult) { $userParam = "&userId=$($script:ZapUserId)" }

# --- Phase 1: Spider ---
Write-Step "Phase 1/3: Spidering (crawling the application)..."
$spiderUrl = [uri]::EscapeDataString($ZapTargetUrl)
$spiderResp = Invoke-ZapApi "/JSON/spider/action/scan/?url=$spiderUrl&maxChildren=0&recurse=true&subtreeOnly=false$contextParam$userParam"
$spiderId = $spiderResp.scan

do {
    Start-Sleep -Seconds 3
    $spiderStatus = [string](Invoke-ZapApi "/JSON/spider/view/status/?scanId=$spiderId").status
    Write-Host "`r    Spider progress: $($spiderStatus.PadLeft(3))%" -NoNewline
} while ([int]$spiderStatus -lt 100)
Write-Host ""

$urls = (Invoke-ZapApi "/JSON/spider/view/results/?scanId=$spiderId").results
$urlCount = 0
if ($urls) { $urlCount = $urls.Count }
Write-Ok "Spider complete. Discovered $urlCount URLs."
Write-Host ""

# --- Phase 2: Ajax Spider ---
Write-Step "Phase 2/3: Ajax spider (JavaScript-rendered content)..."
try {
    $ajaxUrl = [uri]::EscapeDataString($ZapTargetUrl)
    if ($script:ZapUserId -ge 0 -and $script:AuthResult -and $script:ZapContextId) {
        Invoke-ZapApi "/JSON/ajaxSpider/action/scanAsUser/?contextId=$($script:ZapContextId)&userId=$($script:ZapUserId)&url=$ajaxUrl&subtreeOnly=false" | Out-Null
    } else {
        Invoke-ZapApi "/JSON/ajaxSpider/action/scan/?url=$ajaxUrl$contextParam" | Out-Null
    }
    $ajaxTimeout = 180
    $ajaxElapsed = 0
    do {
        Start-Sleep -Seconds 5
        $ajaxElapsed += 5
        $ajaxStatus = (Invoke-ZapApi "/JSON/ajaxSpider/view/status/").status
        Write-Host "`r    Ajax spider: $ajaxStatus ($($ajaxElapsed)s)" -NoNewline
    } while ($ajaxStatus -eq "running" -and $ajaxElapsed -lt $ajaxTimeout)

    if ($ajaxStatus -eq "running") {
        Invoke-ZapApi "/JSON/ajaxSpider/action/stop/" | Out-Null
        Write-Warn "Ajax spider timed out after $($ajaxTimeout)s. Continuing with results so far."
    }
    Write-Host ""

    $ajaxResults = (Invoke-ZapApi "/JSON/ajaxSpider/view/numberOfResults/").numberOfResults
    Write-Ok "Ajax spider complete. Found $ajaxResults additional resources."
} catch {
    Write-Warn "Ajax spider unavailable (needs browser add-on). Skipping."
}
Write-Host ""

# --- Phase 3: Active Scan ---
$scanLabel = "Phase 3/3: Active vulnerability scan"
if ($FullScan) { $scanLabel += " (FULL MODE)" }
Write-Step "$scanLabel..."
Write-Detail "Testing for: SQL injection, XSS, CSRF, path traversal, SSRF, etc."

$scanUrl = [uri]::EscapeDataString($ZapTargetUrl)
$policyParam = ""
if ($script:ScanPolicyName) { $policyParam = "&scanPolicyName=$([uri]::EscapeDataString($script:ScanPolicyName))" }

$scanResp = Invoke-ZapApi "/JSON/ascan/action/scan/?url=$scanUrl&recurse=true&inScopeOnly=false$contextParam$policyParam"
$scanId = $scanResp.scan

$scanStart = Get-Date
$maxScanMinutes = if ($FullScan) { 60 } else { 30 }
$stallTimeoutSec = 300
$lastProgress = 0
$lastProgressTime = Get-Date
do {
    Start-Sleep -Seconds 5
    $scanStatus = [string](Invoke-ZapApi "/JSON/ascan/view/status/?scanId=$scanId").status
    $currentProgress = [int]$scanStatus
    $elapsed = [math]::Round(((Get-Date) - $scanStart).TotalMinutes, 1)
    Write-Host "`r    Active scan: $($scanStatus.PadLeft(3))%  ($($elapsed) min elapsed)" -NoNewline

    # Track progress changes for stall detection
    if ($currentProgress -gt $lastProgress) {
        $lastProgress = $currentProgress
        $lastProgressTime = Get-Date
    }

    # Stall detection: no progress for 5 minutes
    $stallElapsed = ((Get-Date) - $lastProgressTime).TotalSeconds
    if ($stallElapsed -ge $stallTimeoutSec) {
        Write-Host ""
        Write-Warn "Active scan stalled at $currentProgress% for $([math]::Round($stallElapsed / 60, 1)) min. Stopping scan."
        try { Invoke-ZapApi "/JSON/ascan/action/stop/?scanId=$scanId" | Out-Null } catch { $null = $_ }
        break
    }

    # Overall timeout
    if ($elapsed -ge $maxScanMinutes) {
        Write-Host ""
        Write-Warn "Active scan reached $maxScanMinutes min timeout at $currentProgress%. Stopping scan."
        try { Invoke-ZapApi "/JSON/ascan/action/stop/?scanId=$scanId" | Out-Null } catch { $null = $_ }
        break
    }
} while ($currentProgress -lt 100)
Write-Host ""
$scanDuration = [math]::Round(((Get-Date) - $scanStart).TotalMinutes, 1)
Write-Ok "Active scan complete in $scanDuration minutes."
Write-Host ""

# =============================================================
# RESULTS
# =============================================================
Write-Host "================================================================" -ForegroundColor Green
Write-Host "     RESULTS" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""

# For results, use the original TargetUrl (not the Docker-adjusted one)
$resultsUrl = [uri]::EscapeDataString($ZapTargetUrl)

# Summary counts
$alerts = (Invoke-ZapApi "/JSON/alert/view/alertsSummary/?baseurl=$resultsUrl").alertsSummary
$high   = if ($alerts.High)          { [int]$alerts.High }          else { 0 }
$medium = if ($alerts.Medium)        { [int]$alerts.Medium }        else { 0 }
$low    = if ($alerts.Low)           { [int]$alerts.Low }           else { 0 }
$info   = if ($alerts.Informational) { [int]$alerts.Informational } else { 0 }
$total  = $high + $medium + $low + $info

Write-Host "    Vulnerability Summary ($total total findings):" -ForegroundColor White
Write-Host ""
if ($high -gt 0)   { Write-Host "      HIGH:          $high" -ForegroundColor Red }
else               { Write-Host "      HIGH:          0" -ForegroundColor Green }
if ($medium -gt 0) { Write-Host "      MEDIUM:        $medium" -ForegroundColor Yellow }
else               { Write-Host "      MEDIUM:        0" -ForegroundColor Green }
if ($low -gt 0)    { Write-Host "      LOW:           $low" -ForegroundColor DarkYellow }
else               { Write-Host "      LOW:           0" -ForegroundColor Green }
Write-Host "      INFORMATIONAL: $info" -ForegroundColor Gray
Write-Host ""

# Detailed findings (deduplicated)
$topAlerts = (Invoke-ZapApi "/JSON/alert/view/alerts/?baseurl=$resultsUrl&start=0&count=50").alerts
if ($topAlerts -and $topAlerts.Count -gt 0) {
    Write-Step "Findings detail:"
    Write-Host ""
    $seen = @{}
    foreach ($alert in $topAlerts) {
        $key = "$($alert.risk)|$($alert.name)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = @{ Count = 1; Alert = $alert }
        } else {
            $seen[$key].Count++
        }
    }

    # Sort by severity: High > Medium > Low > Informational
    $riskOrder = @{ "High" = 0; "Medium" = 1; "Low" = 2; "Informational" = 3 }
    $sorted = $seen.Values | Sort-Object { $riskOrder[$_.Alert.risk] }

    foreach ($entry in $sorted) {
        $a = $entry.Alert
        $count = $entry.Count
        $riskColor = switch ($a.risk) {
            "High"          { "Red" }
            "Medium"        { "Yellow" }
            "Low"           { "DarkYellow" }
            "Informational" { "Gray" }
            default         { "White" }
        }
        $countStr = if ($count -gt 1) { " (x$count)" } else { "" }

        Write-Host "    [$($a.risk.ToUpper().PadRight(13))] " -ForegroundColor $riskColor -NoNewline
        Write-Host "$($a.name)$countStr" -ForegroundColor White
        Write-Host "                      URL: $($a.url)" -ForegroundColor DarkGray
        if ($a.solution) {
            $solutionPreview = if ($a.solution.Length -gt 100) { $a.solution.Substring(0, 100) + "..." } else { $a.solution }
            Write-Host "                      Fix: $solutionPreview" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

# --- Generate HTML report ---
$reportFile = if ([System.IO.Path]::IsPathRooted($ReportPath)) { $ReportPath } else { Join-Path $script:ProjectRoot $ReportPath }
Write-Step "Generating HTML report..."
$reportHtml = Invoke-RestMethod "http://localhost:$ZapApiPort/OTHER/core/other/htmlreport/?apikey=$ZapApiKey"
$reportHtml | Out-File -FilePath $reportFile -Encoding utf8
Write-Ok "Report saved: $reportFile"

# Also generate JSON report for CI/CD integration
$jsonReportPath = [System.IO.Path]::ChangeExtension($reportFile, ".json")
$jsonAlerts = (Invoke-ZapApi "/JSON/alert/view/alerts/?baseurl=$resultsUrl&start=0&count=500")
$jsonAlerts | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonReportPath -Encoding utf8
Write-Ok "JSON report saved: $jsonReportPath"

# Generate SARIF report
$sarifReportPath = [System.IO.Path]::ChangeExtension($reportFile, ".sarif")
New-SarifReport -OutputPath $sarifReportPath -TargetUrl $ZapTargetUrl -Alerts $jsonAlerts

Write-Host ""

# --- Final summary ---
Write-Host "================================================================" -ForegroundColor Magenta
Write-Host "     SCAN COMPLETE" -ForegroundColor Magenta
Write-Host "================================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "    HTML Report  : $reportFile" -ForegroundColor White
Write-Host "    JSON Report  : $jsonReportPath" -ForegroundColor White
Write-Host "    SARIF Report : $sarifReportPath" -ForegroundColor White
Write-Host "    URLs Found   : $urlCount" -ForegroundColor White
Write-Host "    Total Issues : $total ($high high, $medium medium, $low low)" -ForegroundColor White
if ($script:AuthResult) {
    Write-Host "    Auth Mode    : $($script:AuthResult.Type)" -ForegroundColor White
}
if ($script:ApiSpecSource) {
    Write-Host "    API Spec     : $($script:ApiSpecSource)" -ForegroundColor White
}
Write-Host ""

if ($high -gt 0) {
    Write-Err "ACTION REQUIRED: $high HIGH severity vulnerabilities found!"
    $exitCode = 1
} elseif ($medium -gt 0) {
    Write-Warn "WARNING: $medium MEDIUM severity vulnerabilities found."
    $exitCode = 0
} else {
    Write-Ok "No high or medium vulnerabilities found."
    $exitCode = 0
}
Write-Host ""

# --- Cleanup ---
Cleanup
exit $exitCode
