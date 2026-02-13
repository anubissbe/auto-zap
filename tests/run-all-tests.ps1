#Requires -Version 5.1
<#
.SYNOPSIS
    Auto-ZAP Comprehensive Test Runner (PowerShell)
    Tests framework detection for ALL supported frameworks against auto-zap.ps1
.PARAMETER Mode
    Test mode: "detection" (default), "dry-run", or "full-scan"
#>
param(
    [ValidateSet("detection", "dry-run", "full-scan")]
    [string]$Mode = "detection"
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AutoZap = Join-Path (Split-Path -Parent $ScriptDir) "auto-zap.ps1"
$ResultsDir = Join-Path $ScriptDir "results"

# Test definitions: folder, expected framework pattern, expected port
$Tests = @(
    @{ Folder = "node-nextjs";       Expected = "Next.js";      Port = 3000 }
    @{ Folder = "node-nuxt";         Expected = "Nuxt";         Port = 3000 }
    @{ Folder = "node-remix";        Expected = "Remix";        Port = 3000 }
    @{ Folder = "node-nestjs";       Expected = "NestJS";       Port = 3000 }
    @{ Folder = "node-sveltekit";    Expected = "SvelteKit";    Port = 5173 }
    @{ Folder = "node-astro";        Expected = "Astro";        Port = 4321 }
    @{ Folder = "node-angular";      Expected = "Angular";      Port = 4200 }
    @{ Folder = "node-gatsby";       Expected = "Gatsby";       Port = 8000 }
    @{ Folder = "node-vite";         Expected = "Vite";         Port = 5173 }
    @{ Folder = "node-adonisjs";     Expected = "AdonisJS";     Port = 3333 }
    @{ Folder = "node-fastify";      Expected = "Fastify";      Port = 3000 }
    @{ Folder = "node-hono";         Expected = "Hono";         Port = 3000 }
    @{ Folder = "node-express";      Expected = "Express";      Port = 3000 }
    @{ Folder = "node-generic";      Expected = "Node.js";      Port = 3000 }
    @{ Folder = "python-django";     Expected = "Django";       Port = 8000 }
    @{ Folder = "python-fastapi";    Expected = "FastAPI";      Port = 8000 }
    @{ Folder = "python-flask";      Expected = "Flask";        Port = 5000 }
    @{ Folder = "python-generic";    Expected = "Python";       Port = 8000 }
    @{ Folder = "dotnet-aspnet";     Expected = "ASP.NET";      Port = 5000 }
    @{ Folder = "java-spring-maven"; Expected = "Spring Boot";  Port = 8080 }
    @{ Folder = "java-spring-gradle";Expected = "Spring Boot";  Port = 8080 }
    @{ Folder = "php-wordpress";     Expected = "WordPress";    Port = 8080 }
    @{ Folder = "php-laravel";       Expected = "Laravel";      Port = 8000 }
    @{ Folder = "php-symfony";       Expected = "Symfony";      Port = 8000 }
    @{ Folder = "php-generic";       Expected = "PHP";          Port = 8080 }
    @{ Folder = "ruby-rails";        Expected = "Rails";        Port = 3000 }
    @{ Folder = "go-web";            Expected = "Go";           Port = 8080 }
    @{ Folder = "rust-web";          Expected = "Rust";         Port = 8080 }
    @{ Folder = "elixir-phoenix";    Expected = "Phoenix";      Port = 4000 }
    @{ Folder = "elixir-generic";    Expected = "Elixir";       Port = 4000 }
    @{ Folder = "deno-web";          Expected = "Deno";         Port = 8000 }
    @{ Folder = "docker-app";        Expected = "Docker";       Port = 3000 }
    @{ Folder = "static-html";       Expected = "Static";       Port = 8080 }
)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Auto-ZAP Comprehensive Test Runner (PowerShell)" -ForegroundColor Cyan
Write-Host "  Mode: $Mode | Projects: $($Tests.Count)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $AutoZap)) {
    Write-Host "auto-zap.ps1 not found at: $AutoZap" -ForegroundColor Red
    exit 1
}

New-Item -Path $ResultsDir -ItemType Directory -Force | Out-Null

$Total = 0; $Pass = 0; $Fail = 0; $Skip = 0

foreach ($test in $Tests) {
    $folder = $test.Folder
    $expected = $test.Expected
    $port = $test.Port
    $Total++

    $testSrc = Join-Path $ScriptDir $folder
    if (-not (Test-Path $testSrc)) {
        Write-Host ("  SKIP  {0,-22} -> Test project not found" -f $folder) -ForegroundColor Yellow
        $Skip++
        continue
    }

    # Copy test project to temp dir
    $tempDir = Join-Path $env:TEMP "auto-zap-test-$folder"
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
    Copy-Item $testSrc $tempDir -Recurse

    $logFile = Join-Path $ResultsDir "$folder-ps1.log"

    switch ($Mode) {
        "detection" {
            try {
                $output = & pwsh -NoProfile -Command "
                    Set-Location '$tempDir'
                    & '$AutoZap' -DryRun 2>&1
                " 2>&1 | Out-String
                $output | Out-File $logFile -Encoding UTF8

                if ($output -match "Framework\s+:\s+(.+)") {
                    $detected = $Matches[1].Trim()
                    if ($detected -match [regex]::Escape($expected)) {
                        Write-Host ("  PASS  {0,-22} -> {1}" -f $folder, $detected) -ForegroundColor Green
                        $Pass++
                    } else {
                        Write-Host ("  FAIL  {0,-22} -> {1} (expected: {2})" -f $folder, $detected, $expected) -ForegroundColor Red
                        $Fail++
                    }
                } elseif ($output -match "Detected:\s+(.+)") {
                    $detected = $Matches[1].Trim()
                    if ($detected -match [regex]::Escape($expected)) {
                        Write-Host ("  PASS  {0,-22} -> {1}" -f $folder, $detected) -ForegroundColor Green
                        $Pass++
                    } else {
                        Write-Host ("  FAIL  {0,-22} -> {1} (expected: {2})" -f $folder, $detected, $expected) -ForegroundColor Red
                        $Fail++
                    }
                } else {
                    Write-Host ("  FAIL  {0,-22} -> Not detected (expected: {1})" -f $folder, $expected) -ForegroundColor Red
                    $Fail++
                }
            } catch {
                Write-Host ("  FAIL  {0,-22} -> Error: {1}" -f $folder, $_.Exception.Message) -ForegroundColor Red
                $Fail++
            }
        }
        "dry-run" {
            try {
                $output = & pwsh -NoProfile -Command "
                    Set-Location '$tempDir'
                    & '$AutoZap' -DryRun 2>&1
                " 2>&1 | Out-String
                $output | Out-File $logFile -Encoding UTF8

                if ($output -match "DRY RUN" -or $output -match "Dry run") {
                    Write-Host ("  PASS  {0,-22} -> Dry-run completed" -f $folder) -ForegroundColor Green
                    $Pass++
                } else {
                    Write-Host ("  FAIL  {0,-22} -> Dry-run did not complete" -f $folder) -ForegroundColor Red
                    $Fail++
                }
            } catch {
                Write-Host ("  FAIL  {0,-22} -> Error: {1}" -f $folder, $_.Exception.Message) -ForegroundColor Red
                $Fail++
            }
        }
    }

    # Cleanup temp dir
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ("  Results: {0} passed, {1} failed, {2} skipped (of {3})" -f $Pass, $Fail, $Skip, $Total)
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($Fail -gt 0) {
    Write-Host "Some tests failed. Check logs in $ResultsDir" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All tests passed!" -ForegroundColor Green
    exit 0
}
