<#
.SYNOPSIS
    Build the Auto-ZAP installer.
.DESCRIPTION
    Downloads OWASP ZAP + Eclipse Temurin JRE 17, creates a self-signed
    code signing certificate, builds the NSIS installer, and signs it.

    Run from the build/ directory:
        .\build.ps1

    Prerequisites:
        - NSIS installed (winget install NSIS.NSIS)
        - Windows SDK (for signtool.exe) or skip signing with -SkipSign
.PARAMETER SkipDownload
    Skip downloading ZAP and Java (use existing staging/ files)
.PARAMETER SkipSign
    Skip code signing
.PARAMETER CertPath
    Path to existing .pfx certificate (skips self-signed cert creation)
.PARAMETER CertPassword
    Password for the .pfx certificate
#>
param(
    [switch]$SkipDownload,
    [switch]$SkipSign,
    [string]$CertPath,
    [string]$CertPassword = "AutoZap2026!"
)

$ErrorActionPreference = "Stop"
$buildDir = $PSScriptRoot
$projectDir = Split-Path $buildDir -Parent
$stagingDir = Join-Path $buildDir "staging"
$distDir = Join-Path $projectDir "dist"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Auto-ZAP Installer Build" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ---- Configuration ----
$zapVersion = "2.16.1"
$zapUrl = "https://github.com/zaproxy/zaproxy/releases/download/v${zapVersion}/ZAP_${zapVersion}_Core.zip"
$jreUrl = "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jre/hotspot/normal/eclipse?project=jdk"
$nsisPath = "C:\Program Files (x86)\NSIS\makensis.exe"
$signtoolPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe",
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe"
)

# Find signtool
$signtool = $null
foreach ($p in $signtoolPaths) {
    if (Test-Path $p) { $signtool = $p; break }
}
if (-not $signtool) {
    # Search dynamically
    $found = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Filter "signtool.exe" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "x64" } | Select-Object -First 1
    if ($found) { $signtool = $found.FullName }
}

# Verify NSIS
if (-not (Test-Path $nsisPath)) {
    Write-Host "ERROR: NSIS not found at $nsisPath" -ForegroundColor Red
    Write-Host "Install: winget install NSIS.NSIS" -ForegroundColor Yellow
    exit 1
}

# ---- Create directories ----
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stagingDir "zap") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $stagingDir "jre") -Force | Out-Null
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

# ---- Create LICENSE.txt if missing ----
$licensePath = Join-Path $projectDir "LICENSE.txt"
if (-not (Test-Path $licensePath)) {
    @"
MIT License

Copyright (c) 2026 Euraika

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

This installer bundles the following third-party software:

OWASP ZAP (Zed Attack Proxy)
  License: Apache License 2.0
  https://www.zaproxy.org/

Eclipse Temurin JRE 17
  License: GNU General Public License v2.0 with Classpath Exception
  https://adoptium.net/
"@ | Out-File -FilePath $licensePath -Encoding utf8
    Write-Host "[+] Created LICENSE.txt" -ForegroundColor Green
}

# ---- Step 1: Download OWASP ZAP ----
if (-not $SkipDownload) {
    Write-Host ""
    Write-Host "[*] Step 1/5: Downloading OWASP ZAP $zapVersion..." -ForegroundColor Cyan
    $zapZip = Join-Path $stagingDir "zap.zip"

    if (-not (Test-Path $zapZip)) {
        Write-Host "    URL: $zapUrl"
        Invoke-WebRequest -Uri $zapUrl -OutFile $zapZip -UseBasicParsing
        Write-Host "[+] Downloaded ZAP ($([math]::Round((Get-Item $zapZip).Length / 1MB, 1)) MB)" -ForegroundColor Green
    } else {
        Write-Host "[+] ZAP already downloaded, skipping." -ForegroundColor Green
    }

    # Extract ZAP
    Write-Host "    Extracting ZAP..."
    $zapExtractDir = Join-Path $stagingDir "zap"
    if (Test-Path $zapExtractDir) { Remove-Item $zapExtractDir -Recurse -Force }
    New-Item -ItemType Directory -Path $zapExtractDir -Force | Out-Null

    Expand-Archive -Path $zapZip -DestinationPath $stagingDir -Force

    # ZAP extracts to a subfolder like ZAP_2.16.1
    $zapSubDir = Get-ChildItem $stagingDir -Directory | Where-Object { $_.Name -match "^ZAP" } | Select-Object -First 1
    if ($zapSubDir) {
        Get-ChildItem $zapSubDir.FullName | Move-Item -Destination $zapExtractDir -Force
        Remove-Item $zapSubDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[+] ZAP extracted." -ForegroundColor Green

    # ---- Step 2: Download Eclipse Temurin JRE 17 ----
    Write-Host ""
    Write-Host "[*] Step 2/5: Downloading Eclipse Temurin JRE 17..." -ForegroundColor Cyan
    $jreZip = Join-Path $stagingDir "jre.zip"

    if (-not (Test-Path $jreZip)) {
        Write-Host "    URL: $jreUrl"
        Invoke-WebRequest -Uri $jreUrl -OutFile $jreZip -UseBasicParsing
        Write-Host "[+] Downloaded JRE ($([math]::Round((Get-Item $jreZip).Length / 1MB, 1)) MB)" -ForegroundColor Green
    } else {
        Write-Host "[+] JRE already downloaded, skipping." -ForegroundColor Green
    }

    # Extract JRE
    Write-Host "    Extracting JRE..."
    $jreExtractDir = Join-Path $stagingDir "jre"
    if (Test-Path $jreExtractDir) { Remove-Item $jreExtractDir -Recurse -Force }
    New-Item -ItemType Directory -Path $jreExtractDir -Force | Out-Null

    Expand-Archive -Path $jreZip -DestinationPath $stagingDir -Force

    # JRE extracts to a subfolder like jdk-17.0.x+y-jre
    $jreSubDir = Get-ChildItem $stagingDir -Directory | Where-Object { $_.Name -match "^jdk-17" } | Select-Object -First 1
    if ($jreSubDir) {
        Get-ChildItem $jreSubDir.FullName | Move-Item -Destination $jreExtractDir -Force
        Remove-Item $jreSubDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[+] JRE extracted." -ForegroundColor Green
} else {
    Write-Host "[*] Skipping downloads (using existing staging files)." -ForegroundColor Yellow
}

# ---- Step 3: Create self-signed certificate ----
Write-Host ""
Write-Host "[*] Step 3/5: Creating code signing certificate..." -ForegroundColor Cyan

$pfxPath = Join-Path $buildDir "auto-zap-signing.pfx"
$certSubject = "CN=Auto-ZAP, O=Euraika, L=Belgium, C=BE"

if ($CertPath -and (Test-Path $CertPath)) {
    $pfxPath = $CertPath
    Write-Host "[+] Using provided certificate: $pfxPath" -ForegroundColor Green
} elseif (-not (Test-Path $pfxPath)) {
    # Create self-signed certificate
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $certSubject `
        -FriendlyName "Auto-ZAP Code Signing" `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(3) `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256

    # Export to PFX
    $securePassword = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword | Out-Null

    # Try to install to Trusted Root (so Windows trusts it locally)
    # This may trigger a UAC prompt or fail without admin elevation
    try {
        $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
        $rootStore.Open("ReadWrite")
        $rootStore.Add($cert)
        $rootStore.Close()
        Write-Host "[+] Certificate added to Trusted Root store." -ForegroundColor Green
    } catch {
        Write-Host "[!] Could not add to Trusted Root (may need admin). Signing will still work." -ForegroundColor Yellow
    }

    Write-Host "[+] Self-signed certificate created." -ForegroundColor Green
    Write-Host "    Subject: $certSubject" -ForegroundColor DarkGray
    Write-Host "    PFX: $pfxPath" -ForegroundColor DarkGray
    Write-Host "    Valid until: $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    NOTE: This is a self-signed certificate." -ForegroundColor Yellow
    Write-Host "    Other computers will see 'Unknown publisher' until they trust this cert." -ForegroundColor Yellow
} else {
    Write-Host "[+] Certificate already exists: $pfxPath" -ForegroundColor Green
}

# ---- Step 4: Build NSIS installer ----
Write-Host ""
Write-Host "[*] Step 4/5: Building NSIS installer..." -ForegroundColor Cyan

$nsiScript = Join-Path $buildDir "installer.nsi"
$nsisArgs = @(
    "/V3",
    "/NOCD",
    $nsiScript
)

$proc = Start-Process -FilePath $nsisPath -ArgumentList $nsisArgs -Wait -NoNewWindow -PassThru -WorkingDirectory $buildDir
if ($proc.ExitCode -ne 0) {
    Write-Host "[-] NSIS build failed with exit code $($proc.ExitCode)" -ForegroundColor Red
    exit 1
}

$installerPath = Join-Path $distDir "Auto-ZAP-Setup.exe"
if (Test-Path $installerPath) {
    $size = [math]::Round((Get-Item $installerPath).Length / 1MB, 1)
    Write-Host "[+] Installer built: $installerPath ($size MB)" -ForegroundColor Green
} else {
    Write-Host "[-] Installer not found at expected path." -ForegroundColor Red
    exit 1
}

# ---- Step 5: Sign the installer ----
if (-not $SkipSign -and $signtool) {
    Write-Host ""
    Write-Host "[*] Step 5/5: Signing installer..." -ForegroundColor Cyan

    & $signtool sign /f "$pfxPath" /p "$CertPassword" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /d "Auto-ZAP Security Scanner" /du "https://github.com/bert-euraika/auto-zap" "$installerPath"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Installer signed successfully." -ForegroundColor Green
    } else {
        Write-Host "[!] Signing failed (exit code $LASTEXITCODE)." -ForegroundColor Yellow
        Write-Host "    The installer is still usable but will show 'Unknown publisher'." -ForegroundColor Yellow
    }
} elseif ($SkipSign) {
    Write-Host ""
    Write-Host "[*] Step 5/5: Skipping signing (as requested)." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "[!] Step 5/5: signtool.exe not found. Skipping signing." -ForegroundColor Yellow
    Write-Host "    Install Windows SDK: winget install Microsoft.WindowsSDK" -ForegroundColor Yellow
}

# ---- Done ----
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETE" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Installer : $installerPath" -ForegroundColor White
if (Test-Path $installerPath) {
    $finalSize = [math]::Round((Get-Item $installerPath).Length / 1MB, 1)
    Write-Host "  Size      : $finalSize MB" -ForegroundColor White
}
Write-Host "  Signed    : $(if (-not $SkipSign -and $signtool) { 'Yes (self-signed)' } else { 'No' })" -ForegroundColor White
Write-Host "  Contains  : auto-zap.ps1 + OWASP ZAP $zapVersion + Temurin JRE 17" -ForegroundColor White
Write-Host ""
Write-Host "  To install: Run $installerPath as Administrator" -ForegroundColor Cyan
Write-Host "  After install: auto-zap.cmd from any directory" -ForegroundColor Cyan
Write-Host ""
