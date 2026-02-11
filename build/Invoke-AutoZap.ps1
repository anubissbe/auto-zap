# Auto-ZAP Launcher - sets up bundled Java and ZAP
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:JAVA_HOME = Join-Path $scriptDir "jre"
$env:PATH = "$env:JAVA_HOME\bin;$(Join-Path $scriptDir 'zap');$env:PATH"
& (Join-Path $scriptDir "auto-zap.ps1") @args
