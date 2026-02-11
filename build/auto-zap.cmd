@echo off
setlocal
set "JAVA_HOME=%~dp0jre"
set "PATH=%JAVA_HOME%\bin;%~dp0zap;%PATH%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0auto-zap.ps1" %*
