; ============================================================
; Auto-ZAP Installer - NSIS Script
; Bundles: auto-zap.ps1 + OWASP ZAP + Eclipse Temurin JRE 17
; ============================================================

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "WordFunc.nsh"

; ---- General ----
Name "Auto-ZAP"
OutFile "..\dist\Auto-ZAP-Setup.exe"
InstallDir "$PROGRAMFILES\Auto-ZAP"
InstallDirRegKey HKLM "Software\Auto-ZAP" "InstallDir"
RequestExecutionLevel admin
SetCompressor lzma

; ---- Version Info ----
VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName" "Auto-ZAP"
VIAddVersionKey "CompanyName" "Euraika"
VIAddVersionKey "FileDescription" "Auto-ZAP - Automated OWASP ZAP Security Scanner"
VIAddVersionKey "FileVersion" "1.0.0.0"
VIAddVersionKey "LegalCopyright" "Copyright 2026 Euraika"

; ---- Interface ----
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\orange-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\orange-uninstall.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Welcome to Auto-ZAP Setup"
!define MUI_WELCOMEPAGE_TEXT "This wizard will install Auto-ZAP, a fully automated OWASP ZAP security scanner for web applications.$\r$\n$\r$\nIncludes:$\r$\n  - auto-zap.ps1 (scanner script)$\r$\n  - OWASP ZAP (vulnerability scanner)$\r$\n  - Eclipse Temurin JRE 17 (Java runtime)$\r$\n$\r$\nClick Next to continue."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open Auto-ZAP installation folder"
!define MUI_FINISHPAGE_RUN_FUNCTION "OpenInstallDir"

; ---- Pages ----
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ---- Functions ----
Function OpenInstallDir
    ExecShell "open" "$INSTDIR"
FunctionEnd

; ---- Installer Section ----
Section "Auto-ZAP Core" SecCore
    SectionIn RO ; Required section

    SetOutPath "$INSTDIR"
    File "..\auto-zap.ps1"
    File "..\README.md"
    File "..\LICENSE.txt"

    ; Launcher batch file and PowerShell wrapper
    File "auto-zap.cmd"
    File "Invoke-AutoZap.ps1"

    ; Store install dir in registry
    WriteRegStr HKLM "Software\Auto-ZAP" "InstallDir" "$INSTDIR"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; Add/Remove Programs entry
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP" "DisplayName" "Auto-ZAP"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP" "UninstallString" '"$INSTDIR\uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP" "Publisher" "Euraika"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP" "DisplayVersion" "1.0.0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP" "URLInfoAbout" "https://github.com/bert-euraika/auto-zap"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP" "NoRepair" 1

    ; Estimate size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP" "EstimatedSize" "$0"
SectionEnd

Section "OWASP ZAP" SecZap
    SectionIn RO

    SetOutPath "$INSTDIR\zap"
    File /r "staging\zap\*.*"
SectionEnd

Section "Java Runtime (Temurin JRE 17)" SecJava
    SectionIn RO

    SetOutPath "$INSTDIR\jre"
    File /r "staging\jre\*.*"
SectionEnd

Section "Add to PATH" SecPath
    ; Add to system PATH
    ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
    ${If} $0 != ""
        StrCpy $0 "$0;$INSTDIR"
    ${Else}
        StrCpy $0 "$INSTDIR"
    ${EndIf}
    WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$0"

    ; Broadcast environment change
    SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

Section "Start Menu Shortcuts" SecShortcuts
    CreateDirectory "$SMPROGRAMS\Auto-ZAP"
    CreateShortcut "$SMPROGRAMS\Auto-ZAP\Auto-ZAP.lnk" "$INSTDIR\auto-zap.cmd" "" "" 0
    CreateShortcut "$SMPROGRAMS\Auto-ZAP\README.lnk" "$INSTDIR\README.md"
    CreateShortcut "$SMPROGRAMS\Auto-ZAP\Uninstall.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

; ---- Uninstaller ----
Section "Uninstall"
    ; Remove from PATH
    ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
    ${WordReplace} $0 ";$INSTDIR" "" "+1" $0
    ${WordReplace} $0 "$INSTDIR;" "" "+1" $0
    ${WordReplace} $0 "$INSTDIR" "" "+1" $0
    WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$0"

    ; Remove shortcuts
    RMDir /r "$SMPROGRAMS\Auto-ZAP"

    ; Remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Auto-ZAP"
    DeleteRegKey HKLM "Software\Auto-ZAP"

    ; Remove files
    RMDir /r "$INSTDIR"

    ; Broadcast environment change
    SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

; ---- Section Descriptions ----
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Auto-ZAP scanner script and launcher"
    !insertmacro MUI_DESCRIPTION_TEXT ${SecZap} "OWASP ZAP vulnerability scanner (required)"
    !insertmacro MUI_DESCRIPTION_TEXT ${SecJava} "Eclipse Temurin JRE 17 for running ZAP (required)"
    !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "Add Auto-ZAP to system PATH for command-line access"
    !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} "Create Start Menu shortcuts"
!insertmacro MUI_FUNCTION_DESCRIPTION_END
