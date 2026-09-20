@echo off
REM ============================================================
REM BanJiu-Guard driver test-signing script
REM 1. Generate test cert (makecert)
REM 2. Generate catalog (Inf2Cat)
REM 3. Sign .sys and .cat with signtool
REM NOTE: enable test signing first (bcdedit /set testsigning on) + reboot
REM ============================================================
setlocal ENABLEDELAYEDEXPANSION

set "KIT=D:\program\Windows Kits\10"
set "BIN=%KIT%\bin\10.0.28000.0\x64"
set "TOOLS=%~dp0"
set "DRV_DIR=%~dp0..\src\driver"
set "CERT_DIR=%TOOLS%certs"

if not exist "%CERT_DIR%" mkdir "%CERT_DIR%"

echo [SIGN] 1/4 Generating test certificate...
set "MAKECERT=%KIT%\bin\10.0.17763.0\x64\makecert.exe"
if not exist "%MAKECERT%" (
    echo [SIGN] ERROR: makecert.exe not found
    exit /b 1
)
"%MAKECERT%" -r -pe -ss PrivateCertStore -n "CN=BanJiu-Guard Test Cert" "%CERT_DIR%\BanJiu-Guard.cer"
if errorlevel 1 goto :err

echo [SIGN] 3/4 Signing driver (.sys only, SCM-registered driver doesn't need INF catalog)...
set "SIGNTOOL=%BIN%\signtool.exe"
if not exist "%SIGNTOOL%" set "SIGNTOOL=%KIT%\bin\10.0.17763.0\x64\signtool.exe"
if not exist "%SIGNTOOL%" (
    echo [SIGN] ERROR: signtool.exe not found
    exit /b 1
)
"%SIGNTOOL%" sign /a /v /s PrivateCertStore /n "BanJiu-Guard Test Cert" "%DRV_DIR%\build\BanJiu-Guard.sys"
if errorlevel 1 goto :err

echo.
echo [SIGN] DONE. Driver test-signed: %DRV_DIR%\build\BanJiu-Guard.sys
echo        To load on target machine: bcdedit /set testsigning on  then reboot
echo        NOTE: Test certificate only needs to exist in the signing machine's PrivateCertStore.
echo              No cert import required on the target VM.
exit /b 0

:err
echo [SIGN] Signing FAILED
exit /b 1
