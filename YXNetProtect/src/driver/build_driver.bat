@echo off
REM ============================================================
REM BanJiu-Guard kernel driver build script
REM Uses MSVC cl.exe + WDK headers/libs (no VS WDK template needed)
REM Output: 与 GUI 同目录 (..\..\build\src\gui\BanJiu-Guard.sys)
REM          方便部署：驱动+GUI 同一个目录一次拷贝
REM ============================================================
setlocal ENABLEDELAYEDEXPANSION

set "SRC_DIR=%~dp0"
REM 输出到 GUI 可执行文件同目录：YXNetProtect\build\src\gui\
set "OUT_DIR=%SRC_DIR%..\..\build\src\gui"
if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

call "D:\program\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul

set "KIT=D:\program\Windows Kits\10"
set "KM_INC=%KIT%\Include\10.0.28000.0\km"
set "SHARED_INC=%KIT%\Include\10.0.28000.0\shared"
set "UCRT_INC=%KIT%\Include\10.0.28000.0\ucrt"
set "KM_LIB=%KIT%\Lib\10.0.28000.0\km\x64"

echo [DRV] Compiling yx_driver.cpp ...
cl.exe /nologo /c /Zi /W3 /WX- /Od /utf-8 ^
  /DUNICODE /D_UNICODE /D_KERNEL_MODE /D_AMD64_ /DX86_64 ^
  /DNTDDI_VERSION=0x0A00000C /D_WIN32_WINNT=0x0A00 ^
  /GS- /guard:cf ^
  /Fo"%OUT_DIR%\\" ^
  /I"%KM_INC%" /I"%SHARED_INC%" /I"%UCRT_INC%" ^
  /I"%SRC_DIR%..\common" ^
  "%SRC_DIR%yx_driver.cpp" || goto :err

echo [DRV] Compiling yx_callbacks.cpp ...
cl.exe /nologo /c /Zi /W3 /WX- /Od /utf-8 ^
  /DUNICODE /D_UNICODE /D_KERNEL_MODE /D_AMD64_ /DX86_64 ^
  /DNTDDI_VERSION=0x0A00000C /D_WIN32_WINNT=0x0A00 ^
  /GS- /guard:cf ^
  /Fo"%OUT_DIR%\\" ^
  /I"%KM_INC%" /I"%SHARED_INC%" /I"%UCRT_INC%" ^
  /I"%SRC_DIR%..\common" ^
  "%SRC_DIR%yx_callbacks.cpp" || goto :err

echo [DRV] Linking kernel driver...
link.exe /NOLOGO /DRIVER /RELEASE /SUBSYSTEM:NATIVE ^
  /ENTRY:DriverEntry /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text ^
  /guard:cf /INTEGRITYCHECK ^
  /OUT:"%OUT_DIR%\BanJiu-Guard.sys" ^
  "%OUT_DIR%\yx_driver.obj" "%OUT_DIR%\yx_callbacks.obj" ^
  "%KM_LIB%\ntoskrnl.lib" "%KM_LIB%\fltMgr.lib" || goto :err

echo.
echo [DRV] Signing driver with test certificate...
set "SIGNTOOL=%KIT%\bin\10.0.17763.0\x64\signtool.exe"
if not exist "%SIGNTOOL%" set "SIGNTOOL=%KIT%\bin\10.0.28000.0\x64\signtool.exe"
if not exist "%SIGNTOOL%" (
    echo [DRV] WARNING: signtool.exe not found, skipping signing.
    echo [DRV]         Install WDK or run tools\sign_driver.bat first to generate a test cert.
) else (
    "%SIGNTOOL%" sign /a /v /s PrivateCertStore /n "BanJiu-Guard Test Cert" ^
                  "%OUT_DIR%\BanJiu-Guard.sys"
    if errorlevel 1 (
        echo [DRV] WARNING: Signing failed. Run tools\sign_driver.bat first to create cert.
    ) else (
        echo [DRV] Signed OK.
    )
)

echo.
echo [DRV] SUCCESS: %OUT_DIR%\BanJiu-Guard.sys
dir "%OUT_DIR%\BanJiu-Guard.sys"
exit /b 0

:err
echo [DRV] Build FAILED
exit /b 1
