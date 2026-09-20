@echo off
setlocal

set "KIT=D:\program\Windows Kits\10"
set "KM_INC=%KIT%\Include\10.0.28000.0\km"
set "SHARED_INC=%KIT%\Include\10.0.28000.0\shared"
set "UCRT_INC=%KIT%\Include\10.0.28000.0\ucrt"
set "KM_LIB=%KIT%\Lib\10.0.28000.0\km\x64"
set "SRC_DIR=%~dp0"
set "OUT_DIR=%SRC_DIR%build"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo [TEST] Compiling test_flt.cpp ...
cl.exe /nologo /c /Zi /W3 /WX- /Od /utf-8 ^
  /DUNICODE /D_UNICODE /D_KERNEL_MODE /D_AMD64_ /DX86_64 ^
  /DNTDDI_VERSION=0x0A00000C /D_WIN32_WINNT=0x0A00 ^
  /GS- /guard:cf- ^
  /Fo"%OUT_DIR%\\" ^
  /I"%KM_INC%" /I"%SHARED_INC%" /I"%UCRT_INC%" ^
  "%SRC_DIR%test_flt.cpp" || goto :err

echo [TEST] Linking test_flt.sys ...
link.exe /NOLOGO /DRIVER /RELEASE /SUBSYSTEM:NATIVE ^
  /ENTRY:DriverEntry ^
  /OUT:"%OUT_DIR%\test_flt.sys" ^
  "%OUT_DIR%\test_flt.obj" ^
  "%KM_LIB%\ntoskrnl.lib" "%KM_LIB%\fltMgr.lib" || goto :err

echo.
echo [TEST] SUCCESS: %OUT_DIR%\test_flt.sys
exit /b 0

:err
echo.
echo [TEST] Build FAILED
exit /b 1
