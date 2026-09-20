@echo off
setlocal ENABLEDELAYEDEXPANSION

set "SRC_DIR=%~dp0"
set "OUT_DIR=%~dp0build"

call "D:\program\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul

set "KIT=D:\program\Windows Kits\10"
set "KM_INC=%KIT%\Include\10.0.28000.0\km"
set "SHARED_INC=%KIT%\Include\10.0.28000.0\shared"
set "UCRT_INC=%KIT%\Include\10.0.28000.0\ucrt"
set "KM_LIB=%KIT%\Lib\10.0.28000.0\km\x64"

echo [TEST] Compiling minimal_test.cpp ...
cl.exe /nologo /c /Zi /W3 /WX- /Od /utf-8 ^
  /DUNICODE /D_UNICODE /D_KERNEL_MODE /D_AMD64_ /DX86_64 ^
  /DNTDDI_VERSION=0x0A00000C /D_WIN32_WINNT=0x0A00 ^
  /GS- ^
  /Fo"%OUT_DIR%\\" ^
  /I"%KM_INC%" /I"%SHARED_INC%" /I"%UCRT_INC%" ^
  "%SRC_DIR%minimal_test.cpp" || goto :err

echo [TEST] Linking minimal test driver (DriverEntry, no BufferOverflowK)...
link.exe /NOLOGO /DRIVER /RELEASE /SUBSYSTEM:NATIVE ^
  /ENTRY:DriverEntry ^
  /OUT:"%OUT_DIR%\minimal_test2.sys" ^
  "%OUT_DIR%\minimal_test.obj" ^
  "%KM_LIB%\ntoskrnl.lib" "%KM_LIB%\fltMgr.lib" || goto :err

echo.
echo [TEST] SUCCESS: %OUT_DIR%\minimal_test.sys
exit /b 0

:err
echo [TEST] Build FAILED
exit /b 1
