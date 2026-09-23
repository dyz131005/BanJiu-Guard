@echo off
REM ============================================================
REM BanJiu-Guard - one-click build script
REM Builds: driver (.sys), user-mode (.exe, static MSVC), signtool
REM ============================================================
setlocal ENABLEDELAYEDEXPANSION
set "ROOT=%~dp0"

echo ============================================
echo  BanJiu-Guard Build
echo ============================================

echo.
echo [1/4] Building kernel driver...
call "%ROOT%src\driver\build_driver.bat"
if errorlevel 1 (
    echo [BUILD] Driver build FAILED
    exit /b 1
)

echo.
echo [2/4] Building LightGBM static ML library...
if not exist "%ROOT%third_party\LightGBM\lib_lightgbm.lib" (
    call "%ROOT%third_party\build_lightgbm.bat"
    if errorlevel 1 (
        echo [BUILD] LightGBM build FAILED
        exit /b 1
    )
) else (
    echo [BUILD] lib_lightgbm.lib already exists, skipping.
)

echo.
echo [3/4] Building user-mode (GUI + service)...
cd /d "%ROOT%"
call "D:\program\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
set "PATH=D:\program\Windows Kits\10\bin\10.0.26100.0\x64;D:\program\qt\Tools\Ninja;D:\program\qt\Tools\CMake_64\bin;%PATH%"
if not exist "build" (
    cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=cl -DCMAKE_C_COMPILER=cl -DQT_STATIC_PREFIX="D:/program/qt-static-msvc-noicu"
    if errorlevel 1 exit /b 1
)
cmake --build build --parallel 14
if errorlevel 1 (
    echo [BUILD] User-mode build FAILED
    exit /b 1
)

echo.
echo [4/4] Test-signing driver...
call "%ROOT%tools\sign_driver.bat"

echo.
echo [5/5] Deploying final files to dist\BanJiu-Guard\...
call "%ROOT%deploy_dist.bat"
if errorlevel 1 (
    echo [BUILD] Deploy FAILED
    exit /b 1
)

echo.
echo ============================================
echo  Build complete.
echo  Final files: %ROOT%dist\BanJiu-Guard\  (exe / sys / models / icon.ico)
echo  Installer:   %ROOT%dist\BanJiu-Guard安装程序.exe  (compile build.iss in Inno Setup)
echo ============================================
exit /b 0
