@echo off
REM ============================================================
REM Build LightGBM 4.6.0 static library with MSVC (/MT)
REM 1) Clones source + submodules if missing
REM 2) Builds static lib via CMake + Ninja
REM Output: third_party\LightGBM\lib_lightgbm.lib
REM NOTE: compiler is forced to MSVC cl.exe on purpose.
REM       Do NOT let MinGW/g++ in PATH hijack the configure step
REM       (a MinGW-built .lib cannot be linked by the MSVC linker).
REM ============================================================
setlocal

set "SRC_DIR=%~dp0LightGBM"
set "BUILD_DIR=%~dp0LightGBM\build"
set "GIT_EXE=git"

REM Add common Git install paths (some machines do not have git in PATH)
where git >nul 2>&1
if errorlevel 1 (
    if exist "C:\Program Files\Git\bin\git.exe" set "PATH=C:\Program Files\Git\bin;%PATH%"
)

REM 1) Clone source if missing (shallow clone of v4.6.0)
if not exist "%SRC_DIR%\CMakeLists.txt" (
    echo [LGBM] Source not found, cloning LightGBM v4.6.0...
    %GIT_EXE% clone --depth 1 --branch v4.6.0 https://github.com/lightgbm-org/LightGBM.git "%SRC_DIR%"
    if errorlevel 1 (
        echo [LGBM] git clone FAILED
        exit /b 1
    )
    %GIT_EXE% -C "%SRC_DIR%" submodule update --init --recursive
    if errorlevel 1 (
        echo [LGBM] submodule init FAILED
        exit /b 1
    )
)

REM 2) Strip dllexport for static linking (static lib must not export symbols)
findstr /C:"LIGHTGBM_STATIC_LIB" "%SRC_DIR%\include\LightGBM\export.h" >nul 2>&1
if errorlevel 1 (
    echo [LGBM] Patching export.h for static linking...
    powershell -NoProfile -Command "$p='%SRC_DIR%\include\LightGBM\export.h'; (Get-Content $p -Raw) -replace '#ifdef _MSC_VER','#ifdef LIGHTGBM_STATIC_LIB\n#define LIGHTGBM_EXPORT\n#define LIGHTGBM_C_EXPORT LIGHTGBM_EXTERN_C\n#elif defined(_MSC_VER)' | Set-Content $p -NoNewline"
)

call "D:\program\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "PATH=D:\program\qt\Tools\Ninja;D:\program\qt\Tools\CMake_64\bin;%PATH%"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [LGBM] Configuring with CMake (MSVC + Ninja, /MT static CRT, no OpenMP)...
cmake -S "%SRC_DIR%" -B "%BUILD_DIR%" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_C_COMPILER=cl ^
  -DCMAKE_CXX_COMPILER=cl ^
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ^
  -DBUILD_STATIC_LIB=ON ^
  -DBUILD_CLI=OFF ^
  -DUSE_OPENMP=OFF

if errorlevel 1 (
    echo [LGBM] CMake configure FAILED
    exit /b 1
)

echo [LGBM] Building static library...
cmake --build "%BUILD_DIR%" --parallel

if errorlevel 1 (
    echo [LGBM] Build FAILED
    exit /b 1
)

echo [LGBM] Build SUCCESS
dir "%SRC_DIR%\lib_lightgbm.lib"

endlocal
