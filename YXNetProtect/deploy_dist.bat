@echo off
REM ============================================================
REM BanJiu-Guard - deploy final files to dist\BanJiu-Guard\
REM for Inno Setup packaging.
REM Only FINAL files (exe / sys / model / icon) are copied here.
REM All intermediate & debug files (.obj/.exp/.lib/autogen/CMakeFiles)
REM stay in build\src\gui.
REM ============================================================
setlocal
set "ROOT=%~dp0"
set "SRC=%ROOT%build\src\gui"
set "DST=%ROOT%dist\BanJiu-Guard"

if not exist "%SRC%\BanJiu-Guard.exe" (
    echo [Deploy] ERROR: %SRC%\BanJiu-Guard.exe not found. Build first.
    exit /b 1
)

echo [Deploy] Cleaning %DST%
if exist "%DST%" rmdir /s /q "%DST%"
mkdir "%DST%\models"

echo [Deploy] Copying final files...
copy /y "%SRC%\BanJiu-Guard.exe"           "%DST%\"              >nul
copy /y "%SRC%\BanJiu-Guard.sys"           "%DST%\"              >nul
copy /y "%SRC%\models\lgbm_detector.txt"   "%DST%\models\"        >nul
copy /y "%ROOT%icon.ico"                   "%DST%\"              >nul

echo [Deploy] Done. Final files in %DST%
dir /b "%DST%"
dir /b "%DST%\models"
exit /b 0
