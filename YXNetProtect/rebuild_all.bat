@echo off
call "D:\program\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
set "PATH=D:\program\Windows Kits\10\bin\10.0.26100.0\x64;D:\program\qt\Tools\Ninja;D:\program\qt\Tools\CMake_64\bin;%PATH%"
cd /d "d:\Projects\BanJiu-Guard\YXNetProtect"
if exist build rmdir /s /q build
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=cl -DCMAKE_C_COMPILER=cl -DQT_STATIC_PREFIX="D:/program/qt-static-msvc-noicu"
if errorlevel 1 exit /b 1
cmake --build build --parallel 14
exit /b %errorlevel%
