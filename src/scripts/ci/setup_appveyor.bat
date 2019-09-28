
echo Current build setup MSVS="%MSVS%" PLATFORM="%PLATFORM%" TARGET="%TARGET%"

if %MSVS% == 2015 call "%ProgramFiles(x86)%\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" %PLATFORM%
if %MSVS% == 2017 call "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%
if %MSVS% == 2019 call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%

rem check compiler version
cl

appveyor DownloadFile https://github.com/mozilla/sccache/releases/download/%SCCACHE_VERSION%/sccache-%SCCACHE_VERSION%-x86_64-pc-windows-msvc.tar.gz
tar -xf sccache-%SCCACHE_VERSION%-x86_64-pc-windows-msvc.tar.gz

REM include QtCreator bin dir to get jom
set PATH=%PATH%;C:\Qt\Tools\QtCreator\bin;sccache-%SCCACHE_VERSION%-x86_64-pc-windows-msvc
