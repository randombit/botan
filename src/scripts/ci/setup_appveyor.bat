
echo Current build setup CC="%CC%" PLATFORM="%PLATFORM%" TARGET="%TARGET%"

if %CC% == VC2015 call "%ProgramFiles(x86)%\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" %PLATFORM%
if %CC% == VC2017 call "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%
if %CC% == VC2019 call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%
if %CC% == VC2019p call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Preview\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%
if %CC% == MinGW set PATH=%PATH%;C:\msys64\mingw64\bin

rem check compiler version
if %CC% == MinGW g++ -v
if not %CC% == MinGW cl

appveyor DownloadFile https://github.com/mozilla/sccache/releases/download/%SCCACHE_VERSION%/sccache-%SCCACHE_VERSION%-x86_64-pc-windows-msvc.tar.gz
tar -xf sccache-%SCCACHE_VERSION%-x86_64-pc-windows-msvc.tar.gz

appveyor DownloadFile http://download.qt.io/official_releases/jom/jom.zip -FileName jom.zip
7z e jom.zip

set PATH=%PATH%;sccache-%SCCACHE_VERSION%-x86_64-pc-windows-msvc
