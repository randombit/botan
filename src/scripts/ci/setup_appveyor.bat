
rem (C) 2017,2019,2021 Jack Lloyd
rem Botan is released under the Simplified BSD License (see license.txt)

echo Current build setup CC="%CC%" PLATFORM="%PLATFORM%" TARGET="%TARGET%"

if %CC% == VC2019 call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%
if %CC% == VC2019p call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Preview\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%
if %CC% == MinGW set PATH=%PATH%;C:\msys64\mingw64\bin

rem check compiler version
if %CC% == MinGW (
   g++ -v
) else (
   cl
)

if not exist jom.zip (
  appveyor DownloadFile https://download.qt.io/official_releases/jom/jom_1_1_3.zip -FileName jom.zip
)
7z e jom.zip

if not exist sccache-v%SCCACHE_VERSION%-x86_64-pc-windows-msvc.tar.gz (
  appveyor DownloadFile https://github.com/mozilla/sccache/releases/download/v%SCCACHE_VERSION%/sccache-v%SCCACHE_VERSION%-x86_64-pc-windows-msvc.tar.gz
)
tar -xf sccache-v%SCCACHE_VERSION%-x86_64-pc-windows-msvc.tar.gz
set PATH=%PATH%;sccache-v%SCCACHE_VERSION%-x86_64-pc-windows-msvc
