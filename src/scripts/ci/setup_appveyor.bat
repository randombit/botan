
echo Current build setup MSVS="%MSVS%" PLATFORM="%PLATFORM%" TARGET="%TARGET%"

if %MSVS% == 2013 call "%ProgramFiles(x86)%\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" %PLATFORM%
if %MSVS% == 2015 call "%ProgramFiles(x86)%\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" %PLATFORM%
if %MSVS% == 2017 call "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%

rem check compiler version
cl

git clone --depth 1 https://github.com/randombit/botan-ci-tools
7z e botan-ci-tools/jom_1_1_2.zip
