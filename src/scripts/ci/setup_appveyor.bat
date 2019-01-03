
echo Current build setup MSVS="%MSVS%" PLATFORM="%PLATFORM%" TARGET="%TARGET%"

if %MSVS% == 2015 call "%ProgramFiles(x86)%\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" %PLATFORM%
if %MSVS% == 2017 call "%ProgramFiles(x86)%\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%
if %MSVS% == 2019 call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Preview\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM%

rem check compiler version
cl

set PATH=C:\Qt\Tools\QtCreator\bin;%PATH%
