@echo off
rem Rebuild every corpus test with the era toolchain. Run from a
rem command prompt with the MSVC 6 compiler on PATH (for example the
rem Visual Studio command prompt, or after calling vcvars32.bat).
rem Each test builds into its own directory; exit code 0 is success.

setlocal
cd /d "%~dp0"

where cl >nul 2>nul
if errorlevel 1 (
    echo build.bat: cl not found on PATH - run from an MSVC command prompt
    exit /b 1
)

echo === exit0
cl /nologo /Fo:exit0\ /Fe:exit0\exit0.exe exit0\exit0.c /link /NODEFAULTLIB /ENTRY:ExitMain /SUBSYSTEM:CONSOLE kernel32.lib
if errorlevel 1 exit /b 1

echo === ret0
cl /nologo /Fo:ret0\ /Fe:ret0\ret0.exe ret0\ret0.c
if errorlevel 1 exit /b 1

echo All tests built.
exit /b 0
