@echo off
rem Rebuild every corpus test with the era toolchain. Run from a
rem command prompt with the MSVC 6 compiler on PATH (for example the
rem Visual Studio command prompt, or after calling vcvars32.bat).
rem Each test builds inside its own directory; exit code 0 is success.
rem A fixture's name (build.bat dll) rebuilds only that one.

setlocal
cd /d "%~dp0"

rem The `where` command does not exist on Windows 2000: search PATH
rem the old way instead.
for %%I in (cl.exe) do if "%%~$PATH:I"=="" (
    echo build.bat: cl.exe not found on PATH - run from an MSVC command prompt
    exit /b 1
)

if not "%~1"=="" goto one

call :srcsum
if errorlevel 1 exit /b 1
for %%F in (exit0 ret0 hello hellogui bare runtime memory threads sync sched files fswrite dll) do (
    call :%%F
    if errorlevel 1 exit /b 1
)
echo All tests built.
exit /b 0

rem One fixture (build.bat dll): the stamp tool too, when the fixture
rem needs it and it is not there (the fixtures built on common\f2kt.h
rem stamp their source with it).
:one
set F2KT_ONE=
for %%F in (exit0 ret0 hello hellogui bare runtime memory threads sync sched files fswrite dll) do if /I "%%F"=="%~1" set F2KT_ONE=yes
if not defined F2KT_ONE (
    echo build.bat: no such fixture %~1
    exit /b 1
)
if not exist common\srcsum.exe call :srcsum
call :%~1
if errorlevel 1 exit /b 1
echo %~1 built.
exit /b 0

:srcsum
rem The source-stamp tool: the fixtures built on common\f2kt.h carry
rem the CRC of their source and the header (F2KT_SOURCE_CRC, see f2kt.h).
echo === srcsum
cd common
cl /nologo srcsum.c
if errorlevel 1 (echo build.bat: srcsum failed & exit /b 1)
del srcsum.obj
cd ..
goto :eof

:exit0
echo === exit0
cd exit0
cl /nologo exit0.c /link /NODEFAULTLIB /ENTRY:ExitMain /SUBSYSTEM:CONSOLE kernel32.lib
if errorlevel 1 (echo build.bat: exit0 failed & exit /b 1)
del exit0.obj
cd ..
goto :eof

:ret0
echo === ret0
cd ret0
cl /nologo ret0.c
if errorlevel 1 (echo build.bat: ret0 failed & exit /b 1)
del ret0.obj
cd ..
goto :eof

:hello
echo === hello
cd hello
cl /nologo hello.c
if errorlevel 1 (echo build.bat: hello failed & exit /b 1)
del hello.obj
cd ..
goto :eof

:hellogui
echo === hellogui
cd hellogui
cl /nologo hellogui.c user32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup
if errorlevel 1 (echo build.bat: hellogui failed & exit /b 1)
del hellogui.obj
cd ..
goto :eof

:bare
echo === bare
cd bare
cl /nologo bare.c /link /NODEFAULTLIB /ENTRY:BareMain /SUBSYSTEM:CONSOLE kernel32.lib
if errorlevel 1 (echo build.bat: bare failed & exit /b 1)
del bare.obj
cd ..
goto :eof

:runtime
echo === runtime
cd runtime
call :stamp runtime.c
cl /nologo /DF2KT_SOURCE_CRC=0x%F2KT_CRC% runtime.c
if errorlevel 1 (echo build.bat: runtime failed & exit /b 1)
del runtime.obj
cd ..
goto :eof

:memory
echo === memory
cd memory
call :stamp memory.c
cl /nologo /DF2KT_SOURCE_CRC=0x%F2KT_CRC% memory.c
if errorlevel 1 (echo build.bat: memory failed & exit /b 1)
del memory.obj
cd ..
goto :eof

:threads
echo === threads
cd threads
call :stamp threads.c
cl /nologo /MT /DF2KT_SOURCE_CRC=0x%F2KT_CRC% threads.c
if errorlevel 1 (echo build.bat: threads failed & exit /b 1)
del threads.obj
cd ..
goto :eof

:sync
echo === sync
cd sync
call :stamp sync.c
cl /nologo /MT /DF2KT_SOURCE_CRC=0x%F2KT_CRC% sync.c
if errorlevel 1 (echo build.bat: sync failed & exit /b 1)
del sync.obj
cd ..
goto :eof

:sched
echo === sched
cd sched
call :stamp sched.c
cl /nologo /MT /DF2KT_SOURCE_CRC=0x%F2KT_CRC% sched.c
if errorlevel 1 (echo build.bat: sched failed & exit /b 1)
del sched.obj
cd ..
goto :eof

:files
echo === files
cd files
call :stamp files.c
cl /nologo /DF2KT_SOURCE_CRC=0x%F2KT_CRC% files.c
if errorlevel 1 (echo build.bat: files failed & exit /b 1)
del files.obj
cd ..
goto :eof

:fswrite
echo === fswrite
cd fswrite
call :stamp fswrite.c
cl /nologo /DF2KT_SOURCE_CRC=0x%F2KT_CRC% fswrite.c
if errorlevel 1 (echo build.bat: fswrite failed & exit /b 1)
del fswrite.obj
cd ..
goto :eof

:dll
echo === dll
cd dll
cl /nologo /LD f2kcom.c /link /NODEFAULTLIB /NOENTRY /DEF:f2kcom.def
if errorlevel 1 (echo build.bat: f2kcom failed & exit /b 1)
del f2kcom.obj f2kcom.lib f2kcom.exp
call :stamp dll.c
cl /nologo /DF2KT_SOURCE_CRC=0x%F2KT_CRC% dll.c
if errorlevel 1 (echo build.bat: dll failed & exit /b 1)
del dll.obj
cd ..
goto :eof

rem Set F2KT_CRC to the source stamp of the fixture source %1 (with the
rem shared header), from inside its directory.
:stamp
set F2KT_CRC=
for /f %%H in ('..\common\srcsum.exe %1 ..\common\f2kt.h') do set F2KT_CRC=%%H
if "%F2KT_CRC%"=="" (echo build.bat: srcsum failed on %1 & exit /b 1)
goto :eof
