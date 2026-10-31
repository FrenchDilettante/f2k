@echo off
rem Rebuild every corpus test with the era toolchain. Run from a
rem command prompt with the MSVC 6 compiler on PATH (for example the
rem Visual Studio command prompt, or after calling vcvars32.bat).
rem Each test builds inside its own directory, <dll>\<name> (the
rem fixtures are grouped by the DLL they exercise); exit code 0 is
rem success. The fixtures built on common\f2kt.h include it as
rem "../common/f2kt.h": /I .. (their group's directory) finds it.
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
for %%F in (exit0 ret0 hello hellogui bare runtime memory threads sync sched files fswrite dll dllmain msgtable console spawn pipe winsta registry hellomd crt seh fd wide) do (
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
for %%F in (exit0 ret0 hello hellogui bare runtime memory threads sync sched files fswrite dll dllmain msgtable console spawn pipe winsta registry hellomd crt seh fd wide) do if /I "%%F"=="%~1" set F2KT_ONE=yes
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
cd core\exit0
cl /nologo exit0.c /link /NODEFAULTLIB /ENTRY:ExitMain /SUBSYSTEM:CONSOLE kernel32.lib
if errorlevel 1 (echo build.bat: exit0 failed & exit /b 1)
del exit0.obj
cd ..\..
goto :eof

:ret0
echo === ret0
cd core\ret0
cl /nologo ret0.c
if errorlevel 1 (echo build.bat: ret0 failed & exit /b 1)
del ret0.obj
cd ..\..
goto :eof

:hello
echo === hello
cd core\hello
cl /nologo hello.c
if errorlevel 1 (echo build.bat: hello failed & exit /b 1)
del hello.obj
cd ..\..
goto :eof

:hellogui
echo === hellogui
cd user32\hellogui
cl /nologo hellogui.c user32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup
if errorlevel 1 (echo build.bat: hellogui failed & exit /b 1)
del hellogui.obj
cd ..\..
goto :eof

:bare
echo === bare
cd core\bare
cl /nologo bare.c /link /NODEFAULTLIB /ENTRY:BareMain /SUBSYSTEM:CONSOLE kernel32.lib
if errorlevel 1 (echo build.bat: bare failed & exit /b 1)
del bare.obj
cd ..\..
goto :eof

:runtime
echo === runtime
cd kernel32\runtime
call :stamp runtime.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% runtime.c
if errorlevel 1 (echo build.bat: runtime failed & exit /b 1)
del runtime.obj
cd ..\..
goto :eof

:memory
echo === memory
cd kernel32\memory
call :stamp memory.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% memory.c
if errorlevel 1 (echo build.bat: memory failed & exit /b 1)
del memory.obj
cd ..\..
goto :eof

:threads
echo === threads
cd kernel32\threads
call :stamp threads.c
cl /nologo /MT /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% threads.c
if errorlevel 1 (echo build.bat: threads failed & exit /b 1)
del threads.obj
cd ..\..
goto :eof

:sync
echo === sync
cd kernel32\sync
call :stamp sync.c
cl /nologo /MT /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% sync.c
if errorlevel 1 (echo build.bat: sync failed & exit /b 1)
del sync.obj
cd ..\..
goto :eof

:sched
echo === sched
cd kernel32\sched
call :stamp sched.c
cl /nologo /MT /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% sched.c
if errorlevel 1 (echo build.bat: sched failed & exit /b 1)
del sched.obj
cd ..\..
goto :eof

:files
echo === files
cd kernel32\files
call :stamp files.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% files.c
if errorlevel 1 (echo build.bat: files failed & exit /b 1)
del files.obj
cd ..\..
goto :eof

:fswrite
echo === fswrite
cd kernel32\fswrite
call :stamp fswrite.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% fswrite.c
if errorlevel 1 (echo build.bat: fswrite failed & exit /b 1)
del fswrite.obj
cd ..\..
goto :eof

:dll
echo === dll
cd kernel32\dll
cl /nologo /LD f2kcom.c /link /NODEFAULTLIB /NOENTRY /DEF:f2kcom.def
if errorlevel 1 (echo build.bat: f2kcom failed & exit /b 1)
del f2kcom.obj f2kcom.lib f2kcom.exp
call :stamp dll.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% dll.c
if errorlevel 1 (echo build.bat: dll failed & exit /b 1)
del dll.obj
cd ..\..
goto :eof

rem dllmain's companion DLLs build first, each with no C runtime and
rem DllMain its entry point, at the base its .def names (F2K never
rem relocates an image), f2kbase.dll first (the others import it), then
rem f2kdep.dll (f2kdyn.dll imports it); f2ksub.dll goes into dllsub\.
rem The program links against f2kbase.lib and f2kmid.lib.
:dllmain
echo === dllmain
cd kernel32\dllmain
cl /nologo /LD f2kbase.c /link /NODEFAULTLIB /ENTRY:DllMain /DEF:f2kbase.def kernel32.lib
if errorlevel 1 (echo build.bat: f2kbase failed & exit /b 1)
cl /nologo /LD f2kdep.c /link /NODEFAULTLIB /ENTRY:DllMain /DEF:f2kdep.def kernel32.lib f2kbase.lib
if errorlevel 1 (echo build.bat: f2kdep failed & exit /b 1)
cl /nologo /LD f2kmid.c /link /NODEFAULTLIB /ENTRY:DllMain /DEF:f2kmid.def kernel32.lib f2kbase.lib
if errorlevel 1 (echo build.bat: f2kmid failed & exit /b 1)
cl /nologo /LD f2kdyn.c /link /NODEFAULTLIB /ENTRY:DllMain /DEF:f2kdyn.def kernel32.lib f2kbase.lib f2kdep.lib
if errorlevel 1 (echo build.bat: f2kdyn failed & exit /b 1)
cl /nologo /LD f2kfail.c /link /NODEFAULTLIB /ENTRY:DllMain /DEF:f2kfail.def kernel32.lib f2kbase.lib
if errorlevel 1 (echo build.bat: f2kfail failed & exit /b 1)
cl /nologo /LD f2ksub.c /link /NODEFAULTLIB /ENTRY:DllMain /DEF:f2ksub.def kernel32.lib f2kbase.lib
if errorlevel 1 (echo build.bat: f2ksub failed & exit /b 1)
if not exist dllsub mkdir dllsub
move /y f2ksub.dll dllsub\ > nul
call :stamp dllmain.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% dllmain.c f2kbase.lib f2kmid.lib
if errorlevel 1 (echo build.bat: dllmain failed & exit /b 1)
del *.obj *.lib *.exp
cd ..\..
goto :eof

rem msgtable's message table: mc compiles msgtable.mc (-U: the texts in
rem Unicode, as cmd.exe's are) into msgtable.rc and MSG00409.bin, rc
rem compiles those into msgtable.res, which links into the program.
:msgtable
echo === msgtable
cd kernel32\msgtable
for %%I in (mc.exe rc.exe) do if "%%~$PATH:I"=="" (
    echo build.bat: %%I not found on PATH - msgtable needs the message and resource compilers
    exit /b 1
)
call :stamp msgtable.c
mc -U msgtable.mc
if errorlevel 1 (echo build.bat: msgtable's mc failed & exit /b 1)
rc msgtable.rc
if errorlevel 1 (echo build.bat: msgtable's rc failed & exit /b 1)
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% msgtable.c msgtable.res
if errorlevel 1 (echo build.bat: msgtable failed & exit /b 1)
del msgtable.obj msgtable.res msgtable.rc msgtable.h MSG00409.bin
cd ..\..
goto :eof

:console
echo === console
cd kernel32\console
call :stamp console.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% console.c
if errorlevel 1 (echo build.bat: console failed & exit /b 1)
del console.obj
cd ..\..
goto :eof

rem spawn's companion program, spawnkid.exe (the child every section
rem starts), builds beside it with no source stamp; both with /MD.
:spawn
echo === spawn
cd kernel32\spawn
cl /nologo /MD spawnkid.c
if errorlevel 1 (echo build.bat: spawnkid failed & exit /b 1)
call :stamp spawn.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% spawn.c
if errorlevel 1 (echo build.bat: spawn failed & exit /b 1)
del spawn.obj spawnkid.obj
cd ..\..
goto :eof

rem pipe's companion program, pipekid.exe (the child its sections start,
rem and the stand-in command processor its popen section points COMSPEC
rem at), builds beside it with no source stamp; both with /MD.
:pipe
echo === pipe
cd kernel32\pipe
cl /nologo /MD pipekid.c
if errorlevel 1 (echo build.bat: pipekid failed & exit /b 1)
call :stamp pipe.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% pipe.c
if errorlevel 1 (echo build.bat: pipe failed & exit /b 1)
del pipe.obj pipekid.obj
cd ..\..
goto :eof

:winsta
echo === winsta
cd user32\winsta
call :stamp winsta.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% winsta.c user32.lib
if errorlevel 1 (echo build.bat: winsta failed & exit /b 1)
del winsta.obj
cd ..\..
goto :eof

:registry
echo === registry
cd advapi32\registry
call :stamp registry.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% registry.c advapi32.lib
if errorlevel 1 (echo build.bat: registry failed & exit /b 1)
del registry.obj
cd ..\..
goto :eof

rem The crt fixtures build with /MD: their C runtime is msvcrt.dll's,
rem as cmd.exe's is. hellomd is core\hello\hello.c (hellomd.c includes
rem it), with no source stamp, as hello has none.
:hellomd
echo === hellomd
cd crt\hellomd
cl /nologo /MD hellomd.c
if errorlevel 1 (echo build.bat: hellomd failed & exit /b 1)
del hellomd.obj
cd ..\..
goto :eof

:crt
echo === crt
cd crt\crt
call :stamp crt.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% crt.c
if errorlevel 1 (echo build.bat: crt failed & exit /b 1)
del crt.obj
cd ..\..
goto :eof

:seh
echo === seh
cd crt\seh
call :stamp seh.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% seh.c
if errorlevel 1 (echo build.bat: seh failed & exit /b 1)
del seh.obj
cd ..\..
goto :eof

:fd
echo === fd
cd crt\fd
call :stamp fd.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% fd.c
if errorlevel 1 (echo build.bat: fd failed & exit /b 1)
del fd.obj
cd ..\..
goto :eof

:wide
echo === wide
cd crt\wide
call :stamp wide.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% wide.c
if errorlevel 1 (echo build.bat: wide failed & exit /b 1)
del wide.obj
cd ..\..
goto :eof

rem Set F2KT_CRC to the source stamp of the fixture source %1 (with the
rem shared header), from inside its directory, <dll>\<name>.
:stamp
set F2KT_CRC=
for /f %%H in ('..\..\common\srcsum.exe %1 ..\..\common\f2kt.h') do set F2KT_CRC=%%H
if "%F2KT_CRC%"=="" (echo build.bat: srcsum failed on %1 & exit /b 1)
goto :eof
