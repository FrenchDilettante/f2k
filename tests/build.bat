@echo off
rem Rebuild every corpus test with the era toolchain. Run from a
rem command prompt with the MSVC 6 compiler on PATH (for example the
rem Visual Studio command prompt, or after calling vcvars32.bat).
rem Each test builds inside its own directory, <dll>\<name> (the
rem fixtures are grouped by the DLL they exercise); exit code 0 is
rem success. The fixtures built on common\f2kt.h include it as
rem "../common/f2kt.h": /I .. (their group's directory) finds it.
rem Fixtures' names (build.bat dll, or build.bat threads files) rebuild
rem only those, in the order given.

setlocal
cd /d "%~dp0"

rem The `where` command does not exist on Windows 2000: search PATH
rem the old way instead.
for %%I in (cl.exe) do if "%%~$PATH:I"=="" (
    echo build.bat: cl.exe not found on PATH - run from an MSVC command prompt
    exit /b 1
)

if not "%~1"=="" goto some

call :srcsum
if errorlevel 1 exit /b 1
for %%F in (exit0 ret0 hello hellogui bare runtime memory threads sync sched files fswrite dll dllmain msgtable console spawn pipe screen lineedit ctrl lstr utility toolhelp batspawn shutparm resource winsta guiclass guiwin guigeo guimsg guipaint guidc gditext guidisp exitwin registry token hellomd crt seh fd wide strings process) do (
    call :%%F
    if errorlevel 1 exit /b 1
)
echo All tests built.
exit /b 0

rem Some fixtures (build.bat dll, build.bat threads files): every name
rem checked first, then each built in turn, stopping at the first
rem failure; the stamp tool too, when a fixture needs it and it is not
rem there (the fixtures built on common\f2kt.h stamp their source with
rem it).
:some
for %%A in (%*) do (
    call :known %%A
    if errorlevel 1 exit /b 1
)
if not exist common\srcsum.exe call :srcsum
if errorlevel 1 exit /b 1
for %%A in (%*) do (
    call :%%A
    if errorlevel 1 exit /b 1
    echo %%A built.
)
exit /b 0

rem Whether %1 names a fixture: an unknown name fails, saying so.
:known
set F2KT_ONE=
for %%F in (exit0 ret0 hello hellogui bare runtime memory threads sync sched files fswrite dll dllmain msgtable console spawn pipe screen lineedit ctrl lstr utility toolhelp batspawn shutparm resource winsta guiclass guiwin guigeo guimsg guipaint guidc gditext guidisp exitwin registry token hellomd crt seh fd wide strings process) do if /I "%%F"=="%~1" set F2KT_ONE=yes
if not defined F2KT_ONE (
    echo build.bat: no such fixture %~1
    exit /b 1
)
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

:screen
echo === screen
cd kernel32\screen
call :stamp screen.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% screen.c
if errorlevel 1 (echo build.bat: screen failed & exit /b 1)
del screen.obj
cd ..\..
goto :eof

:lineedit
echo === lineedit
cd kernel32\lineedit
call :stamp lineedit.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% lineedit.c
if errorlevel 1 (echo build.bat: lineedit failed & exit /b 1)
del lineedit.obj
cd ..\..
goto :eof

rem ctrl's companion program, ctrlkid.exe (the child its sections start),
rem builds beside it with no source stamp; both with /MD.
:ctrl
echo === ctrl
cd kernel32\ctrl
cl /nologo /MD ctrlkid.c
if errorlevel 1 (echo build.bat: ctrlkid failed & exit /b 1)
call :stamp ctrl.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% ctrl.c
if errorlevel 1 (echo build.bat: ctrl failed & exit /b 1)
del ctrl.obj ctrlkid.obj
cd ..\..
goto :eof

:utility
echo === utility
cd kernel32\utility
call :stamp utility.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% utility.c
if errorlevel 1 (echo build.bat: utility failed & exit /b 1)
del utility.obj
cd ..\..
goto :eof

rem toolhelp's companion program, thkid.exe (the child its child section
rem starts), builds beside it with no source stamp; both with /MD.
:toolhelp
echo === toolhelp
cd kernel32\toolhelp
cl /nologo /MD thkid.c
if errorlevel 1 (echo build.bat: thkid failed & exit /b 1)
call :stamp toolhelp.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% toolhelp.c
if errorlevel 1 (echo build.bat: toolhelp failed & exit /b 1)
del toolhelp.obj thkid.obj
cd ..\..
goto :eof

rem batspawn's companion program, blkid.exe (the stand-in command
rem processor its sections point ComSpec at and copy as cmd.exe), builds
rem beside it with no source stamp; both with /MD.
:batspawn
echo === batspawn
cd kernel32\batspawn
cl /nologo /MD blkid.c
if errorlevel 1 (echo build.bat: blkid failed & exit /b 1)
call :stamp batspawn.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% batspawn.c
if errorlevel 1 (echo build.bat: batspawn failed & exit /b 1)
del batspawn.obj blkid.obj
cd ..\..
goto :eof

rem shutparm's companion program, shutkid.exe (the child its child
rem section starts), builds beside it with no source stamp; both with
rem /MD.
:shutparm
echo === shutparm
cd kernel32\shutparm
cl /nologo /MD shutkid.c
if errorlevel 1 (echo build.bat: shutkid failed & exit /b 1)
call :stamp shutparm.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% shutparm.c
if errorlevel 1 (echo build.bat: shutparm failed & exit /b 1)
del shutparm.obj shutkid.obj
cd ..\..
goto :eof

rem resource's resources: rc compiles resource.rc into resource.res,
rem which links into the program, with user32 for LoadString; /MD.
:resource
echo === resource
cd kernel32\resource
for %%I in (rc.exe) do if "%%~$PATH:I"=="" (
    echo build.bat: rc.exe not found on PATH - resource needs the resource compiler
    exit /b 1
)
call :stamp resource.c
rc resource.rc
if errorlevel 1 (echo build.bat: resource's rc failed & exit /b 1)
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% resource.c resource.res user32.lib
if errorlevel 1 (echo build.bat: resource failed & exit /b 1)
del resource.obj resource.res
cd ..\..
goto :eof

:lstr
echo === lstr
cd kernel32\lstr
call :stamp lstr.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% lstr.c
if errorlevel 1 (echo build.bat: lstr failed & exit /b 1)
del lstr.obj
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

:guiclass
echo === guiclass
cd user32\guiclass
call :stamp guiclass.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guiclass.c user32.lib
if errorlevel 1 (echo build.bat: guiclass failed & exit /b 1)
del guiclass.obj
cd ..\..
goto :eof

:guiwin
echo === guiwin
cd user32\guiwin
call :stamp guiwin.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guiwin.c user32.lib
if errorlevel 1 (echo build.bat: guiwin failed & exit /b 1)
del guiwin.obj
cd ..\..
goto :eof

:guigeo
echo === guigeo
cd user32\guigeo
call :stamp guigeo.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guigeo.c user32.lib
if errorlevel 1 (echo build.bat: guigeo failed & exit /b 1)
del guigeo.obj
cd ..\..
goto :eof

:guimsg
echo === guimsg
cd user32\guimsg
call :stamp guimsg.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guimsg.c user32.lib
if errorlevel 1 (echo build.bat: guimsg failed & exit /b 1)
del guimsg.obj
cd ..\..
goto :eof

:guipaint
echo === guipaint
cd user32\guipaint
call :stamp guipaint.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guipaint.c user32.lib
if errorlevel 1 (echo build.bat: guipaint failed & exit /b 1)
del guipaint.obj
cd ..\..
goto :eof

:guidc
echo === guidc
cd gdi32\guidc
call :stamp guidc.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guidc.c user32.lib gdi32.lib
if errorlevel 1 (echo build.bat: guidc failed & exit /b 1)
del guidc.obj
cd ..\..
goto :eof

:gditext
echo === gditext
cd gdi32\gditext
call :stamp gditext.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% gditext.c gdi32.lib
if errorlevel 1 (echo build.bat: gditext failed & exit /b 1)
del gditext.obj
cd ..\..
goto :eof

:guidisp
echo === guidisp
cd user32\guidisp
call :stamp guidisp.c
cl /nologo /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% guidisp.c user32.lib gdi32.lib
if errorlevel 1 (echo build.bat: guidisp failed & exit /b 1)
del guidisp.obj
cd ..\..
goto :eof

:exitwin
echo === exitwin
cd user32\exitwin
call :stamp exitwin.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% exitwin.c user32.lib advapi32.lib
if errorlevel 1 (echo build.bat: exitwin failed & exit /b 1)
del exitwin.obj
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

:token
echo === token
cd advapi32\token
call :stamp token.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% token.c advapi32.lib
if errorlevel 1 (echo build.bat: token failed & exit /b 1)
del token.obj
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

:strings
echo === strings
cd crt\strings
call :stamp strings.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% strings.c
if errorlevel 1 (echo build.bat: strings failed & exit /b 1)
del strings.obj
cd ..\..
goto :eof

:process
echo === process
cd crt\process
call :stamp process.c
cl /nologo /MD /I .. /DF2KT_SOURCE_CRC=0x%F2KT_CRC% process.c
if errorlevel 1 (echo build.bat: process failed & exit /b 1)
del process.obj
cd ..\..
goto :eof

rem Set F2KT_CRC to the source stamp of the fixture source %1 (with the
rem shared header), from inside its directory, <dll>\<name>.
:stamp
set F2KT_CRC=
for /f %%H in ('..\..\common\srcsum.exe %1 ..\..\common\f2kt.h') do set F2KT_CRC=%%H
if "%F2KT_CRC%"=="" (echo build.bat: srcsum failed on %1 & exit /b 1)
goto :eof
