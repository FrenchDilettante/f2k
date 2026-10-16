@echo off
rem Rebuild every corpus test with the era toolchain. Run from a
rem command prompt with the MSVC 6 compiler on PATH (for example the
rem Visual Studio command prompt, or after calling vcvars32.bat).
rem Each test builds inside its own directory; exit code 0 is success.

setlocal
cd /d "%~dp0"

rem The `where` command does not exist on Windows 2000: search PATH
rem the old way instead.
for %%I in (cl.exe) do if "%%~$PATH:I"=="" (
    echo build.bat: cl.exe not found on PATH - run from an MSVC command prompt
    exit /b 1
)

echo === exit0
cd exit0
cl /nologo exit0.c /link /NODEFAULTLIB /ENTRY:ExitMain /SUBSYSTEM:CONSOLE kernel32.lib
if errorlevel 1 (echo build.bat: exit0 failed & exit /b 1)
del exit0.obj
cd ..

echo === ret0
cd ret0
cl /nologo ret0.c
if errorlevel 1 (echo build.bat: ret0 failed & exit /b 1)
del ret0.obj
cd ..

echo === hello
cd hello
cl /nologo hello.c
if errorlevel 1 (echo build.bat: hello failed & exit /b 1)
del hello.obj
cd ..

echo === hellogui
cd hellogui
cl /nologo hellogui.c user32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup
if errorlevel 1 (echo build.bat: hellogui failed & exit /b 1)
del hellogui.obj
cd ..

echo === thread
cd thread
cl /nologo thread.c
if errorlevel 1 (echo build.bat: thread failed & exit /b 1)
del thread.obj
cd ..

echo === pingpong
cd pingpong
cl /nologo pingpong.c
if errorlevel 1 (echo build.bat: pingpong failed & exit /b 1)
del pingpong.obj
cd ..

echo === sleep
cd sleep
cl /nologo sleep.c
if errorlevel 1 (echo build.bat: sleep failed & exit /b 1)
del sleep.obj
cd ..

echo === spin
cd spin
cl /nologo spin.c
if errorlevel 1 (echo build.bat: spin failed & exit /b 1)
del spin.obj
cd ..

echo === suspend
cd suspend
cl /nologo suspend.c
if errorlevel 1 (echo build.bat: suspend failed & exit /b 1)
del suspend.obj
cd ..

echo === respawn
cd respawn
cl /nologo respawn.c
if errorlevel 1 (echo build.bat: respawn failed & exit /b 1)
del respawn.obj
cd ..

echo === fileio
cd fileio
cl /nologo fileio.c
if errorlevel 1 (echo build.bat: fileio failed & exit /b 1)
del fileio.obj
cd ..

echo === bare
cd bare
cl /nologo bare.c /link /NODEFAULTLIB /ENTRY:BareMain /SUBSYSTEM:CONSOLE kernel32.lib
if errorlevel 1 (echo build.bat: bare failed & exit /b 1)
del bare.obj
cd ..

echo === runtime
cd runtime
cl /nologo runtime.c
if errorlevel 1 (echo build.bat: runtime failed & exit /b 1)
del runtime.obj
cd ..

echo === memory
cd memory
cl /nologo memory.c
if errorlevel 1 (echo build.bat: memory failed & exit /b 1)
del memory.obj
cd ..

echo === threads
cd threads
cl /nologo /MT threads.c
if errorlevel 1 (echo build.bat: threads failed & exit /b 1)
del threads.obj
cd ..

echo === sync
cd sync
cl /nologo /MT sync.c
if errorlevel 1 (echo build.bat: sync failed & exit /b 1)
del sync.obj
cd ..

echo === sched
cd sched
cl /nologo /MT sched.c
if errorlevel 1 (echo build.bat: sched failed & exit /b 1)
del sched.obj
cd ..

echo === files
cd files
cl /nologo files.c
if errorlevel 1 (echo build.bat: files failed & exit /b 1)
del files.obj
cd ..

echo === fswrite
cd fswrite
cl /nologo fswrite.c
if errorlevel 1 (echo build.bat: fswrite failed & exit /b 1)
del fswrite.obj
cd ..

echo All tests built.
exit /b 0
