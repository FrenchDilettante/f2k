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

echo === bsscheck
cd bsscheck
cl /nologo bsscheck.c /link /NODEFAULTLIB /ENTRY:BssMain /SUBSYSTEM:CONSOLE kernel32.lib
if errorlevel 1 (echo build.bat: bsscheck failed & exit /b 1)
del bsscheck.obj
cd ..

echo === crash
cd crash
cl /nologo crash.c /link /NODEFAULTLIB /ENTRY:CrashMain /SUBSYSTEM:CONSOLE
if errorlevel 1 (echo build.bat: crash failed & exit /b 1)
del crash.obj
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

echo All tests built.
exit /b 0
