@echo off
rem Capture the real-machine output of the sectioned corpus fixtures.
rem
rem Run from a command prompt after build.bat, from a FAT32 volume where
rem possible (see kernel32\files\files.c). Every section runs as its own
rem process, as the F2K suite runs it; each fixture's output.txt collects
rem blocks of
rem
rem   >>> <command line>
rem   <the program's output>
rem   <<< exit code=<ERRORLEVEL>
rem
rem ERRORLEVEL is signed: an NTSTATUS exit code such as 0xC0000005 shows as
rem -1073741819. Each output.txt starts with a provenance header (the OS
rem build, the machine, the date, and the source stamp the binary carries,
rem see common\f2kt.h), which the parser skips.
rem
rem The fixtures built on common\f2kt.h list their own sections
rem (<fixture>.exe --list): every one is captured but the interactive ones
rem (runtime console, ctrl keys), whose output needs a console or keys
rem pressed: capture those by hand into the fixture's overrides.txt. Run
rem after build.bat: the binaries it builds list their sections; older
rem ones do not.
rem
rem Each fixture runs in its own directory, <dll>\<name> (the fixtures are
rem grouped by the DLL they exercise). Fixtures' names (capture.bat dll,
rem or capture.bat threads files) recapture only those, in the order
rem given.
rem
rem The script fixtures, cmd\<name>\<name>.cmd, are captured the same way:
rem each is one block, "cmd /c <name>.cmd" run from its own directory,
rem with command extensions on (see :script).
rem
rem This file keeps CRLF line endings: cmd's label search misreads
rem LF-only batch files. Every redirection leads its command: cmd reads
rem a digit after "=" and before ">>" as a handle number, so a trailing
rem "exit code=0>> output.txt" would lose the line.

setlocal
cd /d "%~dp0"

if not "%~1"=="" goto some

call kernel32\files\setup.bat > nul

call :cap_bare
call :cap_runtime
for %%F in (memory threads sync sched files fswrite dll dllmain msgtable console) do call :listed kernel32 %%F
call :cap_spawn
call :listed kernel32 pipe
for %%F in (screen lineedit ctrl lstr utility toolhelp batspawn shutparm resource profile threx vmedge startup lcid ntquery) do call :listed kernel32 %%F
call :listed user32 winsta
for %%F in (guiclass guiwin guigeo guimsg guipaint guidisp) do call :listed user32 %%F
call :listed user32 exitwin
call :listed user32 endsess
for %%F in (dialog wndlong wintext focus controls menus accel coords keyinput mousein clipbrd wsprintf rects chars props wintree scroll caret editctl) do call :listed user32 %%F
for %%F in (guidc gditext ttfont bitmaps mapmode shapes) do call :listed gdi32 %%F
for %%F in (registry token) do call :listed advapi32 %%F
call :cap_hellomd
call :cap_crt
for %%F in (seh fd wide process strings msvcrt) do call :listed crt %%F
for %%F in (batecho batset batlevel batexit batcd batver battype batredir batcall batcode batclr batpext batdyn batquot batstd batops batline bathelp batdir) do call :script %%F

echo Captured. Run "kernel32\runtime\runtime.exe console" in an interactive console
echo by hand, into kernel32\runtime\overrides.txt, and "kernel32\ctrl\ctrl.exe keys"
echo with its keys pressed, into kernel32\ctrl\overrides.txt.
exit /b 0

rem Some fixtures (capture.bat dll, capture.bat threads files): every
rem name checked first, then each recaptured in turn.
:some
for %%A in (%*) do (
    call :group %%A
    if errorlevel 1 exit /b 1
)
for %%A in (%*) do call :one %%A
exit /b 0

rem The DLL group of fixture %1, into F2KT_DLL: an unknown name fails,
rem saying so.
:group
set F2KT_DLL=
for %%F in (bare) do if /I "%%F"=="%~1" set F2KT_DLL=core
for %%F in (runtime memory threads sync sched files fswrite dll dllmain msgtable console spawn pipe screen lineedit ctrl lstr utility toolhelp batspawn shutparm resource profile threx vmedge startup lcid ntquery) do if /I "%%F"=="%~1" set F2KT_DLL=kernel32
for %%F in (winsta guiclass guiwin guigeo guimsg guipaint guidisp exitwin endsess dialog wndlong wintext focus controls menus accel coords keyinput mousein clipbrd wsprintf rects chars props wintree scroll caret editctl) do if /I "%%F"=="%~1" set F2KT_DLL=user32
for %%F in (guidc gditext ttfont bitmaps mapmode shapes) do if /I "%%F"=="%~1" set F2KT_DLL=gdi32
for %%F in (registry token) do if /I "%%F"=="%~1" set F2KT_DLL=advapi32
for %%F in (hellomd crt seh fd wide process strings msvcrt) do if /I "%%F"=="%~1" set F2KT_DLL=crt
for %%F in (batecho batset batlevel batexit batcd batver battype batredir batcall batcode batclr batpext batdyn batquot batstd batops batline bathelp batdir) do if /I "%%F"=="%~1" set F2KT_DLL=cmd
if not defined F2KT_DLL (
    echo capture.bat: no such fixture %~1
    exit /b 1
)
exit /b 0

rem One fixture (capture.bat dll): recapture it. The files fixture needs
rem its data tree's attributes first (kernel32\files\setup.bat).
:one
call :group %1
if /I "%~1"=="files" call kernel32\files\setup.bat > nul
if /I "%~1"=="bare" (
    call :cap_bare
    goto done
)
if /I "%~1"=="runtime" (
    call :cap_runtime
    goto done
)
if /I "%~1"=="spawn" (
    call :cap_spawn
    goto done
)
if /I "%~1"=="hellomd" (
    call :cap_hellomd
    goto done
)
if /I "%~1"=="crt" (
    call :cap_crt
    goto done
)
if /I "%F2KT_DLL%"=="cmd" (
    call :script %~1
    goto done
)
call :listed %F2KT_DLL% %~1
:done
echo Captured %~1.
exit /b 0

rem Capture bare: no section table, so the script lists its modes.
:cap_bare
call :fixture core bare nostamp
call :cap bare.exe
call :cap bare.exe
for %%M in (ret exit-code badptr data-exec null-write null-read null-call rdata-write code-write kernel-read kernel-write div-zero ud2 int3 hlt cli io-in into stack-overflow) do call :cap bare.exe %%M
cd ..\..
goto :eof

rem Capture runtime: its args block takes its own arguments, the rest their list.
:cap_runtime
call :fixture kernel32 runtime
>> output.txt echo ^>^>^> runtime.exe args one "two words" back\slash "tail\\" x
>> output.txt 2>&1 runtime.exe args one "two words" back\slash "tail\\" x
>> output.txt echo ^<^<^< exit code=%ERRORLEVEL%
call :sections runtime.exe args
cd ..\..
goto :eof

rem Capture spawn: its overlay block replaces the program with a child,
rem which still runs once the program has ended; wait for it (ping as a
rem two-second sleep: Windows 2000 has no timeout command) before the
rem block's last line, so the child's output lands inside the block.
:cap_spawn
call :fixture kernel32 spawn
call :sections spawn.exe overlay
>> output.txt echo ^>^>^> spawn.exe overlay
>> output.txt 2>&1 spawn.exe overlay
set F2KT_RC=%ERRORLEVEL%
ping -n 3 127.0.0.1 > nul
>> output.txt echo ^<^<^< exit code=%F2KT_RC%
cd ..\..
goto :eof

rem Capture hellomd: hello built with /MD, no sections and no stamp.
:cap_hellomd
call :fixture crt hellomd nostamp
call :cap hellomd.exe
cd ..\..
goto :eof

rem Capture crt: its args block takes its own arguments (__getmainargs'
rem quoting rules), the rest their list.
:cap_crt
call :fixture crt crt
>> output.txt echo ^>^>^> crt.exe args one "two words" back\slash "tail\\" a\\\"b "q\"uote" "" x"y z"w
>> output.txt 2>&1 crt.exe args one "two words" back\slash "tail\\" a\\\"b "q\"uote" "" x"y z"w
>> output.txt echo ^<^<^< exit code=%ERRORLEVEL%
call :sections crt.exe args
cd ..\..
goto :eof

rem Enter a fixture's directory, %1\%2 (its DLL's, its name), and start its
rem output.txt afresh, with the provenance header ("nostamp" as %3: the
rem binary has no source stamp).
:fixture
echo === %2
cd %1\%2
if exist output.txt del output.txt
>> output.txt echo # F2K capture of %2 (tests\capture.bat)
>> output.txt ver
>> output.txt echo # machine: %COMPUTERNAME%, %PROCESSOR_IDENTIFIER%, %NUMBER_OF_PROCESSORS% CPU(s)
>> output.txt echo # date: %DATE% %TIME%
if not "%3"=="nostamp" >> output.txt %2.exe --source
goto :eof

rem Capture a fixture built on common\f2kt.h, %2 in %1\%2: every section it
rem lists.
:listed
call :fixture %1 %2
call :sections %2.exe
cd ..\..
goto :eof

rem Capture a script fixture, cmd\%1\%1.cmd: one block, the script run by
rem a cmd.exe of its own (cmd /c, as F2K's harness runs it) from its
rem directory, its standard output and error into output.txt in order.
rem spawnkid.exe, the spawn fixture's companion, is copied beside it for
rem the run and deleted after: on F2K the scripts run from \CORPUS, where
rem it sits. Nothing is captured unless command extensions are on.
:script
call :extensions
if errorlevel 1 goto :eof
call :fixture cmd %1 nostamp
copy ..\..\kernel32\spawn\spawnkid.exe . > nul
call :cap cmd /c %1.cmd
del spawnkid.exe
cd ..\..
goto :eof

rem Whether a cmd.exe started afresh, as each script's is, runs with
rem command extensions on, Windows 2000's default (no EnableExtensions of
rem 0 under HKLM's or HKCU's Software\Microsoft\Command Processor): only
rem then does it expand CMDEXTVERSION. for /f runs its command by such a
rem cmd.exe. The scripts also expect no AutoRun command there.
:extensions
set F2KT_EXT=
for /f %%V in ('echo %%CMDEXTVERSION%%') do set F2KT_EXT=%%V
if not "%F2KT_EXT%"=="%%CMDEXTVERSION%%" if not "%F2KT_EXT%"=="" exit /b 0
echo capture.bat: cmd.exe starts with command extensions off (EnableExtensions
echo under Software\Microsoft\Command Processor): the scripts are captured
echo with them on, Windows 2000's default.
exit /b 1

rem Capture every section %1 lists (%1 --list), but the interactive ones
rem and the one named %2 (captured by the caller with its own arguments).
:sections
set F2KT_SKIP=%2
for /f "tokens=1,2" %%S in ('%1 --list') do if "%%T"=="" if not "%%S"=="%F2KT_SKIP%" call :cap %1 %%S
goto :eof

rem Run one command line, appending its block to output.txt.
:cap
>> output.txt echo ^>^>^> %*
>> output.txt 2>&1 %*
>> output.txt echo ^<^<^< exit code=%ERRORLEVEL%
goto :eof
