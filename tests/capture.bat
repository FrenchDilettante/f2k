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
rem (runtime console), whose output needs a console: capture those by hand
rem into the fixture's overrides.txt. Run after build.bat: the binaries it
rem builds list their sections; older ones do not.
rem
rem Each fixture runs in its own directory, <dll>\<name> (the fixtures are
rem grouped by the DLL they exercise). A fixture's name (capture.bat dll)
rem recaptures only that one.
rem
rem This file keeps CRLF line endings: cmd's label search misreads
rem LF-only batch files. Every redirection leads its command: cmd reads
rem a digit after "=" and before ">>" as a handle number, so a trailing
rem "exit code=0>> output.txt" would lose the line.

setlocal
cd /d "%~dp0"

if not "%~1"=="" goto one

call kernel32\files\setup.bat > nul

call :cap_bare
call :cap_runtime
for %%F in (memory threads sync sched files fswrite dll) do call :listed kernel32 %%F

echo Captured. Run "kernel32\runtime\runtime.exe console" in an interactive console
echo by hand, into kernel32\runtime\overrides.txt.
exit /b 0

rem One fixture (capture.bat dll): recapture only it. The files fixture
rem needs its data tree's attributes first (kernel32\files\setup.bat).
:one
set F2KT_DLL=
for %%F in (bare) do if /I "%%F"=="%~1" set F2KT_DLL=core
for %%F in (runtime memory threads sync sched files fswrite dll) do if /I "%%F"=="%~1" set F2KT_DLL=kernel32
if not defined F2KT_DLL (
    echo capture.bat: no such fixture %~1
    exit /b 1
)
if /I "%~1"=="files" call kernel32\files\setup.bat > nul
if /I "%~1"=="bare" (
    call :cap_bare
    goto done
)
if /I "%~1"=="runtime" (
    call :cap_runtime
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
