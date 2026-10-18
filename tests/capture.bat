@echo off
rem Capture the real-machine output of the sectioned corpus fixtures.
rem
rem Run from a command prompt after build.bat, from a FAT32 volume where
rem possible (see files\files.c). Every section runs as its own process,
rem as the F2K suite runs it; each fixture's output.txt collects blocks of
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
rem This file keeps CRLF line endings: cmd's label search misreads
rem LF-only batch files. Every redirection leads its command: cmd reads
rem a digit after "=" and before ">>" as a handle number, so a trailing
rem "exit code=0>> output.txt" would lose the line.

setlocal
cd /d "%~dp0"

call files\setup.bat > nul

call :fixture bare nostamp
call :cap bare.exe
call :cap bare.exe
for %%M in (ret exit-code badptr data-exec null-write null-read null-call rdata-write code-write kernel-read kernel-write div-zero ud2 int3 hlt cli io-in into stack-overflow) do call :cap bare.exe %%M
cd ..

call :fixture runtime
>> output.txt echo ^>^>^> runtime.exe args one "two words" back\slash "tail\\" x
>> output.txt 2>&1 runtime.exe args one "two words" back\slash "tail\\" x
>> output.txt echo ^<^<^< exit code=%ERRORLEVEL%
call :sections runtime.exe args
cd ..

for %%F in (memory threads sync sched files fswrite) do call :listed %%F

echo Captured. Run "runtime\runtime.exe console" in an interactive console by hand,
echo into runtime\overrides.txt.
exit /b 0

rem Enter a fixture's directory and start its output.txt afresh, with the
rem provenance header ("nostamp" as %2: the binary has no source stamp).
:fixture
echo === %1
cd %1
if exist output.txt del output.txt
>> output.txt echo # F2K capture of %1 (tests\capture.bat)
>> output.txt ver
>> output.txt echo # machine: %COMPUTERNAME%, %PROCESSOR_IDENTIFIER%, %NUMBER_OF_PROCESSORS% CPU(s)
>> output.txt echo # date: %DATE% %TIME%
if not "%2"=="nostamp" >> output.txt %1.exe --source
goto :eof

rem Capture a fixture built on common\f2kt.h: every section it lists.
:listed
call :fixture %1
call :sections %1.exe
cd ..
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
