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
rem -1073741819. Named-only sections that need an interactive console
rem (runtime console) are not captured here: run them by hand.
rem
rem This file keeps CRLF line endings: cmd's label search misreads
rem LF-only batch files.

setlocal
cd /d "%~dp0"

call files\setup.bat > nul

call :fixture bare
call :cap bare.exe
call :cap bare.exe
for %%M in (ret exit-code badptr data-exec null-write null-read null-call rdata-write code-write kernel-read kernel-write div-zero ud2 int3 hlt cli io-in into stack-overflow) do call :cap bare.exe %%M
cd ..

call :fixture runtime
echo ^>^>^> runtime.exe args one "two words" back\slash "tail\\" x>> output.txt
runtime.exe args one "two words" back\slash "tail\\" x>> output.txt 2>&1
echo ^<^<^< exit code=%ERRORLEVEL%>> output.txt
for %%S in (version module teb lasterror env locale crt seh unhandled exit) do call :cap runtime.exe %%S
cd ..

call :fixture memory
for %%S in (sysinfo malloc heap local virtual protect image mapping stack) do call :cap memory.exe %%S
cd ..

call :fixture threads
for %%S in (create exit suspend priority scale tls perthread crt mainexit procexit) do call :cap threads.exe %%S
cd ..

call :fixture sync
for %%S in (event semaphore mutex waitmulti apc critsec interlocked handles pingpong) do call :cap sync.exe %%S
cd ..

call :fixture sched
for %%S in (sleep clock timer rr preempt yield boost freeze starve) do call :cap sched.exe %%S
cd ..

call :fixture files
for %%S in (open read seek meta find handles crt mapping concurrent) do call :cap files.exe %%S
cd ..

call :fixture fswrite
for %%S in (create write share names dirs times crt) do call :cap fswrite.exe %%S
cd ..

echo Captured. Run "runtime\runtime.exe console" in an interactive console by hand.
exit /b 0

rem Enter a fixture's directory and start its output.txt afresh.
:fixture
echo === %1
cd %1
if exist output.txt del output.txt
goto :eof

rem Run one command line, appending its block to output.txt.
:cap
echo ^>^>^> %*>> output.txt
%* >> output.txt 2>&1
echo ^<^<^< exit code=%ERRORLEVEL%>> output.txt
goto :eof
