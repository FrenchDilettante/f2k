@echo off
rem batpext - the search for a command through the extensions PATHEXT
rem lists, between batpext1.bat and batpext1.cmd, which the script
rem writes itself (each prints its own name and the name it was called
rem by): the name alone with PATHEXT as cmd.exe found it, with .CMD
rem before .BAT, unset, with .CMD alone (and the name given with .bat,
rem outside it), and with .EXE alone; a name with an extension PATHEXT
rem does not list, nothing of that name there. Then batpext2.bat in a
rem subdirectory, found through a quoted PATH entry among empty ones,
rem and not found with PATH unset. The script deletes its files and the
rem subdirectory at its start and end.
set BATPEXTS=%PATHEXT%
set BATPEXTP=%PATH%
del batpext1.bat > nul 2> nul
del batpext1.cmd > nul 2> nul
del batpextd\batpext2.bat > nul 2> nul
rd batpextd > nul 2> nul
> batpext1.bat echo @echo batpext1.bat ran as [%%0]
> batpext1.cmd echo @echo batpext1.cmd ran as [%%0]
call batpext1
set PATHEXT=.CMD;.BAT
call batpext1
set PATHEXT=
call batpext1
set PATHEXT=.CMD
call batpext1
call batpext1.bat
set PATHEXT=.EXE
call batpext1
echo ERRORLEVEL %ERRORLEVEL%
set PATHEXT=%BATPEXTS%
call batpext1.f2k
echo ERRORLEVEL %ERRORLEVEL%
md batpextd
> batpextd\batpext2.bat echo @echo batpext2.bat ran as [%%0]
set PATH=;"%CD%\batpextd";;%BATPEXTP%
call batpext2
set PATH=
call batpext2
echo ERRORLEVEL %ERRORLEVEL%
set PATH=%BATPEXTP%
del batpext1.bat
del batpext1.cmd
del batpextd\batpext2.bat
rd batpextd
