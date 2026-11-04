@echo off
rem batdyn - the dynamic variables in forms that hold on any machine:
rem CMDEXTVERSION; RANDOM, whether it is a number from 0 to 32767;
rem CMDCMDLINE, the command line of the cmd.exe running the script (the
rem name it was started by, masked); the separators in TIME and DATE and
rem their lengths; ERRORLEVEL and CD shadowed by real variables of those
rem names, and after the variables are removed. Then substrings counted
rem from either end, replacements in a value (a word, a word in other
rem case, everything up to a word, and a letter removed), a substring
rem of an undefined variable, and a percent sign with no other after it.
rem Then substrings at the value's edges (a count of 0, offsets and
rem counts past either end, a hexadecimal offset, a letter for one);
rem set's argument: a name with blanks after it (the variable at the
rem line's end expanding to nothing), an empty name, a quote with no
rem closing one and text after a closing one; and a variable under a
rem 300-character name, expanded by batdyn1.cmd, which the script writes
rem with that name in it and deletes at its start and end, and listed
rem by set (its ERRORLEVEL).
set ERRORLEVEL=
set CD=
set BATDYNZ=
del batdyn1.cmd > nul 2> nul
echo CMDEXTVERSION [%CMDEXTVERSION%]
set BATDYNR=%RANDOM%
set BATDYNV=no
set /a BATDYNN=%BATDYNR%+0
if "%BATDYNN%"=="%BATDYNR%" if %BATDYNR% GEQ 0 if %BATDYNR% LEQ 32767 set BATDYNV=yes
echo RANDOM a number from 0 to 32767: %BATDYNV%
echo CMDCMDLINE [%CMDCMDLINE%]
echo TIME separators [%TIME:~2,1%%TIME:~5,1%%TIME:~8,1%] past 11 [%TIME:~11%]
echo DATE separators [%DATE:~3,1%%DATE:~6,1%%DATE:~9,1%] past 14 [%DATE:~14%]
spawnkid exit 3
set ERRORLEVEL=42
spawnkid exit 4
echo ERRORLEVEL with a variable of that name [%ERRORLEVEL%]
if errorlevel 4 echo if errorlevel 4: yes
if not errorlevel 4 echo if errorlevel 4: no
set ERRORLEVEL=
echo ERRORLEVEL with the variable removed [%ERRORLEVEL%]
set CD=batdyn
echo CD with a variable of that name [%CD%]
set CD=
echo CD with the variable removed, its second character [%CD:~1,1%]
set BATDYNS=one two three
echo [%BATDYNS:~-5%] [%BATDYNS:~4,3%] [%BATDYNS:~-5,2%] [%BATDYNS:~0,-6%]
echo [%BATDYNS:two=2%] [%BATDYNS:ONE=1%] [%BATDYNS:*two=X%] [%BATDYNS:o=%]
echo [%BATDYNS:~0,0%] [%BATDYNS:~-100%] [%BATDYNS:~5,-100%] [%BATDYNS:~100%] [%BATDYNS:~-100,3%]
echo hexadecimal offset [%BATDYNS:~0x4%]
echo letter for an offset [%BATDYNS:~a%]
spawnkid exit 3
set BATDYNS   %BATDYNZ%
echo set BATDYNS with blanks after it: %ERRORLEVEL%
spawnkid exit 3
set =x
echo set =x: %ERRORLEVEL%
set "BATDYNQ=a b
echo no closing quote [%BATDYNQ%]
set "BATDYNQ=c d" e
echo text after the closing quote [%BATDYNQ%]
set BATDYNL=BATDYNLONG
set BATDYNL=%BATDYNL%%BATDYNL%%BATDYNL%%BATDYNL%%BATDYNL%%BATDYNL%%BATDYNL%%BATDYNL%%BATDYNL%%BATDYNL%
set BATDYNL=%BATDYNL%%BATDYNL%%BATDYNL%
set %BATDYNL%=a value under a 300-character name
> batdyn1.cmd echo @echo 300-character name [%%%BATDYNL%%%]
call batdyn1
spawnkid exit 3
set %BATDYNL% > nul
echo set of the 300-character name: %ERRORLEVEL%
set %BATDYNL%=
echo undefined [%BATDYNNO:~0,2%]
echo 50% off
del batdyn1.cmd
