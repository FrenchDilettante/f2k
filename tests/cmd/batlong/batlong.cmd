@echo off
rem batlong - commands longer than a line. Windows 2000's cmd.exe reads a
rem batch file's line, once expanded, into 2,047 characters (batline shows
rem its edge); a cmd /c string, a for's body once its variable is
rem substituted and call's second expansion each have bounds of their
rem own. Every command is built from BATLONGZ, a thousand zeros: spawnkid
rem exit 000...07 exits with 7 when its whole number reaches it, and a set
rem value's characters past 2,995 or 7,995 show whether it was cut. A
rem refused line prints "The input line is too long." and ends the batch
rem file, so those cases run in a cmd.exe of their own: this script again,
rem given the case's label.
if not "%~1"=="" goto %~1
set BATLONGZ=0000000000
set BATLONGZ=%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%
set BATLONGZ=%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%
echo == cmd /c strings
cmd /c spawnkid exit %%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%7
echo 3000 characters: exit code %ERRORLEVEL%
cmd /c spawnkid exit %%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%7
echo 8000 characters: exit code %ERRORLEVEL%
echo == set in a batch file
cmd /c batlong.cmd set3
echo 3000 characters: exit code %ERRORLEVEL%
cmd /c batlong.cmd set8
echo 8000 characters: exit code %ERRORLEVEL%
echo == a for's body
cmd /c batlong.cmd for3
echo 3000 characters: exit code %ERRORLEVEL%
cmd /c batlong.cmd for8
echo 8000 characters: exit code %ERRORLEVEL%
echo == call's second expansion
cmd /c batlong.cmd call3
echo 3000 characters: exit code %ERRORLEVEL%
cmd /c batlong.cmd call8
echo 8000 characters: exit code %ERRORLEVEL%
goto :eof

:set3
set BATLONGR=%BATLONGZ%%BATLONGZ%%BATLONGZ%7
echo ran: the value ends [%BATLONGR:~-6%], past 2995 [%BATLONGR:~2995%]
goto :eof

:set8
set BATLONGR=%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%%BATLONGZ%7
echo ran: the value ends [%BATLONGR:~-6%], past 7995 [%BATLONGR:~7995%]
goto :eof

:for3
for %%a in (%BATLONGZ%) do set BATLONGR=%%a%%a%%a7
echo ran: the value ends [%BATLONGR:~-6%], past 2995 [%BATLONGR:~2995%]
goto :eof

:for8
for %%a in (%BATLONGZ%) do set BATLONGR=%%a%%a%%a%%a%%a%%a%%a%%a7
echo ran: the value ends [%BATLONGR:~-6%], past 7995 [%BATLONGR:~7995%]
goto :eof

:call3
call set BATLONGR=%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%7
echo ran: the value ends [%BATLONGR:~-6%], past 2995 [%BATLONGR:~2995%]
goto :eof

:call8
call set BATLONGR=%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%%%BATLONGZ%%7
echo ran: the value ends [%BATLONGR:~-6%], past 7995 [%BATLONGR:~7995%]
goto :eof
