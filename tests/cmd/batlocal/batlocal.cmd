@echo off
rem batlocal - setlocal and endlocal: a variable changed, added and deleted
rem and put back, setlocals nested, endlocal and set on one line, endlocal
rem without a setlocal, the current directory put back, a called label's
rem setlocal ended with it, an endlocal in a called label leaving its
rem caller's, a called batch file's setlocal left open, setlocal's ERRORLEVEL
rem (no argument, a known one, two, an unknown one; endlocal's), 33 setlocals
rem in one batch file (in a cmd.exe of its own), and setlocal and endlocal
rem outside a batch file (cmd /c).
if not "%~1"=="" goto %~1
if exist batlocal.d\batlocal.tag del batlocal.d\batlocal.tag
if exist batlocal.d rd batlocal.d
if exist batlocl.cmd del batlocl.cmd
set BATLOCA=outer
set BATLOCB=
set BATLOCC=
echo == setlocal and endlocal
setlocal
set BATLOCA=inner
set BATLOCB=new
echo inside: [%BATLOCA%] [%BATLOCB%]
endlocal
echo after endlocal: [%BATLOCA%] [%BATLOCB%]
setlocal
set BATLOCA=
echo deleted inside: [%BATLOCA%]
endlocal
echo after endlocal: [%BATLOCA%]
echo == nested
setlocal
set BATLOCA=one
setlocal
set BATLOCA=two
endlocal
echo after one endlocal: [%BATLOCA%]
endlocal
echo after the second: [%BATLOCA%]
echo == endlocal and set on one line
setlocal
set BATLOCB=carried
endlocal & set BATLOCB=%BATLOCB%
echo carried out: [%BATLOCB%]
set BATLOCB=
echo == endlocal without a setlocal
endlocal
echo still: [%BATLOCA%]
echo == the current directory
md batlocal.d
echo tag> batlocal.d\batlocal.tag
setlocal
cd batlocal.d
if exist batlocal.tag (echo inside: in batlocal.d) else echo inside: not in batlocal.d
endlocal
if exist batlocal.tag (echo after endlocal: in batlocal.d) else echo after endlocal: not in batlocal.d
del batlocal.d\batlocal.tag
rd batlocal.d
echo == a called label's setlocal ends with it
call :sub
echo after the call: [%BATLOCA%] [%BATLOCC%]
echo == an endlocal in a called label leaves its caller's setlocal
setlocal
set BATLOCA=caller
call :ender
echo after the call: [%BATLOCA%]
endlocal
echo after endlocal: [%BATLOCA%]
echo == a called batch file's setlocal left open
> batlocl.cmd echo @setlocal
>> batlocl.cmd echo @set BATLOCA=from the called file
call batlocl.cmd
echo after the called file: [%BATLOCA%]
del batlocl.cmd
echo == setlocal's errorlevel
cmd /c exit 5
setlocal
echo no argument: %ERRORLEVEL%
endlocal
setlocal enableextensions
echo enableextensions: %ERRORLEVEL%
endlocal
cmd /c exit 5
setlocal ENABLEDELAYEDEXPANSION DISABLEDELAYEDEXPANSION
echo two arguments: %ERRORLEVEL%
endlocal
setlocal bogus
echo an unknown argument: %ERRORLEVEL%
set BATLOCA=set after the unknown argument
endlocal
echo after endlocal: [%BATLOCA%]
cmd /c exit 5
setlocal
cmd /c exit 6
endlocal
echo endlocal keeps: %ERRORLEVEL%
echo == 33 setlocals
cmd /c batlocal.cmd deep
echo exit code %ERRORLEVEL%
echo == outside a batch file
cmd /c setlocal bogus
echo exit code %ERRORLEVEL%
cmd /c "set BATLOCD=x& setlocal& set BATLOCD=y& endlocal& set BATLOCD"
echo exit code %ERRORLEVEL%
goto :eof

:sub
setlocal
set BATLOCA=in the label
set BATLOCC=the label's
echo in the label: [%BATLOCA%] [%BATLOCC%]
goto :eof

:ender
endlocal
echo in the label after endlocal: [%BATLOCA%]
goto :eof

:deep
set BATLOCN=0
for /l %%i in (1,1,33) do set BATLOCN=%%i& setlocal
echo after 33: [%BATLOCN%]
endlocal
echo after an endlocal: [%BATLOCN%]
goto :eof
