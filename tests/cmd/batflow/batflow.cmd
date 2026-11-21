@echo off
rem batflow - the control flow tests/core/test_cmd_flow.py holds against
rem expectations written by hand, captured: goto ahead and back, call
rem :label with arguments, shift and exit /b, call from a for loop, for /l,
rem for /f over a string and a command, %%~nx and %%~x, if exist and if not
rem exist with else and a block over several lines, nested if /i and GTR,
rem if defined, if errorlevel, if cmdextversion; for at cmd /c's rules; a
rem chain of 40 batch files each run without call. Then what that test
rem never ran: for over wildcards, with none matching and with no wildcard,
rem for /d and for /r, for /f over a file (skip=, eol=, tokens=, usebackq
rem over a quoted name, a command and a string), goto and call to a label
rem that does not exist, call :label outside a batch file, and echo ) in
rem and out of blocks. The chain, which never returns, and the missing
rem labels, which end a batch file, run in a cmd.exe of their own: this
rem script again, given the case's label.
if not "%~1"=="" goto %~1
rd /s /q batflow.d > nul 2> nul
del batflow.txt "batflow d.txt" batflowc.cmd > nul 2> nul
set BATFLOWN=
goto :start
echo never
:again
set BATFLOWN=%BATFLOWN%x
if not "%BATFLOWN%"=="xxx" goto again
echo looped %BATFLOWN%
goto :tests
:start
echo started
goto again
:tests
call :sub one "two three"
echo back %errorlevel%
for %%a in (a b) do call :sub %%a
for /l %%i in (1,2,5) do echo l%%i
for /f "tokens=1,3* delims=," %%a in ("x,y,z,w,v") do echo f [%%a] [%%b] [%%c]
for %%f in (batflow.cmd) do echo %%~nxf %%~xf
if exist batflow.cmd (echo exists) else echo missing
if not exist batflow-nope.cmd (
  echo not there

  echo two lines
) else (
  echo never
)
if /i ABC==abc if 10 GTR 9 echo nested
if defined BATFLOWN (echo defined) else echo undefined
if errorlevel 4 echo four or more
if cmdextversion 2 echo extensions
for /f %%v in ('echo piped out') do echo command [%%v]
echo == for at cmd /c's rules
cmd /c for %%a in (1 2) do @echo %%a ^& echo end
echo exit code %ERRORLEVEL%
echo == a chain of 40 batch files
> batflowc.cmd echo @echo off
>> batflowc.cmd echo if "%%1"=="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" goto done
>> batflowc.cmd echo batflowc %%1x
>> batflowc.cmd echo :done
>> batflowc.cmd echo echo chained %%1
cmd /c batflow.cmd chain
echo exit code %ERRORLEVEL%
echo == for over names
md batflow.d
md batflow.d\sub
> batflow.d\one.txt echo x
> batflow.d\three.dat echo x
> batflow.d\sub\two.txt echo x
for %%f in (batflow.d\*.txt) do echo wildcard [%%f]
for %%f in (batflow.d\*.none) do echo never: [%%f]
for %%f in (batflow.d\nosuch.txt) do echo no wildcard [%%f]
for %%f in (batflow.d\*.txt;batflow.d\*.dat) do echo two patterns [%%f]
for /d %%d in (batflow.d\s*) do echo directory [%%d]
for /d %%d in (batflow.d\*.txt) do echo never: [%%d]
for /r batflow.d %%f in (*.txt) do echo recursive [%%~nxf]
for /r batflow.d %%f in (two.txt) do if exist "%%f" (echo recursive, no wildcard [%%~nxf]: exists) else echo recursive, no wildcard [%%~nxf]: missing
echo == for /f over a file
> batflow.txt echo header line
>> batflow.txt echo #a comment
>> batflow.txt echo one two
>> batflow.txt echo.
>> batflow.txt echo ;semicolon
>> batflow.txt echo three
for /f %%a in (batflow.txt) do echo default [%%a]
for /f "skip=1" %%a in (batflow.txt) do echo skip=1 [%%a]
for /f "eol=# tokens=*" %%a in (batflow.txt) do echo eol=# [%%a]
for /f "tokens=2" %%a in (batflow.txt) do echo tokens=2 [%%a]
copy batflow.txt "batflow d.txt" > nul
for /f "usebackq skip=2" %%a in ("batflow d.txt") do echo usebackq file [%%a]
for /f "usebackq" %%a in (`echo back quoted`) do echo usebackq command [%%a]
for /f "usebackq" %%a in ('a literal string') do echo usebackq string [%%a]
for /f %%a in (batflow-nope.txt) do echo never: [%%a]
echo ERRORLEVEL %ERRORLEVEL%
echo == missing labels
cmd /c batflow.cmd nogoto
echo exit code %ERRORLEVEL%
cmd /c batflow.cmd nocall
echo exit code %ERRORLEVEL%
cmd /c call :batflow_nolabel
echo exit code %ERRORLEVEL%
echo == echo )
echo )
echo a ) b
(
echo inside a block
echo ^)
)
(echo one line & echo ^))
if 1==1 (echo in an if: ^)) else echo never
rd /s /q batflow.d
del batflow.txt "batflow d.txt" batflowc.cmd
goto :eof

:sub
echo sub [%0] [%1] [%~2]
shift
echo shifted [%1]
exit /b 4

:chain
batflowc x
echo never after the chain
goto :eof

:nogoto
goto batflow_nolabel
echo after the goto
goto :eof

:nocall
call :batflow_nolabel
echo after the call: ERRORLEVEL %ERRORLEVEL%
goto :eof
