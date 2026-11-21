@echo off
rem batforq - for's values are text, never syntax: for over file names
rem holding an ampersand, parentheses, a caret and a percent sign (one
rem name per pattern, so no directory order shows), for /f over lines and
rem fields holding & | > < ( ) ^ and %, and if in a for's body over values
rem that would not parse as its text. Each value prints in brackets: a
rem value run as a command would print INJECTED or create batforq.out.
rem The cases whose failure could end a batch file run in a cmd.exe of
rem their own: this script again, given the case's label.
if not "%~1"=="" goto %~1
rd /s /q batforq.d > nul 2> nul
del batforq.txt batforq.csv batforq.out > nul 2> nul
md batforq.d
> "batforq.d\a&b.txt" echo x
> "batforq.d\c (1).txt" echo x
> "batforq.d\d^e.txt" echo x
> "batforq.d\f%%g.txt" echo x
echo == for over file names
cd batforq.d
for %%f in (a*.txt) do echo [%%f]
for %%f in (c*.txt) do echo [%%f]
for %%f in (d*.txt) do echo [%%f]
for %%f in (f*.txt) do echo [%%f]
for %%f in (c*.txt) do (echo [%%f])
for %%f in (a*.txt) do (echo [%%f] & echo [%%~nf] [%%~xf])
for %%f in (c*.txt) do if exist %%f echo exists: [%%f]
for %%f in (a*.txt) do if exist "%%f" (echo exists: [%%f]) else echo missing: [%%f]
set BATFORQN=0
for %%f in (*.txt) do set /a BATFORQN+=1 > nul
echo files: %BATFORQN%
cd ..
echo == for /f over lines
> batforq.txt echo a ^& echo INJECTED
>> batforq.txt echo b ^| echo INJECTED
>> batforq.txt echo c ^> batforq.out
>> batforq.txt echo d ^< batforq.txt
>> batforq.txt echo e ^(f^) g ^)
>> batforq.txt echo h ^^ i ^^^& echo INJECTED
>> batforq.txt echo ")" j ^& echo INJECTED
>> batforq.txt echo k %%PATH%% l
for /f "delims=" %%a in (batforq.txt) do echo [%%a]
for /f "delims=" %%a in (batforq.txt) do (echo [%%a])
for /f "delims=" %%a in ('type batforq.txt') do echo [%%a]
echo == for /f over fields
> batforq.csv echo a ^& echo INJECTED,b ^| echo INJECTED
>> batforq.csv echo ^(c^),d^)
>> batforq.csv echo e ^> batforq.out,f ^^ g
>> batforq.csv echo "h & i",j ^& echo INJECTED
for /f "tokens=1,2 delims=," %%a in (batforq.csv) do echo [%%a] [%%b]
for /f "tokens=1,2 delims=," %%a in (batforq.csv) do (echo [%%a] [%%b])
for /f "tokens=1* delims=&" %%a in ("x & echo INJECTED & y") do echo [%%a] [%%b]
for %%a in ("x y") do for %%b in (%%~a) do echo nested: [%%b]
echo == if in a for's body
cmd /c batforq.cmd ifempty
echo exit code %ERRORLEVEL%
cmd /c batforq.cmd ifblank
echo exit code %ERRORLEVEL%
cmd /c batforq.cmd ifamp
echo exit code %ERRORLEVEL%
echo == what ran
if exist batforq.out (echo batforq.out: created) else echo batforq.out: none
rd /s /q batforq.d
del batforq.txt batforq.csv
if exist batforq.out del batforq.out
goto :eof

:ifempty
for %%a in ("") do if not %%~a==x echo an empty value: not x
echo after the loop
goto :eof

:ifblank
for /f "delims=" %%a in ("a b") do if %%a==x (echo a b: x) else echo a b: not x
echo after the loop
goto :eof

:ifamp
for /f "delims=" %%a in ("a & b") do if "%%a"=="a & b" echo quoted: equal
for /f "delims=" %%a in ("a & b") do if %%a==x (echo unquoted: x) else echo unquoted: not x
echo after the loop
goto :eof
