@echo off
rem batdelay - delayed expansion: off by default, setlocal
rem enabledelayedexpansion, a block and a for's command seeing what they set,
rem if's words, a for's set, the ERRORLEVEL as a command runs, a variable's
rem edits, an undefined variable and a lone bang, carets with bangs (doubled,
rem single, quoted), a bang and a caret in a for /f value, nested setlocal
rem disabledelayedexpansion, endlocal turning it off, and cmd /v:on's
rem command line (a set variable, an undefined one) beside cmd /c's.
if exist batdelay.txt del batdelay.txt
set BATDLA=one
set BATDLB=
> batdelay.txt echo a!b
>> batdelay.txt echo x^^c!
echo == off by default
echo [!BATDLA!]
echo == setlocal enabledelayedexpansion
setlocal enabledelayedexpansion
echo [!BATDLA!] [%BATDLA%] [!batdla!]
echo == a block
set BATDLA=before
(
set BATDLA=after
echo percent [%BATDLA%] bang [!BATDLA!]
)
echo == a for's command
for %%i in (1 2 3) do (
set BATDLB=!BATDLB!%%i
echo pass %%i: [!BATDLB!]
)
echo == if
if "!BATDLB!"=="123" (echo if: yes) else echo if: no
if !BATDLB! GTR 100 echo if GTR: yes
echo == a for's set
set BATDLC=x y
for %%i in (!BATDLC!) do echo item [%%i]
echo == the errorlevel
cmd /c exit 3 & echo percent %ERRORLEVEL% bang !ERRORLEVEL!
echo == edits
set BATDLD=abcdef
echo [!BATDLD:~1,3!] [!BATDLD:cd=-!] [!BATDLD:~-2!]
echo == undefined and lone bangs
echo [!BATDLNONE!] [a!b] [c!]
echo == carets
echo [^^!BATDLA^^!]
echo [^!BATDLA^!]
echo "[^!BATDLA^!]"
echo [a^^b] [c^d] !BATDLA!
echo [a^^b] [c^d] no bang
echo == a for /f value with a bang and a caret
for /f "delims=" %%l in (batdelay.txt) do echo [%%l]
echo == nested setlocal disabledelayedexpansion
setlocal disabledelayedexpansion
echo nested off: [!BATDLA!]
endlocal
echo back on: [!BATDLA!]
endlocal
echo == after endlocal
echo [!BATDLA!]
echo == cmd /v:on
cmd /v:on /c "set BATDLG=v& echo [!BATDLG!] [!BATDLNONE!]"
cmd /c "set BATDLG=v& echo [!BATDLG!]"
cmd /v:on /c "set BATDLG=v& cmd /c echo [!BATDLG!]"
del batdelay.txt
