@echo off
rem batline - how cmd.exe reads a line, in the parts a script can show.
rem Where a command word ends: cd.. and cd\ and cd/ run from a
rem subdirectory the script makes (spawnkid.exe's where shows the
rem directory each leaves, relative to the script's own); echo run into
rem each character that may end its word; a tab after echo and after a
rem program's name; a program's name run into a comma, a semicolon and
rem an equals sign (spawnkid.exe's args shows the command line it gets).
rem Leading at signs, with and without a blank between them. Echo ON and
rem OFF with blanks around the word, the variable at the line's end
rem expanding to nothing. A quoted command word, quotes inside one, and
rem one naming nothing. The subdirectory's name typed as a command. The
rem prompt a line is echoed after: an unknown dollar code, a dollar at
rem its end, and prompts of 4 and 600 characters (the size of what a
rem cmd.exe of its own echoes under each). Last, lines of 2046, 2047 and
rem 2048 characters after expansion, in a batch file and as a cmd /c
rem string, each run by a cmd.exe of its own: spawnkid.exe exits with
rem its argument, zeros ending in a 7, read as octal, so 7 means the
rem whole line ran, 0 that it was cut, and 5 (the batch file's
rem ERRORLEVEL before it) that it never ran. The script deletes its
rem files and the subdirectory at its start and end.
set BATLINEZ=
set F2KHOME=%CD%
del batline1.cmd > nul 2> nul
del batline2.cmd > nul 2> nul
del batline.out > nul 2> nul
rd batlined > nul 2> nul
md batlined
echo cd.. from the subdirectory:
cd batlined
cd..
"%F2KHOME%\spawnkid" where
cd %F2KHOME%
echo cd\ from the subdirectory:
cd batlined
cd\
"%F2KHOME%\spawnkid" where
cd %F2KHOME%
echo cd/ from the subdirectory:
cd batlined
cd/
"%F2KHOME%\spawnkid" where
cd %F2KHOME%
echo.dot
echo,comma
echo;semicolon
echo=equals
echo:colon
echo/slash
echo\backslash
echo(paren
echo[bracket
echo]bracket
echo+plus
echo	a tab after echo
spawnkid exit 0
spawnkid	exit 4
echo a tab after a program's name: %ERRORLEVEL%
spawnkid,one
spawnkid;one
spawnkid=one
@@@echo three at signs
@ @echo two at signs, a blank between
prompt $G
echo  ON  %BATLINEZ%
echo with echo on
echo  OFF  %BATLINEZ%
echo after echo OFF
@echo off
"spawnkid" exit 3
echo "spawnkid" exit 3: %ERRORLEVEL%
"spawn"kid exit 2
echo "spawn"kid exit 2: %ERRORLEVEL%
"spawnkid" args one
"batlinez" one
echo "batlinez" one: %ERRORLEVEL%
echo the subdirectory's name as a command:
spawnkid exit 5
batlined
echo batlined: %ERRORLEVEL%
"%F2KHOME%\spawnkid" where
cd %F2KHOME%
prompt [a$xb]
echo on
rem an unknown code
@echo off
prompt [c]$
echo on
rem a dollar at the end
@echo off
set BATLINEF=0000000000
set BATLINEF=%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%
set BATLINEF=%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%%BATLINEF%
> batline2.cmd echo rem
prompt [ab]
cmd /c batline2.cmd > batline.out
for %%F in (batline.out) do echo a prompt of 4 characters, echoed with rem: %%~zF bytes
set PROMPT=[%BATLINEF:~0,598%]
cmd /c batline2.cmd > batline.out
for %%F in (batline.out) do echo a prompt of 600 characters, echoed with rem: %%~zF bytes
prompt $G
> batline1.cmd echo @echo off
>> batline1.cmd echo spawnkid exit 5
>> batline1.cmd echo spawnkid exit %%BATLINEF%%%%BATLINEF%%%%BATLINET%%
>> batline1.cmd echo echo after the line, ERRORLEVEL %%ERRORLEVEL%%
set BATLINET=%BATLINEF:~0,31%7
cmd /c batline1.cmd
echo 2046 characters in a batch file: exit code %ERRORLEVEL%
cmd /c spawnkid exit %%BATLINEF%%%%BATLINEF%%%%BATLINET%%
echo 2046 characters as a cmd /c string: exit code %ERRORLEVEL%
set BATLINET=%BATLINEF:~0,32%7
cmd /c batline1.cmd
echo 2047 characters in a batch file: exit code %ERRORLEVEL%
cmd /c spawnkid exit %%BATLINEF%%%%BATLINEF%%%%BATLINET%%
echo 2047 characters as a cmd /c string: exit code %ERRORLEVEL%
set BATLINET=%BATLINEF:~0,33%7
cmd /c batline1.cmd
echo 2048 characters in a batch file: exit code %ERRORLEVEL%
cmd /c spawnkid exit %%BATLINEF%%%%BATLINEF%%%%BATLINET%%
echo 2048 characters as a cmd /c string: exit code %ERRORLEVEL%
del batline1.cmd
del batline2.cmd
del batline.out
rd batlined
