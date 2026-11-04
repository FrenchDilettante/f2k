@echo off
rem bathelp - the help switch, a slash and a question mark, of the
rem built-in commands. Help texts are worded differently on F2K, so the
rem script prints none: each command's output goes to a file, and the
rem script prints the ERRORLEVEL after it and whether the output is that
rem command's help, by comparing its size with the size of the help the
rem switch alone gives (or prints the output when it is not). Each
rem command reads nul, so a help that would wait for a key cannot.
rem First the ERRORLEVEL after the switch alone, after a program that
rem exited with 3: cd, type, ver, set, path, prompt, echo, cls and call;
rem and the exit code of a cmd.exe of its own running rem and exit with
rem the switch. Then where the switch counts: after a path given to cd,
rem run into more text after cd, echo and set, after a word given to
rem echo and set, after cd and echo run into a comma or a dot, and after
rem call cd (cd's help or call's). Last, cmd.exe's own: the switch
rem alone, before /c and a command, and inside the /c string, alone and
rem after cd, with the exit code of each. The script deletes its files
rem at its start and end.
del bathelp.out > nul 2> nul
del bathelp.rcd > nul 2> nul
del bathelp.rec > nul 2> nul
del bathelp.rse > nul 2> nul
del bathelp.rca > nul 2> nul
del bathelp.rcm > nul 2> nul
spawnkid exit 3
> bathelp.rcd < nul cd /?
echo cd's help: ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3
> bathelp.out < nul type /?
echo type's help: ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3
> bathelp.out < nul ver /?
echo ver's help: ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3
> bathelp.rse < nul set /?
echo set's help: ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3
> bathelp.out < nul path /?
echo path's help: ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3
> bathelp.out < nul prompt /?
echo prompt's help: ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3
> bathelp.rec < nul echo /?
echo echo's help: ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3
> bathelp.out < nul cls /?
echo cls's help: ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3
> bathelp.rca < nul call /?
echo call's help: ERRORLEVEL %ERRORLEVEL%
> bathelp.out < nul cmd /c rem /?
echo rem's help, by a cmd.exe of its own: exit code %ERRORLEVEL%
for %%A in (bathelp.out) do if %%~zA==0 (echo   nothing on its output) else echo   text on its output
> bathelp.out < nul cmd /c exit /?
echo exit's help, by a cmd.exe of its own: exit code %ERRORLEVEL%
for %%A in (bathelp.out) do if %%~zA==0 (echo   nothing on its output) else echo   text on its output
spawnkid exit 3
> bathelp.out < nul cd bathelpz /?
echo cd bathelpz, the switch after it: ERRORLEVEL %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rcd) do if %%~zA==%%~zB (echo   cd's help) else (echo   not cd's help, its output:& type bathelp.out)
spawnkid exit 3
> bathelp.out < nul cd /?x
echo cd, the switch run into an x: ERRORLEVEL %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rcd) do if %%~zA==%%~zB (echo   cd's help) else (echo   not cd's help, its output:& type bathelp.out)
spawnkid exit 3
> bathelp.out < nul cd,/?
echo cd run into a comma, then the switch: ERRORLEVEL %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rcd) do if %%~zA==%%~zB (echo   cd's help) else (echo   not cd's help, its output:& type bathelp.out)
spawnkid exit 3
> bathelp.out < nul echo /?x
echo echo, the switch run into an x: ERRORLEVEL %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rec) do if %%~zA==%%~zB (echo   echo's help) else (echo   not echo's help, its output:& type bathelp.out)
spawnkid exit 3
> bathelp.out < nul echo x /?
echo echo x, the switch after it: ERRORLEVEL %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rec) do if %%~zA==%%~zB (echo   echo's help) else (echo   not echo's help, its output:& type bathelp.out)
spawnkid exit 3
> bathelp.out < nul echo./?
echo echo run into a dot, then the switch: ERRORLEVEL %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rec) do if %%~zA==%%~zB (echo   echo's help) else (echo   not echo's help, its output:& type bathelp.out)
spawnkid exit 3
> bathelp.out < nul set /?x
echo set, the switch run into an x: ERRORLEVEL %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rse) do if %%~zA==%%~zB (echo   set's help) else (echo   not set's help, its output:& type bathelp.out)
spawnkid exit 3
> bathelp.out < nul set bathelpz /?
echo set bathelpz, the switch after it: ERRORLEVEL %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rse) do if %%~zA==%%~zB (echo   set's help) else (echo   not set's help, its output:& type bathelp.out)
spawnkid exit 3
> bathelp.out < nul call cd /?
echo call cd, the switch after it: ERRORLEVEL %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rcd) do if %%~zA==%%~zB echo   cd's help
for %%A in (bathelp.out) do for %%B in (bathelp.rca) do if %%~zA==%%~zB echo   call's help
for %%A in (bathelp.out) do if %%~zA==0 echo   nothing on its output
> bathelp.rcm < nul cmd /?
echo cmd.exe's help: exit code %ERRORLEVEL%
> bathelp.out < nul cmd /? /c spawnkid exit 4
echo cmd.exe with the switch before /c spawnkid exit 4: exit code %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rcm) do if %%~zA==%%~zB (echo   cmd.exe's help) else (echo   not cmd.exe's help, its output:& type bathelp.out)
> bathelp.out < nul cmd /c /?
echo cmd.exe with the switch alone as its /c string: exit code %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rcm) do if %%~zA==%%~zB (echo   cmd.exe's help) else (echo   not cmd.exe's help, its output:& type bathelp.out)
> bathelp.out < nul cmd /c cd /?
echo cmd.exe with cd and the switch as its /c string: exit code %ERRORLEVEL%
for %%A in (bathelp.out) do for %%B in (bathelp.rcd) do if %%~zA==%%~zB (echo   cd's help) else (echo   not cd's help, its output:& type bathelp.out)
del bathelp.out
del bathelp.rcd
del bathelp.rec
del bathelp.rse
del bathelp.rca
del bathelp.rcm
