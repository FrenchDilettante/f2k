@echo off
rem batclr - which built-in commands set ERRORLEVEL to 0 when they
rem succeed, in a .bat file and in a .cmd file: cd, type, ver, echo,
rem rem, path shown and set, prompt, cls and set, each run after a
rem program that exited with 1, ERRORLEVEL printed after each. The
rem script writes them into batclr1.bat, types that into batclr2.cmd,
rem calls each, then runs each by a cmd.exe of its own; it deletes the
rem two, and the file type reads, at its start and end. What the
rem commands print goes to nul. Last, cls alone, with a bad switch and
rem with a word, its output to batclr.out (the bytes it wrote there),
rem each after a program that exited with 3 (the ERRORLEVEL after it).
del batclr1.bat > nul 2> nul
del batclr2.cmd > nul 2> nul
del batclr.txt > nul 2> nul
del batclr.out > nul 2> nul
> batclr.txt echo a line to type
> batclr1.bat echo @echo off
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo cd .
>> batclr1.bat echo echo cd: %%ERRORLEVEL%%
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo type batclr.txt ^> nul
>> batclr1.bat echo echo type: %%ERRORLEVEL%%
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo ver ^> nul
>> batclr1.bat echo echo ver: %%ERRORLEVEL%%
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo echo an echo ^> nul
>> batclr1.bat echo echo echo: %%ERRORLEVEL%%
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo rem a remark
>> batclr1.bat echo echo rem: %%ERRORLEVEL%%
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo path ^> nul
>> batclr1.bat echo echo path shown: %%ERRORLEVEL%%
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo path %%PATH%%
>> batclr1.bat echo echo path set: %%ERRORLEVEL%%
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo prompt $P$G
>> batclr1.bat echo echo prompt: %%ERRORLEVEL%%
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo cls ^> nul
>> batclr1.bat echo echo cls: %%ERRORLEVEL%%
>> batclr1.bat echo spawnkid exit 1
>> batclr1.bat echo set BATCLRX=1
>> batclr1.bat echo echo set: %%ERRORLEVEL%%
type batclr1.bat > batclr2.cmd
echo called .bat:
call batclr1.bat
echo called .cmd:
call batclr2.cmd
echo a cmd.exe of its own, .bat:
cmd /c batclr1.bat
echo a cmd.exe of its own, .cmd:
cmd /c batclr2.cmd
echo cls, its output to a file:
spawnkid exit 3
cls > batclr.out
echo cls: %ERRORLEVEL%
for %%F in (batclr.out) do echo   it wrote %%~zF bytes
spawnkid exit 3
cls /x > batclr.out
echo cls /x: %ERRORLEVEL%
for %%F in (batclr.out) do echo   it wrote %%~zF bytes
spawnkid exit 3
cls foo > batclr.out
echo cls foo: %ERRORLEVEL%
for %%F in (batclr.out) do echo   it wrote %%~zF bytes
del batclr1.bat
del batclr2.cmd
del batclr.txt
del batclr.out
