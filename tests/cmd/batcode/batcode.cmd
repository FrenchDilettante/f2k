@echo off
rem batcode - how a batch file ends, in batch files the script writes
rem itself and deletes at its start and end. batcode1.cmd ends with
rem exit /b 5 after a program that exited with 7, batcode2.cmd with exit
rem /b alone after one that exited with 6: each is called (the
rem ERRORLEVEL its caller sees), then run by a cmd.exe of its own (the
rem exit code that cmd.exe ends with, which ERRORLEVEL shows after it).
rem Then, each run by a cmd.exe of its own, batch files whose last
rem command is a cd that fails (batcode3.cmd, and batcode4.cmd after a
rem program that exited with 7), a call of batcode1.cmd (batcode5.cmd),
rem a call of a program exiting with 3 (batcode6.cmd), and a call of
rem batcode8.cmd, which ends with exit 9, no /b (batcode7.cmd). Last,
rem command strings given to cmd /c: a cd that fails, a type that fails,
rem exit /b 5, and exit /b alone after a program that exited with 7.
rem Then how a cmd.exe of its own reads its switches, each reading nul
rem and writing to nul (so one that took no string and went on to read
rem commands ends at once): cmd/c with no blank, an unknown switch
rem before /c, /c with no string and with two quotes alone, each after a
rem program that exited with 5. Last, the exit code of cmd /c strings
rem ending with exit alone after a program that exited with 7 and after
rem a cd that fails, with exit /b alone after that cd, and with exit and
rem exit /b given numbers in other forms: hexadecimal, a leading zero,
rem digits then letters, a minus sign, letters alone.
del batcode1.cmd > nul 2> nul
del batcode2.cmd > nul 2> nul
del batcode3.cmd > nul 2> nul
del batcode4.cmd > nul 2> nul
del batcode5.cmd > nul 2> nul
del batcode6.cmd > nul 2> nul
del batcode7.cmd > nul 2> nul
del batcode8.cmd > nul 2> nul
> batcode1.cmd echo @echo off
>> batcode1.cmd echo spawnkid exit 7
>> batcode1.cmd echo exit /b 5
>> batcode1.cmd echo echo batcode1 never prints this
> batcode2.cmd echo @echo off
>> batcode2.cmd echo spawnkid exit 6
>> batcode2.cmd echo exit /b
> batcode3.cmd echo @echo off
>> batcode3.cmd echo cd batcodez
> batcode4.cmd echo @echo off
>> batcode4.cmd echo spawnkid exit 7
>> batcode4.cmd echo cd batcodez
> batcode5.cmd echo @echo off
>> batcode5.cmd echo call batcode1
> batcode6.cmd echo @echo off
>> batcode6.cmd echo call spawnkid exit 3
> batcode7.cmd echo @echo off
>> batcode7.cmd echo call batcode8
>> batcode7.cmd echo echo batcode7 never prints this
> batcode8.cmd echo @echo off
>> batcode8.cmd echo exit 9
call batcode1
echo call batcode1: %ERRORLEVEL%
call batcode2
echo call batcode2: %ERRORLEVEL%
cmd /c batcode1.cmd
echo cmd /c batcode1.cmd: %ERRORLEVEL%
cmd /c batcode2.cmd
echo cmd /c batcode2.cmd: %ERRORLEVEL%
cmd /c batcode3.cmd
echo cmd /c batcode3.cmd: %ERRORLEVEL%
cmd /c batcode4.cmd
echo cmd /c batcode4.cmd: %ERRORLEVEL%
cmd /c batcode5.cmd
echo cmd /c batcode5.cmd: %ERRORLEVEL%
cmd /c batcode6.cmd
echo cmd /c batcode6.cmd: %ERRORLEVEL%
cmd /c batcode7.cmd
echo cmd /c batcode7.cmd: %ERRORLEVEL%
cmd /c cd batcodez
echo cmd /c cd batcodez: %ERRORLEVEL%
cmd /c type batcodez.txt
echo cmd /c type batcodez.txt: %ERRORLEVEL%
cmd /c exit /b 5
echo cmd /c exit /b 5: %ERRORLEVEL%
cmd /c "spawnkid exit 7 & exit /b"
echo cmd /c of exit /b after a program that exited with 7: %ERRORLEVEL%
spawnkid exit 5
cmd/c spawnkid exit 3 < nul > nul
echo cmd/c with no blank, then spawnkid exit 3: %ERRORLEVEL%
spawnkid exit 5
cmd /j /c spawnkid exit 3 < nul > nul
echo cmd /j /c spawnkid exit 3, an unknown switch first: %ERRORLEVEL%
spawnkid exit 5
cmd /c < nul > nul
echo cmd /c with no string: %ERRORLEVEL%
spawnkid exit 5
cmd /c "" < nul > nul
echo cmd /c with two quotes for its string: %ERRORLEVEL%
cmd /c "spawnkid exit 7 & exit"
echo cmd /c of exit alone after a program that exited with 7: %ERRORLEVEL%
cmd /c "cd batcodez 2> nul & exit"
echo cmd /c of exit alone after a cd that fails: %ERRORLEVEL%
cmd /c "cd batcodez 2> nul & exit /b"
echo cmd /c of exit /b alone after a cd that fails: %ERRORLEVEL%
cmd /c exit 0x10
echo cmd /c exit 0x10: %ERRORLEVEL%
cmd /c exit 010
echo cmd /c exit 010: %ERRORLEVEL%
cmd /c exit 3abc
echo cmd /c exit 3abc: %ERRORLEVEL%
cmd /c exit -1
echo cmd /c exit -1: %ERRORLEVEL%
cmd /c exit abc
echo cmd /c exit abc: %ERRORLEVEL%
cmd /c exit /b 0x10
echo cmd /c exit /b 0x10: %ERRORLEVEL%
cmd /c exit /b 3abc
echo cmd /c exit /b 3abc: %ERRORLEVEL%
del batcode1.cmd
del batcode2.cmd
del batcode3.cmd
del batcode4.cmd
del batcode5.cmd
del batcode6.cmd
del batcode7.cmd
del batcode8.cmd
