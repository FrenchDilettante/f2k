@echo off
rem batcall - call and the batch files it runs, which the script writes
rem itself and deletes at its start and end. batcall1.cmd prints its
rem arguments by number from 0 to 9, all of them together, the first two
rem without their quotes and its own name's forms, shifts them and
rem prints them again, then runs a program exiting with 4. It is called
rem with twelve arguments split at blanks, commas, semicolons and
rem equals signs, quoted ones and an empty pair of quotes among them; by
rem its name with the extension, separators leading its arguments; and
rem by its quoted name. Then call of a program, call of an echo whose
rem line call expands a second time, call alone (ERRORLEVEL after each),
rem and batcall2.cmd, which runs batcall3.cmd without call: control
rem never comes back to it, but to this script, its caller.
del batcall1.cmd > nul 2> nul
del batcall2.cmd > nul 2> nul
del batcall3.cmd > nul 2> nul
> batcall1.cmd echo @echo off
>> batcall1.cmd echo echo batcall1 arg0 [%%0]
>> batcall1.cmd echo echo batcall1 args [%%1] [%%2] [%%3] [%%4] [%%5] [%%6] [%%7] [%%8] [%%9]
>> batcall1.cmd echo echo batcall1 all [%%*]
>> batcall1.cmd echo echo batcall1 unquoted [%%~1] [%%~2]
>> batcall1.cmd echo echo batcall1 name [%%~n0] [%%~x0] [%%~nx0]
>> batcall1.cmd echo shift
>> batcall1.cmd echo echo batcall1 shifted [%%0] [%%1] [%%2] [%%9] all [%%*]
>> batcall1.cmd echo spawnkid exit 4
call batcall1 one "two words" three,four;five=six "" "a,b" seven eight nine ten
echo ERRORLEVEL after the call: %ERRORLEVEL%
call batcall1.cmd ,;x y
call "batcall1" "y z"
call spawnkid exit 6
echo call spawnkid exit 6: %ERRORLEVEL%
set BATCALLX=expanded twice
spawnkid exit 5
call echo second expansion [%%BATCALLX%%]
echo after call echo: %ERRORLEVEL%
spawnkid exit 5
call
echo after call alone: %ERRORLEVEL%
> batcall2.cmd echo @echo off
>> batcall2.cmd echo echo batcall2 runs batcall3 without call
>> batcall2.cmd echo batcall3 from batcall2
>> batcall2.cmd echo echo batcall2 never prints this
> batcall3.cmd echo @echo off
>> batcall3.cmd echo echo batcall3 [%%0] [%%*]
call batcall2
echo back in batcall
del batcall1.cmd
del batcall2.cmd
del batcall3.cmd
