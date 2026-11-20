@echo off
rem batpipe - cmd.exe's |: a built-in or a program into pipekid.exe (the
rem pipe fixture's companion: upper passes its input on in capitals, cat
rem as it is, count prints the lines and bytes it read, emit <n> prints n
rem lines, exit <n> exits with n reading nothing), chains of two and
rem three, past the pipe's buffer, an empty input, a pipe with > and >>
rem after it and < before it, 2>&1 and 2> nul into a pipe (spawnkid.exe's
rem out writes one line to its standard output, then one to its standard
rem error), ERRORLEVEL, && and || after a pipe, the left side's writes
rem failing once the right side has exited, & and parentheses around a
rem pipe, if before one, a pipe inside a for, built-ins on the left
rem (echo, type, dir, set and cd: run by a cmd.exe of their own, so set
rem and cd leave this one as it was), and type's error into a pipe.
del batpipe.out > nul 2> nul
rd /s /q batpipe.d > nul 2> nul
echo == two stages
echo hello | pipekid upper
echo hello| pipekid count
echo |pipekid count
pipekid emit 3 | pipekid upper
echo == three and four stages
pipekid emit 4 | pipekid cat | pipekid count
pipekid emit 2 | pipekid upper | pipekid upper | pipekid count
echo == past the buffer, and nothing
pipekid emit 3000 | pipekid count
pipekid emit 3000 | pipekid cat | pipekid count
pipekid exit 0 | pipekid count
echo == redirections
pipekid emit 2 | pipekid upper > batpipe.out
type batpipe.out
pipekid emit 1 | pipekid upper >> batpipe.out
type batpipe.out
type batpipe.out | pipekid count
pipekid count < batpipe.out | pipekid upper
spawnkid out 2>&1 | pipekid upper
spawnkid out 2> nul | pipekid upper
spawnkid out 2>&1 1> nul | pipekid upper
echo == ERRORLEVEL
pipekid exit 3 | pipekid exit 5
echo ERRORLEVEL %ERRORLEVEL%
pipekid exit 7 | pipekid count
echo ERRORLEVEL %ERRORLEVEL%
pipekid emit 3000 2> nul | pipekid exit 0
echo ERRORLEVEL %ERRORLEVEL%
pipekid emit 1 | pipekid exit 0 && echo and: ran
pipekid emit 1 | pipekid exit 4 || echo or: ran
pipekid exit 4 | pipekid exit 0 || echo or after a failing left side: ran
echo == grouping
(echo a& echo b) | pipekid upper
echo c& echo d | pipekid upper
pipekid emit 1 | pipekid upper & echo after the pipe
if 1==1 pipekid emit 1 | pipekid upper
for %%i in (x y) do @echo %%i| pipekid upper
echo == built-ins
md batpipe.d
echo x> batpipe.d\one.txt
echo x> batpipe.d\two.txt
dir /b batpipe.d | pipekid upper
dir /b batpipe.d | pipekid count
set BATPIPEV=
set BATPIPEV=yes| pipekid count
if defined BATPIPEV (echo BATPIPEV: set) else echo BATPIPEV: not set
cd batpipe.d | pipekid count
if exist one.txt (echo cd: took effect) else echo cd: no effect
type batnone.txt | pipekid count
del batpipe.out
rd /s /q batpipe.d
