@echo off
rem batops - the command operators and the caret: and-then and or-else
rem after programs exiting with 0 and 3, after a cd that fails and a
rem set clearing an undefined variable, and the two in one line, the
rem ERRORLEVEL each leaves; the always operator, its line expanded
rem before either command runs; a pipeline's ERRORLEVEL; echo piped into
rem a program reading its standard input (spawnkid.exe's read, one
rem ReadFile), with and without a blank before the bar; and the caret
rem escaping the operators and itself, kept inside quotes, and ending a
rem line to join the next to it.
spawnkid exit 0 && echo and-then after exit 0
spawnkid exit 3 && echo and-then after exit 3
echo ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3 || echo or-else after exit 3
spawnkid exit 0 || echo or-else after exit 0
spawnkid exit 3 && echo and-then after exit 3 || echo or-else after the and-then
cd batopsz 2> nul || echo or-else after a cd that fails
cd batopsz 2> nul && echo and-then after a cd that fails
echo ERRORLEVEL %ERRORLEVEL%
set BATOPSZ=|| echo or-else after clearing an undefined variable
echo ERRORLEVEL %ERRORLEVEL%
spawnkid exit 2
spawnkid exit 3 & echo always, ERRORLEVEL expanded before [%ERRORLEVEL%]
echo ERRORLEVEL %ERRORLEVEL%
spawnkid exit 3 | spawnkid exit 5
echo ERRORLEVEL after exit 3 piped into exit 5: %ERRORLEVEL%
spawnkid exit 5 | spawnkid exit 0
echo ERRORLEVEL after exit 5 piped into exit 0: %ERRORLEVEL%
echo x| spawnkid read
echo x | spawnkid read
echo a ^& b ^| c ^> d ^< e
echo caret ^^
echo "a ^& b"
echo one ^
two
