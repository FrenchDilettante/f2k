@echo off
rem batset - set, and variables expanded in a batch file: setting a
rem variable and listing it by its name's start, its value expanded
rem (its name without regard to case), a value with blanks, a name that
rem is not defined (the message, and ERRORLEVEL after it), ERRORLEVEL
rem after a set that succeeds, clearing a variable, an undefined
rem variable expanding to nothing (in a batch file, unlike at the
rem prompt), and a doubled percent sign for one.
set BATSX=
set BATSY=
set BATSX=1
set BATSX
echo [%BATSX%]
echo [%batsx%]
set BATSY=two words
echo [%BATSY%]
set BATSNOPE
echo ERRORLEVEL after set BATSNOPE: %ERRORLEVEL%
set BATSX=3
echo ERRORLEVEL after set BATSX=3: %ERRORLEVEL%
echo [%BATSX%]
set BATSX=
set BATSX
echo [%BATSX%]
echo [%BATSNOPE%]
echo 100%% and %%BATSY%%
echo ERRORLEVEL at the end: %ERRORLEVEL%
