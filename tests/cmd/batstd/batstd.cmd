@echo off
rem batstd - where the standard output and error go, each file observed
rem through type: spawnkid.exe's out writes one line to its standard
rem output, then one to its standard error. Its output to a file, then
rem its error joined to its output, and the other way round; its output
rem joined to its error, then its error to a file, and the other way
rem round; a redirection in the middle of a command, an echo and a
rem program's arguments (spawnkid.exe's args prints its command line,
rem the script's directory as home); and a digit right before the
rem redirection: after a letter, after an equals sign, after a blank,
rem and alone after echo. Then type's output and error apart, each
rem file observed through type, after a program that exited with 3 (the
rem ERRORLEVEL after it): two files, a missing one between them, a
rem wildcard name matching both, one, and none. Last, the bytes type
rem copies, counted: a file holding a Ctrl+Z between two lines (copy
rem /a adds it at the first line's end, copy /b joins the second), and
rem a file cmd /u wrote echo's text into. The script deletes its files
rem at its start and end.
set F2KHOME=%CD%
del batstd.out > nul 2> nul
del batstd.err > nul 2> nul
del batstd1.bst > nul 2> nul
del batstd2.bst > nul 2> nul
del batstdc.bin > nul 2> nul
del batstdd.bin > nul 2> nul
del batstdu.bin > nul 2> nul
echo output to a file, then error to output:
spawnkid out > batstd.out 2>&1
type batstd.out
echo error to output, then output to a file:
spawnkid out 2>&1 > batstd.out
type batstd.out
echo output to error, then error to a file:
spawnkid out 1>&2 2> batstd.err
type batstd.err
echo error to a file, then output to error:
spawnkid out 2> batstd.err 1>&2
type batstd.err
echo in the middle of an echo:
echo one > batstd.out two
type batstd.out
echo in the middle of a program's arguments:
spawnkid args a > batstd.out b
type batstd.out
echo a digit after a letter:
echo x2> batstd.out
type batstd.out
echo a digit after an equals sign:
echo x=2> batstd.out
type batstd.out
echo a digit after a blank:
echo x 2> batstd.out
type batstd.out
echo a digit alone after echo:
echo 1> batstd.out
type batstd.out
> batstd1.bst echo one
> batstd2.bst echo two
echo type of two files:
spawnkid exit 3
type batstd1.bst batstd2.bst > batstd.out 2> batstd.err
echo ERRORLEVEL %ERRORLEVEL%, its output:
type batstd.out
echo its error:
type batstd.err
echo type of a missing file between two:
spawnkid exit 3
type batstd1.bst batstdz.bst batstd2.bst > batstd.out 2> batstd.err
echo ERRORLEVEL %ERRORLEVEL%, its output:
type batstd.out
echo its error:
type batstd.err
echo type of a wildcard name matching both:
spawnkid exit 3
type batstd*.bst > batstd.out 2> batstd.err
echo ERRORLEVEL %ERRORLEVEL%, its output:
type batstd.out
echo its error:
type batstd.err
echo type of a wildcard name matching one:
spawnkid exit 3
type batstd1.* > batstd.out 2> batstd.err
echo ERRORLEVEL %ERRORLEVEL%, its output:
type batstd.out
echo its error:
type batstd.err
echo type of a wildcard name matching none:
spawnkid exit 3
type batstdz.* > batstd.out 2> batstd.err
echo ERRORLEVEL %ERRORLEVEL%, its output:
type batstd.out
echo its error:
type batstd.err
echo a Ctrl+Z between two lines:
copy /b batstd1.bst batstdc.bin /a > nul
copy /b batstdc.bin + batstd2.bst batstdd.bin > nul
for %%F in (batstdd.bin) do echo   the file holds %%~zF bytes
type batstdd.bin > batstd.out
for %%F in (batstd.out) do echo   type wrote %%~zF bytes
echo a file cmd /u wrote:
cmd /u /c echo one> batstdu.bin
for %%F in (batstdu.bin) do echo   the file holds %%~zF bytes
type batstdu.bin > batstd.out
for %%F in (batstd.out) do echo   type wrote %%~zF bytes
del batstd.out
del batstd.err
del batstd1.bst
del batstd2.bst
del batstdc.bin
del batstdd.bin
del batstdu.bin
