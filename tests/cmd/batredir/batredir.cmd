@echo off
rem batredir - the redirections, each observed through type of the file
rem it made: output to a new file, then to a file replaced, appended, a
rem redirection written before its command, input from a file into
rem spawnkid.exe's read (one ReadFile of its standard input), a
rem program's error output and cmd's own to a file, output and error
rem output to one file, and nul. spawnkid.exe's out writes one line to
rem its standard output, then one to its standard error.
del batredir.out > nul 2> nul
del batredir.err > nul 2> nul
del batredir.in > nul 2> nul
echo one> batredir.out
echo two>> batredir.out
type batredir.out
echo replaced> batredir.out
type batredir.out
> batredir.out echo the redirection first
type batredir.out
echo a line to read> batredir.in
spawnkid read < batredir.in
spawnkid out > batredir.out
type batredir.out
spawnkid out 2> batredir.err
type batredir.err
type batnone.txt 2> batredir.err
type batredir.err
spawnkid out > batredir.out 2>&1
type batredir.out
spawnkid out > nul
spawnkid out 2> nul
spawnkid out > nul 2>&1
echo to nul> nul
del batredir.out
del batredir.err
del batredir.in
