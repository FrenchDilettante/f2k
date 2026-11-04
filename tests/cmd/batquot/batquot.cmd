@echo off
rem batquot - the quotes of a cmd /c string, each string run by a
rem cmd.exe of its own. spawnkid.exe's args prints the command line it
rem was given and its arguments (the script's directory as home), so
rem its output shows which quotes survive; "batq x.cmd", a batch file
rem with a blank in its name that the script writes itself and deletes
rem at its start and end, prints its arguments (no batq file is there,
rem so a name cut at its blank runs nothing). The strings: no quote
rem first; the whole string quoted; the program's name quoted with more
rem quotes after; two quotes around a name with no blank in it; two
rem quotes around the batch file's name, then around that name without
rem its extension; the batch file's quoted name inside a quoted string;
rem the batch file's quoted name with /s; and blanks before the quote.
set F2KHOME=%CD%
del "batq x.cmd" > nul 2> nul
> "batq x.cmd" echo @echo batq x.cmd ran [%%*]
echo no quote first:
cmd /c spawnkid args a "b c"
echo the whole string quoted:
cmd /c "spawnkid args a b"
echo the name quoted, more quotes after:
cmd /c "spawnkid" args "b c"
echo two quotes around a name with no blank:
cmd /c "spawnkid.exe" args
echo two quotes around a name with a blank:
cmd /c "batq x.cmd"
echo the same without its extension:
cmd /c "batq x"
echo that name quoted inside a quoted string:
cmd /c ""batq x.cmd" one"
echo that name quoted, with /s:
cmd /s /c "batq x.cmd"
echo blanks before the quote:
cmd /c   "spawnkid args d"
del "batq x.cmd"
