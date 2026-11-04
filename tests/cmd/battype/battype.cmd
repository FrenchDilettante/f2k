@echo off
rem battype - type: a file the script writes itself (echo redirected
rem into it, then a line appended), and a file that does not exist (the
rem message, and ERRORLEVEL after it).
del battype.txt > nul 2> nul
echo first line> battype.txt
echo second line>> battype.txt
type battype.txt
type batnone.txt
echo type batnone.txt: %ERRORLEVEL%
del battype.txt
