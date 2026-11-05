@echo off
rem batdir - dir over a directory the script makes, batdird: three files
rem of 7, 120 and 1,200 bytes (echo, then copy /b joining them) and a
rem subdirectory holding a fourth of 6 bytes. The long format sorted by
rem name, one file in the directory's order, /B, /A:D, /A:-D, /O:-S, /-C,
rem /S, the DIRCMD variable's switches and /-B overriding one, and a file
rem that does not exist (the message, and ERRORLEVEL after it). Then start
rem /WAIT /B of spawnkid (its exit code, its output), with a title and /D
rem (the directory it starts in), and start /B, which does not wait
rem (ERRORLEVEL after each), then a pause for that one to end. The dates
rem and times, the volume's label and serial number, the bytes free and
rem the directory's full path are masked.
rd /s /q batdird > nul 2> nul
md batdird
md batdird\sub
echo alpha> batdird\a.txt
echo abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef> batdird\t.tmp
copy /b batdird\t.tmp+batdird\t.tmp batdird\b.txt > nul
copy /b batdird\b.txt+batdird\b.txt+batdird\b.txt+batdird\b.txt+batdird\b.txt batdird\c.tmp > nul
copy /b batdird\c.tmp+batdird\c.tmp batdird\c.dat > nul
del batdird\*.tmp
echo four> batdird\sub\d.txt
dir batdird /O:N
dir batdird\c.dat
dir /B /O:N batdird
dir /A:D /O:N batdird
dir /A:-D /O:N batdird
dir /O:-S /A:-D /B batdird
dir /-C /A:-D /O:N batdird
dir /S /O:N batdird
set DIRCMD=/B /O:N
dir batdird
dir /-B /A:-D batdird
set DIRCMD=
dir batdird\none.txt
echo dir batdird\none.txt: %ERRORLEVEL%
spawnkid exit 9
start /WAIT /B spawnkid exit 4
echo start /WAIT /B: %ERRORLEVEL%
start /WAIT /B spawnkid out
echo start /WAIT /B spawnkid out: %ERRORLEVEL%
set F2KHOME=%CD%
start "batdir" /WAIT /B /Dbatdird "%CD%\spawnkid.exe" where
echo start /D: %ERRORLEVEL%
spawnkid exit 9
start /B spawnkid exit 7
echo start /B: %ERRORLEVEL%
spawnkid sleep 200
rd /s /q batdird
