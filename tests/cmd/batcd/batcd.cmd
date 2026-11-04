@echo off
rem batcd - cd inside a script, into a subdirectory and back: cd alone
rem printing the current directory (the script's directory masked), the
rem current directory a child sees (spawnkid.exe's where, relative to
rem F2KHOME, the script's directory), the drive's hidden variable (=C:
rem when the script runs from drive C:) a child inherits, and cd to a
rem directory that does not exist (the message, and ERRORLEVEL after
rem it). The hidden variable's name is the CD variable's first two
rem characters, so the script holds on any drive.
rd batcdsub > nul 2> nul
md batcdsub
set F2KHOME=%CD%
cd batcdsub
cd
..\spawnkid where
..\spawnkid env =%CD:~0,2%
cd ..
spawnkid where
spawnkid env =%CD:~0,2%
cd batcdnone
echo cd batcdnone: %ERRORLEVEL%
spawnkid where
rd batcdsub
