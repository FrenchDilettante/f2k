@echo off
rem batlevel - a program's exit code through the ERRORLEVEL variable:
rem spawnkid.exe (the spawn fixture's companion, beside the script)
rem exiting with a code it is given: 3, 0, 256, 0xFFFFFFFF (ERRORLEVEL
rem is signed) and an NTSTATUS; ERRORLEVEL kept across an internal
rem command (echo); a command naming no program (its message, and
rem ERRORLEVEL after it); and the script's own exit code, the last
rem program's.
spawnkid exit 3
echo spawnkid exit 3: %ERRORLEVEL%
echo after an echo: %ERRORLEVEL%
spawnkid exit 0
echo spawnkid exit 0: %ERRORLEVEL%
spawnkid exit 256
echo spawnkid exit 256: %ERRORLEVEL%
spawnkid exit 0xFFFFFFFF
echo spawnkid exit 0xFFFFFFFF: %ERRORLEVEL%
spawnkid exit 0xC0000005
echo spawnkid exit 0xC0000005: %ERRORLEVEL%
batnoprog
echo batnoprog: %ERRORLEVEL%
spawnkid exit 7
