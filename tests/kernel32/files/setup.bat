@echo off
rem Set the attributes the files fixture expects on its data tree: git
rem cannot carry them. Run once after copying tests\kernel32\files to the
rem real machine (the F2K disk build sets the same attributes with mattrib).

setlocal
cd /d "%~dp0"
attrib +r DATA\RDONLY.TXT
attrib +h DATA\HIDDEN.TXT
attrib DATA\*.*
