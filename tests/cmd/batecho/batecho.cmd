@echo off
rem batecho - what echo prints: text, blanks after echo, an empty line
rem (echo.), the echo state (echo alone, with echo off and on), and, with
rem echo on, each command after the prompt: under a fixed prompt, then
rem under the default one, the current directory, which the declaration
rem masks.
echo text
echo   three blanks after echo
echo.
echo
echo off
echo
prompt $G
echo on
echo with echo on
echo
@echo off
prompt $P$G
echo on
echo under the current directory's prompt
@echo off
echo
