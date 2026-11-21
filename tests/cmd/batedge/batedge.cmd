@echo off
rem batedge - small corners of the batch language: %%~ with a modifier
rem cmd.exe does not know (each in a cmd.exe of its own: Windows 2000 ends
rem the batch file there); a caret at a line's end (joining the next line
rem and escaping its first character, after rem, inside quotes, doubled,
rem and set's value of a line feed); call's second pass over carets; if's
rem string order (LSS, GTR, EQU and /i over case, punctuation, a hyphen,
rem digits), its numbers past 2^31-1, octal and hexadecimal; and a label
rem of 40 characters (goto and call), then, each in a cmd.exe of its own,
rem one of 140, a goto by a label's first 39 characters, and one to a name
rem that differs from a label only past its 128th.
if not "%~1"=="" goto %~1
echo == %%~ with a modifier it does not know
cmd /c batedge.cmd tildeq
echo exit code %ERRORLEVEL%
cmd /c batedge.cmd tildenq
echo exit code %ERRORLEVEL%
cmd /c batedge.cmd tildex
echo exit code %ERRORLEVEL%
echo == a caret at a line's end
echo joined^
 here
echo first^
&echo second
rem a remark^
echo after rem: this line ran
echo "quoted^
echo after the quote: this line ran"
echo doubled^^
echo after doubled: this line ran
set BATEDGEL=^


if defined BATEDGEL (echo BATEDGEL: defined) else echo BATEDGEL: undefined
echo [%BATEDGEL%]
echo == call and carets
call echo "a^b"
call echo a^^b
call echo a^^^^b
call :carets "a^b" a^^b
set BATEDGEC=a^^b
call echo %%BATEDGEC%%
echo == if's string order
if a LSS B (echo a LSS B: yes) else echo a LSS B: no
if B LSS a (echo B LSS a: yes) else echo B LSS a: no
if A LSS a (echo A LSS a: yes) else echo A LSS a: no
if a LSS A (echo a LSS A: yes) else echo a LSS A: no
if a EQU A (echo a EQU A: yes) else echo a EQU A: no
if Z GTR a (echo Z GTR a: yes) else echo Z GTR a: no
if _ LSS a (echo _ LSS a: yes) else echo _ LSS a: no
if [ LSS a (echo [ LSS a: yes) else echo [ LSS a: no
if 1 LSS a (echo 1 LSS a: yes) else echo 1 LSS a: no
if a-b LSS ab (echo a-b LSS ab: yes) else echo a-b LSS ab: no
if ab LSS a-b (echo ab LSS a-b: yes) else echo ab LSS a-b: no
if a-c LSS ab (echo a-c LSS ab: yes) else echo a-c LSS ab: no
if 10a LSS 9a (echo 10a LSS 9a: yes) else echo 10a LSS 9a: no
if 10 LSS 9 (echo 10 LSS 9: yes) else echo 10 LSS 9: no
if /i a LSS B (echo /i a LSS B: yes) else echo /i a LSS B: no
if /i B GTR a (echo /i B GTR a: yes) else echo /i B GTR a: no
if /i a EQU A (echo /i a EQU A: yes) else echo /i a EQU A: no
if 2147483648 EQU 2147483647 (echo 2147483648 EQU 2147483647: yes) else echo 2147483648 EQU 2147483647: no
if 99999999999 GTR 2147483647 (echo 99999999999 GTR 2147483647: yes) else echo 99999999999 GTR 2147483647: no
if -2147483649 EQU -2147483648 (echo -2147483649 EQU -2147483648: yes) else echo -2147483649 EQU -2147483648: no
if 010 EQU 8 (echo 010 EQU 8: yes) else echo 010 EQU 8: no
if 0x10 EQU 16 (echo 0x10 EQU 16: yes) else echo 0x10 EQU 16: no
echo == long labels
goto batedge_goto_forty_012345678901234567890
echo never: skipped by the goto
:batedge_goto_forty_012345678901234567890
echo after a goto to a label of 40 characters
call :batedge_call_forty_012345678901234567890 one
cmd /c batedge.cmd long140
echo exit code %ERRORLEVEL%
cmd /c batedge.cmd prefix
echo exit code %ERRORLEVEL%
cmd /c batedge.cmd past128
echo exit code %ERRORLEVEL%
goto :eof

:carets
echo [%1] [%2]
goto :eof

:batedge_call_forty_012345678901234567890
echo in a label of 40 characters, called: [%1]
goto :eof

:tildeq
call :tildeqs one
echo after the call
goto :eof

:tildeqs
echo [%~1] [%~q1]
echo after the line
goto :eof

:tildenq
call :tildenqs one
echo after the call
goto :eof

:tildenqs
echo [%~n1] [%~nq1]
echo after the line
goto :eof

:tildex
call :tildexs one
echo after the call
goto :eof

:tildexs
echo [%~x]
echo after the line
goto :eof

:long140
goto batedge_goto_long_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901
echo never: skipped by the goto
:batedge_goto_long_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901
echo after a goto to a label of 140 characters
goto :eof

:prefix
goto batedge_prefix_forty_012345678901234567
echo after a goto by the first 39 characters of a label
goto :eof

:batedge_prefix_forty_0123456789012345678
echo reached the label of 40 characters by its first 39
goto :eof

:past128
goto batedge_past_128_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012b
echo after a goto to a name differing from a label past its 128th character
goto :eof

:batedge_past_128_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012a
echo reached the label ending a by a name ending b
goto :eof
