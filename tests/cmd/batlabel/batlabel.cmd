@echo off
rem batlabel - goto and call to labels around 128 characters, each case a
rem batch file of its own (batlabl.cmd, run by a cmd.exe of its own) so that
rem no case's label scan meets another case's label, nor a goto before it
rem (batedge's long labels met both): a label of 128 characters; one of 129
rem gone to by its whole name and by its first 128; a name of 140 characters
rem whose first 128 are a label's; a short label after a line naming a label
rem of 140 characters; a label of 40 characters gone to by its first 39;
rem call of a label of 129 characters.
if exist batlabl.cmd del batlabl.cmd
set L128=batlabel_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678
set L129=%L128%9
set L140=%L128%901234567890
set L39=batlabel_prefix_forty_01234567890123456
echo == a goto to a label of 128 characters
> batlabl.cmd echo @echo off
>> batlabl.cmd echo goto %L128%
>> batlabl.cmd echo echo never: skipped by the goto
>> batlabl.cmd echo :%L128%
>> batlabl.cmd echo echo reached the label of 128 characters
cmd /c batlabl.cmd
echo exit code %ERRORLEVEL%
echo == a goto to a label of 129 characters
> batlabl.cmd echo @echo off
>> batlabl.cmd echo goto %L129%
>> batlabl.cmd echo echo never: skipped by the goto
>> batlabl.cmd echo :%L129%
>> batlabl.cmd echo echo reached the label of 129 characters
cmd /c batlabl.cmd
echo exit code %ERRORLEVEL%
echo == a goto by the first 128 characters of a label of 129
> batlabl.cmd echo @echo off
>> batlabl.cmd echo goto %L128%
>> batlabl.cmd echo echo after the goto
>> batlabl.cmd echo :%L129%
>> batlabl.cmd echo echo reached the label of 129 characters
cmd /c batlabl.cmd
echo exit code %ERRORLEVEL%
echo == a goto of 140 characters to a label of its first 128
> batlabl.cmd echo @echo off
>> batlabl.cmd echo goto %L140%
>> batlabl.cmd echo echo after the goto
>> batlabl.cmd echo :%L128%
>> batlabl.cmd echo echo reached the label of 128 characters
cmd /c batlabl.cmd
echo exit code %ERRORLEVEL%
echo == a goto past a label of 140 characters
> batlabl.cmd echo @echo off
>> batlabl.cmd echo goto short
>> batlabl.cmd echo echo never: skipped by the goto
>> batlabl.cmd echo :%L140%
>> batlabl.cmd echo echo never: after the long label
>> batlabl.cmd echo :short
>> batlabl.cmd echo echo reached the short label
cmd /c batlabl.cmd
echo exit code %ERRORLEVEL%
echo == a goto by the first 39 characters of a label of 40
> batlabl.cmd echo @echo off
>> batlabl.cmd echo goto %L39%
>> batlabl.cmd echo echo after the goto
>> batlabl.cmd echo :%L39%7
>> batlabl.cmd echo echo reached the label of 40 characters
cmd /c batlabl.cmd
echo exit code %ERRORLEVEL%
echo == a call of a label of 129 characters
> batlabl.cmd echo @echo off
>> batlabl.cmd echo call :%L129% one
>> batlabl.cmd echo echo back from the call
>> batlabl.cmd echo goto :eof
>> batlabl.cmd echo :%L129%
>> batlabl.cmd echo echo in the label of 129 characters: [%%1]
cmd /c batlabl.cmd
echo exit code %ERRORLEVEL%
del batlabl.cmd
