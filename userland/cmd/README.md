# cmd.exe

`cmd.exe` is F2K's command interpreter: it reads command lines from the console (or from a file or a pipe) or runs the one it is given, runs its built-in commands, starts programs and runs batch files, with their redirections, pipes and chains of commands.
It behaves as Windows 2000's `cmd.exe` does with its command extensions on, for the part of it that exists (see [Differences from Windows 2000](#differences-from-windows-2000)).

## Usage

```text
cmd [/Q] [/S] [/A | /U] [/D] [/E:ON | /E:OFF] [/F:ON | /F:OFF] [/V:ON | /V:OFF] [/T:fg]
    [[/C | /K] string]
```

## Switches

| Switch                                   | Effect                                                                           |
| ---------------------------------------- | -------------------------------------------------------------------------------- |
| `/C string`                              | Runs `string`, then ends, with its last command's return code (see below).       |
| `/K string`                              | Runs `string`, then goes on interactively.                                       |
| `/Q`                                     | Starts with echo off: no prompt, and batch files' lines are not echoed.          |
| `/S`                                     | Removes the first and the last quote of `string`, whatever it holds (see below). |
| `/A`, `/U`, `/D`, `/E`, `/F`, `/V`, `/T` | Accepted and ignored, with their `:` values (`/E:ON`, `/T:1F`).                  |
| `/?`                                     | Prints the shell's help and ends with 1, running nothing else, `/C` or `/K` too. |

A switch is `/` and a letter, in either case, and switches may run together (`/q/c`); the program's name ends at a blank or at a `/` (`cmd/c x`).
Any other letter is ignored too.
`/C` and `/K` end the switches: the rest of the command line, its leading blanks skipped, is `string`.
A word that is not a switch ends the switches, and the shell starts interactively, ignoring the rest.

Without `/C` or `/K`, the shell prints its banner, `F2K [Version 5.00.2195]`, then an empty line and its first prompt.
With either, there is no banner.

### The string after /C or /K

The string's quotes are handled as Windows 2000's `cmd /?` describes:

1. They are kept when there is no `/S`, the string holds exactly two quotes, there is no special character (`&<>()@^|`) between them, there is a blank between them, and the text between them names a program file (searched for as a command's word is, see [How programs are found](#how-programs-are-found)).
2. Otherwise, when the string's first character is a quote, that quote and the string's last quote are removed, and the text after the last quote is kept.

The string is then expanded and run as a line typed at the prompt is.
A string longer than a line (2,047 characters, see [Command lines](#command-lines)) prints `The input line is too long.` and sets ERRORLEVEL to 1.

## Command lines

The shell prompts, reads a line from the console, expands its variables (see [Variable expansion](#variable-expansion)), reads its commands (see [Commands on a line](#commands-on-a-line) and [Redirection](#redirection)), then runs them.

A command line is 2,047 characters at most, its line break aside: the longest Windows 2000 takes, as Microsoft documents it (Windows XP and later take 8,191).
This holds for a line typed or read, for the string after `/C` or `/K`, for a batch file's line (cut there), and for a line once its variables are expanded.

- Blanks and `@` characters before the command word are dropped.
- A built-in command is recognized whatever its case; its word ends at a blank, at `,`, `;` or `=`, or at one of `+ / [ ] ( . \ :` (`ver;` runs `ver`, `cd..` and `cd\` run `cd`).
- Any other word names a program: it ends at a blank, at `,`, `;` or `=`, or at a `/` after its first character, outside quotes (`x,a` and `cmd/c` name `x` and `cmd`); quotes may hold any of these (`"C:\My Tools\x.exe" a`).
- After a command, an empty line comes before the next prompt; after an empty line or `cls` there is none.
- With echo off, the shell prints no prompt.
- Ctrl+C or Ctrl+Break at the prompt abandons the line being typed: the console leaves what was typed, and the next prompt comes on the row below, with no empty line between.
  Neither key ends the shell.
- A line whose variables expand past 2,047 characters prints `The input line is too long.` and runs nothing.

### Commands from a file or a pipe

When the standard input is no console (`cmd < commands.txt`, `type commands.txt | cmd`), the shell reads its lines from it: bytes in the OEM code page, each line ended by LF, a CR before it dropped.
With echo on, it prints the prompt, then the line it read, as the console would have echoed it, then runs it.
It reads a byte at a time, so that a program a line starts reads the input from the next line on.
At the input's end, after its last prompt, the shell ends with 0.

## Commands on a line

A line may hold several commands, joined by these operators:

| Operator   | Runs                                                                                      |
| ---------- | ----------------------------------------------------------------------------------------- |
| `a & b`    | `a`, then `b`.                                                                            |
| `a && b`   | `a`, then `b` when `a` succeeded (its return code is 0, see [Exit status](#exit-status)). |
| `a \|\| b` | `a`, then `b` when `a` failed (its return code is not 0).                                 |
| `a \| b`   | `a` and `b` at once, `a`'s standard output piped into `b`'s standard input.               |
| `( ... )`  | The commands inside, as one command: a group's redirections apply to all of them.         |

They bind from the loosest, `&`, then `||`, then `&&`, to the tightest, `|`: `a || b && c` runs `b && c` when `a` fails, and `a & b | c` pipes `b` alone into `c`.
A command's return code is the last one's it ran: a group's is its last command's, `a && b`'s is `a`'s when `a` failed, and a pipe's is its last command's (and so is the ERRORLEVEL after it).
The line's variables are expanded once, before any of its commands runs: `x & echo %ERRORLEVEL%` shows the ERRORLEVEL from before `x`.

- `(` opens a group only where a command starts; anywhere else it is text, and so is a `)` outside a group (`echo (a)` prints `(a)`).
  A group opens and closes on one line.
- A line may end with `&`; nothing before `&`, `&&`, `||` or `|` prints `& was unexpected at this time.` (the operator), and nothing after `&&`, `||` or `|` prints `The syntax of the command is incorrect.`.
  So does a group not closed, an empty group, a redirection without a file, or more than 16 redirections on a command; after a group's `)`, a word that is no redirection is unexpected.
  The line then runs nothing; its return code and the ERRORLEVEL are 1.

### Pipes

The commands a pipe joins run at once, each its own process, joined by anonymous pipes; the shell waits for them all.
A program is started itself, its standard input the pipe from the command before, its standard output the pipe to the command after, its own redirections applied over them (`x 2>&1 | y` sends `x`'s errors down the pipe too).
Anything else, a built-in command, a batch file, a group or a word naming no program, runs in a shell of its own, as Windows' cmd runs it: `COMSPEC`'s program (the shell's own file without one), started as `"program" /S /D /c" command"`, the command as the line holds it once expanded, the blanks before it dropped and those after it kept (`echo x | y` hands `y` the text `x `), which that shell expands again.
A pipe joins 16 commands at most.

### Escapes and quotes

Outside quotes, `^` makes the character after it text, and goes: `echo a ^& b` prints `a & b`, `echo ^^` prints `^`; a `^` that ends a batch file's line joins the next line to it, in its place, and one that ends a line typed or read from the standard input goes.
Inside quotes every character is text, `^` included, and the quotes stay: `echo "a & b"` prints `"a & b"`.
An operator or a redirection inside quotes, or after `^`, is part of the command, handed to it as text.

## Redirection

A command's handles may be redirected, anywhere among its words (`> out.txt echo x` writes `x`):

| Redirection | Handle `n` (1 without one, 0 for `<`)                                    |
| ----------- | ------------------------------------------------------------------------ |
| `n> file`   | Written to `file`, made, or emptied when it exists.                      |
| `n>> file`  | Written after `file`'s end, made when it is missing.                     |
| `n< file`   | Read from `file`, which must exist.                                      |
| `n>&m`      | A duplicate of handle `m`, as it is at that point (`2>&1`, `1>&2`).      |
| `n<&m`      | The same, for input.                                                     |

Handle 0 is the standard input, 1 the standard output, 2 the standard error; 3 to 9 may be opened and duplicated within the command, and are gone after it.
A digit right before `>` or `<` is the handle only where a word starts, after a blank, `,`, `;`, `=` or an operator: `echo 1> f` writes `ECHO is on.` (the `1` is the handle), and `echo x=2> f` writes `x=` (its error goes to `f`), while `echo a1> f` writes `a1`.
The redirections apply in order, from left to right: `x > f 2>&1` sends both outputs to `f`, `x 2>&1 > f` sends errors where the output went before.
The blanks between an operator and its file are dropped, the file's name ends at a blank or an operator, and its quotes go (`> "a b.txt"`); the blanks around the redirection stay in the command's text (`echo x > f` writes `x` with its blank).

- A device's name is the device, in any directory and with any extension: `nul` takes everything written and reads nothing, `con` is the console.
- While the command runs, the shell's own standard handles are the redirected ones: a built-in writes there (its messages on the standard error follow `2>`), and a program is handed them.
  A built-in's output to a file or a pipe is written as bytes in the OEM code page.
- A file that cannot be opened is reported as a built-in's error is (`The system cannot find the file specified.` for a missing `<` file, `The system cannot find the path specified.` for a missing directory), and so is a handle that is not open (`The handle could not be duplicated during redirection of handle n.`): the command does not run, and returns 1 with the ERRORLEVEL 1.
- A group's redirections, after its `)`, hold for every command in it.

## Built-in commands

A built-in command prints its help instead of running, its syntax then what each argument does, when one of its words starts with `/?`, outside quotes and wherever it is (`cd /?`, `cd x /?`, `cd /?x`, `cd,/?`, `exit /?`); words are separated by blanks and by `,`, `;` and `=`.
For `echo`, `set` and `rem`, only the text right after the command does: `echo /?x` prints echo's help, while `echo x /?` prints `x /?` and `echo./?` prints `/?`; `set x /?` lists the variables starting with `x`, the `/?` left out.
`call cd /?` prints call's help.
The help goes to the standard output; the command returns 1 (`rem`'s 0), and leaves the ERRORLEVEL as it is.

### File names and switches

`del`, `md`, `rd`, `copy`, `ren` and `move` read their arguments as Windows' cmd does: names are separated by blanks and by `,`, `;` and `=`; a name in double quotes may hold blanks, and loses its quotes.
A `/` starts a switch, in either case, wherever it is among the names (`del a.txt /q`); switches may run together (`/q/s`).
A switch the command does not take prints `Invalid switch - /x` on the standard error and sets ERRORLEVEL to 1; so does a command without the names it needs, with `The syntax of the command is incorrect.`.
In a name's last component, `*` and `?` are wildcards, matched as FindFirstFileW matches them.
Hidden and system files are left out of what `del` and `copy` select by a name (unless `del /A` says otherwise).

A question (`(Y/N)?`, `(Yes/No/All):`) reads a line from the console: `Y` or `N` (or `A`), in either case, alone on the line; any other line asks again, and a line that cannot be read, or Ctrl+C, answers No.

### call

```text
call [command]
```

Runs `command`, its variables expanded a second time: in a batch file, `call echo %%X%%` prints X's value.
When it names a batch file, that batch file runs and the batch file the `call` is in goes on at its next line once it ends.
A program or a built-in command runs as it would without `call`.

The ERRORLEVEL then becomes what `command` returned: the ERRORLEVEL a batch file leaves (`exit /b 5`'s 5), a program's exit code, 0 for a built-in command that succeeds (`call echo` sets 0), 1 for a command not recognized.
`call` returns it too.
`call` alone fails, and sets ERRORLEVEL to 1.

### cd, chdir

```text
cd [/D] [path]
chdir [/D] [path]
```

Alone, prints the current directory.
With a path, changes the current directory to it.
The path is taken as typed, blanks inside it included (`cd C:\Program Files`); quotes around it are removed (`cd "C:\Program Files"`).
`/D` changes the drive too, as changing the directory always does here; any other switch (`cd/`) prints `The syntax of the command is incorrect.` and sets ERRORLEVEL to 1.
When the directory cannot be changed, `cd` prints `The system cannot find the path specified.` on the standard error and sets ERRORLEVEL to 1.
Otherwise it sets ERRORLEVEL to 0, and keeps the new directory in its drive's hidden variable (`=C:`), which the programs the shell starts inherit.

### cls

```text
cls
```

Clears the console's screen buffer and puts the cursor at the top left.
When the standard output is not a console, it writes a form feed (0x0C) instead.
Words after it are ignored; a switch (`cls /x`) prints `The syntax of the command is incorrect.`, clears nothing, and sets ERRORLEVEL to 1.

### color

```text
color [attr]
```

Colours the console: `attr` is two hexadecimal digits, the background's colour then the text's (one digit is the text's, on black).
The digits are `0` black, `1` blue, `2` green, `3` aqua, `4` red, `5` purple, `6` yellow, `7` white, `8` grey, `9` light blue, `A` light green, `B` light aqua, `C` light red, `D` light purple, `E` light yellow and `F` bright white.
Every cell of the screen buffer takes the colours, its character kept, and so does what is written after.

- `color` alone puts back the colours the screen had before the first `color`.
- The same digit twice changes nothing and sets ERRORLEVEL to 1, with no message.
- Anything but one or two digits prints `The syntax of the command is incorrect.` and sets ERRORLEVEL to 1.

When the standard output is not a console, nothing changes.
Otherwise `color` sets ERRORLEVEL to 0.

### copy

```text
copy [/Y | /-Y] [/A | /B] source [/A | /B] [+ source [/A | /B] [+ ...]] [destination [/A | /B]]
```

- `copy a b` copies the file `a` to `b`, its attributes and last write time with it.
  When `b` is a directory (or ends with `\`), the copy goes into it under its own name; without a destination, into the current directory.
- A source that is a directory stands for its files.
  A source with wildcards copies each file it matches, its name printed (as typed, the file's own name after the directory) before it is copied; a destination with wildcards gives each copy the name `ren` would give it (`copy *.txt *.bak`).
- `copy a+b c` joins: the files each source matches are written one after the other into `c`, each one's name printed first.
  A source with wildcards and a destination that is a single file (no directory, no wildcards) join the same way.
  Without a destination, the sources are joined into the first, which the others are appended to.
- `/A` copies a file as text: a source ends at its first Ctrl+Z (0x1A), and a destination gets a Ctrl+Z after its bytes.
  `/B` copies all the bytes, as they are.
  A switch holds for the file before it and the files after it, until the next one; without one, joined files are text and others binary.
- `/Y` replaces an existing destination without asking, and `/-Y` asks `Overwrite C:\path\b? (Yes/No/All):` first (its full path); `A` answers Yes to the questions after it too.
  The COPYCMD variable may hold either switch, which the command line overrides; with neither, `copy` asks at the prompt, and not in a batch file.
- `/V`, `/N` and `/Z` are taken, and change nothing.

Once done, `copy` prints how many files it wrote, right-aligned in nine columns: `1 file(s) copied.` (a join is one file).
A source that matches nothing prints `The system cannot find the file specified.`, a file copied onto itself `The file cannot be copied onto itself.`, both on the standard error; any failure sets ERRORLEVEL to 1, and a `copy` that succeeds sets it to 0.

### date

```text
date [/T | date]
```

- `date /T` prints the date as `%DATE%` shows it, then a blank: `Wed 11/04/2026 `.
- `date date` sets the date: the month, the day and the year, separated by `-`, `/` or `.` (a day's name before them is skipped).
  A year of one or two digits is 1980 to 2079 (`85` is 1985, `26` is 2026); the date must be from 1980 to 2099.
- `date` alone prints `The current date is: Wed 11/04/2026`, then asks `Enter the new date: (mm-dd-yy) `; an empty line keeps the date.

A date that cannot be read or set prints `The system cannot accept the date entered.` on the standard error, and the question is asked again.
`date` sets ERRORLEVEL to 0.

### del, erase

```text
del [/P] [/F] [/S] [/Q] [/A[[:]attributes]] names
erase [/P] [/F] [/S] [/Q] [/A[[:]attributes]] names
```

Deletes the files each name matches.
A name that is a directory stands for every file in it.

- Before deleting every file of a directory (a directory's name, `*` or `*.*`), `del` asks `C:\path\*, Are you sure (Y/N)? `, the pattern's full path; N deletes nothing.
- `/Q` deletes them without asking.
- `/P` asks `C:\path\file, Delete (Y/N)?` before each file.
- `/F` deletes read-only files too; without it, a read-only file's full path is printed, then `Access is denied.`, on the standard error.
- `/S` deletes the files the name matches in its directory and in every subdirectory below it, and prints `Deleted file - C:\path\file` for each.
- `/A` selects files by their attributes: `R` read-only, `H` hidden, `S` system, `A` ready for archiving, each after a `-` for the files without it; `/A` alone selects every file.
  Without `/A`, hidden and system files are left alone.

Directories are never deleted.
A name that matches no file prints `Could Not Find` and its full path on the standard error.

`del` sets ERRORLEVEL to 0, even when a name matched nothing or a file could not be deleted; it returns 1 then (see [Exit status](#exit-status)).
Without a name, or with a switch it does not take, it sets ERRORLEVEL to 1.

### echo

```text
echo [on | off]
echo text
echo.
```

- `echo` alone prints `ECHO is on.` or `ECHO is off.`.
- `echo on` and `echo off` turn echo on and off, in either case.
- `echo text` prints `text` as typed, blanks included, then CR LF.

The one character after `echo` that separates it from its text is not printed: a blank, a tab, or one of `.` `,` `;` `=` `:` `/` `\` `(` `[` `]` `+`.
So `echo.` prints an empty line, and `echo.on` prints `on`.
`echo` followed by any other character (`echox`) is a program's name.

### exit

```text
exit [/B] [code]
```

- `exit [code]` ends the shell, with `code` as its exit code (the ERRORLEVEL without one), from anywhere, a batch file included.
- `exit /B [code]` in a batch file ends that batch file; the ERRORLEVEL becomes `code`, or stays as it is without one.
  `exit /B` itself returns 0, so a batch file run by `cmd /c` that ends with `exit /b 3` ends the shell with 0 (see [Exit status](#exit-status)).
- `exit /B [code]` outside a batch file ends the shell, with `code`, or the ERRORLEVEL without one.

`code` is read as C's `atoi` reads a number: an optional sign, then decimal digits, the rest ignored, 0 without digits.
A negative code wraps to 32 bits.

### md, mkdir

```text
md path [path ...]
mkdir path [path ...]
```

Creates each directory, and the directories above it that do not exist (`md a\b\c`).
A path already taken prints `A subdirectory or file path already exists.` on the standard error.
Any failure sets ERRORLEVEL to 1; otherwise `md` sets it to 0.

### move

```text
move [/Y | /-Y] source[,source ...] destination
```

Moves each file or directory the sources name into the directory `destination`, or renames it to `destination` (on the same drive).

- A source with wildcards moves the files it matches (not the directories), each one's full path printed once it is moved.
- Several files to one that is not a directory print `Cannot move multiple files to a single file.`.
- A file it would replace is asked about as `copy` asks (`/Y`, `/-Y`, COPYCMD, and no question in a batch file).
- A source that matches nothing prints `The system cannot find the file specified.`.

Any failure sets ERRORLEVEL to 1; otherwise `move` sets it to 0.

### path

```text
path
path [=]directories
path ;
```

Alone, prints `PATH=` and the PATH variable's value, or `No Path` when there is none.
With directories, sets PATH to them, the blanks around them dropped.
`path ;` deletes PATH.
In a `.cmd` batch file, `path` sets ERRORLEVEL to 0; at the prompt and in a `.bat` file it leaves it as it is.

### pause

```text
pause
```

Prints `Press any key to continue . . . `, waits for a key that types a character (it is not echoed, and needs no Enter), then ends the line.
With the standard input redirected, it reads one byte instead.
Its arguments are ignored, and it leaves the ERRORLEVEL as it is.

### popd

```text
popd
```

Changes back to the directory `pushd` saved last, and forgets it.
With none saved, it does nothing.
A directory that cannot be changed to prints `The system cannot find the path specified.` and sets ERRORLEVEL to 1; otherwise `popd` leaves the ERRORLEVEL as it is.

### prompt

```text
prompt [=][text]
```

With `text`, sets the PROMPT variable to it, its trailing blanks kept (see [Prompt codes](#prompt-codes)).
Alone, deletes PROMPT, so that the shell prompts with `$P$G`.
ERRORLEVEL is as after `path`: 0 in a `.cmd` batch file, as it was elsewhere.

### pushd

```text
pushd [path]
```

Saves the current directory, then changes to `path` (its quotes removed).
`pushd` alone lists the saved directories, one a line, the last saved first.
A path that cannot be changed to prints `The system cannot find the path specified.` on the standard error and sets ERRORLEVEL to 1, saving nothing; otherwise `pushd` sets it to 0.
The prompt's `$+` shows a `+` for each saved directory.

### rd, rmdir

```text
rd [/S] [/Q] path [path ...]
rmdir [/S] [/Q] path [path ...]
```

Removes each directory, which must be empty: one that is not prints `The directory is not empty.`, and one that does not exist `The system cannot find the file specified.`, on the standard error.
`/S` removes it with all it holds, read-only files included, after asking `path, Are you sure (Y/N)?` (the path as given); `/Q` removes it without asking.
Any failure sets ERRORLEVEL to 1; otherwise `rd` leaves it as it is.

### rem

```text
rem [comment]
```

Does nothing.
In a batch file with echo on, a `rem` line is echoed; a label line (`::comment`) is not.

### ren, rename

```text
ren [drive:][path]name newname
rename [drive:][path]name newname
```

Renames each file or directory `name` matches to `newname`, in its own directory: `newname` has no drive or directory.
Wildcards in `newname` keep parts of each file's name, read from the start of both:

- `?` keeps the name's next character (none at a `.` or the name's end);
- `*` at the end keeps the rest of the name, and `*` before a character keeps the name up to its last such character, that character included;
- `.` skips past the name's next `.`, and writes one;
- any other character is written in place of the name's next one (a `.` in the name stays to be matched).

The dots and blanks the new name ends with are dropped: `ren *.txt *.bak` changes the extensions, `ren a.* b.*` the names.
A name that matches nothing prints `The system cannot find the file specified.`, and a new name already taken `A duplicate file name exists, or the file cannot be found.`, on the standard error.
Any failure sets ERRORLEVEL to 1; otherwise `ren` sets it to 0.

### set

```text
set
set prefix
set name=[value]
set "name=value"
```

- `set` alone lists every environment variable, one `NAME=value` per line, in the order the environment holds them; the drives' current directories (`=C:=C:\`) are left out.
- `set prefix` lists the variables whose names start with `prefix`, whatever the case; when there are none, it prints `Environment variable prefix not defined` on the standard error and sets ERRORLEVEL to 1.
  The prefix loses one trailing blank and keeps the others: `set X > nul` lists `X`, `set X` (three blanks) looks for `X  `.
- `set name=value` sets the variable.
  The name is everything before the first `=`, blanks included, and the value everything after it, trailing blanks included: `set X = 1` sets `X` to `1`.
- `set name=` deletes the variable; when there is no such variable, ERRORLEVEL becomes 1, with no message.
- `set "name=value"` sets what lies between the first quote and the last.
- `set =value` prints `The syntax of the command is incorrect.` and sets ERRORLEVEL to 1.

A `set` that succeeds sets ERRORLEVEL to 0 in a `.cmd` batch file, and leaves it as it is at the prompt and in a `.bat` file.

### shift

```text
shift [/n]
```

In a batch file, moves its arguments down one: `%0` takes `%1`'s value, `%1` `%2`'s, and so on, `%9` the next argument.
With `/n` (a digit from 0 to 8), the arguments from `%n` on move, those before it stay.
`%*` does not change.
Any other switch prints `The syntax of the command is incorrect.` and sets ERRORLEVEL to 1; outside a batch file, `shift` does nothing.

### time

```text
time [/T | time]
```

- `time /T` prints the time on a 12-hour clock, without seconds: `06:31 PM`.
- `time time` sets the time: `h[:m[:s[.cc]]]`, the parts left out 0, the hundredths after `.` or `,`; an `a` or `p` (`am`, `pm`) after it reads the hour on a 12-hour clock.
- `time` alone prints `The current time is: 18:31:59.12`, then asks `Enter the new time: `; an empty line keeps the time.

A time that cannot be read or set prints `The system cannot accept the time entered.` on the standard error, and the question is asked again.
`time` sets ERRORLEVEL to 0.

### title

```text
title [text]
```

Sets the console window's title to `text`, as typed, its trailing blanks dropped.
It leaves the ERRORLEVEL as it is.

### type

```text
type file [file ...]
```

Writes each file's bytes to the standard output, unchanged.
File names are separated by blanks; a name in quotes may hold blanks.
In a name's last component, `*` and `?` are wildcards: the name stands for each file it matches.
With several names, or a name with wildcards (even one matching a single file), each file's name comes before its bytes, on the standard error, after an empty line and followed by two: the standard output holds the files' bytes alone.

A file that cannot be read, or a wildcard name matching no file, prints its error (`The system cannot find the file specified.` for a missing one) on the standard error and sets ERRORLEVEL to 1; with several names, `Error occurred while processing: name.` follows, and the other files are still written.
`type` without a name prints `The syntax of the command is incorrect.` and sets ERRORLEVEL to 1.
When every file is written, `type` sets ERRORLEVEL to 0.

### ver

```text
ver
```

Prints an empty line, then `F2K [Version 5.00.2195]`, and sets ERRORLEVEL to 0.
Its arguments are ignored.

### Errors

A built-in command reports a Win32 error with Windows 2000's text for it: `The system cannot find the file specified.`, `The system cannot find the path specified.`, `Access is denied.`, `The process cannot access the file because it is being used by another process.`, `The filename, directory name, or volume label syntax is incorrect.`, and, for the file built-ins, `The file exists.`, `The directory is not empty.`, `The filename or extension is too long.`, `The directory name is invalid.` and `Cannot create a file when that file already exists.`.
Any other error is printed as `cmd: error N`.

## How programs are found

A line whose word is not a built-in command names a program.
The word's quotes are removed, and the program is looked for:

1. in the current directory;
2. then in each of PATH's directories, in order.

A name holding `\`, `/` or `:` is a path, looked for only where it points.
PATH's directories are separated by `;`; quotes around one are removed, and empty ones are skipped.

In each place, a name with an extension is tried as it is, whether PATHEXT lists it or not (`call x.bat` with PATHEXT `.CMD`); a name without one is tried with each of PATHEXT's extensions added in turn (`x` as `x.COM`, `x.EXE`, ...).
Only files count, not directories: a directory's name is not recognized.
The first file found is the program.

- **A batch file** (`.bat` or `.cmd`) runs in the shell (see [Batch files](#batch-files)).
- **Any other file** is started as a Windows program: the file found is the program, and the command, expanded, without its redirections, its escapes resolved and without the blanks around it, is its command line; when the word ended at a delimiter other than a blank, a blank goes after it (`x,a` gives `x ,a`, `cmd/c y` gives `cmd /c y`).
  It shares the shell's console and gets its environment, its current directory, its inheritable handles, and its standard handles as the command's redirections leave them (through STARTUPINFO's standard handles).
  The shell waits for it to end, and its exit code becomes the ERRORLEVEL.
  Ctrl+C and Ctrl+Break reach the program (which they end, unless it handles them), and the shell goes on.
- **When nothing is found**, or the program's file cannot be found when it is started, the shell prints this on the standard error, sets ERRORLEVEL to 9009 and returns 1 (so `cmd /c nope` ends with 1, and `call nope` leaves the ERRORLEVEL 1):

  ```text
  'word' is not recognized as an internal or external command,
  operable program or batch file.
  ```

- **When the program cannot be started** for any other reason, the shell prints `'word' cannot be run (error N).`, `N` being the Win32 error code, and the ERRORLEVEL stays as it is.

## Variable expansion

Before a line runs, each `%NAME%` in it is replaced by the variable's value.
Names are compared whatever the case of their letters.

At the prompt, and in the string after `/C` or `/K`:

- an undefined `%NAME%` stays as typed, and its closing `%` may open the next variable (`%X%A%`, with `A` set to `1` and no `X`, gives `%X1`);
- `%%` and a `%` with no closing one stay as typed.

In a batch file:

- `%0` is the batch file's name as typed, and `%1` to `%9` its arguments, nothing past the last one, as `shift` leaves them;
- `%*` is everything after the name, as typed, the blanks after the name left out (`x ,;a b` gives `,;a b`);
- `%~1` to `%~9` are the arguments without the quotes around them;
- `%~` and modifier letters before the digit are parts of the argument's full path, or of the file it names: `f` the full path, `d` its drive, `p` its directory, `n` its name, `x` its extension, `a` its attributes (`--a------`, the letters `drahscotl` or `-`), `z` its size; they combine (`%~dp0`, `%~nx1`), the attributes and size first, separated by blanks, and those two are left out for a name that names nothing.
  `%0`, unquoted, is the batch file as it was found, its extension and the case of its name on the disk included (`call x` gives `%~x0` `.cmd`); quoted, its name as typed;
- `%%` is `%`;
- an undefined `%NAME%` is nothing, an undefined `%NAME:...%` loses `%NAME:` and what follows is read on (`%NOPE:~0,2%` gives `~0,2`), and a `%` with no closing one is dropped;
- `%~` with the letters `s` or `t` stays as typed.

A batch file's arguments are separated by blanks, `,`, `;` and `=` outside quotes, and keep their quotes.

### Substrings

`%NAME:~offset,count%` is part of a variable's value, as `set /?` describes it, at the prompt and in a batch file alike, for the dynamic variables too (`%CD:~0,2%` is the current drive, `C:`):

- `offset` units are skipped from its start, or, negative, all but the last `-offset` units;
- `count` units are kept, or, negative, all but the last `-count` units; without `,count`, the rest of the value;
- what lies past the value's ends is left out.

The numbers are read as C's `strtol` reads them with base 0: an optional sign, then `0x` and hexadecimal digits, `0` and octal digits, or decimal digits (`%X:~0x4%` skips 4).
Numbers that cannot be read, or text after them, give the text between the `%`s: `%X:~a%` is `X:~a`.
At the prompt, the substring of an undefined variable stays as typed.

### Replacements

`%NAME:old=new%` is the variable's value with each `old` replaced by `new`, whatever the case of their letters; `%NAME:*old=new%` replaces everything up to the first `old`, that `old` included.
An empty `new` removes `old`; an empty `old` changes nothing.

### Dynamic variables

These names have a value even when the environment has no variable of the name; one that does wins.

| Variable          | Value                                                                        |
| ----------------- | ---------------------------------------------------------------------------- |
| `%CD%`            | The current directory.                                                       |
| `%DATE%`          | The local date, as `Tue 11/03/2026`.                                         |
| `%TIME%`          | The local time to the hundredth, as `18:31:59.12` (` 9:05:03.00` before 10). |
| `%RANDOM%`        | A number from 0 to 32767.                                                    |
| `%ERRORLEVEL%`    | The ERRORLEVEL, as a signed number (`-1073741510` for 0xC000013A).           |
| `%CMDEXTVERSION%` | `2`.                                                                         |
| `%CMDCMDLINE%`    | The shell's own command line.                                                |

## Batch files

A file found with the extension `.bat` or `.cmd` runs in the shell, line by line.

- A line ends at LF, a CR before it dropped; a last line without a line break runs too.
  A line longer than 2,047 bytes is cut there.
  The bytes are read in the OEM code page.
- Empty lines and labels (a line whose first character, after blanks, is `:`, `::` comments included) are skipped and never echoed.
- With echo on, each line is echoed after expansion: an empty line, the prompt, then the line without its leading blanks, followed by a blank when the command has arguments (`>echo hi `, but `>echo`).
  A line starting with `@` is not echoed, and neither is a line read while echo is off (the `echo on` line itself).
  A line holding one command echoes as the shell reads it: its escapes resolved, and its redirections after it, each after a blank, with its handle (`echo hi>out` echoes `>echo hi 1>out`); a line of several commands echoes as it is.
- `echo off` and `echo on` in a batch file hold for the batch files it runs; once the batch file run from the prompt (or by `/C` or `/K`) ends, echo is back as it was before it.
- `call name` runs another batch file and comes back to the next line.
  A batch file run without `call` takes the place of the one it is run from: control does not come back.
- Batch files may nest 32 deep.
  Past that, the shell prints `****** B A T C H   R E C U R S I O N  exceeds STACK limits ******` and every batch file ends.
- `exit /b [code]` ends the batch file; `exit [code]` ends the shell.
- When a batch file ends, the ERRORLEVEL is its last command's, or the code `exit /b` gave, and its return code is its last command's (0 for `exit /b`); run by `call`, its return code is the ERRORLEVEL.
- When the batch file run from the prompt (or by `/C` or `/K`) is a `.cmd` file, a `set`, `path` or `prompt` that succeeds sets ERRORLEVEL to 0, in it and in every batch file it runs, a `.bat` file included; under a `.bat` file, it leaves it.
- A batch file that cannot be opened prints its error and sets ERRORLEVEL to 1.

### Ctrl+C in a batch file

After Ctrl+C or Ctrl+Break, between two lines or while a program the batch file started runs, the shell asks before the next line:

```text
Terminate batch job (Y/N)?
```

`Y` ends every running batch file, back to the prompt (with `/C`, the shell then ends).
`N` goes on with the next line.
Any other answer asks again, and so does Ctrl+C at the question, on a new line.
When no answer can be read, the batch files end.

## Prompt codes

The prompt is the PROMPT variable's text, or `$P$G` when there is none (or when it is 512 characters or more).
Its `$` codes, in either case, are replaced:

| Code | Shows                                                        |
| ---- | ------------------------------------------------------------ |
| `$A` | `&`                                                          |
| `$B` | `\|`                                                         |
| `$C` | `(`                                                          |
| `$D` | The date, as `Tue 11/03/2026`.                               |
| `$E` | Escape (0x1B).                                               |
| `$F` | `)`                                                          |
| `$G` | `>`                                                          |
| `$H` | Backspace: the character before is erased.                   |
| `$L` | `<`                                                          |
| `$M` | Nothing (the remote name of a network drive: there is none). |
| `$N` | The current drive's letter.                                  |
| `$P` | The current drive and directory.                             |
| `$Q` | `=`                                                          |
| `$S` | A space.                                                     |
| `$T` | The time, as `18:31:59.12`.                                  |
| `$V` | The version, `F2K [Version 5.00.2195]`.                      |
| `$_` | A line break.                                                |
| `$$` | `$`                                                          |
| `$+` | One `+` for each directory `pushd` saved.                    |

Any other code ends the prompt: what follows it is not shown (`[a$xb]` shows `[a`); a `$` that ends the text shows nothing.

## Exit status

| Code                           | When                                                    |
| ------------------------------ | ------------------------------------------------------- |
| `code`                         | `exit code`, or `exit /b code` outside a batch file.    |
| 0                              | The standard input ended.                               |
| The last command's return code | `/C`, once the string has run.                          |
| The ERRORLEVEL                 | `exit` alone, or `exit /b` alone outside a batch file.  |
| 1                              | `cmd /?`.                                               |
| 1                              | The standard input could not be read.                   |

When the standard input cannot be read, the shell prints `cmd: the standard input cannot be read (error N)` on the standard error.

A command's return code is not the ERRORLEVEL, though they are often the same:

| Return code    | Of                                                                                                                                                                                                                                                                                    |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The exit code  | A program, once it ends.                                                                                                                                                                                                                                                              |
| 1              | A built-in command that fails (each one that sets ERRORLEVEL to 1 below, and `del` that leaves a file or finds none); a command not recognized; a help printed (`cd /?`, but `rem /?` returns 0); a program that cannot be started; a line that cannot run; a redirection that fails. |
| 0              | Any other built-in command, `exit /b code` included.                                                                                                                                                                                                                                  |
| Its last one   | A batch file, a group, a line of commands, a pipe (its last command's).                                                                                                                                                                                                               |
| The ERRORLEVEL | `call`, once its command has run (a batch file's ERRORLEVEL, see [call](#call)).                                                                                                                                                                                                      |

So `cmd /c` of a batch file ends with 7 when its last line runs a program that exits with 7, and with 0 when its last line is an `echo` or `exit /b 3`, whatever the ERRORLEVEL; when its last line is `call` of a batch file ending with `exit /b 5`, with 5.

The ERRORLEVEL is 0 when the shell starts, and changes only as these say:

| ERRORLEVEL      | Set by                                                                                                                                                                                                                                                                                                                                             |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The exit code   | A program, once it ends; a pipe's last command.                                                                                                                                                                                                                                                                                                    |
| 9009            | A command not recognized.                                                                                                                                                                                                                                                                                                                          |
| `code`          | `exit /b code` in a batch file.                                                                                                                                                                                                                                                                                                                    |
| 1               | A failed `cd`, `color`, `copy`, `md`, `move`, `popd`, `pushd`, `rd`, `ren` or `type`; `del` without a name or with a wrong switch; `set` with no match, nothing to delete or no name; a switch refused (`cd/`, `cls /x`); `call` alone; a batch file not opened; a `/C` or `/K` string too long; a line that cannot run; a redirection that fails. |
| 0               | A `cd`, `color`, `copy`, `date`, `md`, `move`, `pushd`, `ren`, `time`, `type` or `ver` that succeeds; any `del` with a name; under a `.cmd` batch file, a `set`, `path` or `prompt` that succeeds.                                                                                                                                                 |
| Its return code | `call` (see [call](#call)).                                                                                                                                                                                                                                                                                                                        |

Anything else leaves the ERRORLEVEL as it is: `echo`, `rem`, `cls`, `title`, `pause`, `shift` and any help printed never change it, and `rd` and `popd` only when they fail.

## Environment variables

| Variable                                                                    | Use                                                                                                                        |
| --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `PATH`                                                                      | Read: the directories programs are looked for in. `path` shows and sets it. Unset, only the current directory is searched. |
| `PATHEXT`                                                                   | Read: the extensions programs are looked for with. Unset, `.COM;.EXE;.BAT;.CMD`.                                           |
| `PROMPT`                                                                    | Read: the prompt's text. `prompt` sets and deletes it. Unset, `$P$G`.                                                      |
| `COMSPEC`                                                                   | Read: the shell a pipe's built-in command runs in (see [Pipes](#pipes)). Unset, the shell's own file.                      |
| `ERRORLEVEL`, `CD`, `DATE`, `TIME`, `RANDOM`, `CMDEXTVERSION`, `CMDCMDLINE` | Dynamic variables, when the environment has none of the name (see [Dynamic variables](#dynamic-variables)).                |

`set` sets and deletes any variable, and the programs the shell starts get its environment.

## Differences from Windows 2000

- The banner, `ver` and `$V` show `F2K [Version 5.00.2195]`; Windows 2000 shows `Microsoft Windows 2000 [Version 5.00.2195]`, and its banner has a copyright line too.
- A group opens and closes on one line: a `(` left open is a syntax error, where Windows reads on (`More?` at the prompt, the next lines in a batch file); and a `^` ending a line typed or read from the standard input goes, where Windows asks `More?` and reads on.
- A line that cannot run ends nothing: Windows ends a batch file at one.
- `>>` appends after the file's last byte, whatever it is: Windows' cmd writes over a Ctrl+Z ending the file.
- A command a pipe runs in a shell of its own is handed as the line holds it, its escapes kept: Windows rebuilds it from what it read, so `echo a^&b | x` runs `echo a&b` there.
- Handles 3 to 9 reach no program: Windows hands them to a C runtime's program through its startup information.
- These built-in commands of Windows 2000's are not there: `assoc`, `break`, `dir`, `endlocal`, `for`, `ftype`, `goto`, `if`, `setlocal`, `start`, `verify` and `vol`.
  Their names are looked for as programs, and are not recognized (ERRORLEVEL 9009).
- The help `/?` prints is F2K's own text, and describes F2K's shell.
- `set` has no `/A` or `/P`: `set /a` lists the variables whose names start with `/a`.
- `%~` with `s` (short names), `t` (the time) or `$PATH:`, and delayed expansion (`!VAR!`), are not expanded.
- `call` takes no label (`call :name`).
- A file found by a name with an extension that is no program's (`readme.txt`) is started as a program, and cannot run: Windows opens it with the program its extension is associated with.
- A batch file's line longer than 2,047 characters once expanded prints `The input line is too long.` and the batch file goes on; Windows 2000 ends it, with a second message and the exit code 255.
  A `/C` string that expands past 2,047 characters is too long too, where Windows 2000 runs it.
- `cmd /u` is ignored: a built-in's output to a file or a pipe is in the OEM code page, where Windows writes UTF-16.
- `pushd` takes no network path (there is no temporary drive letter), and saves 64 directories at most (4,096 characters together); past that it prints `Not enough storage is available to process this command.`.
- `copy`'s `/V`, `/N` and `/Z` do nothing, and joining text onto a file that already ends with a Ctrl+Z (`copy /a a+b`) leaves that Ctrl+Z in the middle.
- `color` alone puts back the colours the screen had before the first `color`, not a DefaultColor setting or `/T`'s; a wrong argument prints the syntax error rather than `color`'s help.
- `ren`, `copy`, `del` and `move` match long names only, never the short (8.3) names Windows also matches.
- `/A`, `/U`, `/D`, `/E`, `/F`, `/V` and `/T` are ignored: command extensions are always on, and there is no AutoRun command, no file name completion and no delayed expansion, and `/T`'s colours are not applied (Windows 2000 has no `/T`).
- A batch file is opened once and read through: changing it while it runs changes nothing.
- Batch files nest 32 deep at most.
- A program that cannot be started for another reason than its absence is reported as `'word' cannot be run (error N).`.
- `$D`, `$T`, `%DATE%`, `%TIME%`, `date` and `time` always use the US format.

## Example

```text
F2K [Version 5.00.2195]

C:\WINNT\system32>set F2KX=hello

C:\WINNT\system32>echo %F2KX% %NOPE%
hello %NOPE%

C:\WINNT\system32>pwd
C:\WINNT\system32

C:\WINNT\system32>type f2kbat.cmd
@echo off
rem the batch file cmd's tests run
echo first %1
echo all %*
call f2ksub.cmd sub
echo back %errorlevel%
exit /b 4
echo never

C:\WINNT\system32>type f2ksub.cmd
echo in %0 %~1
exit /b 2

C:\WINNT\system32>f2kbat x
first x
all x
in f2ksub.cmd sub
back 2

C:\WINNT\system32>echo %errorlevel%
4

C:\WINNT\system32>nope
'nope' is not recognized as an internal or external command,
operable program or batch file.

C:\WINNT\system32>exit
```

With `/C`, `cmd /c echo hi` prints `hi` and ends with 0, and `cmd /c f2kbat one "two three"` ends with 0, the return code of the batch file's last command, `exit /b 4`.

## Building and running

`make userland` builds `cmd.exe` into `target/userland/i686-f2k-pe/release/`.
It is not on the disk the tests boot (`make disk`): `make cmd-disk` copies that disk, adds `cmd.exe` to `\WINNT\system32`, and makes its boot run `CMDLINE` (`WINNT\system32\cmd.exe` by default).
`make run` boots that disk into `cmd.exe` in a QEMU window, and `make vbox-image` writes it as a VirtualBox disk.

Its source is `src/main.rs` (the program) and the library beside it, tested on the host by `make run-tests`: `src/lib.rs` (lines, built-in commands, expansion and the prompt), `src/syntax.rs` (operators, groups, redirections and escapes), `src/switches.rs` (the command line), `src/help.rs` (what `/?` prints), `src/search.rs` (how programs are found), `src/batch.rs` (batch files) and `src/builtins/` (the file, console and clock built-ins' arguments and messages); `src/exec/` runs those built-ins.
`tests/core/test_cmd.py` types at its prompt, and runs it with `/C` (redirections, pipes, `&&` and `||`, commands piped into a shell), on QEMU; `tests/core/test_cmd_help.py` boots `cmd /?` and `cmd /c cd /?`; `tests/core/test_cmd_files.py` runs a batch file of file built-ins with `/C`, and types `color`, `del`, `pushd` and `pause` at the prompt.
