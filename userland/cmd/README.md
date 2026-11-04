# cmd.exe

`cmd.exe` is F2K's command interpreter: it reads command lines from the console or runs the one it is given, runs its built-in commands, starts programs and runs batch files.
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

A switch is `/` and a letter, in either case, and switches may run together (`/q/c`).
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
A string longer than a line (1,024 characters) prints `The input line is too long.` and sets ERRORLEVEL to 1.

## Command lines

The shell prompts, reads a line from the console (1,024 characters at most, its line break included), expands its variables (see [Variable expansion](#variable-expansion)), then runs it.

- Blanks and `@` characters before the command word are dropped.
- A built-in command is recognized whatever its case; its word ends at a blank or at `,`, `;` or `=` (`ver;` runs `ver`).
- Any other word names a program: it ends at a blank, and a quoted word (`"C:\My Tools\x.exe" a`) runs to its closing quote.
- After a command, an empty line comes before the next prompt; after an empty line or `cls` there is none.
- With echo off, the shell prints no prompt.
- Ctrl+C or Ctrl+Break at the prompt abandons the line being typed: the console leaves what was typed, and the next prompt comes on the row below, with no empty line between.
  Neither key ends the shell.
- A line whose variables expand past 1,024 characters prints `The input line is too long.` and runs nothing.

## Built-in commands

### call

```text
call [command]
```

Runs `command`.
When it names a batch file, that batch file runs and the batch file the `call` is in goes on at its next line once it ends.
A program or a built-in command runs as it would without `call`.
`call` alone does nothing.

### cd, chdir

```text
cd [path]
chdir [path]
```

Alone, prints the current directory.
With a path, changes the current directory to it.
The path is taken as typed, blanks inside it included, quotes too: `cd C:\Program Files`, not `cd "C:\Program Files"`.
When the directory cannot be changed, `cd` prints `The system cannot find the path specified.` on the standard error and sets ERRORLEVEL to 1.
Otherwise it sets ERRORLEVEL to 0.

### cls

```text
cls
```

Clears the console's screen buffer and puts the cursor at the top left.
When the standard output is not a console, it writes a form feed (0x0C) instead.
Its arguments are ignored.

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

- `exit [code]` ends the shell, with `code` as its exit code (0 without one), from anywhere, a batch file included.
- `exit /B [code]` in a batch file ends that batch file; the ERRORLEVEL becomes `code`, or stays as it is without one.
  `exit /B` itself returns 0, so a batch file run by `cmd /c` that ends with `exit /b 3` ends the shell with 0 (see [Exit status](#exit-status)).
- `exit /B [code]` outside a batch file ends the shell, with `code`, or the ERRORLEVEL without one.

`code` is read as C's `atoi` reads a number: an optional sign, then decimal digits, the rest ignored, 0 without digits.
A negative code wraps to 32 bits.

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

### prompt

```text
prompt [=][text]
```

With `text`, sets the PROMPT variable to it, its trailing blanks kept (see [Prompt codes](#prompt-codes)).
Alone, deletes PROMPT, so that the shell prompts with `$P$G`.
ERRORLEVEL is as after `path`: 0 in a `.cmd` batch file, as it was elsewhere.

### rem

```text
rem [comment]
```

Does nothing.
In a batch file with echo on, a `rem` line is echoed; a label line (`::comment`) is not.

### set

```text
set
set prefix
set name=[value]
set "name=value"
```

- `set` alone lists every environment variable, one `NAME=value` per line, in the order the environment holds them; the drives' current directories (`=C:=C:\`) are left out.
- `set prefix` lists the variables whose names start with `prefix`, whatever the case; when there are none, it prints `Environment variable prefix not defined` on the standard error and sets ERRORLEVEL to 1.
- `set name=value` sets the variable.
  The name is everything before the first `=`, blanks included, and the value everything after it, trailing blanks included: `set X = 1` sets `X` to `1`.
- `set name=` deletes the variable; when there is no such variable, ERRORLEVEL becomes 1, with no message.
- `set "name=value"` sets what lies between the first quote and the last.
- `set =value` prints `The syntax of the command is incorrect.` and sets ERRORLEVEL to 1.

A `set` that succeeds sets ERRORLEVEL to 0 in a `.cmd` batch file, and leaves it as it is at the prompt and in a `.bat` file.

### type

```text
type file [file ...]
```

Writes each file's bytes to the standard output, unchanged.
File names are separated by blanks; a name in quotes may hold blanks.
With several files, each file's name comes before its bytes, on the standard error, after an empty line and followed by two: the standard output holds the files' bytes alone.

A file that cannot be read prints its error (`The system cannot find the file specified.` for a missing one) on the standard error and sets ERRORLEVEL to 1; with several files, `Error occurred while processing: name.` follows, and the other files are still written.
`type` without a name prints `The syntax of the command is incorrect.` and sets ERRORLEVEL to 1.
When every file is written, `type` sets ERRORLEVEL to 0.

### ver

```text
ver
```

Prints an empty line, then `F2K [Version 5.00.2195]`, and sets ERRORLEVEL to 0.
Its arguments are ignored.

### Errors

A built-in command reports a Win32 error with Windows 2000's text for it: `The system cannot find the file specified.`, `The system cannot find the path specified.`, `Access is denied.`, `The process cannot access the file because it is being used by another process.`, and `The filename, directory name, or volume label syntax is incorrect.`.
Any other error is printed as `cmd: error N`.

## How programs are found

A line whose word is not a built-in command names a program.
The word's quotes are removed, and the program is looked for:

1. in the current directory;
2. then in each of PATH's directories, in order.

A name holding `\`, `/` or `:` is a path, looked for only where it points.
PATH's directories are separated by `;`; quotes around one are removed, and empty ones are skipped.

In each place, a name whose extension is one of PATHEXT's, in either case, is tried as it is; any other name is tried with each of PATHEXT's extensions added in turn (`x` as `x.COM`, `x.EXE`, ...; `x.txt` as `x.txt.COM`, ...).
Only files count, not directories.
The first file found is the program.

- **A batch file** (`.bat` or `.cmd`) runs in the shell (see [Batch files](#batch-files)).
- **Any other file** is started as a Windows program: the file found is the program, and the line, expanded and without the blanks around it, is its command line.
  It shares the shell's console and gets its environment, its current directory and its inheritable handles.
  The shell waits for it to end, and its exit code becomes the ERRORLEVEL.
  Ctrl+C and Ctrl+Break reach the program (which they end, unless it handles them), and the shell goes on.
- **When nothing is found**, or the program's file cannot be found when it is started, the shell prints this on the standard error and sets ERRORLEVEL to 9009:

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

- `%0` is the batch file's name as typed, and `%1` to `%9` its arguments, nothing past the last one;
- `%*` is all its arguments, as typed;
- `%~1` to `%~9` are the arguments without the quotes around them;
- `%%` is `%`;
- an undefined `%NAME%` is nothing, and a `%` with no closing one is dropped;
- `%~` with modifier letters (`%~dp0`, `%~nx1`) stays as typed.

A batch file's arguments are separated by blanks, `,`, `;` and `=` outside quotes, and keep their quotes.

### Substrings

`%NAME:~offset,count%` is part of a variable's value, as `set /?` describes it, at the prompt and in a batch file alike, for the dynamic variables too (`%CD:~0,2%` is the current drive, `C:`):

- `offset` units are skipped from its start, or, negative, all but the last `-offset` units;
- `count` units are kept, or, negative, all but the last `-count` units; without `,count`, the rest of the value;
- what lies past the value's ends is left out.

The numbers are decimal, with an optional sign.
The substring of an undefined variable expands as the undefined variable does: nothing in a batch file, as typed at the prompt.

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
  A line longer than 1,024 bytes is cut there.
  The bytes are read in the OEM code page.
- Empty lines and labels (a line whose first character, after blanks, is `:`, `::` comments included) are skipped and never echoed.
- With echo on, each line is echoed after expansion: an empty line, the prompt, then the line without its leading blanks, followed by a blank when the command has arguments (`>echo hi `, but `>echo`).
  A line starting with `@` is not echoed, and neither is a line read while echo is off (the `echo on` line itself).
- `echo off` and `echo on` in a batch file hold for the batch files it runs; once the batch file run from the prompt (or by `/C` or `/K`) ends, echo is back as it was before it.
- `call name` runs another batch file and comes back to the next line.
  A batch file run without `call` takes the place of the one it is run from: control does not come back.
- Batch files may nest 32 deep.
  Past that, the shell prints `****** B A T C H   R E C U R S I O N  exceeds STACK limits ******` and every batch file ends.
- `exit /b [code]` ends the batch file; `exit [code]` ends the shell.
- When a batch file ends, the ERRORLEVEL is its last command's, or the code `exit /b` gave, and its return code is its last command's (0 for `exit /b`).
- In a `.cmd` file, a `set`, `path` or `prompt` that succeeds sets ERRORLEVEL to 0; in a `.bat` file, it leaves it.
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
| `$+` | Nothing (one `+` per `pushd` level: there is no `pushd`).    |

Any other code shows nothing, and so does a `$` that ends the text.

## Exit status

| Code                           | When                                                    |
| ------------------------------ | ------------------------------------------------------- |
| `code`                         | `exit code`, or `exit /b code` outside a batch file.    |
| 0                              | `exit` alone, or the console's input ended.             |
| The last command's return code | `/C`, once the string has run.                          |
| The ERRORLEVEL                 | `exit /b` alone outside a batch file.                   |
| 1                              | The console's input could not be read.                  |

When the console's input cannot be read, the shell prints `cmd: the standard input cannot be read (error N)` on the standard error.

A command's return code is not the ERRORLEVEL, though they are often the same:

| Return code   | Of                                                                                                                  |
| ------------- | ------------------------------------------------------------------------------------------------------------------- |
| The exit code | A program, once it ends.                                                                                            |
| 9009          | A command not recognized.                                                                                           |
| 1             | A built-in command that fails (each one that sets ERRORLEVEL to 1 below); a program that cannot be started.         |
| 0             | Any other built-in command, `exit /b code` included.                                                                |
| Its last one  | A batch file, and `call`.                                                                                           |

So `cmd /c` of a batch file ends with 7 when its last line runs a program that exits with 7, and with 0 when its last line is an `echo` or `exit /b 3`, whatever the ERRORLEVEL.

The ERRORLEVEL is 0 when the shell starts, and changes only as these say:

| ERRORLEVEL    | Set by                                                                                                                               |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| The exit code | A program, once it ends.                                                                                                             |
| 9009          | A command not recognized.                                                                                                            |
| `code`        | `exit /b code` in a batch file.                                                                                                      |
| 1             | A failed `cd` or `type`; `set` with no match, nothing to delete or no name; a batch file not opened; a `/C` or `/K` string too long. |
| 0             | A `cd`, `type` or `ver` that succeeds; in a `.cmd` batch file, a `set`, `path` or `prompt` that succeeds.                            |

Anything else leaves the ERRORLEVEL as it is: `echo`, `rem` and `cls` never change it.

## Environment variables

| Variable                                                                    | Use                                                                                                                        |
| --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `PATH`                                                                      | Read: the directories programs are looked for in. `path` shows and sets it. Unset, only the current directory is searched. |
| `PATHEXT`                                                                   | Read: the extensions programs are looked for with. Unset, `.COM;.EXE;.BAT;.CMD`.                                           |
| `PROMPT`                                                                    | Read: the prompt's text. `prompt` sets and deletes it. Unset, `$P$G`.                                                      |
| `ERRORLEVEL`, `CD`, `DATE`, `TIME`, `RANDOM`, `CMDEXTVERSION`, `CMDCMDLINE` | Dynamic variables, when the environment has none of the name (see [Dynamic variables](#dynamic-variables)).                |

The shell does not read or set `COMSPEC`.
`set` sets and deletes any variable, and the programs the shell starts get its environment.

## Differences from Windows 2000

- The banner, `ver` and `$V` show `F2K [Version 5.00.2195]`; Windows 2000 shows `Microsoft Windows 2000 [Version 5.00.2195]`, and its banner has a copyright line too.
- There is no redirection (`<`, `>`, `>>`, `2>`), no pipe (`|`), no chaining of commands (`&`, `&&`, `||`), no grouping in parentheses and no `^` escape: these characters are part of the line, handed as they are to the command or the program.
- These built-in commands of Windows 2000's are not there: `assoc`, `break`, `color`, `copy`, `date`, `del` and `erase`, `dir`, `endlocal`, `for`, `ftype`, `goto`, `if`, `md` and `mkdir`, `move`, `pause`, `popd`, `pushd`, `rd` and `rmdir`, `ren` and `rename`, `setlocal`, `shift`, `start`, `time`, `title`, `verify` and `vol`.
  Their names are looked for as programs, and are not recognized (ERRORLEVEL 9009).
- Neither the shell nor its commands take `/?`: `cmd /?` starts the shell, and `echo /?` prints `/?`.
- `set` has no `/A` or `/P`: `set /a` lists the variables whose names start with `/a`.
- `%VAR:old=new%`, `%~` with modifier letters (`%~dp0`) and delayed expansion (`!VAR!`) are not expanded.
- `call` takes no label (`call :name`) and does not expand its line a second time.
- `cd` has no `/D` switch and does not remove quotes.
- `/A`, `/U`, `/D`, `/E`, `/F`, `/V` and `/T` are ignored: command extensions are always on, and there is no AutoRun command, no file name completion, no delayed expansion and no colour.
- Commands are read from the console only: with the standard input redirected from a file or a pipe, the shell ends at once with 1 (`/C` reads nothing, so it is unaffected).
- A batch file is opened once and read through: changing it while it runs changes nothing.
- Batch files nest 32 deep at most.
- A program that cannot be started for another reason than its absence is reported as `'word' cannot be run (error N).`.
- `$D`, `$T`, `%DATE%` and `%TIME%` always use the US format.

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

Its source is `src/main.rs` (the program) and the library beside it, tested on the host by `make run-tests`: `src/lib.rs` (lines, built-in commands, expansion and the prompt), `src/switches.rs` (the command line), `src/search.rs` (how programs are found) and `src/batch.rs` (batch files).
`tests/core/test_cmd.py` types at its prompt, and runs it with `/C`, on QEMU.
