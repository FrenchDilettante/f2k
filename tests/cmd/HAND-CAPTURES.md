# cmd.exe hand captures

What the script fixtures cannot capture: the interactive prompt, Ctrl+C and Ctrl+Break, and the few cases that would open a window or need a dialog closed.
Each item below is done by hand on the Windows 2000 machine, in one console session, and its result pasted under it.

## Where the results go

A script fixture's capture is one block, `>>> cmd /c <name>.cmd`, and `f2kboot` refuses any other block in it, so these results cannot go into a script fixture's `output.txt` or `overrides.txt`.
The ctrl fixture's interactive block (`tests/kernel32/ctrl/`) is different: `keys` is a section of a program (`F2KT_INTERACTIVE` in `ctrl.c`), captured by hand into `overrides.txt` as `>>> ctrl.exe keys`, and its `[keys]` table lets the harness press the same keys on F2K.
Nothing here is a program's section, so each result goes into the **Result** block under its item, in this file, as the screen shows it.
They settle the open lines of the cmd.exe assumption notes, and they are the expectations for a later test that types at F2K's prompt, as `tests/core/test_cmd.py` does.

## Setup

1. Start a console: Start, Run, `cmd`, OK.
   Leave the window at its defaults (80 columns, a 25-row window over a 300-row buffer) unless an item says otherwise.
2. Go to the script fixtures' directory and copy the spawn fixture's companion beside you:

   ```text
   cd /d <the tests directory>\cmd
   copy ..\kernel32\spawn\spawnkid.exe .
   prompt $G
   ```

   `prompt $G` keeps paths off the screen; `spawnkid exit N` exits with N, `spawnkid sleep N` sleeps N milliseconds.
3. To copy the screen: the window menu (top left), Edit, Select All, then Enter.
   Paste into the item's **Result** block, empty rows included: the rows are what is being observed.
4. At the end: `del spawnkid.exe`, and delete every `bat*` file an item made (each item names its files).

## 1. The prompt's empty lines

Assumption: an empty line comes before the prompt after every non-empty command; an empty line typed alone prompts again with no empty line between the two prompts.

1. `cls`, Enter.
2. `ver`, Enter.
3. Enter alone, twice.
4. Three blanks, Enter.
5. `echo x`, Enter.

Note the rows from the first prompt to the last.

**Result:**

```text
```

## 2. The prompt after cls

Assumption: after `cls` the prompt is on the screen's top row, with no empty line before it.

1. `echo before`, Enter.
2. `cls`, Enter.
3. `echo after`, Enter.

Note the screen's first three rows.

**Result:**

```text
```

## 3. Echo off in a batch file, then the prompt

Assumption: a batch file's `echo off` does not outlast it at the prompt.

1. `> batecof.cmd echo @echo off`, Enter.
2. `batecof`, Enter.
3. Enter alone.
4. `del batecof.cmd`, Enter.

Note whether the prompt shows after the batch file ends.

**Result:**

```text
```

## 4. Ctrl+C and Ctrl+Break at the prompt

Assumption: the console leaves what was typed, no `^C` is shown, the next prompt comes on the row below with no empty line between, and the ERRORLEVEL is unchanged.

1. `spawnkid exit 3`, Enter.
2. Type `ab`, no Enter, then press Ctrl+C.
3. `echo %ERRORLEVEL%`, Enter.
4. Type `ab`, no Enter, then press Ctrl+Break.
5. `echo %ERRORLEVEL%`, Enter.

Note whether `^C` shows after `ab`, the rows between `ab` and the next prompt, and both ERRORLEVELs (3 if unchanged).

**Result:**

```text
```

## 5. Ctrl+C and Ctrl+Break while a program runs

Assumption: the program ends with 0xC000013A (ERRORLEVEL -1073741510), and cmd.exe prints nothing for the key.

1. `spawnkid sleep 10000`, Enter, then press Ctrl+C within a few seconds.
2. `echo %ERRORLEVEL%`, Enter.
3. `spawnkid sleep 10000`, Enter, then press Ctrl+Break within a few seconds.
4. `echo %ERRORLEVEL%`, Enter.

Note whether `^C` shows, the rows before the next prompt, and both ERRORLEVELs.

**Result:**

```text
```

## 6. Ctrl+C in a batch file: Terminate batch job (Y/N)?

Assumptions: the question is `Terminate batch job (Y/N)?` and a blank, with no `^C` before it; `y` ends every running batch file, `n` goes on; any other answer asks again; Ctrl+C at the question asks again on a new line; answering leaves the ERRORLEVEL as it was.

Make three batch files in Notepad (`notepad batctrl.cmd` and so on, Yes to create each), one command per line:

- `batctrl.cmd`: `@echo off`, `echo before`, `spawnkid exit 3`, `spawnkid sleep 10000`, `echo after, ERRORLEVEL %ERRORLEVEL%`.
- `batctrl2.cmd`: `@echo off`, `spawnkid exit 3`, `pause`, `echo after the pause, ERRORLEVEL %ERRORLEVEL%`.
- `batctrl3.cmd`: `@echo off`, `call batctrl`, `echo back in batctrl3`.

Then:

1. `batctrl`, Enter; once `before` shows, press Ctrl+C.
   At the question, type `x` and Enter; then press Ctrl+C; then type `n` and Enter.
   Then `echo %ERRORLEVEL%`, Enter.
2. `batctrl`, Enter; once `before` shows, press Ctrl+C; answer `y` and Enter.
   Then `echo %ERRORLEVEL%`, Enter.
3. `batctrl2`, Enter; at `Press any key to continue . . .`, press Ctrl+C; answer `n` and Enter.
4. `batctrl3`, Enter; once `before` shows, press Ctrl+C; answer `y` and Enter.
   Note whether `back in batctrl3` shows (whether `y` ends the caller too).
5. `del batctrl.cmd batctrl2.cmd batctrl3.cmd`, Enter.

Note, for each: whether `^C` shows before the question, the question's exact text and where the cursor waits, what `x` and Ctrl+C at the question print, the `after` lines' ERRORLEVEL (the one after answering, since the line is read after it), and the ERRORLEVEL at the prompt.

**Result:**

```text
```

## 7. set /? on a short console

Assumption: the help is printed whole, never paged.

1. The window menu, Properties, Layout: screen buffer height 25, window height 25; OK, this window only.
2. `set /?`, Enter.
   If `Press any key to continue . . .` shows, note after how many rows, and press Space until the prompt comes back.
3. The same for `cmd /?`, `for /?` and `if /?`.
4. `set /? > batpage.txt`, Enter: note whether it comes back at once, with no key pressed.
5. `del batpage.txt`, and the buffer height back to 300.

**Result:**

```text
```

## 8. cmd with a word that is not a switch

Assumption: `cmd foo` starts an interactive shell and ignores the word.

1. `cmd foo`, Enter.
2. If a prompt comes: `exit`, Enter.
3. `echo %ERRORLEVEL%`, Enter.

Note the rows `cmd foo` printed (a banner, the prompt) and what `exit` returned to.

**Result:**

```text
```

## 9. A file of another type typed as a command

Assumption (contradicted by `start /?`): a name with an extension PATHEXT does not list gets PATHEXT's extensions appended, and is not found.
`start /?` says it opens through its file association; a script cannot try it, as it would wait on the window.

1. `echo hello> batassoc.txt`, Enter.
2. `batassoc.txt`, Enter: note whether Notepad opens, and whether the prompt comes back before you close it.
   Close Notepad, then `echo %ERRORLEVEL%`, Enter.
3. `> batassoc.cmd echo batassoc.txt`, Enter, then `>> batassoc.cmd echo echo after`, Enter.
4. `batassoc`, Enter: note whether `after` shows before you close Notepad.
   Close Notepad.
5. `echo hello> batassoc.zzq`, Enter, then `batassoc.zzq`, Enter: an extension with no association.
   Note what shows (a message, or an Open With dialog: cancel it), then `echo %ERRORLEVEL%`, Enter.
6. `del batassoc.txt batassoc.cmd batassoc.zzq`, Enter.

**Result:**

```text
```

## 10. A program that cannot be started

Assumption: a program found but not started prints `'x' cannot be run (error N).` and leaves ERRORLEVEL unchanged.
A script cannot try it: Windows 2000 hands an `.exe` that is not a Windows image to NTVDM, which may hang or open a window.

1. `type nul > batbad.exe`, Enter (an empty file).
2. `spawnkid exit 3`, Enter, then `batbad`, Enter.
   Note what shows; if a window or a dialog opens, note its text and close it.
3. `echo %ERRORLEVEL%`, Enter.
4. `echo hello> batbad.exe`, Enter (text, no executable header), and steps 2 and 3 again.
5. `del batbad.exe`, Enter.

**Result:**

```text
```

## 11. A batch file that cannot be opened

Assumption: its error's text is printed and ERRORLEVEL is 1.
Needs an NTFS directory (the capture volume is FAT32); `%TEMP%` on the system drive is usually one.

1. `pushd %TEMP%`, Enter.
2. `echo @echo hello> batdeny.cmd`, Enter.
3. `cacls batdeny.cmd /E /D %USERNAME%`, Enter: it denies you every access to the file.
4. `echo %ERRORLEVEL%`, Enter, then `batdeny`, Enter, then `echo %ERRORLEVEL%`, Enter.
5. `call batdeny`, Enter, then `echo %ERRORLEVEL%`, Enter.
6. `cacls batdeny.cmd /E /R %USERNAME%`, Enter, then `del batdeny.cmd`, Enter, then `popd`, Enter.

Note the message each run prints and the ERRORLEVELs before and after.

**Result:**

```text
```

## 12. A UTF-16 file with a byte-order mark

Assumption: `type` copies a file's bytes unchanged, a byte-order mark included.
A script cannot write the mark: its files are ASCII, and `cmd /u` writes UTF-16 without one (`batstd` types such a file).

1. `notepad batbom.txt`, Enter, Yes to create it; type `one`, then File, Save As, Encoding: Unicode, Save; close Notepad.
2. `type batbom.txt`, Enter: note what shows.
3. `type batbom.txt > batbom.out`, Enter, then `dir batbom.*`, Enter: note both sizes.
4. `del batbom.txt batbom.out`, Enter.

**Result:**

```text
```

## 13. $T before ten o'clock

Assumption: `$T` pads an hour below 10 with a blank (` 9:05:03.00`).
Only when the clock shows an hour below 10; otherwise set it and set it back.

1. `time /t`, Enter: note the time, to restore it.
2. If the hour is 10 or later: `time 09:05:00`, Enter.
3. `prompt $T$G`, Enter, then Enter alone; then `echo [%TIME%]`, Enter.
4. `prompt $G`, Enter; restore the time with `time`, if it was changed.

**Result:**

```text
```
