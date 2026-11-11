# dlgshow

`dlgshow.exe` shows a dialog of user32's dialog manager and prints what the keyboard does to it.
It is a test program: `tests/core/test_dialogs.py` takes a screenshot of it and types into it.

## Usage

```text
dlgshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

The dialog is made from a template in memory (`CreateDialogIndirectParamW`), centred on the screen in the dialog font ("MS Shell Dlg", 8 points): a line of static text, the default push button OK, the push button Cancel, the auto check box "Keep the window", the group box "Mode" around the auto radio buttons "Standard" (checked) and "Scientific", and an etched line.
Its message loop hands every message to `IsDialogMessageW`.

Once the dialog shows and its queue is empty (painted, the focus on OK), one line:

```text
dlgshow: ready, focus 1
```

Then one line for each key-down the dialog takes, with the id of the control that has the focus after it, and one for each command its procedure receives:

```text
key 0x09: focus 2
key 0x09: focus 101
key 0x20: focus 101
WM_COMMAND id=101 code=0
```

OK or Cancel (Enter, Esc, or the buttons' commands) ends it, with a last line saying which and the options' states:

```text
WM_COMMAND id=1 code=0
dlgshow: OK, keep 1, mode standard
```

## Exit status

| Code | When                         |
| ---- | ---------------------------- |
| 0    | OK or Cancel ended it.       |
| 1    | The dialog could not be made. |

On a failure, `dlgshow` writes one line to the standard error:

```text
dlgshow: the dialog cannot be made
```

## Environment

`dlgshow` reads no environment variables.

## Differences from Windows 2000

Windows 2000 has no `dlgshow` program.
It runs on Windows 2000 too, where its dialog must be allowed the foreground to take typed keys.

## Building and installing

`make userland` builds `dlgshow.exe` into `target/userland/i686-f2k-pe/release/`.
The disk the tests boot leaves it out: its test adds it to a copy of the disk, in `\WINNT\system32`, with the system's fonts.
Its source is `src/main.rs` (the program) and `src/lib.rs` (its template and the lines it prints, tested on the host by `make run-tests`).
