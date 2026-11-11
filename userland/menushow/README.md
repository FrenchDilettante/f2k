# menushow

`menushow.exe` shows a window with a caption, a border and a menu bar, and prints the menu messages the keyboard makes it receive.
It is a test program: `tests/core/test_nonclient.py` takes screenshots of it and types into it.

## Usage

```text
menushow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

The window has calc's styles (a caption with its system menu and minimize box, a fixed frame) and the title "Calculator", centred on the screen.
Its client area is 260 by 200 pixels: its window's size comes from `AdjustWindowRectEx`.
Its menu bar is calc's, built with `CreateMenu`, `CreatePopupMenu` and `AppendMenuW`: Edit (Copy, and Paste grayed), View (the radio items Standard and Scientific, Standard checked, a separator, Digit grouping) and Help (Help Topics, a separator, About Calculator).

Once the window shows and its queue is empty, one line:

```text
menushow: ready
```

Then one line for each menu message its procedure receives, which it hands on to `DefWindowProcW` (so the default window procedure runs the keyboard menu loop):

```text
WM_SYSCOMMAND 0xF100 lParam=0
WM_ENTERMENULOOP 0
WM_INITMENU the bar
WM_MENUSELECT 0 flags 0x0090 the bar
WM_ENTERIDLE 2
```

`WM_SYSCOMMAND`, `WM_ENTERMENULOOP`, `WM_EXITMENULOOP`, `WM_INITMENU`, `WM_INITMENUPOPUP`, `WM_UNINITMENUPOPUP`, `WM_MENUSELECT`, `WM_ENTERIDLE` and `WM_COMMAND` are printed, with their parameters as numbers and the menus they name by name: "the bar", "Edit", "View", "Help", "NULL".

A command from View's radio items moves the radio check to it.
After a command, once the queue is empty again, one line:

```text
menushow: settled
```

Closing the window (Alt+F4) ends it.

## Exit status

| Code | When                          |
| ---- | ----------------------------- |
| 0    | Its window was closed.        |
| 1    | The window could not be made. |

On a failure, `menushow` writes one line to the standard error:

```text
menushow: the window cannot be made
```

## Environment

`menushow` reads no environment variables.

## Differences from Windows 2000

Windows 2000 has no `menushow` program.
It runs on Windows 2000 too, where its window must be allowed the foreground to take typed keys.

## Building and installing

`make userland` builds `menushow.exe` into `target/userland/i686-f2k-pe/release/`.
The disk the tests boot leaves it out: its test adds it to a copy of the disk, in `\WINNT\system32`, with the system's fonts.
Its source is `src/main.rs` (the program) and `src/lib.rs` (its menu and the lines it prints, tested on the host by `make run-tests`).
