# keyshow

`keyshow.exe` makes a window that takes the keyboard and prints each keyboard message the window receives.
It is a test program: `tests/core/test_guikeys.py` types into it.

## Usage

```text
keyshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

Once its window is the foreground window and has the focus, one line:

```text
keyshow: ready
```

Then one line for each keyboard message its window procedure receives (`WM_KEYDOWN`, `WM_KEYUP`, `WM_SYSKEYDOWN`, `WM_SYSKEYUP`, `WM_CHAR`, `WM_SYSCHAR`): the message, its wParam and its lParam in hex.

```text
WM_KEYDOWN wParam=0x0041 lParam=0x001E0001
WM_CHAR wParam=0x0061 lParam=0x001E0001
WM_KEYUP wParam=0x0041 lParam=0xC01E0001
```

The window is a small bordered pop-up at (40, 40).
Its message loop calls `TranslateMessage` on each message, so a key's character follows its `WM_KEYDOWN`.
The procedure answers 0 to every keyboard message: `DefWindowProc` acts on none of them.

Escape's `WM_CHAR` destroys the window, and keyshow ends.

## Exit status

| Code | When                                                                      |
| ---- | ------------------------------------------------------------------------- |
| 0    | Escape ended it.                                                          |
| 1    | The window could not be made, or could not be made the foreground window. |

On a failure, `keyshow` writes one of these lines to the standard error:

```text
keyshow: the window cannot be made
keyshow: the window is not the foreground window
```

## Environment

`keyshow` reads no environment variables.

## Differences from Windows 2000

Windows 2000 has no `keyshow` program.
It runs on Windows 2000 too, where its window must be allowed the foreground: started from a console that is the foreground window, it is.

## Building and installing

`make userland` builds `keyshow.exe` into `target/userland/i686-f2k-pe/release/`.
The disk the tests boot leaves it out: its test adds it to a copy of the disk, in `\WINNT\system32`.
Its source is `src/main.rs` (the program) and `src/lib.rs` (the lines it prints, tested on the host by `make run-tests`).
A boot runs it when the kernel command line names it: `-- WINNT\system32\keyshow.exe`.
