# pwd

`pwd.exe` prints the current directory.

## Usage

```text
pwd
```

## Arguments

None.
Anything on the command line is ignored.

## Output

One line: the current directory as `GetCurrentDirectoryW` gives it, then CR LF.
A directory has no trailing backslash, except a drive's root (`C:\`).

To a console the line is written as UTF-16 (`WriteConsoleW`); to a file or a pipe it is converted to the OEM code page.
An unpaired surrogate in the directory's name shows as U+FFFD.

## Exit status

| Code | When                                                                                  |
| ---- | ------------------------------------------------------------------------------------- |
| 0    | The directory was printed.                                                            |
| 1    | The current directory could not be read, or the standard output could not be written. |

On a failure, `pwd` writes one of these lines to the standard error and nothing to the standard output, `N` being the Win32 error code:

```text
pwd: the current directory cannot be read (error N)
pwd: the standard output cannot be written (error N)
```

## Environment

`pwd` reads no environment variables.

## Differences from Windows 2000

Windows 2000 has no `pwd` program: its `cmd.exe` prints the current directory with `cd` alone.
`pwd` prints the same line.

## Example

```text
C:\WINNT\system32>pwd
C:\WINNT\system32

C:\WINNT\system32>cd \

C:\>pwd
C:\
```

## Building and installing

`make userland` builds `pwd.exe` into `target/userland/i686-f2k-pe/release/`, and `make disk` copies it to `\WINNT\system32` on the disk image, beside the system DLLs.
Its source is `src/main.rs` (the program) and `src/lib.rs` (the line it prints, tested on the host by `make run-tests`).
A boot runs it when the kernel command line names it: `-- WINNT\system32\pwd.exe`.
