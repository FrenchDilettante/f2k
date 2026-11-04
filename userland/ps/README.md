# ps

`ps.exe` lists the running processes.

## Usage

```text
ps
```

## Arguments

None.
Anything on the command line is ignored.

## Output

A header line, then one line per process, sorted by process ID, each line ended by CR LF:

| Column | Meaning                                                                                                        |
| ------ | -------------------------------------------------------------------------------------------------------------- |
| `PID`  | The process's ID: 0 for the idle process, 8 for the System process.                                            |
| `PPID` | The ID of the process that created it; 0 for a program the boot started and for the idle and System processes. |
| `THR`  | How many threads it has; 0 for a process created without one yet.                                              |
| `PRI`  | Its base priority: 8 for the normal priority class and the System process, 0 for the idle process.             |
| `NAME` | Its image's file name, with its extension, cut at 15 characters; `[System Process]` for the idle process.      |

The idle process holds the idle thread; the System process holds the kernel's system threads (today one, the console's control thread).
A process that has ended is not listed, even while a handle still holds it open.

The numbers are right-aligned under their headings, and a number wider than its column widens it.
The name follows two spaces after `PRI`.
The list is a ToolHelp snapshot (`CreateToolhelp32Snapshot`), so `ps` lists itself.

```text
  PID  PPID  THR  PRI  NAME
    0     0    1    0  [System Process]
    8     0    1    8  System
   16     0    1    8  sched.exe
   24     0    1    8  ps.exe
```

To a console the lines are written as UTF-16 (`WriteConsoleW`); to a file or a pipe they are converted to the OEM code page.

## Exit status

| Code | When                                                                            |
| ---- | ------------------------------------------------------------------------------- |
| 0    | The list was printed.                                                           |
| 1    | The processes could not be listed, or the standard output could not be written. |

On a failure, `ps` writes one of these lines to the standard error, `N` being the Win32 error code:

```text
ps: the processes cannot be listed (error N)
ps: the standard output cannot be written (error N)
```

When the listing fails partway, the lines already printed stay.

## Environment

`ps` reads no environment variables.

## Differences from Windows 2000

Windows 2000 has no `ps` program.
Compared with what Windows 2000's process listing holds:

- there is no CPU-time column, nor any other column than the five above;
- `ps` takes no arguments: it always lists every process;
- the System process holds one thread where Windows 2000's holds many.

## Example

A boot that runs `sched.exe`'s sleep section and `ps.exe` side by side:

```text
concurrent -- CORPUS\sched.exe sleep ;; WINNT\system32\ps.exe
```

prints a list like the one under [Output](#output), `sched.exe` still asleep in it, then `ps` ends with 0 and `sched.exe` after it.

## Building and installing

`make userland` builds `ps.exe` into `target/userland/i686-f2k-pe/release/`, and `make disk` copies it to `\WINNT\system32` on the disk image, beside the system DLLs.
Its source is `src/main.rs` (the program) and `src/lib.rs` (the lines it prints and their order, tested on the host by `make run-tests`).
A boot runs it when the kernel command line names it: `-- WINNT\system32\ps.exe`.
