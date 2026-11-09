# shutdown

`shutdown.exe` shuts the local computer down, or restarts it.
Its command line is the Windows 2000 Resource Kit tool's (Microsoft KB 317371).

## Usage

```text
shutdown [\\computername] [/l] [/a] [/r] [/t:xx] ["msg"] [/y] [/c]
```

## Switches

The switches are read whatever their case.

| Switch            | Meaning                                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------ |
| `\\computername`  | The computer to shut down. Only the local computer's own name is taken (compared whatever its case).         |
| `/l`              | The local computer. Without `\\computername`, the local computer is meant anyway.                            |
| `/a`              | Abort a pending shutdown. Every other argument is then ignored.                                              |
| `/r`              | Restart the computer instead of only shutting it down.                                                       |
| `/t:xx`           | Wait `xx` seconds before the shutdown, counting down on the console. 20 without it; `/t:0` does not wait.    |
| `"msg"`           | A message shown above the countdown, 127 characters at most. Several unquoted words are joined by a blank.   |
| `/y`              | Answer yes to the question asked before the shutdown.                                                        |
| `/c`              | Force the running programs to quit: they are ended without being asked first (`EWX_FORCE`).                  |
| `/?`              | Print the usage.                                                                                             |

The arguments are split as Microsoft's C runtime splits a command line: blanks separate them, double quotes group blanks into one argument and are dropped, and backslashes are plain unless they stand before a double quote.

## What it does

1. It enables `SeShutdownPrivilege` in its own token (`OpenProcessToken`, `LookupPrivilegeValue`, `AdjustTokenPrivileges`), as every Windows program that shuts the computer down does.
2. Without `/y`, it asks `Shut down QEMU (Y/N)?` (`Restart QEMU (Y/N)?` with `/r`, `QEMU` being the computer's name), until a line answers Y or N. N, Ctrl+C or the input's end cancels: `Shutdown cancelled.`, and the program ends.
3. It prints the message, if one was given, then counts down on one line, rewritten each second:

   ```text
   Shutting down QEMU in 20 seconds (Ctrl+C cancels)
   ```

   Ctrl+C during the countdown cancels the shutdown: `Shutdown cancelled.`, and the program ends.
4. It prints `Shutting down QEMU.` (or `Restarting QEMU.`) and calls `ExitWindowsEx` with `EWX_SHUTDOWN` (or `EWX_REBOOT`), plus `EWX_FORCE` with `/c`.

`ExitWindowsEx` returns once the request is taken.
Then each program is asked to end, `shutdown` itself last: a program with windows through them (`WM_QUERYENDSESSION`, then `WM_ENDSESSION`), a console program through `CTRL_SHUTDOWN_EVENT` (a program without a handler for it ends).
The computer then stops on "It is now safe to turn off your computer." or restarts, unless a window answered FALSE, which cancels the shutdown.
As on Windows 2000, `EWX_SHUTDOWN` does not turn the power off.

## Exit status

| Code | When                                                                                                                                   |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | The shutdown was asked for (`ExitWindowsEx` succeeded), or `/?` printed the usage.                                                     |
| 1    | No shutdown was asked for: N or Ctrl+C cancelled it, the computer named is not this one, a call failed, or `/a`.                       |
| 2    | The command line has a switch `shutdown` does not take, a `/t:` without a number, or a message too long; the usage follows the reason. |

On the standard error, `N` being the Win32 error code:

```text
shutdown: \\NAME is not this computer (QEMU): only the local computer can be shut down
shutdown: the computer's name cannot be read (error N)
shutdown: the shutdown privilege cannot be enabled (error N)
shutdown: the shutdown cannot be started (error N)
shutdown: unknown switch: /x
shutdown: /T:xx takes a number of seconds: /t:x
shutdown: the message is longer than 127 characters
Unable to abort the system shutdown because no shutdown was in progress.
```

The last is `/a`'s answer, Windows' own text for `ERROR_NO_SHUTDOWN_IN_PROGRESS`.

## Environment

`shutdown` reads no environment variables.
The computer's name is `GetComputerName`'s, from the registry (`QEMU` on F2K's disk).

## Differences from the Resource Kit tool

- The Resource Kit tool asks winlogon for the shutdown (`InitiateSystemShutdown`), which counts down in a dialog and can be aborted from another command line with `/a`.
  F2K has no winlogon: `shutdown` counts down itself, on the console, and Ctrl+C cancels it.
  So no shutdown is ever pending for `/a`, which always answers that none was in progress.
- Only the local computer can be shut down: a `\\computername` naming another computer is refused.
- The question, the countdown line and the error messages are F2K's own: the Resource Kit tool's are not documented.
- On F2K no privilege is checked: the privilege calls succeed, and `ExitWindowsEx` would succeed without them.

## Example

```text
C:\WINNT\system32>shutdown /l /t:5 "Saving is over" /y
Saving is over
Shutting down QEMU in 1 second (Ctrl+C cancels)
Shutting down QEMU.
```

The countdown line goes from 5 to 1, then the session ends and the screen reads "It is now safe to turn off your computer."
`shutdown /l /r /t:0 /y` restarts the computer at once.

## Building and installing

`make userland` builds `shutdown.exe` into `target/userland/i686-f2k-pe/release/`, and `make disk` copies it to `\WINNT\system32` on the disk image, beside the system DLLs.
Its source is `src/main.rs` (the program) and `src/lib.rs` (its command line, its messages and its exit codes, tested on the host by `make run-tests`).
The program's calls to the system are the runtime's (`userland/exe`, `src/shutdown.rs`).
