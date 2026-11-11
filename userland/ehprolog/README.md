# ehprolog

`ehprolog.exe` calls msvcrt's `_EH_prolog` as a function Visual C++ compiles with `/O1` or `/Os` calls it, and checks the frame it builds.
It is a test program: `tests/core/test_ehprolog.py` runs it.

## Usage

```text
ehprolog
```

## Arguments

None.
Anything on the command line is ignored.

## Output

A function with C++ unwind state, compiled with `/O1`, starts with `mov eax, <handler>; call _EH_prolog`.
`ehprolog` has one such function, in assembly: it records its registers and fs:[0], sets ECX and EDX to known values, calls `_EH_prolog` with a handler in EAX, records the frame it returns with, then unlinks the registration and returns through the frame as the compiled function's epilogue does (`mov ecx, [ebp-0Ch]; mov fs:[0], ecx; mov esp, ebp; pop ebp; ret`).

Then one line for each check of what it recorded, in this order:

```text
ebp: the slot of the function's return address, less 4: ok
[ebp]: the caller's ebp: ok
[ebp-4]: -1: ok
[ebp-8]: the handler from eax: ok
[ebp-12]: the previous fs:[0]: ok
fs:[0]: ebp-12: ok
esp: ebp-12: ok
ecx: unchanged: ok
edx: unchanged: ok
[ebp+8]: the first argument: ok
fs:[0] after the epilogue: the previous fs:[0]: ok
```

A check that does not hold prints the value found and the one expected in place of `ok`:

```text
[ebp-4]: -1: 0x00000000, expected 0xffffffff
```

## Exit status

| Code | When                        |
| ---- | --------------------------- |
| 0    | Every check holds.          |
| 1    | A check does not hold.      |

## Environment

`ehprolog` reads no environment variables.

## Differences from Windows 2000

Windows 2000 has no `ehprolog` program.
It runs on Windows 2000 too, against Windows 2000's own msvcrt.dll.

## Building and installing

`make userland` builds `ehprolog.exe` into `target/userland/i686-f2k-pe/release/`.
The disk the tests boot leaves it out: its test adds it to a copy of the disk, in `\WINNT\system32`.
Its source is `src/main.rs` (the program and its function with the C++ frame) and `src/lib.rs` (the checks and the lines it prints, tested on the host by `make run-tests`).
