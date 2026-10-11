# F2K Test Corpus

C programs compiled on a real Windows 2000 machine with the era's
toolchain. They are the compatibility baseline: every test is a real
PE32 executable whose imports and behavior are dictated by that
environment, not by what F2K happens to implement.

## Conventions

- One `.c` file per test; the file stem is the test name.
- Compiled binaries go in `bin/<name>.exe` and are committed to the
  repository. They are small and they are the point.
- Exit code 0 means pass. A test that wants to distinguish failures
  returns distinct nonzero codes and documents them in its header.
- Tests are ordered by what they exercise: each test should add a
  bounded, known amount of API surface to the previous one.
- When adding a test, record the actual `dumpbin /dependents` output
  in the inventory below (observed on the build machine, not assumed).

## Building

On a real Windows 2000 machine (MSVC 6):

```
cl /nologo exit0.c /link /NODEFAULTLIB /ENTRY:ExitMain /SUBSYSTEM:CONSOLE kernel32.lib
cl /nologo ret0.c
```

## Inventory

| Test    | Entry                  | Expected exit | Imports exercised                                          |
|---------|------------------------|---------------|------------------------------------------------------------|
| `exit0` | `ExitMain` (no CRT)    | 0             | `ExitProcess` only                                         |
| `ret0`  | `mainCRTStartup` (CRT) | 0             | CRT startup surface (`GetVersion`, `GetCommandLineA`, `GetStartupInfoA`, `Heap*`, `ExitProcess`, ...) - confirm with `dumpbin /dependents ret0.exe` |

## How F2K consumes these

Until F2K can read from its FAT32 disk partition, the QEMU boot smoke
test embeds a fixture directly in the kernel image (`include_bytes!`)
and prints the observed process exit code on COM1. The pass criterion
is the expected exit code from the inventory above. Once disk I/O
exists, fixtures load from the disk image instead and the embedding
goes away.
