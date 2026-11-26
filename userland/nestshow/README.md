# nestshow

`nestshow.exe` nests window procedures deep inside the kernel and receives another thread's message inside `GetMessage`, both through the kernel's user-mode callbacks.
It is a test program: `tests/core/test_nesting.py` runs it.

## Usage

```text
nestshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

Its window's `WM_CREATE` makes a child window of the same class, whose `WM_CREATE` makes the next, 20 levels deep, each printing `level N: WM_CREATE` as it starts and `level N: child made yes` once the window below it is made (the 20th makes none).
Then `top window made yes, 20 levels`.
A thread of its own then sends the window `WM_USER + 1` while the main thread waits in `GetMessage`: the procedure prints `WM_USER+1 wParam=7 InSendMessage=1` and answers 42, the thread prints `thread: SendMessage answered 42` and posts the message that ends the loop.
Last, the window is destroyed with its children: `destroyed yes`.

## Exit code

0, or 1 when the top window could not be made.
