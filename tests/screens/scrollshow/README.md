# scrollshow

`scrollshow.exe` shows a window with both standard scroll bars and two ScrollBar controls, so their drawing can be looked at.
It is a test program: `test_scrollbars.py`, beside it, takes a screenshot of it.

## Usage

```text
scrollshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

The window has a caption with its system menu, a fixed frame and both scroll bars, the title "Scroll bars", centred on the screen.
Its client area, scroll bars included, is 260 by 200 pixels: its window's size comes from `AdjustWindowRectEx`.

- The vertical bar: range 0-99, page 20, position 30.
- The horizontal bar: range 0-49, page 10, position 0, its left arrow disabled.
- A horizontal ScrollBar control at (20, 30), 160 by 17: range 0-10, position 5.
- A vertical ScrollBar control at (200, 20), 17 by 120: range 0-4, both arrows disabled.

It prints `scrollshow: ready` once the window shows and its queue is idle.
Closing the window (Alt+F4) ends it with exit code 0; it ends with 1 if a window cannot be made.
