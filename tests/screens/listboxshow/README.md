# listboxshow

`listboxshow.exe` shows a window with three ListBox controls, so their drawing can be looked at.
It is a test program: `test_listboxes.py`, beside it, takes a screenshot of it.

## Usage

```text
listboxshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

The window has a caption with its system menu and a fixed frame, the title "List boxes", centred on the screen.
Its client area is 300 by 200 pixels, in the 3D face colour: its window's size comes from `AdjustWindowRectEx`.

- A list box at (10, 10), 130 by 180, with a border and a vertical scroll bar: fifteen items, the third selected, the focus on it (its focus rectangle drawn), more items than show (the scroll bar shown).
- A multiple-selection list box at (160, 10), 130 by 100, with a border: five items, the first and the fourth selected, no scroll bar.
- A disabled list box at (160, 130), 130 by 60, with a border: two items, its text greyed.

It prints `listboxshow: ready` once the window shows and its queue is idle.
Closing the window (Alt+F4) ends it with exit code 0; it ends with 1 if a window cannot be made.
