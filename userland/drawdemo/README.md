# drawdemo

`drawdemo.exe` draws a sample sheet of user32's drawing calls in a window, for a screenshot to compare by eye with Windows 2000 drawing the same.
It is F2K's own: no test reads its pixels against a capture.

## Usage

```text
fish \WINNT\system32\drawdemo.exe
```

It needs the graphics mode, which FiSH sets before it runs it.

## Arguments

None.
Anything on the command line is ignored.

## What it draws

A borderless window at (20, 20), 600 by 440 pixels, its client area filled with `COLOR_3DFACE`:

- the edges `EDGE_RAISED`, `EDGE_SUNKEN`, `EDGE_ETCHED` and `EDGE_BUMP`, and a soft raised one (`BF_SOFT`), each with `BF_MIDDLE` and its label centered in it;
- three solid brushes' fills, a band inverted across them (`InvertRect`), and two frames (`FrameRect`: the black stock brush's, and `COLOR_3DSHADOW`'s inside it);
- a focus rectangle (`DrawFocusRect`) around a label, and another drawn through `GetDC`'s DC after the paint;
- `DrawText`'s alignments in a framed box (top left, centered, bottom right), a paragraph `DT_WORDBREAK` wraps with an underlined mnemonic, tabs `DT_EXPANDTABS` expands, and a line in the rectangle `DT_CALCRECT` bounds, framed;
- a dialog's two push buttons: the default one framed in black with the focus inside, and a plain one.

The window paints once, in its `WM_PAINT`, through `BeginPaint`'s DC, then quits.
The screen keeps the drawing after it ends.

## Exit status

| Code | When                                                   |
| ---- | ------------------------------------------------------ |
| 0    | The sheet was drawn.                                   |
| 1    | The window class could not be registered, or the window could not be made. |
