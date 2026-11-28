# mapshow

`mapshow.exe` shows a window whose client area is drawn through gdi32's mapping modes and saved DC states, so their drawing can be looked at.
It is a test program: `test_mapshow.py`, beside it, takes a screenshot of it.

## Usage

```text
mapshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

The window has a caption with its system menu and a fixed frame, the title "Mapping", centred on the screen.
Its client area is 260 by 200 pixels, white, drawn in its `WM_PAINT`, each part between `SaveDC` and `RestoreDC`:

- top left, in `MM_ANISOTROPIC` at 8 pixels a logical unit: a picture in a 10 by 10 logical square (a yellow square, a red Rectangle, a blue Ellipse, a green RoundRect, a black `PatBlt` mark at the logical origin, and a line past the square's corner), clipped to the square by `IntersectClipRect`;
- top middle: the same picture flipped, y up (a negative viewport extent);
- top right: an 8 by 8 bitmap (a black top row and left column, a red pixel) blitted by `BitBlt` through a mapping 4 times larger, upright and flipped;
- bottom left: in `MM_ISOTROPIC`, a 100 by 100 window asked onto a 240 by -90 viewport: the circle `Ellipse(0, 0, 100, 100)` stays round, 90 pixels across;
- bottom right, once every state is restored: a green Rectangle in `MM_TEXT`'s client coordinates.

It prints `mapshow: ready` once the window shows and its queue is idle.
Closing the window (Alt+F4) ends it with exit code 0; it ends with 1 if the window cannot be made.
