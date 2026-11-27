# shapeshow

`shapeshow.exe` shows a window whose client area is drawn with gdi32's pens, lines and shapes, so their drawing can be looked at.
It is a test program: `tests/core/test_shapeshow.py` takes a screenshot of it.

## Usage

```text
shapeshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

The window has a caption with its system menu and a fixed frame, the title "Shapes", centred on the screen.
Its client area is 260 by 200 pixels, white, drawn in its `WM_PAINT`:

- a Rectangle with a red brush, an Ellipse with a blue one and a RoundRect with a green one, each outlined in black;
- a pentagram Polygon under `WINDING` with a yellow brush, a width-3 red Polyline, and one horizontal line in each cosmetic style (`PS_SOLID`, `PS_DASH`, `PS_DOT`, `PS_DASHDOT`, `PS_DASHDOTDOT`);
- a width-9 blue corner under each `ExtCreatePen` join (miter, bevel, round), a width-5 green `PS_INSIDEFRAME` Ellipse with the null brush, and an `R2_NOT` Rectangle outline over a black bar.

It prints `shapeshow: ready` once the window shows and its queue is idle.
Closing the window (Alt+F4) ends it with exit code 0; it ends with 1 if the window cannot be made.
