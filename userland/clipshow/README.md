# clipshow

`clipshow.exe` shows a window that paints its whole client area over its bordered child controls, so the children's painting after it can be looked at.
It is a test program: `tests/core/test_childpaint.py` takes a screenshot of it.

## Usage

```text
clipshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

The window has a caption with its system menu and a fixed frame, the title "Child frames", centred on the screen.
Its client area is 300 by 200 pixels: its class has no background brush and no `WS_CLIPCHILDREN`, and its `WM_PAINT` fills the whole client area in teal, over its children.

- A Static at (10, 10), 120 by 40, with `WS_BORDER`: the text "Bordered" in a one-pixel black frame.
- An Edit at (10, 70), 120 by 24, with `WS_EX_CLIENTEDGE`: the text "Edit" in a sunken edge.
- A ListBox at (150, 10), 130 by 100, with `WS_BORDER` and `WS_VSCROLL`: ten items, more than show, so its scroll bar shows.

Each child paints after the window, its frame included, so the frames show over the fill.
Once the window has painted and its queue is idle, the program invalidates its whole client area again (erasing); once the queue is idle again it prints `clipshow: ready`.
Closing the window (Alt+F4) ends it with exit code 0; it ends with 1 if a window cannot be made.
