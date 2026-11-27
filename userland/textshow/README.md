# textshow

`textshow.exe` shows a window whose client area is drawn with gdi32's text layout: alignment, the current position, character extra, justification, `PolyTextOutW` and text through a mapping mode, so their drawing can be looked at.
It is a test program: `tests/core/test_textshow.py` takes a screenshot of it.

## Usage

```text
textshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

The window has a caption with its system menu and a fixed frame, the title "Text Layout", centred on the screen.
Its client area is 260 by 200 pixels, white, drawn in its `WM_PAINT` in the stock System font, black text on yellow or cyan opaque cells:

- top row: "Ab" at three reference points, each marked by a red pixel: `TA_LEFT | TA_TOP` at (10, 8), `TA_CENTER | TA_BASELINE` at (80, 21), `TA_RIGHT | TA_BOTTOM` at (150, 24), their cells all in rows 8 to 23;
- `TA_UPDATECP` from `MoveToEx(10, 32)`: "Ab" yellow, "Hello" cyan, "Ab" yellow, side by side;
- `SetTextCharacterExtra(4)`: "Hello" at (10, 56), cyan;
- `SetTextJustification(40, 2)`: "a b c" at (10, 80), yellow, its two spaces 20 pixels wider each;
- `PolyTextOutW`: "Ab" at (10, 104), and "abc" at (130, 104) with `ETO_OPAQUE` over (120, 104) to (250, 124);
- `MM_ANISOTROPIC` at 2 pixels a unit from (10, 140): "Ab" under `TA_RIGHT` at logical (20, 0), its cells ending at (50, 140).

It prints `textshow: ready` once the window shows and its queue is idle.
Closing the window (Alt+F4) ends it with exit code 0; it ends with 1 if the window cannot be made.
