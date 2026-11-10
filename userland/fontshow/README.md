# fontshow

`fontshow.exe` draws lines of text on the screen through gdi32's `TextOutW`, to be looked at: the built-in font, then Tahoma, the TrueType face the system loads at its start from `\WINNT\Fonts\tahoma.ttf`.

It is a test program: the disk the tests boot does not carry it, nor the font.
`tests/core/test_tahoma.py` boots a copy of that disk with both added, and saves the screen.

## Usage

```text
fish fontshow
```

It draws on the screen DC (`CreateDCW` of the `DISPLAY` driver), so it runs under FiSH, which sets the graphics mode first.

## Arguments

None.
Anything on the command line is ignored.

## Output

The screen: seven lines of black text on white cells, from the top left.

| Row | Font                                        |
| --- | ------------------------------------------- |
| 8   | the built-in 8x16 font (the stock font)     |
| 40  | Tahoma, lfHeight -11 (8 points at 96 DPI)   |
| 64  | Tahoma, -13                                 |
| 90  | Tahoma, -16                                 |
| 120 | Tahoma, -24 (from the outlines: no strike)  |
| 160 | Tahoma, -11, weight 700 (emboldened by GDI) |
| 184 | "MS Shell Dlg 2", -11 (Tahoma's substitute) |

On its standard output, one line per font: its height and weight, the face name `GetTextFaceW` answers, the cell height `GetTextMetricsW` answers, and whether the font is a TrueType one.

## Exit status

| Code | When                                                                                         |
| ---- | -------------------------------------------------------------------------------------------- |
| 0    | Every call succeeded, and every "Tahoma" font was the TrueType face Tahoma.                  |
| 1    | The screen DC could not be made, a call failed, or Tahoma was missing (the built-in font answered for it). |
