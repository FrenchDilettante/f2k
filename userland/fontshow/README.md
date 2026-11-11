# fontshow

`fontshow.exe` draws lines of text on the screen through gdi32's `TextOutW`, to be looked at: the stock fonts, then each face the system loads at its start from `\WINNT\Fonts` (Wine's Tahoma, Tahoma Bold, MS Sans Serif, System and Marlett) at the sizes the user interface uses.

It is a test program: the disk the tests boot does not carry it, nor the fonts.
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

The screen: sixteen lines of black text on white cells, from the top left.

| Row | Font                                                                            |
| --- | ------------------------------------------------------------------------------- |
| 8   | the stock `SYSTEM_FONT` (the System face, a DC's default)                       |
| 30  | the stock `DEFAULT_GUI_FONT` ("MS Shell Dlg" at 8 points: MS Sans Serif)        |
| 52  | Tahoma, lfHeight -11 (8 points at 96 DPI)                                       |
| 70  | Tahoma, -13                                                                     |
| 90  | Tahoma, -16                                                                     |
| 114 | Tahoma, -24 (from the outlines: no strike)                                      |
| 150 | Tahoma, -11, weight 700 (the Tahoma Bold face)                                  |
| 168 | Tahoma, -13, weight 700 (Tahoma Bold)                                           |
| 190 | "MS Shell Dlg 2", -11 (Tahoma's substitute)                                     |
| 210 | "MS Shell Dlg", -11 (MS Sans Serif, standing in for Microsoft Sans Serif)       |
| 232 | MS Sans Serif, a cell of 13 (its 8-point strike)                                |
| 252 | MS Sans Serif, 16                                                               |
| 276 | MS Sans Serif, 20                                                               |
| 306 | System, 16 (its strike of the stock font)                                       |
| 330 | System, 18                                                                      |
| 362 | Marlett, -16: minimise, maximise, restore and close; the four arrows; the check mark |

On its standard output, one line per font: its row, the face name `GetTextFaceW` answers, and the cell height, average width, weight and kind (TrueType or not) `GetTextMetricsW` answers.

## Exit status

| Code | When                                                                                                                       |
| ---- | -------------------------------------------------------------------------------------------------------------------------- |
| 0    | Every call succeeded, and every face asked for by name was that face, of its kind (the built-in font never answered for it). |
| 1    | The screen DC could not be made, a call failed, or a face was missing.                                                     |
