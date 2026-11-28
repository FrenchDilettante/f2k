# comboboxshow

`comboboxshow.exe` shows a window with three ComboBox controls, the first one's list dropped down, so their drawing can be looked at.
It is a test program: `test_comboboxes.py`, beside it, takes a screenshot of it.

## Usage

```text
comboboxshow
```

## Arguments

None.
Anything on the command line is ignored.

## Output

The window has a caption with its system menu and a fixed frame, the title "Combo boxes", centred on the screen.
Its client area is 300 by 200 pixels, in the 3D face colour: its window's size comes from `AdjustWindowRectEx`.

- A `CBS_DROPDOWNLIST` combo box at (10, 10), 130 wide, made 150 high: six items, the third selected, the focus on it, its list dropped down below it (`CB_SHOWDROPDOWN`), cut to its six items.
- A `CBS_DROPDOWN` combo box at (160, 10), 130 wide: three items, its edit holding the text "Typed".
- A `CBS_SIMPLE` combo box at (160, 50), 130 by 140, with a vertical scroll bar: its edit above its list of five items, the second selected.

It prints `comboboxshow: ready` once the window shows and its queue is idle.
Closing the window (Alt+F4) ends it with exit code 0; it ends with 1 if a window cannot be made.
