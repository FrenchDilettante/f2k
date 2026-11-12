# calc.exe: Windows 2000 against F2K (the two screenshots in .scratch/)

The controls' places and sizes match pixel for pixel; the differences are drawing and one size.
The captures: `../calcprobe.w2k.txt` (the probe on Windows 2000), `../com1-logs.txt` (F2K's COM1
under `fish calcprobe.exe calc.exe`, with the creation and placement trace), and the controls and
menus fixtures' new blocks.

## What the captures settled

1. **The window's height.** calc itself asks for it after creating its controls:
   `SetWindowPos(main, 0, 0, 0, 260, 462, SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE)` on F2K, where
   Windows 2000 ends at 260x252. 252 is the client's top (41: frame 3, caption 19, menu 19) plus
   208, the bottom of the last child calc makes: Static id 1000, 2x2 at (0,206), a marker no one
   sees. So calc sizes its window to that marker's place, and on F2K something it reads of the
   marker or of its own window (GetWindowRect, a mapping of points) is 210 pixels off.
   - F2K's creation call carries `x = CW_USEDEFAULT, y = -41` for the dialog (user32's dialog
     manager); worth a look against what the window's rectangle answers before the show.
   - The rerun probe (only F2K's implemented calls now) prints the main window's and every child's
     screen rectangle on both systems, which shows the off-by-210 directly.
2. **Button labels: font and white boxes.** Windows 2000's button prepares the DC before
   WM_DRAWITEM (controls `drawdc`):
   - two WM_CTLCOLORBTN to the parent first;
   - background mode OPAQUE, background color COLOR_BTNFACE (not white), text color black;
   - the font WM_SETFONT gave the button selected (SYSTEM_FONT when none);
   - a brush other than WHITE_BRUSH.
   calc's buttons carry "MS Shell Dlg" -11 weight 400 (the probe), so selecting the button's font
   and setting the background color fixes both. F2K's `button.rs` `draw_item` does neither.
3. **The display.** Static id 403, style 0x50020302 (SS_RIGHT | SS_NOTIFY | SS_CENTERIMAGE |
   WS_GROUP), ex 0x204 (WS_EX_CLIENTEDGE | WS_EX_NOPARENTNOTIFY), text "0. " (a trailing blank).
   - The client edge is 2 pixels: BTNSHADOW then 3DDKSHADOW top-left, BTNHIGHLIGHT then BTNFACE (3DLIGHT,
     the same color in this scheme) bottom-right (controls `edges`).
   - SS_CENTERIMAGE centres the line: DEFAULT_GUI_FONT's 13-pixel line in a 30-pixel client starts
     at row 8 ((30 - 13) / 2), in a 26-pixel one at row 6 (controls `centred`), as DrawText's
     DT_VCENTER | DT_SINGLELINE would.
4. **The memory box.** Static id 401, style 0x50020301 (SS_CENTER | SS_NOTIFY | SS_CENTERIMAGE),
   ex 0x204, no text: a client-edged empty static, which F2K draws not at all. Same edge as 3.
5. **SS_SUNKEN** becomes WS_EX_STATICEDGE at creation (the ex style reads 0x20000), a 1-pixel
   edge: BTNSHADOW top-left, BTNHIGHLIGHT bottom-right. With WS_EX_CLIENTEDGE, the two stack (3
   pixels).
6. **The caption icon.** The class has both icons (GCL_HICON, GCL_HICONSM non-NULL) and
   WM_GETICON answers NULL for both: Windows 2000 draws the class's small icon.
7. **Menu underlines.** SPI_GETKEYBOARDCUES answers FALSE on Windows 2000, and WM_QUERYUISTATE
   answers 0 for a window, its child and a dialog alike: the hidden underlines come from the
   system setting, not from the window's UI state. F2K's SystemParametersInfoW serves no
   SPI_GETKEYBOARDCUES (it logs so).
8. **Main window**: style 0x14CA0044 (WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | DS_SETFONT |
   DS_3DLOOK), ex 0x00050100 (WS_EX_CONTROLPARENT | WS_EX_APPWINDOW | WS_EX_WINDOWEDGE), class
   "SciCalc".

## Also seen

- **WindowFromPoint skips a static.** It answered "not the control" for every static on Windows
  2000, so the controls fixture now prints which window it found (the control, its parent, or
  another one).
- **A kernel panic on F2K** after the first probe run. The probe found no window (EnumWindows is a
  stub), terminated calc, then exited, and so did fish. At cmd's prompt the kernel then panicked
  with a garbage message: the panic printed a run of the kernel's string table. That kernel was
  this branch's (aae962a plus the trace), before the raw-access fix. The probe no longer
  terminates calc.
- **Menus with the foreground granted.** This time Windows 2000 granted the foreground, so menus'
  keyloop, keyesc and keychar captured real menu loops. Their pending reasons now name F2K's
  differences:
  - no WM_CAPTURECHANGED;
  - Esc on the bar, and Enter on a grayed item, go to WM_MENUCHAR instead of ending the loop;
  - a doubled WM_MENUSELECT.
