# Fonts

This directory holds the fonts F2K reads from its volume at run time.
They are data files: no F2K binary embeds them.

## Wine Tahoma

`tahoma.ttf` and its FontForge source `tahoma.sfd` are the Wine project's Tahoma, a font made to resemble Windows' Tahoma.
The owner fetched both from the Wine project (<https://www.winehq.org>) on 2026-11-09, unmodified.

| File         | SHA-256                                                            |
| ------------ | ------------------------------------------------------------------ |
| `tahoma.ttf` | `8385eb7b3930798411953b8789245ae47e9a9e8480f7f37ecb8da1d895363954` |
| `tahoma.sfd` | `24dc5676167812b3dfe8fdf8e519b6608186d0ebb8d709093853d6bd5cfbc9b3` |

**Copyright.**
Copyright (c) 2004 Larry Snyder.
Based on Bitstream Vera Sans, Copyright (c) 2003 by Bitstream, Inc.
As the font's own notice says, it was renamed in accordance with Bitstream Vera's licence, and Bitstream Inc. is not to be contacted about it.

**Licence.**
The GNU Lesser General Public License, version 2.1 or (at your option) any later version, as the font's `name` table states.
The licence text is in `COPYING.LIB`.

**Source.**
`tahoma.sfd` is the font's source, the preferred form for modifying it.
FontForge generates `tahoma.ttf` from it.

**What it holds:**

- family `Tahoma`, PostScript name `WineTahoma`, version 0.001;
- TrueType outlines;
- embedded bitmap strikes at 8, 9, 10, 11, 12, 13, 15 and 16 pixels per em (the `EBLC`/`EBDT` tables).

**The fixtures' copy.**
`tests/gdi32/ttfont/f2ktahom.ttf` is this font renamed "F2K Tahoma", so that the real machine, which has Microsoft's own Tahoma, captures this one.
It differs from `tahoma.ttf` only in its `name` table, whose family, full, unique and PostScript names (`F2KTahoma` the last) `scripts/font_rename.py` writes, and in what that table's new length moves: the offsets of the tables after it, and the checksums.
The script and `tahoma.sfd` are its source.
