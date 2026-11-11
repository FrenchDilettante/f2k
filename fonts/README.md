# Fonts

This directory holds the fonts F2K reads from its volume at run time.
They are data files: no F2K binary embeds them.

They are the Wine project's fonts (<https://www.winehq.org>), which stand in for Windows' own; the files are unmodified.
Each comes as its TrueType file and its FontForge source (`.sfd`), the preferred form for modifying it; FontForge generates the `.ttf` from the `.sfd`.

**Licence.**
Every font here is under the GNU Lesser General Public License, version 2.1 or (at your option) any later version, as each font's `name` table states.
The licence text is in `COPYING.LIB`.

| Font          | Files                                    | Stands in for                                                                 | Copyright                              | Outlines | Bitmap strikes (pixels per em) |
| ------------- | ---------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------- | -------- | ------------------------------ |
| Tahoma        | `tahoma.ttf`, `tahoma.sfd`               | Tahoma, the user interface's face and "MS Shell Dlg 2"                        | Larry Snyder, 2004 (see below)         | yes      | 8, 9, 10, 11, 12, 13, 15, 16   |
| Tahoma Bold   | `tahomabd.ttf`, `tahomabd.sfd`           | Tahoma Bold, the captions' face                                               | Larry Snyder, 2004 (see below)         | yes      | 9, 10, 11, 12, 13, 15, 16      |
| MS Sans Serif | `ms_sans_serif.ttf`, `ms_sans_serif.sfd` | MS Sans Serif, and Microsoft Sans Serif behind "MS Shell Dlg"                 | Huw D M Davies, Dmitry Timoshkov, 2004 | no       | 13, 16, 20                     |
| System        | `system.ttf`, `system.sfd`               | System, the stock SYSTEM_FONT                                                 | Huw D M Davies, Dmitry Timoshkov, 2004 | no       | 16, 18                         |
| Marlett       | `marlett.ttf`, `marlett.sfd`             | Marlett, the glyphs of the caption buttons, scroll bar arrows and check marks | TransGaming Technologies               | yes      | none                           |

A font without outlines draws only at its strikes' sizes, as Windows' raster fonts do.

**Tahoma's copyright.**
Copyright (c) 2004 Larry Snyder.
Based on Bitstream Vera Sans, Copyright (c) 2003 by Bitstream, Inc.
As the fonts' own notice says, they were renamed in accordance with Bitstream Vera's licence, and Bitstream Inc. is not to be contacted about them.

**Deviations.**
MS Sans Serif here stands in for two of Windows 2000's faces: the MS Sans Serif raster font, and Microsoft Sans Serif, the TrueType face that the logical name "MS Shell Dlg" resolves to.

| File                | SHA-256                                                            |
| ------------------- | ------------------------------------------------------------------ |
| `tahoma.ttf`        | `8385eb7b3930798411953b8789245ae47e9a9e8480f7f37ecb8da1d895363954` |
| `tahoma.sfd`        | `24dc5676167812b3dfe8fdf8e519b6608186d0ebb8d709093853d6bd5cfbc9b3` |
| `tahomabd.ttf`      | `74bbeb9b687f073e7f2e4c4bea8dae36fd959b9d893a4d3eac859a475ac20d14` |
| `tahomabd.sfd`      | `8ee47af67357df1512c152e0c657c536bb161301a6498251fa3593cbb3d73758` |
| `ms_sans_serif.ttf` | `91877b45939e98d01b4c82e20c575db692c3e82a01ec3748277f3a3471d359cd` |
| `ms_sans_serif.sfd` | `d8cc5e8e93d70478e810b9aa3272006da57e819a063c2b34f5cf92a233b0f3f3` |
| `system.ttf`        | `fae4ce39aeb8d5fb93a228e43e54342cf6d3b9f8dffe40a5df9a87fefb4d5d7c` |
| `system.sfd`        | `88596900ca3df8dcf6ef257793a3b52baf666cc7f72140598bd2aef4787e9a41` |
| `marlett.ttf`       | `1a9b951ca1815344050ae6158263991e2145918bc74ad65d82bc6ec4056a57d1` |
| `marlett.sfd`       | `eaaf88567db49cdacac4ec9e61a4ce14648e682f48343d8b9c9056cb5a1d3970` |

## The fixtures' copy

`tests/gdi32/ttfont/f2ktahom.ttf` is `tahoma.ttf` renamed "F2K Tahoma", so that the real machine, which has Microsoft's own Tahoma, captures this one.
It differs from `tahoma.ttf` only in its `name` table, whose family, full, unique and PostScript names (`F2KTahoma` the last) `scripts/font_rename.py` writes, and in what that table's new length moves: the offsets of the tables after it, and the checksums.
The script and `tahoma.sfd` are its source.
