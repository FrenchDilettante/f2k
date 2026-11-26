//! The USER constants (winuser.h) the GUI programs name. The programs import only from the system
//! DLLs, as Windows 2000's own do, so they share this copy of the ones they need rather than
//! linking rtl's (`rtl::user`, `rtl::window`, `rtl::display`, `rtl::menu`, `rtl::scroll`); each
//! value checked against the SDK's header.

// --- The messages (WM_*) and PeekMessage's flags (PM_*) ------------------------------------------

pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_SYSCHAR: u32 = 0x0106;
pub const WM_INITDIALOG: u32 = 0x0110;
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_INITMENU: u32 = 0x0116;
pub const WM_INITMENUPOPUP: u32 = 0x0117;
pub const WM_MENUSELECT: u32 = 0x011F;
pub const WM_ENTERIDLE: u32 = 0x0121;
pub const WM_UNINITMENUPOPUP: u32 = 0x0125;
pub const WM_ENTERMENULOOP: u32 = 0x0211;
pub const WM_EXITMENULOOP: u32 = 0x0212;
pub const WM_USER: u32 = 0x0400;

/// The message stays in the queue.
pub const PM_NOREMOVE: u32 = 0x0000;

// --- The window, dialog and control styles (WS_*, DS_*, BS_*, SS_*, SBS_*) -----------------------

pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_CAPTION: u32 = 0x00C0_0000;
pub const WS_BORDER: u32 = 0x0080_0000;
pub const WS_VSCROLL: u32 = 0x0020_0000;
pub const WS_HSCROLL: u32 = 0x0010_0000;
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_GROUP: u32 = 0x0002_0000;
pub const WS_TABSTOP: u32 = 0x0001_0000;
pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;

pub const DS_SETFONT: u32 = 0x0040;
pub const DS_MODALFRAME: u32 = 0x0080;
pub const DS_CENTER: u32 = 0x0800;

pub const BS_PUSHBUTTON: u32 = 0x0;
pub const BS_DEFPUSHBUTTON: u32 = 0x1;
pub const BS_AUTOCHECKBOX: u32 = 0x3;
pub const BS_GROUPBOX: u32 = 0x7;
pub const BS_AUTORADIOBUTTON: u32 = 0x9;

pub const SS_LEFT: u32 = 0x00;
pub const SS_ETCHEDHORZ: u32 = 0x10;

pub const SBS_HORZ: u32 = 0x0;
pub const SBS_VERT: u32 = 0x1;

// --- ShowWindow, the system metrics and colours (SW_*, SM_*, COLOR_*)
// -----------------------------

pub const SW_SHOW: i32 = 5;

pub const SM_CXSCREEN: i32 = 0;
pub const SM_CYSCREEN: i32 = 1;

/// The system colours' indexes, as a class's background takes them (the index plus one).
pub const COLOR_WINDOW: usize = 5;
pub const COLOR_3DFACE: usize = 15;
pub const COLOR_3DSHADOW: usize = 16;

// --- The menus (MF_*) ----------------------------------------------------------------------------

pub const MF_STRING: u32 = 0x0000;
pub const MF_BYCOMMAND: u32 = 0x0000;
pub const MF_GRAYED: u32 = 0x0001;
pub const MF_CHECKED: u32 = 0x0008;
pub const MF_POPUP: u32 = 0x0010;
pub const MF_SEPARATOR: u32 = 0x0800;

// --- The scroll bars (SB_*, SIF_*, ESB_*) --------------------------------------------------------

pub const SB_HORZ: i32 = 0;
pub const SB_VERT: i32 = 1;
pub const SB_CTL: i32 = 2;

pub const SIF_RANGE: u32 = 0x1;
pub const SIF_PAGE: u32 = 0x2;
pub const SIF_POS: u32 = 0x4;

pub const ESB_DISABLE_LTUP: u32 = 0x1;
pub const ESB_DISABLE_BOTH: u32 = 0x3;

// --- DrawEdge's and DrawText's flags (EDGE_*, BF_*, DT_*) ----------------------------------------

pub const EDGE_RAISED: u32 = 0x0005;
pub const EDGE_ETCHED: u32 = 0x0006;
pub const EDGE_BUMP: u32 = 0x0009;
pub const EDGE_SUNKEN: u32 = 0x000A;

pub const BF_RECT: u32 = 0x000F;
pub const BF_MIDDLE: u32 = 0x0800;
pub const BF_SOFT: u32 = 0x1000;
pub const BF_ADJUST: u32 = 0x2000;

pub const DT_TOP: u32 = 0x0000;
pub const DT_LEFT: u32 = 0x0000;
pub const DT_CENTER: u32 = 0x0001;
pub const DT_RIGHT: u32 = 0x0002;
pub const DT_VCENTER: u32 = 0x0004;
pub const DT_BOTTOM: u32 = 0x0008;
pub const DT_WORDBREAK: u32 = 0x0010;
pub const DT_SINGLELINE: u32 = 0x0020;
pub const DT_EXPANDTABS: u32 = 0x0040;
pub const DT_CALCRECT: u32 = 0x0400;
