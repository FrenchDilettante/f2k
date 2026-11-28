//! USER's shared shapes: the one home of winuser.h's constants the kernel's win32k, rtl and the
//! DLLs name (the messages, PeekMessage's flags, the queue-status bits, the virtual keys as wParam
//! carries them, the window and class styles, the buttons' and statics' messages and styles,
//! WM_SYSCOMMAND's commands, the clipboard formats, GetUserObjectInformation's indexes), the
//! structures Windows 2000's winuser.h lays out on x86 (MSG, PAINTSTRUCT, CREATESTRUCTW,
//! SendInput's INPUT, GUITHREADINFO), and F2K's
//! own shapes of the services behind them: the receipt win32k's GetMessage and PeekMessage services
//! hand user32 ([`Receipt`]), and the routines of the NtUserCall* services ([`ONE_PARAM_*`],
//! [`NO_PARAM_*`], [`TWO_PARAM_*`], [`HWND_LOCK_*`], [`HWND_PARAM_LOCK_*`]) and of
//! NtUserGetThreadState ([`THREAD_STATE_*`]). Only F2K's user32 calls those services, so their
//! shapes are F2K's.
//!
//! A message another thread sent, or one win32k sent on its own behalf, reaches the window
//! procedure by a callback from inside the receiving thread's own message calls
//! ([`crate::callback`]), never through a receipt.
//!
//! [`ONE_PARAM_*`]: ONE_PARAM_POST_QUIT_MESSAGE
//! [`NO_PARAM_*`]: NO_PARAM_CREATE_MENU
//! [`TWO_PARAM_*`]: TWO_PARAM_SET_CARET_POS
//! [`HWND_LOCK_*`]: HWND_LOCK_UPDATE_WINDOW
//! [`HWND_PARAM_LOCK_*`]: HWND_PARAM_LOCK_ENABLE_WINDOW
//! [`THREAD_STATE_*`]: THREAD_STATE_FOCUS_WINDOW

use crate::console::layout;
use crate::gdi::Rect;
use crate::pod::Pod;

// --- The messages (winuser.h's WM_*) -------------------------------------------------------------

pub const WM_NULL: u32 = 0x0000;
pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_MOVE: u32 = 0x0003;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_ACTIVATE: u32 = 0x0006;
pub const WM_SETFOCUS: u32 = 0x0007;
pub const WM_KILLFOCUS: u32 = 0x0008;
pub const WM_ENABLE: u32 = 0x000A;
pub const WM_SETREDRAW: u32 = 0x000B;
pub const WM_SETTEXT: u32 = 0x000C;
pub const WM_GETTEXT: u32 = 0x000D;
pub const WM_GETTEXTLENGTH: u32 = 0x000E;
pub const WM_PAINT: u32 = 0x000F;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_QUERYENDSESSION: u32 = 0x0011;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_ERASEBKGND: u32 = 0x0014;
pub const WM_ENDSESSION: u32 = 0x0016;
pub const WM_SHOWWINDOW: u32 = 0x0018;
pub const WM_SETTINGCHANGE: u32 = 0x001A;
pub const WM_DEVMODECHANGE: u32 = 0x001B;
pub const WM_ACTIVATEAPP: u32 = 0x001C;
pub const WM_CANCELMODE: u32 = 0x001F;
pub const WM_SETCURSOR: u32 = 0x0020;
pub const WM_MOUSEACTIVATE: u32 = 0x0021;
pub const WM_GETMINMAXINFO: u32 = 0x0024;
pub const WM_NEXTDLGCTL: u32 = 0x0028;
pub const WM_DRAWITEM: u32 = 0x002B;
pub const WM_VKEYTOITEM: u32 = 0x002E;
pub const WM_CHARTOITEM: u32 = 0x002F;
pub const WM_SETFONT: u32 = 0x0030;
pub const WM_GETFONT: u32 = 0x0031;
pub const WM_SETHOTKEY: u32 = 0x0032;
pub const WM_QUERYDRAGICON: u32 = 0x0037;
pub const WM_COMPAREITEM: u32 = 0x0039;
pub const WM_WINDOWPOSCHANGING: u32 = 0x0046;
pub const WM_WINDOWPOSCHANGED: u32 = 0x0047;
pub const WM_COPYDATA: u32 = 0x004A;
pub const WM_CONTEXTMENU: u32 = 0x007B;
pub const WM_STYLECHANGING: u32 = 0x007C;
pub const WM_STYLECHANGED: u32 = 0x007D;
pub const WM_GETICON: u32 = 0x007F;
pub const WM_SETICON: u32 = 0x0080;
pub const WM_NCCREATE: u32 = 0x0081;
pub const WM_NCDESTROY: u32 = 0x0082;
pub const WM_NCCALCSIZE: u32 = 0x0083;
pub const WM_NCHITTEST: u32 = 0x0084;
pub const WM_NCPAINT: u32 = 0x0085;
pub const WM_NCACTIVATE: u32 = 0x0086;
pub const WM_GETDLGCODE: u32 = 0x0087;
pub const WM_NCMOUSEMOVE: u32 = 0x00A0;
pub const WM_NCLBUTTONDOWN: u32 = 0x00A1;
pub const WM_NCLBUTTONUP: u32 = 0x00A2;
pub const WM_NCLBUTTONDBLCLK: u32 = 0x00A3;
pub const WM_KEYFIRST: u32 = 0x0100;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_DEADCHAR: u32 = 0x0103;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const WM_SYSCHAR: u32 = 0x0106;
pub const WM_SYSDEADCHAR: u32 = 0x0107;
pub const WM_KEYLAST: u32 = 0x0108;
pub const WM_INITDIALOG: u32 = 0x0110;
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_SYSCOMMAND: u32 = 0x0112;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_INITMENU: u32 = 0x0116;
pub const WM_INITMENUPOPUP: u32 = 0x0117;
pub const WM_SYSTIMER: u32 = 0x0118;
pub const WM_MENUSELECT: u32 = 0x011F;
pub const WM_MENUCHAR: u32 = 0x0120;
pub const WM_ENTERIDLE: u32 = 0x0121;
pub const WM_UNINITMENUPOPUP: u32 = 0x0125;
pub const WM_CHANGEUISTATE: u32 = 0x0127;
pub const WM_UPDATEUISTATE: u32 = 0x0128;
pub const WM_QUERYUISTATE: u32 = 0x0129;
pub const WM_CTLCOLORMSGBOX: u32 = 0x0132;
pub const WM_CTLCOLOREDIT: u32 = 0x0133;
pub const WM_CTLCOLORLISTBOX: u32 = 0x0134;
pub const WM_CTLCOLORBTN: u32 = 0x0135;
pub const WM_CTLCOLORDLG: u32 = 0x0136;
pub const WM_CTLCOLORSCROLLBAR: u32 = 0x0137;
pub const WM_CTLCOLORSTATIC: u32 = 0x0138;
pub const WM_MOUSEFIRST: u32 = 0x0200;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_LBUTTONDBLCLK: u32 = 0x0203;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_RBUTTONDBLCLK: u32 = 0x0206;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MBUTTONUP: u32 = 0x0208;
pub const WM_MBUTTONDBLCLK: u32 = 0x0209;
pub const WM_MOUSEWHEEL: u32 = 0x020A;
pub const WM_MOUSELAST: u32 = 0x020D;
pub const WM_PARENTNOTIFY: u32 = 0x0210;
pub const WM_ENTERMENULOOP: u32 = 0x0211;
pub const WM_EXITMENULOOP: u32 = 0x0212;
pub const WM_CAPTURECHANGED: u32 = 0x0215;
pub const WM_IME_CHAR: u32 = 0x0286;
pub const WM_CUT: u32 = 0x0300;
pub const WM_COPY: u32 = 0x0301;
pub const WM_PASTE: u32 = 0x0302;
pub const WM_CLEAR: u32 = 0x0303;
pub const WM_UNDO: u32 = 0x0304;
pub const WM_RENDERFORMAT: u32 = 0x0305;
pub const WM_RENDERALLFORMATS: u32 = 0x0306;
pub const WM_DESTROYCLIPBOARD: u32 = 0x0307;
pub const WM_USER: u32 = 0x0400;

/// How far a mouse message's non-client form is below its client form: WM_NCMOUSEMOVE is
/// WM_MOUSEMOVE's, WM_NCLBUTTONDOWN WM_LBUTTONDOWN's, through WM_NCMBUTTONDBLCLK.
pub const NC_MOUSE_OFFSET: u32 = WM_MOUSEMOVE - WM_NCMOUSEMOVE;

/// The mouse messages' wParam (winuser.h's MK_*): the buttons and the modifiers down.
pub const MK_LBUTTON: u32 = 0x0001;
pub const MK_RBUTTON: u32 = 0x0002;
pub const MK_SHIFT: u32 = 0x0004;
pub const MK_CONTROL: u32 = 0x0008;
pub const MK_MBUTTON: u32 = 0x0010;

/// WM_MOUSEACTIVATE's answers (winuser.h's MA_*): the window activated or not, the click eaten or
/// not.
pub const MA_ACTIVATE: u32 = 1;
pub const MA_ACTIVATEANDEAT: u32 = 2;
pub const MA_NOACTIVATE: u32 = 3;
pub const MA_NOACTIVATEANDEAT: u32 = 4;

/// WM_QUERYENDSESSION's and WM_ENDSESSION's lParam for a logoff (winuser.h's ENDSESSION_LOGOFF): 0
/// for a shutdown.
pub const ENDSESSION_LOGOFF: u32 = 0x8000_0000;

/// WM_ACTIVATE's state, its wParam's low word (winuser.h's WA_*): the window is deactivated, or
/// activated by some other means than a mouse click.
pub const WA_INACTIVE: u32 = 0;
pub const WA_ACTIVE: u32 = 1;

/// PostMessage's window that names every top-level window (HWND_BROADCAST).
pub const HWND_BROADCAST: u32 = 0xFFFF;

// --- PeekMessage's flags (winuser.h's PM_*) ------------------------------------------------------

/// The message stays in the queue.
pub const PM_NOREMOVE: u32 = 0x0000;
/// The message is taken out of the queue (WM_PAINT excepted: only validating the window does).
pub const PM_REMOVE: u32 = 0x0001;
/// No yield to other threads when nothing is found (there is nothing to yield on F2K's queue).
pub const PM_NOYIELD: u32 = 0x0002;

// --- The queue-status bits (winuser.h's QS_*) ----------------------------------------------------

pub const QS_KEY: u32 = 0x0001;
pub const QS_MOUSEMOVE: u32 = 0x0002;
pub const QS_MOUSEBUTTON: u32 = 0x0004;
pub const QS_POSTMESSAGE: u32 = 0x0008;
pub const QS_TIMER: u32 = 0x0010;
pub const QS_PAINT: u32 = 0x0020;
pub const QS_SENDMESSAGE: u32 = 0x0040;
pub const QS_HOTKEY: u32 = 0x0080;
pub const QS_ALLPOSTMESSAGE: u32 = 0x0100;
pub const QS_MOUSE: u32 = QS_MOUSEMOVE | QS_MOUSEBUTTON;
pub const QS_INPUT: u32 = QS_MOUSE | QS_KEY;
/// Every kind of message a thread waits for: what WaitMessage wakes on.
pub const QS_ALLINPUT: u32 =
    QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY | QS_SENDMESSAGE;

/// PeekMessage's kinds of message to look at (PM_QS_*): the queue-status bits in the high word.
/// None of them set looks at every kind.
pub const PM_QS_INPUT: u32 = QS_INPUT << 16;
pub const PM_QS_POSTMESSAGE: u32 = (QS_POSTMESSAGE | QS_HOTKEY | QS_TIMER) << 16;
pub const PM_QS_PAINT: u32 = QS_PAINT << 16;
pub const PM_QS_SENDMESSAGE: u32 = QS_SENDMESSAGE << 16;

// --- SendMessageTimeout's flags (winuser.h's SMTO_*) ---------------------------------------------

/// The sender waits as SendMessage does (it would also handle what is sent to it meanwhile).
pub const SMTO_NORMAL: u32 = 0x0000;
/// The sender does not handle what is sent to it while it waits.
pub const SMTO_BLOCK: u32 = 0x0001;
/// The sender gives up at once when the receiving thread is hung.
pub const SMTO_ABORTIFHUNG: u32 = 0x0002;
/// A hung receiver does not end the wait before the timeout.
pub const SMTO_NOTIMEOUTIFNOTHUNG: u32 = 0x0008;

/// Whether `message` carries a pointer the window manager does not carry to another thread
/// (Windows 2000's sync-only messages, those below WM_USER whose wParam or lParam points at a
/// structure or a text): SendNotifyMessage refuses one to another thread's window with
/// ERROR_MESSAGE_SYNC_ONLY.
pub fn sync_only(message: u32) -> bool {
    matches!(
        message,
        WM_CREATE
            | WM_SETTEXT
            | WM_GETTEXT
            | WM_GETMINMAXINFO
            | WM_DRAWITEM
            | 0x002C // WM_MEASUREITEM
            | 0x002D // WM_DELETEITEM
            | WM_COMPAREITEM
            | WM_WINDOWPOSCHANGING
            | WM_WINDOWPOSCHANGED
            | WM_COPYDATA
            | 0x004E // WM_NOTIFY
            | 0x0053 // WM_HELP
            | WM_STYLECHANGING
            | WM_STYLECHANGED
            | WM_NCCREATE
            | WM_NCCALCSIZE
    )
}

// --- The virtual keys (winuser.h's VK_*) ---------------------------------------------------------

/// The virtual keys as the key messages' wParam carries them: the keyboard layouts' values
/// ([`crate::console::layout`]'s byte-sized VK_*), widened.
pub const VK_TAB: u32 = layout::VK_TAB as u32;
/// The mouse's buttons as the key states hold them (winuser.h's VK_LBUTTON, VK_RBUTTON,
/// VK_MBUTTON): GetKeyState and GetAsyncKeyState answer them as keys.
pub const VK_LBUTTON: u32 = 0x01;
pub const VK_RBUTTON: u32 = 0x02;
pub const VK_MBUTTON: u32 = 0x04;
pub const VK_RETURN: u32 = layout::VK_RETURN as u32;
pub const VK_SHIFT: u32 = layout::VK_SHIFT as u32;
pub const VK_CONTROL: u32 = layout::VK_CONTROL as u32;
pub const VK_MENU: u32 = layout::VK_MENU as u32;
pub const VK_ESCAPE: u32 = layout::VK_ESCAPE as u32;
pub const VK_SPACE: u32 = layout::VK_SPACE as u32;
pub const VK_END: u32 = layout::VK_END as u32;
pub const VK_HOME: u32 = layout::VK_HOME as u32;
pub const VK_LEFT: u32 = layout::VK_LEFT as u32;
pub const VK_UP: u32 = layout::VK_UP as u32;
pub const VK_RIGHT: u32 = layout::VK_RIGHT as u32;
pub const VK_DOWN: u32 = layout::VK_DOWN as u32;
pub const VK_INSERT: u32 = layout::VK_INSERT as u32;
pub const VK_DELETE: u32 = layout::VK_DELETE as u32;
pub const VK_F4: u32 = layout::VK_F4 as u32;
pub const VK_F10: u32 = layout::VK_F10 as u32;

// --- The window and class styles (winuser.h's WS_*, WS_EX_*, CS_*) ------------------------------

pub const WS_OVERLAPPED: u32 = 0x0000_0000;
pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_MINIMIZE: u32 = 0x2000_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_DISABLED: u32 = 0x0800_0000;
pub const WS_CLIPSIBLINGS: u32 = 0x0400_0000;
pub const WS_CLIPCHILDREN: u32 = 0x0200_0000;
pub const WS_MAXIMIZE: u32 = 0x0100_0000;
/// WS_BORDER | WS_DLGFRAME.
pub const WS_CAPTION: u32 = 0x00C0_0000;
pub const WS_BORDER: u32 = 0x0080_0000;
pub const WS_DLGFRAME: u32 = 0x0040_0000;
pub const WS_VSCROLL: u32 = 0x0020_0000;
pub const WS_HSCROLL: u32 = 0x0010_0000;
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_THICKFRAME: u32 = 0x0004_0000;
pub const WS_GROUP: u32 = 0x0002_0000;
pub const WS_TABSTOP: u32 = 0x0001_0000;
pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;
pub const WS_MAXIMIZEBOX: u32 = 0x0001_0000;
pub const WS_OVERLAPPEDWINDOW: u32 =
    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;

pub const WS_EX_DLGMODALFRAME: u32 = 0x0000_0001;
pub const WS_EX_NOPARENTNOTIFY: u32 = 0x0000_0004;
pub const WS_EX_TOPMOST: u32 = 0x0000_0008;
pub const WS_EX_TRANSPARENT: u32 = 0x0000_0020;
pub const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
pub const WS_EX_WINDOWEDGE: u32 = 0x0000_0100;
pub const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;
pub const WS_EX_CONTEXTHELP: u32 = 0x0000_0400;
pub const WS_EX_CONTROLPARENT: u32 = 0x0001_0000;
pub const WS_EX_STATICEDGE: u32 = 0x0002_0000;
pub const WS_EX_APPWINDOW: u32 = 0x0004_0000;
pub const WS_EX_LAYERED: u32 = 0x0008_0000;

pub const CS_VREDRAW: u32 = 0x0001;
pub const CS_HREDRAW: u32 = 0x0002;
pub const CS_DBLCLKS: u32 = 0x0008;
pub const CS_OWNDC: u32 = 0x0020;
pub const CS_CLASSDC: u32 = 0x0040;
pub const CS_PARENTDC: u32 = 0x0080;
pub const CS_NOCLOSE: u32 = 0x0200;
pub const CS_SAVEBITS: u32 = 0x0800;
pub const CS_BYTEALIGNCLIENT: u32 = 0x1000;
pub const CS_BYTEALIGNWINDOW: u32 = 0x2000;
pub const CS_GLOBALCLASS: u32 = 0x4000;
pub const CS_IME: u32 = 0x0001_0000;

// --- The controls' messages and styles (winuser.h's BM_*, BS_*, STM_*, SS_*) ---------------------

pub const BM_GETCHECK: u32 = 0x00F0;
pub const BM_SETCHECK: u32 = 0x00F1;
pub const BM_GETSTATE: u32 = 0x00F2;
pub const BM_SETSTATE: u32 = 0x00F3;
pub const BM_SETSTYLE: u32 = 0x00F4;
pub const BM_CLICK: u32 = 0x00F5;
pub const BM_GETIMAGE: u32 = 0x00F6;
pub const BM_SETIMAGE: u32 = 0x00F7;

/// The button kinds (the style's low four bits).
pub const BS_PUSHBUTTON: u32 = 0x0;
pub const BS_DEFPUSHBUTTON: u32 = 0x1;
pub const BS_CHECKBOX: u32 = 0x2;
pub const BS_AUTOCHECKBOX: u32 = 0x3;
pub const BS_RADIOBUTTON: u32 = 0x4;
pub const BS_3STATE: u32 = 0x5;
pub const BS_AUTO3STATE: u32 = 0x6;
pub const BS_GROUPBOX: u32 = 0x7;
pub const BS_AUTORADIOBUTTON: u32 = 0x9;
/// The kind whose paint goes to the parent as WM_DRAWITEM.
pub const BS_OWNERDRAW: u32 = 0xB;
pub const BS_TYPEMASK: u32 = 0xF;
/// The text alignment bits.
pub const BS_LEFT: u32 = 0x0100;
pub const BS_CENTER: u32 = 0x0300;
pub const BS_VCENTER: u32 = 0x0C00;
/// The button sends BN_SETFOCUS, BN_KILLFOCUS and BN_DBLCLK too.
pub const BS_NOTIFY: u32 = 0x4000;

pub const STM_SETICON: u32 = 0x0170;
pub const STM_GETICON: u32 = 0x0171;
pub const STM_SETIMAGE: u32 = 0x0172;
pub const STM_GETIMAGE: u32 = 0x0173;

/// The image kinds of LoadImage and of STM_SETIMAGE and STM_GETIMAGE (winuser.h's IMAGE_*).
pub const IMAGE_BITMAP: u32 = 0;
pub const IMAGE_ICON: u32 = 1;
pub const IMAGE_CURSOR: u32 = 2;
pub const IMAGE_ENHMETAFILE: u32 = 3;

/// The static kinds (the style's low five bits).
pub const SS_LEFT: u32 = 0x00;
pub const SS_CENTER: u32 = 0x01;
pub const SS_RIGHT: u32 = 0x02;
pub const SS_ICON: u32 = 0x03;
pub const SS_BLACKRECT: u32 = 0x04;
pub const SS_GRAYRECT: u32 = 0x05;
pub const SS_WHITERECT: u32 = 0x06;
pub const SS_BLACKFRAME: u32 = 0x07;
pub const SS_GRAYFRAME: u32 = 0x08;
pub const SS_WHITEFRAME: u32 = 0x09;
pub const SS_USERITEM: u32 = 0x0A;
pub const SS_SIMPLE: u32 = 0x0B;
pub const SS_LEFTNOWORDWRAP: u32 = 0x0C;
pub const SS_OWNERDRAW: u32 = 0x0D;
pub const SS_BITMAP: u32 = 0x0E;
pub const SS_ENHMETAFILE: u32 = 0x0F;
pub const SS_ETCHEDHORZ: u32 = 0x10;
pub const SS_ETCHEDVERT: u32 = 0x11;
pub const SS_ETCHEDFRAME: u32 = 0x12;
pub const SS_TYPEMASK: u32 = 0x1F;
pub const SS_NOPREFIX: u32 = 0x80;
/// The static notifies its parent of clicks (and is found under the mouse).
pub const SS_NOTIFY: u32 = 0x0100;
/// A text static's line centred vertically (one line: DrawText's DT_SINGLELINE | DT_VCENTER).
pub const SS_CENTERIMAGE: u32 = 0x0200;
/// A sunken border: WS_EX_STATICEDGE, given at creation.
pub const SS_SUNKEN: u32 = 0x1000;
/// The ellipsis styles, one field of two bits.
pub const SS_ELLIPSISMASK: u32 = 0xC000;

// --- WM_SYSCOMMAND's commands (winuser.h's SC_*) -------------------------------------------------

pub const SC_SIZE: u32 = 0xF000;
pub const SC_MOVE: u32 = 0xF010;
pub const SC_MINIMIZE: u32 = 0xF020;
pub const SC_MAXIMIZE: u32 = 0xF030;
pub const SC_CLOSE: u32 = 0xF060;
pub const SC_KEYMENU: u32 = 0xF100;
pub const SC_RESTORE: u32 = 0xF120;

// --- The clipboard's predefined formats (winuser.h's CF_*) ---------------------------------------

pub const CF_TEXT: u32 = 1;
pub const CF_OEMTEXT: u32 = 7;
pub const CF_UNICODETEXT: u32 = 13;
pub const CF_LOCALE: u32 = 16;

// --- GetUserObjectInformation's indexes (winuser.h's UOI_*) --------------------------------------

pub const UOI_FLAGS: u32 = 1;
pub const UOI_NAME: u32 = 2;
pub const UOI_TYPE: u32 = 3;
pub const UOI_USER_SID: u32 = 4;

// --- The structures (winuser.h) ------------------------------------------------------------------

/// POINT: GDI's, one type for both headers' uses.
pub use crate::gdi::Point;

/// MSG: a message as GetMessage and PeekMessage retrieve it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Msg {
    pub hwnd: u32,
    pub message: u32,
    pub wparam: u32,
    pub lparam: i32,
    /// When the message was posted (or made, for the ones the queue makes), in milliseconds since
    /// the boot.
    pub time: u32,
    /// The cursor's position then.
    pub pt: Point,
}

// SAFETY: integers only.
unsafe impl Pod for Msg {}

/// PAINTSTRUCT: what BeginPaint hands its caller.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PaintStruct {
    pub hdc: u32,
    /// fErase: the background still needs erasing (a BOOL).
    pub erase: i32,
    /// rcPaint: the area to paint, in client coordinates.
    pub paint: Rect,
    pub restore: i32,
    pub inc_update: i32,
    pub reserved: [u8; 32],
}

// SAFETY: integers and bytes only.
unsafe impl Pod for PaintStruct {}

/// CREATESTRUCTW: WM_NCCREATE's and WM_CREATE's lParam.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CreateStructW {
    pub create_params: u32,
    pub instance: u32,
    pub menu: u32,
    pub parent: u32,
    pub cy: i32,
    pub cx: i32,
    pub y: i32,
    pub x: i32,
    pub style: u32,
    /// lpszName: the window name.
    pub name: u32,
    /// lpszClass: the class name, or its atom.
    pub class: u32,
    pub ex_style: u32,
}

// SAFETY: integers only.
unsafe impl Pod for CreateStructW {}

/// STYLESTRUCT: WM_STYLECHANGING's and WM_STYLECHANGED's lParam, the style before and after a
/// SetWindowLong of GWL_STYLE or GWL_EXSTYLE (their wParam).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StyleStruct {
    pub style_old: u32,
    pub style_new: u32,
}

// SAFETY: integers only.
unsafe impl Pod for StyleStruct {}

/// MINMAXINFO (40 bytes): WM_GETMINMAXINFO's lParam, the sizes and the place a window may take,
/// which the window manager fills with its defaults before it sends the message and the procedure
/// may change.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinMaxInfo {
    /// ptReserved.
    pub reserved: Point,
    /// ptMaxSize: the maximized window's size.
    pub max_size: Point,
    /// ptMaxPosition: the maximized window's place.
    pub max_position: Point,
    /// ptMinTrackSize and ptMaxTrackSize: the smallest and the largest size a resize gives it.
    pub min_track: Point,
    pub max_track: Point,
}

// SAFETY: five POINTs, integers only.
unsafe impl Pod for MinMaxInfo {}

// --- F2K's receipt -------------------------------------------------------------------------------

/// What a receipt holds: WM_QUIT (GetMessage answers 0 for it), a posted message or one the queue
/// made (WM_PAINT, WM_TIMER), or nothing (PeekMessage on a queue with nothing for the filter). The
/// messages sent to the thread never reach a receipt: the reads deliver them by callback first
/// ([`crate::callback`]), as Windows 2000's xxxReceiveMessage does. (2 was a sent message's.)
pub const RECEIVED_QUIT: u32 = 0;
pub const RECEIVED_MESSAGE: u32 = 1;
pub const RECEIVED_NONE: u32 = 3;

/// The units WM_COPYDATA's carried form starts with: its COPYDATASTRUCT (dwData, cbData, then
/// lpData 0, which the receiver points at the bytes), its bytes after it, two a unit, the last
/// unit's high byte 0 for an odd count.
pub const COPY_DATA_HEAD: usize = 6;

/// What win32k's GetMessage and PeekMessage services write into user32's buffer: what it is, and
/// the message.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Receipt {
    pub kind: u32,
    pub msg: Msg,
}

// SAFETY: integers only.
unsafe impl Pod for Receipt {}

// --- The NtUserCall* services' routines (F2K's numbering) ----------------------------------------

/// NtUserCallOneParam's routines: PostQuitMessage (the parameter is the exit code), ReplyMessage
/// (the parameter is the answer; the result is whether the thread was answering another thread's
/// message), EnumClipboardFormats (the parameter is the format before, 0 for the first; the result
/// the next one, 0 past the last), and InSendMessage (no parameter; the result whether the message
/// the thread is delivering was sent by another thread). (2 ended a sent message's delivery from
/// a receipt, before the reads delivered them by callback.)
pub const ONE_PARAM_POST_QUIT_MESSAGE: u32 = 0;
pub const ONE_PARAM_REPLY_MESSAGE: u32 = 1;
pub const ONE_PARAM_ENUM_CLIPBOARD_FORMATS: u32 = 3;
pub const ONE_PARAM_IN_SEND_MESSAGE: u32 = 4;
/// IsHungAppWindow (the parameter is the window; the result whether its thread is hung).
pub const ONE_PARAM_IS_HUNG_APP_WINDOW: u32 = 5;
/// ShowCursor (the parameter is whether to show; the result the new display count, an i32).
pub const ONE_PARAM_SHOW_CURSOR: u32 = 6;
/// GetQueueStatus (the parameter is the QS_* flags; the result the kinds held in the high word,
/// those new since the last look in the low word).
pub const ONE_PARAM_GET_QUEUE_STATUS: u32 = 7;

/// F2K's NtUserMessageCall's timeout, SendMessageTimeout's (none for SendMessage's): its SMTO_*
/// flags, and how long the sender waits for another thread's answer, in milliseconds.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendTimeout {
    pub flags: u32,
    pub timeout: u32,
}

// SAFETY: two integers.
unsafe impl Pod for SendTimeout {}

/// The keyboard layout every thread has, as its HKL: US English's (the language 0x0409 in both
/// halves), the one layout F2K has. GetKeyboardLayout answers it, and the clipboard's CF_LOCALE
/// is its language.
pub const KEYBOARD_LAYOUT: u32 = 0x0409_0409;

// --- SendInput's records (winuser.h) -------------------------------------------------------------

/// INPUT's types: a mouse event, a keyboard event, another device's.
pub const INPUT_MOUSE: u32 = 0;
pub const INPUT_KEYBOARD: u32 = 1;
pub const INPUT_HARDWARE: u32 = 2;

/// KEYBDINPUT's flags: the key is an extended one (its scan code came after 0xE0), it goes up
/// (else down), the event carries a character in wScan instead of a key, the key is named by its
/// scan code alone (wVk ignored).
pub const KEYEVENTF_EXTENDEDKEY: u32 = 0x0001;
pub const KEYEVENTF_KEYUP: u32 = 0x0002;
pub const KEYEVENTF_UNICODE: u32 = 0x0004;
pub const KEYEVENTF_SCANCODE: u32 = 0x0008;

/// MOUSEINPUT's flags: the event moves the mouse, presses or releases a button, turns the wheel
/// (mouseData its amount), and its move is to an absolute place (0-65535 across the screen) rather
/// than by an amount.
pub const MOUSEEVENTF_MOVE: u32 = 0x0001;
pub const MOUSEEVENTF_LEFTDOWN: u32 = 0x0002;
pub const MOUSEEVENTF_LEFTUP: u32 = 0x0004;
pub const MOUSEEVENTF_RIGHTDOWN: u32 = 0x0008;
pub const MOUSEEVENTF_RIGHTUP: u32 = 0x0010;
pub const MOUSEEVENTF_MIDDLEDOWN: u32 = 0x0020;
pub const MOUSEEVENTF_MIDDLEUP: u32 = 0x0040;
pub const MOUSEEVENTF_WHEEL: u32 = 0x0800;
pub const MOUSEEVENTF_ABSOLUTE: u32 = 0x8000;

/// MOUSEINPUT: an INPUT's mouse event ([`Input::mouse`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MouseInput {
    pub dx: i32,
    pub dy: i32,
    pub data: u32,
    pub flags: u32,
    pub time: u32,
    pub extra_info: u32,
}

/// INPUT as SendInput reads it, its union seen as a KEYBDINPUT (28 bytes: the union is
/// MOUSEINPUT's size, the largest member, so a keyboard event leaves two words over).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Input {
    pub kind: u32,
    /// KEYBDINPUT: wVk, wScan, dwFlags, time, dwExtraInfo.
    pub vk: u16,
    pub scan: u16,
    pub flags: u32,
    pub time: u32,
    pub extra_info: u32,
    /// MOUSEINPUT's last two words.
    pub rest: [u32; 2],
}

// SAFETY: integers only, with no padding (two u16 then u32s, at their alignment).
unsafe impl Pod for Input {}

impl Input {
    /// The union seen as the MOUSEINPUT it is for an INPUT_MOUSE record: dx (wVk and wScan's
    /// place), dy, mouseData, dwFlags, time, dwExtraInfo.
    pub fn mouse(&self) -> MouseInput {
        MouseInput {
            dx: (u32::from(self.vk) | u32::from(self.scan) << 16) as i32,
            dy: self.flags as i32,
            data: self.time,
            flags: self.extra_info,
            time: self.rest[0],
            extra_info: self.rest[1],
        }
    }
}

/// GUITHREADINFO: what GetGUIThreadInfo answers of a thread's input state.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuiThreadInfo {
    pub cb_size: u32,
    /// GUI_* flags.
    pub flags: u32,
    pub hwnd_active: u32,
    pub hwnd_focus: u32,
    pub hwnd_capture: u32,
    pub hwnd_menu_owner: u32,
    pub hwnd_move_size: u32,
    pub hwnd_caret: u32,
    /// rcCaret: the caret's rectangle, in its window's client coordinates.
    pub rc_caret: Rect,
}

// SAFETY: integers only.
unsafe impl Pod for GuiThreadInfo {}

/// GUITHREADINFO's flags (winuser.h's GUI_*): the caret is shown (it blinks).
pub const GUI_CARETBLINKING: u32 = 0x0000_0001;

/// NtUserCallNoParam's routines: CreateMenu and CreatePopupMenu (the result is the new menu's
/// handle), the empty cursor or icon object LoadIcon fills in with NtUserSetCursorIconData (the
/// result is its handle), and DestroyCaret.
pub const NO_PARAM_CREATE_MENU: u32 = 0;
pub const NO_PARAM_CREATE_POPUP_MENU: u32 = 1;
pub const NO_PARAM_CREATE_EMPTY_CURSOR: u32 = 2;
/// DestroyCaret (the calling thread's caret destroyed; the result 1).
pub const NO_PARAM_DESTROY_CARET: u32 = 3;
/// ReleaseCapture (the calling thread's mouse capture taken from its window, which is sent
/// WM_CAPTURECHANGED; the result 1).
pub const NO_PARAM_RELEASE_CAPTURE: u32 = 4;

/// NtUserCallTwoParam's routines: SetCaretPos (the two parameters are the place; the result 1).
/// (1 handed a received message's text over, before callbacks carried it.)
pub const TWO_PARAM_SET_CARET_POS: u32 = 0;
/// MsgWaitForMultipleObjects' wait ([`MsgWait`] at the first parameter; the second 0): the
/// result as WaitForMultipleObjects answers, WAIT_OBJECT_0 + the count for input of the wake
/// mask's kinds come to the queue since a read last looked for them.
pub const TWO_PARAM_MSG_WAIT: u32 = 2;
/// SetCursorPos (the two parameters are the screen point; the result 1).
pub const TWO_PARAM_SET_CURSOR_POS: u32 = 3;

/// MsgWaitForMultipleObjects' arguments, as [`TWO_PARAM_MSG_WAIT`] reads them: the handles (fewer
/// than 64, at `handles`), the timeout in milliseconds (INFINITE, 0xFFFFFFFF, for none), the
/// queue-status bits of the input that ends the wait, and MsgWaitForMultipleObjectsEx's flags
/// (the `MWMO_` ones).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MsgWait {
    pub count: u32,
    pub handles: u32,
    pub timeout: u32,
    pub wake_mask: u32,
    pub flags: u32,
}

/// MsgWaitForMultipleObjectsEx's flags (winuser.h's MWMO_*): every object and an input end the
/// wait, not one of them; user APCs run and end it (WAIT_IO_COMPLETION); input the queue holds
/// counts, not only input come since a read last looked for it.
pub const MWMO_WAITALL: u32 = 0x0001;
pub const MWMO_ALERTABLE: u32 = 0x0002;
pub const MWMO_INPUTAVAILABLE: u32 = 0x0004;
/// Every flag MsgWaitForMultipleObjectsEx takes; another fails with ERROR_INVALID_PARAMETER.
pub const MWMO_VALID: u32 = MWMO_WAITALL | MWMO_ALERTABLE | MWMO_INPUTAVAILABLE;

// SAFETY: five integers.
unsafe impl Pod for MsgWait {}

/// NtUserCallHwndLock's routines: UpdateWindow (a WM_PAINT sent to the window when its update
/// region is not empty); SetForegroundWindow (the window's thread made the foreground one, the
/// window its active window); the default window procedure's WM_ACTIVATE (the focus to the window
/// being activated, as DefWindowProc's documentation gives it).
pub const HWND_LOCK_UPDATE_WINDOW: u32 = 0;
pub const HWND_LOCK_SET_FOREGROUND_WINDOW: u32 = 1;
pub const HWND_LOCK_ACTIVATE_FOCUS: u32 = 2;

/// NtUserCallHwndParamLock's routines: EnableWindow (the parameter is bEnable; the result the
/// window's former WS_DISABLED, as the style's state byte holds it); the default window
/// procedure's WM_SETREDRAW (the parameter is its wParam: the window's WS_VISIBLE set or cleared,
/// nothing shown, hidden or painted; the result 0); the default window procedure's
/// WM_WINDOWPOSCHANGING (the parameter is the WINDOWPOS's address: a resize's size clamped into
/// the window's tracking sizes, as WM_GETMINMAXINFO answers them, in place; the result 0);
/// ValidateRgn (the parameter is the region's handle, 0 for all of the update region: Windows
/// 2000's SFI_XXXVALIDATERGN; the result 0).
pub const HWND_PARAM_LOCK_ENABLE_WINDOW: u32 = 0;
pub const HWND_PARAM_LOCK_SET_REDRAW: u32 = 1;
pub const HWND_PARAM_LOCK_WINDOW_POS_CHANGING: u32 = 2;
pub const HWND_PARAM_LOCK_VALIDATE_RGN: u32 = 3;

/// NtUserGetThreadState's routines: the calling thread's focus window (GetFocus) and its active
/// window (GetActiveWindow); the time and the cursor position (x in the low word, y in the high
/// word) of the last message its reads retrieved (GetMessageTime, GetMessagePos); its capture
/// window and the cursor's place and shape.
pub const THREAD_STATE_FOCUS_WINDOW: u32 = 0;
pub const THREAD_STATE_ACTIVE_WINDOW: u32 = 1;
pub const THREAD_STATE_MESSAGE_TIME: u32 = 2;
pub const THREAD_STATE_MESSAGE_POS: u32 = 3;
/// GetCapture: the calling thread's capture window.
pub const THREAD_STATE_CAPTURE_WINDOW: u32 = 4;
/// GetCursorPos: the cursor's screen position, x in the low word, y in the high word (each a
/// SHORT).
pub const THREAD_STATE_CURSOR_POS: u32 = 5;
/// GetCursor: the cursor's shape, as SetCursor set it.
pub const THREAD_STATE_CURSOR: u32 = 6;

/// NtUserGetUpdateRect's answer bits: the update region is not empty; the caller is to send the
/// window WM_ERASEBKGND (it asked for the erase, and one was pending).
pub const UPDATE_NOT_EMPTY: u32 = 0x1;
pub const UPDATE_ERASE: u32 = 0x2;
/// NtUserGetUpdateRect's and NtUserGetUpdateRgn's answer bit (F2K's): the caller is to send the
/// window WM_NCPAINT, before any WM_ERASEBKGND (it asked for the erase, and its frame was to be
/// painted).
pub const UPDATE_FRAME: u32 = 0x4;

/// RedrawWindow's flags (winuser.h's RDW_*).
pub const RDW_INVALIDATE: u32 = 0x0001;
pub const RDW_INTERNALPAINT: u32 = 0x0002;
pub const RDW_ERASE: u32 = 0x0004;
pub const RDW_VALIDATE: u32 = 0x0008;
pub const RDW_NOINTERNALPAINT: u32 = 0x0010;
pub const RDW_NOERASE: u32 = 0x0020;
pub const RDW_NOCHILDREN: u32 = 0x0040;
pub const RDW_ALLCHILDREN: u32 = 0x0080;
pub const RDW_UPDATENOW: u32 = 0x0100;
pub const RDW_ERASENOW: u32 = 0x0200;
pub const RDW_FRAME: u32 = 0x0400;
pub const RDW_NOFRAME: u32 = 0x0800;

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use super::*;

    /// The structures' sizes and offsets, as winuser.h lays them out on x86; the receipt's parts
    /// where user32 finds them.
    #[test]
    fn the_layouts_are_windows_2000s() {
        assert_eq!(size_of::<Point>(), 8);
        assert_eq!(size_of::<Msg>(), 28);
        assert_eq!(offset_of!(Msg, time), 16);
        assert_eq!(offset_of!(Msg, pt), 20);
        assert_eq!(size_of::<PaintStruct>(), 64);
        assert_eq!(offset_of!(PaintStruct, paint), 8);
        assert_eq!(offset_of!(PaintStruct, reserved), 32);
        assert_eq!(size_of::<CreateStructW>(), 48);
        assert_eq!(offset_of!(CreateStructW, cy), 16);
        assert_eq!(offset_of!(CreateStructW, x), 28);
        assert_eq!(offset_of!(CreateStructW, ex_style), 44);
        assert_eq!(size_of::<Receipt>(), 32);
        assert_eq!(offset_of!(Receipt, msg), 4);
        assert_eq!(size_of::<StyleStruct>(), 8);
        assert_eq!(size_of::<Input>(), 28);
        assert_eq!(offset_of!(Input, flags), 8);
        assert_eq!(offset_of!(Input, extra_info), 16);
        assert_eq!(size_of::<GuiThreadInfo>(), 48);
        assert_eq!(offset_of!(GuiThreadInfo, rc_caret), 32);
        assert_eq!(size_of::<SendTimeout>(), 8);
    }

    /// An INPUT_MOUSE record's MOUSEINPUT, read through the keyboard's view of the union.
    #[test]
    fn the_mouse_input_is_read_through_the_union() {
        let mut words = [0u32; 7];
        words[0] = INPUT_MOUSE;
        words[1] = (-5i32) as u32;
        words[2] = 40000;
        words[3] = 120;
        words[4] = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
        words[5] = 77;
        words[6] = 9;
        let input = Input::from_bytes(crate::pod::slice_bytes(&words)).unwrap();
        assert_eq!(
            input.mouse(),
            MouseInput {
                dx: -5,
                dy: 40000,
                data: 120,
                flags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                time: 77,
                extra_info: 9,
            }
        );
    }

    /// The messages whose pointer no asynchronous send carries are below WM_USER; a registered
    /// message, or one of the program's own, is never one.
    #[test]
    fn the_sync_only_messages_carry_pointers() {
        assert!(sync_only(WM_SETTEXT) && sync_only(WM_NCCREATE) && sync_only(WM_WINDOWPOSCHANGED));
        assert!(!sync_only(WM_NULL) && !sync_only(WM_CLOSE) && !sync_only(WM_TIMER));
        assert!(!sync_only(WM_USER) && !sync_only(WM_USER + 30) && !sync_only(0xC000));
        assert_eq!(QS_ALLINPUT, 0x00FF);
    }

    /// PeekMessage's kinds are the status bits in the high word.
    #[test]
    fn the_peek_kinds_are_the_status_bits() {
        assert_eq!(PM_QS_INPUT, 0x0007_0000);
        assert_eq!(PM_QS_POSTMESSAGE, 0x0098_0000);
        assert_eq!(PM_QS_PAINT, 0x0020_0000);
        assert_eq!(PM_QS_SENDMESSAGE, 0x0040_0000);
    }
}
