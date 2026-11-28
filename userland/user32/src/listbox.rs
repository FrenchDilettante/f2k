//! The ListBox control: the class user32 registers in every process
//! ([`crate::class::register_system_classes`]), its procedure here in its two forms
//! ([`list_box_proc_w`], [`list_box_proc_a`]), as Windows 2000's user32 runs it; and the calls
//! over it, DlgDirListA/W, DlgDirSelectExA/W and GetListBoxInfo.
//!
//! A list box's state is a fixed local block of its own ([`State`], Windows 2000's LBIV), found by
//! its window in a table of the process's ([`kept`], over [`crate::records`]), as an edit's is (its
//! window can be gone before its WM_NCDESTROY reaches the procedure). Its items are a fixed local
//! block of [`Item`] records, grown as items come (LB_INITSTORAGE grows it ahead); an item's text
//! is a fixed block of its UTF-16 units of its own, NUL-terminated (an ANSI list box's too,
//! converted where a narrow message reads or writes it). No step locks a block, so the last error
//! is left as it was (the listbox capture's err=- after each message that succeeds).
//!
//! What it holds, as the creation's style sets it (a later SetWindowLong leaves the kind as it
//! was, as Windows 2000's keeps it in the LBIV): strings (a list box that is not owner-drawn, or
//! LBS_HASSTRINGS), or for an owner-drawn list box without LBS_HASSTRINGS a value for each item
//! (LB_ADDSTRING's lParam, which LB_GETTEXT copies out as four bytes); LBS_NODATA's items hold
//! nothing (LB_SETCOUNT). LBS_SORT puts LB_ADDSTRING's strings in order (CompareStringW in the
//! list box's locale, ignoring case, as Windows 2000's Compare: the shorter of two strings equal
//! as far as it goes first), an owner-drawn list box's values through WM_COMPAREITEM;
//! LB_INSERTSTRING never sorts. As the listbox capture shows Windows 2000's:
//!
//! - an index past the items is LB_ERR with ERROR_INVALID_INDEX for LB_INSERTSTRING (whose -1 is
//!   the end), LB_DELETESTRING, LB_GETTEXT, LB_GETTEXTLEN, LB_GETITEMDATA, LB_SETITEMDATA,
//!   LB_SETTOPINDEX and LB_GETITEMRECT; LB_SETCURSEL's is LB_ERR with no error and the selection
//!   kept (-1 clears it, and answers LB_ERR too); LB_GETSEL's LB_ERR with no error;
//! - LB_FINDSTRING finds the first item from the one after wParam's, round the end, whose text
//!   starts with lParam's (ignoring case), LB_FINDSTRINGEXACT the one whose text is lParam's;
//!   LB_SELECTSTRING selects LB_FINDSTRING's item; an owner-drawn list box without strings finds
//!   the item whose value is lParam;
//! - LB_SETITEMDATA answers TRUE; LB_RESETCONTENT and LB_SETITEMHEIGHT 0; LB_DELETESTRING the items
//!   left;
//! - LB_GETITEMHEIGHT of a list box whose items are one height answers it whatever the index: the
//!   font's (the System font's with none), or the parent's WM_MEASUREITEM answer for an
//!   LBS_OWNERDRAWFIXED list box, which it sends once at its creation (itemHeight the font's); an
//!   LBS_OWNERDRAWVARIABLE list box sends WM_MEASUREITEM for each item it takes, and keeps each
//!   item's height; LB_SETITEMHEIGHT refuses a height past 255 (LB_ERR, ERROR_INVALID_PARAMETER);
//! - LB_GETITEMRECT answers whether the item shows, its rectangle filled either way (above the top
//!   index a negative one);
//! - a single-selection list box answers LB_ERR to LB_SETSEL (ERROR_INVALID_PARAMETER),
//!   LB_SELITEMRANGE (ERROR_INVALID_INDEX), LB_SELITEMRANGEEX (ERROR_INVALID_LB_MESSAGE),
//!   LB_GETSELCOUNT and LB_GETSELITEMS (no error); a multiple-selection one (LBS_MULTIPLESEL or
//!   LBS_EXTENDEDSEL) LB_ERR to LB_SETCURSEL, and its LB_GETCURSEL is its caret's item; LB_SETSEL
//!   of -1 sets every item and leaves the caret, of an item moves the caret there, past the items
//!   LB_ERR with ERROR_INVALID_PARAMETER; LB_SELITEMRANGEEX with its first index past its last
//!   deselects the range;
//! - WM_DELETEITEM goes to the parent for each LB_DELETESTRING (whatever the kind: its value), and
//!   for each item of an owner-drawn list box when LB_RESETCONTENT or the destruction removes them
//!   all (the last first);
//! - nothing a message changes is notified: LBN_SELCHANGE (with LBS_NOTIFY) follows the keys and
//!   the mouse alone, LBN_DBLCLK a double click; LBN_SETFOCUS and LBN_KILLFOCUS go whatever the
//!   style;
//! - an owner-drawn list box's paint is WM_DRAWITEM (ODA_DRAWENTIRE) for each item it shows; a
//!   selection a message changes is drawn at once, WM_DRAWITEM with ODA_SELECT for the item left
//!   and the one selected; LB_DELETESTRING redraws the items from the one it removed;
//! - LB_DIR lists the files (and with DDL_DIRECTORY, after them, the directories, "[name]", and
//!   with DDL_DRIVES the drives, "[-x-]") its pattern finds, answering the last one's index and
//!   leaving FindNextFileW's ERROR_NO_MORE_FILES; a pattern that finds nothing is LB_ERR with
//!   FindFirstFileW's error; LB_INITSTORAGE grows the items' block ahead (the items it can hold
//!   answered), LB_ERRSPACE with ERROR_NOT_ENOUGH_MEMORY when it cannot;
//! - LB_GETLISTBOXINFO answers the items per column of an LBS_MULTICOLUMN list box, 0 for another;
//! - WM_GETDLGCODE is DLGC_WANTARROWS | DLGC_WANTCHARS.
//!
//! The keys: the arrows step the caret (Left and Right as Up and Down but in an LBS_MULTICOLUMN
//! list box, where they step a column), PgUp and PgDn a page less an item, Home and End to the
//! ends, the list scrolled to show the caret; a single-selection list box with no selection takes
//! the caret's item for the first arrow; the selection follows the caret but in an
//! LBS_MULTIPLESEL list box, where Space toggles the caret's item (LBS_EXTENDEDSEL: Shift extends
//! from the anchor, Ctrl moves the caret alone, Ctrl+Space toggles); LBN_SELCHANGE follows each
//! change of the caret or the selection. A character selects the next item (round the end) whose
//! text starts with it. LBS_WANTKEYBOARDINPUT asks the parent first (WM_VKEYTOITEM, WM_CHARTOITEM:
//! -2 done, -1 the list box's own handling, an index the item to go to). The mouse: a press takes
//! the focus and the capture and selects the item under it (as the keys do, Shift and Ctrl for
//! LBS_EXTENDEDSEL), a move under the capture follows, the release lets the capture go; a double
//! click is LBN_DBLCLK.
//!
//! The list box paints in WM_PAINT: its background with the brush its parent's
//! WM_CTLCOLORLISTBOX answers, each item's text from two pixels in (in its font, WM_SETFONT's or
//! the System font), a selected item in COLOR_HIGHLIGHT and COLOR_HIGHLIGHTTEXT, disabled text in
//! COLOR_GRAYTEXT, the caret's item framed with DrawFocusRect while it has the focus. WS_VSCROLL
//! (WS_HSCROLL for LBS_MULTICOLUMN) is its own scroll bar, set to the items and shown only when
//! they do not all show (LBS_DISABLENOSCROLL: disabled instead); WM_VSCROLL, WM_HSCROLL and
//! WM_MOUSEWHEEL scroll. Without LBS_NOINTEGRALHEIGHT a list box whose items are one height is cut
//! to show whole items.
//!
//! A combo box's list (LBS_COMBOBOX) is a list box whose notifications go to its combo box, which
//! tells it so ([`set_owner`]); the combo box itself is not served yet. What is not served is
//! logged once: LB_SETTABSTOPS' own stops (LBS_USETABSTOPS expands tabs at the default stops),
//! LB_SETHORIZONTALEXTENT's sideways scroll, a mouse drag past the list's edge (no autoscroll).

use rtl::display::{COLOR_GRAYTEXT, COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT};
use rtl::edge::{InStr, InWStr, OutBuf};
use rtl::gdi::{Rect, TRANSPARENT};
use rtl::pod::Pod;
use rtl::scroll::{
    ScrollInfo,
    SB_HORZ,
    SB_VERT,
    SCROLLINFO_SIZE,
    SIF_DISABLENOSCROLL,
    SIF_PAGE,
    SIF_POS,
    SIF_RANGE,
};
use rtl::user::{
    VK_CONTROL,
    VK_DOWN,
    VK_END,
    VK_HOME,
    VK_LEFT,
    VK_RIGHT,
    VK_SHIFT,
    VK_SPACE,
    VK_UP,
    WM_CAPTURECHANGED,
    WM_CHAR,
    WM_CHARTOITEM,
    WM_COMMAND,
    WM_COMPAREITEM,
    WM_CREATE,
    WM_CTLCOLORLISTBOX,
    WM_DRAWITEM,
    WM_ENABLE,
    WM_ERASEBKGND,
    WM_GETDLGCODE,
    WM_GETFONT,
    WM_KEYDOWN,
    WM_KILLFOCUS,
    WM_LBUTTONDBLCLK,
    WM_LBUTTONDOWN,
    WM_LBUTTONUP,
    WM_MOUSEMOVE,
    WM_MOUSEWHEEL,
    WM_NCCREATE,
    WM_NCDESTROY,
    WM_PAINT,
    WM_SETFOCUS,
    WM_SETFONT,
    WM_SETREDRAW,
    WM_SIZE,
    WM_VKEYTOITEM,
    WS_BORDER,
    WS_DISABLED,
    WS_EX_CLIENTEDGE,
    WS_HSCROLL,
    WS_VSCROLL,
};
use rtl::window::{
    GWL_EXSTYLE,
    GWL_STYLE,
    SWP_FRAMECHANGED,
    SWP_NOACTIVATE,
    SWP_NOMOVE,
    SWP_NOSIZE,
    SWP_NOZORDER,
};
use rtl::winerror::{ERROR_INVALID_INDEX, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};

use crate::dialog::{DLGC_WANTARROWS, DLGC_WANTCHARS};
use crate::imports::{self, LocalFixed, LMEM_FIXED, LMEM_MOVEABLE, LMEM_ZEROINIT};
use crate::{answered, message, paint, procedure, window};

// --- The messages, the styles, the notifications -------------------------------------------------

/// The list box messages (winuser.h's LB_*).
pub const LB_ADDSTRING: u32 = 0x0180;
pub const LB_INSERTSTRING: u32 = 0x0181;
pub const LB_DELETESTRING: u32 = 0x0182;
pub const LB_SELITEMRANGEEX: u32 = 0x0183;
pub const LB_RESETCONTENT: u32 = 0x0184;
pub const LB_SETSEL: u32 = 0x0185;
pub const LB_SETCURSEL: u32 = 0x0186;
pub const LB_GETSEL: u32 = 0x0187;
pub const LB_GETCURSEL: u32 = 0x0188;
pub const LB_GETTEXT: u32 = 0x0189;
pub const LB_GETTEXTLEN: u32 = 0x018A;
pub const LB_GETCOUNT: u32 = 0x018B;
pub const LB_SELECTSTRING: u32 = 0x018C;
pub const LB_DIR: u32 = 0x018D;
pub const LB_GETTOPINDEX: u32 = 0x018E;
pub const LB_FINDSTRING: u32 = 0x018F;
pub const LB_GETSELCOUNT: u32 = 0x0190;
pub const LB_GETSELITEMS: u32 = 0x0191;
pub const LB_SETTABSTOPS: u32 = 0x0192;
pub const LB_GETHORIZONTALEXTENT: u32 = 0x0193;
pub const LB_SETHORIZONTALEXTENT: u32 = 0x0194;
pub const LB_SETCOLUMNWIDTH: u32 = 0x0195;
pub const LB_ADDFILE: u32 = 0x0196;
pub const LB_SETTOPINDEX: u32 = 0x0197;
pub const LB_GETITEMRECT: u32 = 0x0198;
pub const LB_GETITEMDATA: u32 = 0x0199;
pub const LB_SETITEMDATA: u32 = 0x019A;
pub const LB_SELITEMRANGE: u32 = 0x019B;
pub const LB_SETANCHORINDEX: u32 = 0x019C;
pub const LB_GETANCHORINDEX: u32 = 0x019D;
pub const LB_SETCARETINDEX: u32 = 0x019E;
pub const LB_GETCARETINDEX: u32 = 0x019F;
pub const LB_SETITEMHEIGHT: u32 = 0x01A0;
pub const LB_GETITEMHEIGHT: u32 = 0x01A1;
pub const LB_FINDSTRINGEXACT: u32 = 0x01A2;
pub const LB_SETLOCALE: u32 = 0x01A5;
pub const LB_GETLOCALE: u32 = 0x01A6;
pub const LB_SETCOUNT: u32 = 0x01A7;
pub const LB_INITSTORAGE: u32 = 0x01A8;
pub const LB_ITEMFROMPOINT: u32 = 0x01A9;
pub const LB_GETLISTBOXINFO: u32 = 0x01B2;
/// The list box messages' range: one not served answers LB_ERR, logged.
const LB_FIRST: u32 = 0x0180;
const LB_LAST: u32 = 0x01B2;

/// The list box styles (winuser.h's LBS_*).
pub const LBS_NOTIFY: u32 = 0x0001;
pub const LBS_SORT: u32 = 0x0002;
pub const LBS_NOREDRAW: u32 = 0x0004;
pub const LBS_MULTIPLESEL: u32 = 0x0008;
pub const LBS_OWNERDRAWFIXED: u32 = 0x0010;
pub const LBS_OWNERDRAWVARIABLE: u32 = 0x0020;
pub const LBS_HASSTRINGS: u32 = 0x0040;
pub const LBS_USETABSTOPS: u32 = 0x0080;
pub const LBS_NOINTEGRALHEIGHT: u32 = 0x0100;
pub const LBS_MULTICOLUMN: u32 = 0x0200;
pub const LBS_WANTKEYBOARDINPUT: u32 = 0x0400;
pub const LBS_EXTENDEDSEL: u32 = 0x0800;
pub const LBS_DISABLENOSCROLL: u32 = 0x1000;
pub const LBS_NODATA: u32 = 0x2000;
pub const LBS_NOSEL: u32 = 0x4000;
pub const LBS_COMBOBOX: u32 = 0x8000;

/// The notifications (winuser.h's LBN_*), the code in WM_COMMAND's wParam's high word.
pub const LBN_ERRSPACE: u32 = 0xFFFE;
pub const LBN_SELCHANGE: u32 = 1;
pub const LBN_DBLCLK: u32 = 2;
pub const LBN_SELCANCEL: u32 = 3;
pub const LBN_SETFOCUS: u32 = 4;
pub const LBN_KILLFOCUS: u32 = 5;

/// The answers (winuser.h's LB_OKAY, LB_ERR, LB_ERRSPACE).
const LB_OKAY: i32 = 0;
const LB_ERR: i32 = -1;
const LB_ERRSPACE: i32 = -2;

/// The attributes LB_DIR and DlgDirList take (winuser.h's DDL_*).
pub const DDL_READWRITE: u32 = 0x0000;
pub const DDL_READONLY: u32 = 0x0001;
pub const DDL_HIDDEN: u32 = 0x0002;
pub const DDL_SYSTEM: u32 = 0x0004;
pub const DDL_DIRECTORY: u32 = 0x0010;
pub const DDL_ARCHIVE: u32 = 0x0020;
pub const DDL_POSTMSGS: u32 = 0x2000;
pub const DDL_DRIVES: u32 = 0x4000;
pub const DDL_EXCLUSIVE: u32 = 0x8000;
/// The file attributes a DDL_ value names (FILE_ATTRIBUTE_READONLY, HIDDEN, SYSTEM, ARCHIVE).
const FILE_BITS: u32 = DDL_READONLY | DDL_HIDDEN | DDL_SYSTEM | DDL_ARCHIVE;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;

/// The Win32 errors the list box's refusals leave that rtl does not name.
const ERROR_LISTBOX_ID_NOT_FOUND: u32 = 1416;
const ERROR_INVALID_LB_MESSAGE: u32 = 1432;
const ERROR_SETCOUNT_ON_BAD_LB: u32 = 1433;
const ERROR_LB_WITHOUT_TABSTOPS: u32 = 1434;

/// The owner-draw structures' values (winuser.h's ODT_, ODA_, ODS_).
const ODT_LISTBOX: u32 = 2;
const ODA_DRAWENTIRE: u32 = 0x0001;
const ODA_SELECT: u32 = 0x0002;
const ODA_FOCUS: u32 = 0x0004;
const ODS_SELECTED: u32 = 0x0001;
const ODS_DISABLED: u32 = 0x0004;
const ODS_FOCUS: u32 = 0x0010;

/// The messages and keys rtl does not name.
const WM_HSCROLL: u32 = 0x0114;
const WM_VSCROLL: u32 = 0x0115;
const VK_PRIOR: u32 = 0x21;
const VK_NEXT: u32 = 0x22;
const SB_LINEUP: u32 = 0;
const SB_LINEDOWN: u32 = 1;
const SB_PAGEUP: u32 = 2;
const SB_PAGEDOWN: u32 = 3;
const SB_THUMBPOSITION: u32 = 4;
const SB_THUMBTRACK: u32 = 5;
const SB_TOP: u32 = 6;
const SB_BOTTOM: u32 = 7;
/// ExtTextOut's ETO_CLIPPED: the text cut to its rectangle.
const ETO_CLIPPED: u32 = 0x0004;
/// CompareStringW's NORM_IGNORECASE.
const NORM_IGNORECASE: u32 = 0x0001;

/// How far an item's text starts in from its rectangle's left.
const TEXT_INDENT: i32 = 2;
/// The highest item LB_SETITEMHEIGHT takes.
const MOST_HEIGHT: u32 = 255;
/// The items the block first holds, and its least growth.
const GROW: usize = 16;

/// The list box's extra bytes: Windows 2000's hold the LBIV's address (F2K's state is in [`kept`]).
pub const LISTBOX_EXTRA: i32 = 4;

/// The cases logged in this process: a message, a style.
static LOGGED: rtl::stub::Logged<16> = rtl::stub::Logged::new();

/// The control's procedure, as its log lines name it.
const LISTBOX_PROC: rtl::stub::Entry = crate::stub::procedure("ListBoxWndProc");

// --- The state
// ---------------------------------------------------------------------------------------

/// [`State::flags`]: the list box has the focus, holds the mouse's capture (a press being
/// tracked), draws nothing (WM_SETREDRAW FALSE, LBS_NOREDRAW), is cutting itself to whole items,
/// is tracking a double click's press.
const FOCUSED: u32 = 0x1;
const CAPTURED: u32 = 0x2;
const NO_REDRAW: u32 = 0x4;
const SIZING: u32 = 0x8;
const DOUBLE: u32 = 0x10;

/// A list box's state (Windows 2000's LBIV, F2K's layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct State {
    /// The items: a fixed local block of [`Item`] records, `count` of them used (0: none yet).
    items: usize,
    /// WM_SETFONT's font (0: the System font).
    font: usize,
    /// The window its notifications and owner-draw messages go to: its parent (a combo box's
    /// list: its combo box).
    owner: usize,
    count: u32,
    /// The first item shown (a column's first in an LBS_MULTICOLUMN list box).
    top: u32,
    /// A single-selection list box's selected item (-1: none).
    selection: i32,
    /// The caret's item (the focus rectangle's), and LBS_EXTENDEDSEL's anchor (-1: none).
    caret: i32,
    anchor: i32,
    /// The items' height (one for all but in an LBS_OWNERDRAWVARIABLE list box).
    item_height: u32,
    flags: u32,
    /// The control's id, as its creation gave it (its notifications' when its window is gone).
    id: u32,
    /// LBS_MULTICOLUMN's columns' width, LB_SETHORIZONTALEXTENT's extent.
    column_width: u32,
    extent: u32,
    /// The locale its strings sort and compare in (LB_SETLOCALE).
    locale: u32,
    /// Its style at its creation: its kind ([`State::owner_draw`], [`State::multiple`]...).
    style: u32,
}

// SAFETY: integers only, with no padding: three words first, then twelve 32-bit fields (an even
// count, which ends at a word's boundary).
unsafe impl Pod for State {}

/// The kinds of owner-draw list box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnerDraw {
    None,
    Fixed,
    Variable,
}

/// The kinds of selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selection {
    Single,
    Multiple,
    Extended,
}

impl State {
    fn owner_draw(&self) -> OwnerDraw {
        if self.style & LBS_OWNERDRAWVARIABLE != 0 && self.style & LBS_MULTICOLUMN == 0 {
            OwnerDraw::Variable
        } else if self.style & (LBS_OWNERDRAWFIXED | LBS_OWNERDRAWVARIABLE) != 0 {
            OwnerDraw::Fixed
        } else {
            OwnerDraw::None
        }
    }

    /// Whether its items are strings (else each a value).
    fn has_strings(&self) -> bool {
        self.owner_draw() == OwnerDraw::None
            || (self.style & LBS_HASSTRINGS != 0 && self.style & LBS_NODATA == 0)
    }

    fn no_data(&self) -> bool {
        self.style & LBS_NODATA != 0
    }

    fn multiple(&self) -> Selection {
        if self.style & LBS_EXTENDEDSEL != 0 {
            Selection::Extended
        } else if self.style & LBS_MULTIPLESEL != 0 {
            Selection::Multiple
        } else {
            Selection::Single
        }
    }

    fn single(&self) -> bool {
        self.multiple() == Selection::Single
    }

    fn sorted(&self) -> bool {
        self.style & LBS_SORT != 0 && !self.no_data()
    }

    fn notifies(&self) -> bool {
        self.style & LBS_NOTIFY != 0
    }

    fn multicolumn(&self) -> bool {
        self.style & LBS_MULTICOLUMN != 0
    }

    fn focused(&self) -> bool {
        self.flags & FOCUSED != 0
    }

    fn height(&self) -> i32 {
        self.item_height.max(1) as i32
    }

    fn column(&self) -> i32 {
        self.column_width.max(1) as i32
    }
}

/// An item (Windows 2000's LBItem, F2K's layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Item {
    /// Its text: a fixed local block of `length` units and a terminator (0: none, or an empty
    /// string's).
    text: usize,
    /// Its value: LB_SETITEMDATA's, or an owner-drawn list box's item itself.
    data: usize,
    length: u32,
    /// Its height in an LBS_OWNERDRAWVARIABLE list box.
    height: u32,
    /// Whether it is selected in a multiple-selection list box.
    selected: u32,
    reserved: u32,
}

// SAFETY: integers only, with no padding: two words, then four 32-bit fields.
unsafe impl Pod for Item {}

/// The list boxes' state blocks, by window: the process's table (see the module notes).
mod kept {
    use crate::records::Table;

    /// Each list box's record: its window, its state block.
    static LIST_BOXES: Table<2> = Table::new();

    /// The state block `block` kept for `window`; false when the heap has no room for its record.
    pub fn keep(window: usize, block: usize) -> bool {
        LIST_BOXES.with(|boxes| boxes.set([window, block]))
    }

    /// The state block of `window`.
    pub fn block(window: usize) -> Option<usize> {
        LIST_BOXES
            .with(|boxes| boxes.get(window))
            .map(|[_, block]| block)
    }

    /// The state block of `window`, no longer kept.
    pub fn forget(window: usize) -> Option<usize> {
        LIST_BOXES
            .with(|boxes| boxes.take(window))
            .map(|[_, block]| block)
    }
}

/// The fixed block `block` (a list box's state, its items, an item's text) as values of `T`; none
/// for no block.
fn fixed<T: Pod>(block: usize) -> Option<LocalFixed<T>> {
    // SAFETY: the blocks a list box's state names, and the state block its window's record names,
    // are its own fixed blocks, made LMEM_ZEROINIT or written whole before they are read, freed
    // only once nothing names them; the value returned is read or written and dropped within one
    // step of the list box's, which sends no message meanwhile, so no other value names the block.
    unsafe { LocalFixed::new(block) }
}

/// The state of the list box `window`; none for a window this procedure keeps none for.
fn load(window: usize) -> Option<State> {
    fixed::<State>(kept::block(window)?)?
        .as_slice()
        .first()
        .copied()
}

/// The state of the list box `window` written back.
fn store(window: usize, state: &State) {
    if let Some(mut block) = kept::block(window).and_then(fixed::<State>) {
        if let Some(slot) = block.as_mut_slice().first_mut() {
            *slot = *state;
        }
    }
}

/// Whether `window` is a list box of this process's (a combo box's list too).
pub fn is_list_box(window: usize) -> bool {
    kept::block(window).is_some()
}

/// Whether the list box `window` holds strings: whether a narrow caller's string messages reach
/// its procedure converted (an owner-drawn list box's values are not strings).
pub fn holds_strings(window: usize) -> bool {
    load(window).is_some_and(|s| s.has_strings())
}

/// The window the list box `window`'s notifications go to set to `owner`: a combo box tells its
/// list (LBS_COMBOBOX) so.
pub fn set_owner(window: usize, owner: usize) {
    if let Some(mut s) = load(window) {
        s.owner = owner;
        store(window, &s);
    }
}

/// A case the control does not serve, logged once for the message it came with.
fn unserved(key: u32, what: &str, call: (usize, u32, u32, i32)) {
    crate::stub::message_once(&LOGGED, key, &LISTBOX_PROC, what, call);
}

// --- The items
// ---------------------------------------------------------------------------------------

/// The item at `index`; none past the items.
fn item(s: &State, index: u32) -> Option<Item> {
    if index >= s.count {
        return None;
    }
    fixed::<Item>(s.items)?
        .as_slice()
        .get(index as usize)
        .copied()
}

/// The item at `index` written.
fn put_item(s: &State, index: u32, value: Item) {
    if index >= s.count {
        return;
    }
    if let Some(mut items) = fixed::<Item>(s.items) {
        if let Some(slot) = items.as_mut_slice().get_mut(index as usize) {
            *slot = value;
        }
    }
}

/// How many items the block holds.
fn capacity(s: &State) -> usize {
    if s.items == 0 {
        0
    } else {
        imports::local_size(s.items) / core::mem::size_of::<Item>()
    }
}

/// The block grown to hold `more` items beyond the count; false (ERROR_NOT_ENOUGH_MEMORY) when it
/// cannot be.
fn reserve(s: &mut State, more: usize) -> bool {
    let Some(wanted) = (s.count as usize).checked_add(more) else {
        imports::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    };
    let room = capacity(s);
    if wanted <= room {
        return true;
    }
    let grown = wanted.max(room + room / 2).max(GROW);
    let Some(bytes) = grown
        .checked_mul(core::mem::size_of::<Item>())
        .filter(|&bytes| bytes <= i32::MAX as usize)
    else {
        imports::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    };
    let block = if s.items == 0 {
        imports::local_alloc(LMEM_FIXED | LMEM_ZEROINIT, bytes)
    } else {
        imports::local_realloc(s.items, bytes, LMEM_MOVEABLE | LMEM_ZEROINIT)
    };
    match block {
        Some(block) => {
            s.items = block;
            true
        }
        None => {
            imports::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            false
        }
    }
}

/// `value` put in at `index` (at most the count), the items after it moved on; false when the
/// block has no room for it.
fn insert_slot(s: &mut State, index: u32, value: Item) -> bool {
    if !reserve(s, 1) {
        return false;
    }
    let Some(mut items) = fixed::<Item>(s.items) else {
        return false;
    };
    let slots = items.as_mut_slice();
    let (at, end) = (index as usize, s.count as usize);
    slots.copy_within(at..end, at + 1);
    slots[at] = value;
    s.count += 1;
    true
}

/// The item at `index` taken out, the items after it moved back.
fn remove_slot(s: &mut State, index: u32) -> Option<Item> {
    let taken = item(s, index)?;
    let mut items = fixed::<Item>(s.items)?;
    let slots = items.as_mut_slice();
    let (at, end) = (index as usize, s.count as usize);
    slots.copy_within(at + 1..end, at);
    slots[end - 1] = Item::default();
    s.count -= 1;
    Some(taken)
}

/// A fixed block holding `units` and a terminator (0 for an empty string); none when there is no
/// room.
fn keep_units(units: &[u16]) -> Option<usize> {
    if units.is_empty() {
        return Some(0);
    }
    let block = imports::local_alloc(LMEM_FIXED | LMEM_ZEROINIT, 2 * (units.len() + 1))?;
    let mut held = fixed::<u16>(block)?;
    held.as_mut_slice()[..units.len()].copy_from_slice(units);
    Some(block)
}

/// Run `f` on the item's text (empty for none).
fn with_item_text<R>(value: &Item, f: impl FnOnce(&[u16]) -> R) -> R {
    match fixed::<u16>(value.text) {
        Some(units) => {
            let units = units.as_slice();
            f(&units[..(value.length as usize).min(units.len())])
        }
        None => f(&[]),
    }
}

/// The item's text block freed.
fn free_item(value: &Item) {
    if value.text != 0 {
        imports::local_free(value.text);
    }
}

/// The text a message's lParam names (LB_ADDSTRING's, LB_FINDSTRING's...), in the narrow form for
/// `ansi`, handed to `f` wide; none when its conversion found no room.
fn with_param_text<R>(lparam: i32, ansi: bool, f: impl FnOnce(&[u16]) -> R) -> Option<R> {
    if lparam == 0 {
        return Some(f(&[]));
    }
    if ansi {
        // SAFETY: the message's lParam as its sender hands it over: a NUL-terminated string,
        // narrow in this form.
        let text = unsafe { InStr::new(lparam as usize as *const u8) };
        return crate::with_wide(text.bytes(), f);
    }
    // SAFETY: as above, wide in this form.
    let text = unsafe { InWStr::new(lparam as usize as *const u16) }.units();
    if let Some(units) = text.aligned() {
        return Some(f(units));
    }
    let mut block = imports::HeapBlock::new(2 * text.len())?;
    let units = block.units_mut();
    text.copy_to(units);
    Some(f(&units[..text.len()]))
}

/// `units` written into the buffer at `buffer` (narrow for `ansi`), terminated: the units (bytes)
/// written before the terminator. The caller's buffer holds the text: LB_GETTEXTLEN's measure.
fn put_text(buffer: i32, ansi: bool, units: &[u16]) -> i32 {
    if buffer == 0 {
        return LB_ERR;
    }
    if ansi {
        let length = procedure::narrow_length(units);
        // SAFETY: LB_GETTEXT's lParam as its sender hands it over: a buffer that holds the item's
        // text and its terminator.
        let mut out = unsafe { OutBuf::new(buffer as usize as *mut u8, length + 1) };
        return procedure::put_narrow(&mut out, units) as i32;
    }
    // SAFETY: as above, wide in this form.
    let mut out = unsafe { OutBuf::new(buffer as usize as *mut u16, units.len() + 1) };
    out.put(units);
    out.set(units.len(), 0);
    units.len() as i32
}

/// The order of two strings as Windows 2000's list box compares them: CompareStringW over the
/// length of the shorter, ignoring case, in the list box's locale; two strings equal that far
/// ordered by their lengths.
fn compare(locale: u32, a: &[u16], b: &[u16]) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let shorter = a.len().min(b.len());
    match imports::compare_string(locale, NORM_IGNORECASE, &a[..shorter], &b[..shorter]) {
        1 => Ordering::Less,
        3 => Ordering::Greater,
        _ => a.len().cmp(&b.len()),
    }
}

/// Whether `text` starts with `prefix` (ignoring case, in the list box's locale).
fn starts_with(locale: u32, text: &[u16], prefix: &[u16]) -> bool {
    text.len() >= prefix.len()
        && imports::compare_string(locale, NORM_IGNORECASE, &text[..prefix.len()], prefix) == 2
}

/// Whether `text` is `whole` (ignoring case, in the list box's locale).
fn equals(locale: u32, text: &[u16], whole: &[u16]) -> bool {
    imports::compare_string(locale, NORM_IGNORECASE, text, whole) == 2
}

// --- The parent's messages
// ---------------------------------------------------------------------------

/// MEASUREITEMSTRUCT (winuser.h's), as WM_MEASUREITEM's lParam names it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct MeasureItemStruct {
    ctl_type: u32,
    ctl_id: u32,
    item_id: u32,
    item_width: u32,
    item_height: u32,
    item_data: u32,
}

/// DRAWITEMSTRUCT (winuser.h's), as WM_DRAWITEM's lParam names it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct DrawItemStruct {
    ctl_type: u32,
    ctl_id: u32,
    item_id: u32,
    item_action: u32,
    item_state: u32,
    hwnd_item: u32,
    hdc: u32,
    rc_item: Rect,
    item_data: u32,
}

/// DELETEITEMSTRUCT (winuser.h's), as WM_DELETEITEM's lParam names it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct DeleteItemStruct {
    ctl_type: u32,
    ctl_id: u32,
    item_id: u32,
    hwnd_item: u32,
    item_data: u32,
}

/// COMPAREITEMSTRUCT (winuser.h's), as WM_COMPAREITEM's lParam names it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct CompareItemStruct {
    ctl_type: u32,
    ctl_id: u32,
    hwnd_item: u32,
    item_id1: u32,
    item_data1: u32,
    item_id2: u32,
    item_data2: u32,
    locale: u32,
}

/// The messages the parent receives that rtl does not name.
const WM_MEASUREITEM: u32 = 0x002C;
const WM_DELETEITEM: u32 = 0x002D;

/// The list box's id: its window's (GWL_ID), the one its creation gave it once the window is gone.
fn id_of(window: usize, s: &State) -> u32 {
    window::window_data(window).map_or(s.id, |data| data.id)
}

/// `message` with the structure `value` sent to the list box's owner, wParam its id: the owner's
/// answer (0 for no owner). The structure lives on this frame for the send, which is the
/// procedure's own call.
fn to_owner<T>(window: usize, message: u32, value: &mut T) -> i32 {
    let Some(s) = load(window) else {
        return 0;
    };
    if s.owner == 0 {
        return 0;
    }
    message::send(
        s.owner,
        message,
        id_of(window, &s),
        value as *mut T as usize as i32,
    )
    .unwrap_or(0)
}

/// The notification `code` sent to the list box's owner (WM_COMMAND: its id and the code, the list
/// box's handle).
fn notify(window: usize, code: u32) {
    let Some(s) = load(window) else {
        return;
    };
    if s.owner == 0 {
        return;
    }
    let id = id_of(window, &s);
    let _ = message::send(
        s.owner,
        WM_COMMAND,
        code << 16 | (id & 0xFFFF),
        window as i32,
    );
}

/// The notification `code`, sent only for an LBS_NOTIFY list box (LBN_SELCHANGE, LBN_DBLCLK,
/// LBN_SELCANCEL).
fn notify_if_asked(window: usize, code: u32) {
    if load(window).is_some_and(|s| s.notifies()) {
        notify(window, code);
    }
}

/// WM_DELETEITEM for the item `index` (its value `data`) sent to the owner.
fn delete_item_message(window: usize, index: u32, data: usize) {
    let Some(s) = load(window) else {
        return;
    };
    let mut item = DeleteItemStruct {
        ctl_type: ODT_LISTBOX,
        ctl_id: id_of(window, &s),
        item_id: index,
        hwnd_item: window as u32,
        item_data: data as u32,
    };
    to_owner(window, WM_DELETEITEM, &mut item);
}

/// WM_MEASUREITEM for the item `index` (its value or string `data`; the whole list box's height
/// for an LBS_OWNERDRAWFIXED one) sent to the owner: the height it answers.
fn measure(window: usize, index: u32, data: usize) -> u32 {
    let Some(s) = load(window) else {
        return 0;
    };
    let width = window::client_rect(window).map_or(0, |client| client.right.max(0) as u32);
    let mut item = MeasureItemStruct {
        ctl_type: ODT_LISTBOX,
        ctl_id: id_of(window, &s),
        item_id: index,
        item_width: width,
        item_height: font_height(window, s.font),
        item_data: data as u32,
    };
    to_owner(window, WM_MEASUREITEM, &mut item);
    item.item_height
}

/// WM_COMPAREITEM of the values `a` (a new item) and `b` (the item `index`) sent to the owner: its
/// answer's order.
fn compare_items(window: usize, a: usize, index: u32, b: usize) -> core::cmp::Ordering {
    let Some(s) = load(window) else {
        return core::cmp::Ordering::Equal;
    };
    let mut item = CompareItemStruct {
        ctl_type: ODT_LISTBOX,
        ctl_id: id_of(window, &s),
        hwnd_item: window as u32,
        item_id1: u32::MAX,
        item_data1: a as u32,
        item_id2: index,
        item_data2: b as u32,
        locale: s.locale,
    };
    to_owner(window, WM_COMPAREITEM, &mut item).cmp(&0)
}

// --- The geometry
// ------------------------------------------------------------------------------------

/// The list box's client area (its origin (0, 0)).
fn client(window: usize) -> Rect {
    window::client_rect(window).unwrap_or_default()
}

/// The height of a line of `font` (0: the System font), as the list box's DC measures it.
fn font_height(window: usize, font: usize) -> u32 {
    let dc = crate::dc::get_dc(window);
    if dc == 0 {
        return 16;
    }
    let previous = (font != 0)
        .then(|| imports::select_object(dc, font))
        .flatten();
    let height = imports::text_metrics(dc).map_or(16, |metric| metric.height.max(1) as u32);
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
    crate::dc::release_dc(window, dc);
    height
}

/// The height of the item `index`.
fn height_of(s: &State, index: u32) -> i32 {
    match s.owner_draw() {
        OwnerDraw::Variable => item(s, index).map_or(s.height(), |value| value.height as i32),
        _ => s.height(),
    }
}

/// The items an LBS_MULTICOLUMN list box's column holds (one at least).
fn per_column(window: usize, s: &State) -> u32 {
    (client(window).bottom / s.height()).max(1) as u32
}

/// The item `index`'s rectangle in the client area (above or past it for an item not shown).
fn item_rect(window: usize, s: &State, index: u32) -> Rect {
    let area = client(window);
    if s.multicolumn() {
        let rows = per_column(window, s) as i64;
        let offset = i64::from(index) - i64::from(s.top);
        let column = offset.div_euclid(rows) as i32;
        let row = offset.rem_euclid(rows) as i32;
        let left = column * s.column();
        let top = row * s.height();
        return Rect::new(left, top, left + s.column(), top + s.height());
    }
    let top = match s.owner_draw() {
        OwnerDraw::Variable => {
            let (from, to, sign) = if index >= s.top {
                (s.top, index, 1)
            } else {
                (index, s.top, -1)
            };
            sign * (from..to).map(|at| height_of(s, at)).sum::<i32>()
        }
        _ => (i64::from(index) - i64::from(s.top)) as i32 * s.height(),
    };
    Rect::new(0, top, area.right, top + height_of(s, index))
}

/// How many items show whole from the top (one at least): a page.
fn page(window: usize, s: &State) -> u32 {
    let area = client(window);
    if s.multicolumn() {
        let columns = (area.right / s.column()).max(1) as u32;
        return per_column(window, s) * columns;
    }
    match s.owner_draw() {
        OwnerDraw::Variable => {
            let mut bottom = 0;
            let mut shown = 0;
            for index in s.top..s.count {
                bottom += height_of(s, index);
                if bottom > area.bottom {
                    break;
                }
                shown += 1;
            }
            shown.max(1)
        }
        _ => (area.bottom / s.height()).max(1) as u32,
    }
}

/// The highest top index: the one that shows the last items at the bottom.
fn most_top(window: usize, s: &State) -> u32 {
    let area = client(window);
    if s.multicolumn() {
        let rows = per_column(window, s);
        let columns = (area.right / s.column()).max(1) as u32;
        let last_column = s.count.saturating_sub(1) / rows;
        return last_column.saturating_sub(columns - 1) * rows;
    }
    match s.owner_draw() {
        OwnerDraw::Variable => {
            let mut room = area.bottom;
            let mut top = s.count;
            while top > 0 {
                room -= height_of(s, top - 1);
                if room < 0 {
                    break;
                }
                top -= 1;
            }
            top.min(s.count.saturating_sub(1))
        }
        _ => s
            .count
            .saturating_sub((area.bottom / s.height()).max(1) as u32),
    }
}

/// The item under the client point (`x`, `y`), and whether the point is past the items (outside
/// the client area, or below the last item): the nearest item then.
fn item_at(window: usize, s: &State, x: i32, y: i32) -> (u32, bool) {
    if s.count == 0 {
        return (0, true);
    }
    let area = client(window);
    let outside = !area.contains(x, y);
    let (x, y) = (
        x.clamp(0, (area.right - 1).max(0)),
        y.clamp(0, (area.bottom - 1).max(0)),
    );
    let found = if s.multicolumn() {
        let rows = per_column(window, s);
        let row = (y / s.height()).min(rows as i32 - 1) as u32;
        s.top + (x / s.column()) as u32 * rows + row
    } else {
        match s.owner_draw() {
            OwnerDraw::Variable => {
                let mut bottom = 0;
                let mut at = s.top;
                while at < s.count {
                    bottom += height_of(s, at);
                    if y < bottom {
                        break;
                    }
                    at += 1;
                }
                at
            }
            _ => s.top + (y / s.height()) as u32,
        }
    };
    if found >= s.count {
        (s.count - 1, true)
    } else {
        (found, outside)
    }
}

// --- The scroll bars
// ---------------------------------------------------------------------------------

/// The list box's own scroll bar set to its items: WS_VSCROLL's to the items and the top index,
/// an LBS_MULTICOLUMN list box's WS_HSCROLL to its columns (hidden when everything shows, disabled
/// with LBS_DISABLENOSCROLL).
fn update_scroll(window: usize) {
    let Some(s) = load(window) else {
        return;
    };
    if s.flags & NO_REDRAW != 0 {
        return;
    }
    let (bar, wanted, max, page, pos) = if s.multicolumn() {
        let rows = per_column(window, &s);
        let columns = (client(window).right / s.column()).max(1) as u32;
        (
            SB_HORZ,
            WS_HSCROLL,
            s.count.saturating_sub(1) / rows,
            columns,
            s.top / rows,
        )
    } else {
        (
            SB_VERT,
            WS_VSCROLL,
            s.count.saturating_sub(1),
            page(window, &s),
            s.top,
        )
    };
    // The bar the creation's style asked for: SetScrollInfo hiding it clears the style's bit.
    if s.style & wanted == 0 {
        return;
    }
    let info = ScrollInfo {
        cb_size: SCROLLINFO_SIZE,
        mask: SIF_RANGE
            | SIF_PAGE
            | SIF_POS
            | if s.style & LBS_DISABLENOSCROLL != 0 {
                SIF_DISABLENOSCROLL
            } else {
                0
            },
        min: 0,
        max: max as i32,
        page: if s.count == 0 { 1 } else { page },
        pos: pos as i32,
        track_pos: 0,
    };
    // SAFETY: the local structure, whole.
    unsafe { crate::scrollbar::set_scroll_info(window, bar, &info, 1) };
}

/// The top index set to `top` (kept to the items: a column's first in an LBS_MULTICOLUMN list box),
/// the list box redrawn and its scroll bar set when it moved.
fn set_top(window: usize, top: u32) {
    let Some(mut s) = load(window) else {
        return;
    };
    let mut top = top.min(most_top(window, &s));
    if s.multicolumn() {
        let rows = per_column(window, &s);
        top -= top % rows;
    }
    if top == s.top {
        return;
    }
    s.top = top;
    store(window, &s);
    invalidate(window);
    update_scroll(window);
}

/// The list box scrolled to show the item `index` whole.
fn show_item(window: usize, index: u32) {
    let Some(s) = load(window) else {
        return;
    };
    if index >= s.count {
        return;
    }
    if index < s.top {
        set_top(window, index);
        return;
    }
    if s.multicolumn() {
        let shown = page(window, &s);
        if index >= s.top + shown {
            let rows = per_column(window, &s);
            set_top(window, (index / rows + 1) * rows - shown);
        }
        return;
    }
    let area = client(window);
    let mut top = s.top;
    let mut probe = s;
    loop {
        probe.top = top;
        if item_rect(window, &probe, index).bottom <= area.bottom || top >= index {
            break;
        }
        top += 1;
    }
    if top != s.top {
        set_top(window, top);
    }
}

// --- The drawing
// -------------------------------------------------------------------------------------

/// The whole client area to be repainted.
fn invalidate(window: usize) {
    if load(window).is_some_and(|s| s.flags & NO_REDRAW == 0) {
        let _ = imports::invalidate_rect(window, 0, true);
    }
}

/// The client area from the item `index`'s top down to be repainted (all of it for an item above
/// the top, or a multicolumn list box).
fn invalidate_from(window: usize, index: u32) {
    let Some(s) = load(window) else {
        return;
    };
    if s.flags & NO_REDRAW != 0 {
        return;
    }
    if index < s.top || s.multicolumn() {
        invalidate(window);
        return;
    }
    let area = client(window);
    let from = Rect::new(0, item_rect(window, &s, index).top, area.right, area.bottom);
    if !from.is_empty() {
        let _ = imports::invalidate_rect(window, &from as *const Rect as usize, true);
    }
}

/// Whether the list box draws at once: shown, its redraw on.
fn draws(window: usize, s: &State) -> bool {
    s.flags & NO_REDRAW == 0 && window::is_window_visible(window) != 0
}

/// The list box's DC readied to draw: its font selected, its parent's WM_CTLCOLORLISTBOX sent
/// (which sets the DC's colors): the brush it answered (the default procedure's for none), and the
/// font it replaced.
fn ready_dc(window: usize, s: &State, dc: usize) -> (usize, Option<usize>) {
    let previous = (s.font != 0)
        .then(|| imports::select_object(dc, s.font))
        .flatten();
    let mut brush = if s.owner != 0 {
        message::send(s.owner, WM_CTLCOLORLISTBOX, dc as u32, window as i32).unwrap_or(0) as usize
    } else {
        0
    };
    if brush == 0 {
        brush =
            message::default_procedure(window, WM_CTLCOLORLISTBOX, dc as u32, window as i32, false)
                as usize;
    }
    (brush, previous)
}

/// Whether the item `index` is selected.
fn is_selected(s: &State, index: u32) -> bool {
    if s.single() {
        s.selection == index as i32
    } else {
        item(s, index).is_some_and(|value| value.selected != 0)
    }
}

/// The item `index` drawn into `dc` (readied, `brush` its background): an owner-drawn one by its
/// owner (WM_DRAWITEM with `action`), another's text in the list box's colors, its focus rectangle
/// when it has the caret and the list box the focus.
fn draw_item(window: usize, s: &State, dc: usize, brush: usize, index: u32, action: u32) {
    let rect = item_rect(window, s, index);
    let selected = is_selected(s, index);
    let disabled = window::style_of(window).unwrap_or(0) & WS_DISABLED != 0;
    let caret = s.focused() && s.caret == index as i32;
    if s.owner_draw() != OwnerDraw::None {
        let mut state = 0;
        if selected {
            state |= ODS_SELECTED;
        }
        if disabled {
            state |= ODS_DISABLED;
        }
        if action == ODA_FOCUS && caret {
            state |= ODS_FOCUS;
        }
        let mut drawn = DrawItemStruct {
            ctl_type: ODT_LISTBOX,
            ctl_id: id_of(window, s),
            item_id: index,
            item_action: action,
            item_state: state,
            hwnd_item: window as u32,
            hdc: dc as u32,
            rc_item: rect,
            item_data: item(s, index).map_or(0, |value| value.data as u32),
        };
        to_owner(window, WM_DRAWITEM, &mut drawn);
        return;
    }
    let Some(value) = item(s, index) else {
        return;
    };
    let text_color = imports::text_color(dc);
    if selected {
        crate::draw::fill(dc, rect, COLOR_HIGHLIGHT as usize + 1);
        imports::set_text_color(
            dc,
            crate::display::get_sys_color(COLOR_HIGHLIGHTTEXT as i32),
        );
    } else {
        crate::draw::fill(dc, rect, brush);
    }
    if disabled {
        imports::set_text_color(dc, crate::display::get_sys_color(COLOR_GRAYTEXT as i32));
    }
    imports::set_bk_mode(dc, TRANSPARENT);
    with_item_text(&value, |units| {
        if s.style & LBS_USETABSTOPS != 0 && units.contains(&0x09) {
            let mut inner = rect;
            inner.left += TEXT_INDENT;
            crate::draw::draw_text_in(
                dc,
                units,
                inner,
                crate::draw::DT_LEFT
                    | crate::draw::DT_SINGLELINE
                    | crate::draw::DT_EXPANDTABS
                    | crate::draw::DT_NOPREFIX,
            );
        } else {
            imports::ext_text_out(
                dc,
                rect.left + TEXT_INDENT,
                rect.top,
                ETO_CLIPPED,
                Some(&rect),
                units,
            );
        }
    });
    imports::set_text_color(dc, text_color);
    if caret {
        crate::draw::focus_rect_in(dc, rect);
    }
}

/// What a step changed for the drawing: items to draw at once (each with its owner-draw action),
/// or the whole list box to repaint.
struct Marks {
    items: [(u32, u32); 6],
    len: usize,
    all: bool,
}

impl Marks {
    fn new() -> Marks {
        Marks {
            items: [(0, 0); 6],
            len: 0,
            all: false,
        }
    }

    /// The item `index` to draw for `action` (none for a negative index).
    fn add(&mut self, index: i32, action: u32) {
        if index < 0 {
            return;
        }
        if self.len == self.items.len() {
            self.all = true;
            return;
        }
        self.items[self.len] = (index as u32, action);
        self.len += 1;
    }
}

/// The marked items drawn at once in a DC of the list box's own (when it draws: shown, its redraw
/// on), or the whole of it invalidated.
fn draw_marks(window: usize, marks: &Marks) {
    if marks.all {
        invalidate(window);
        return;
    }
    if marks.len == 0 {
        return;
    }
    let Some(s) = load(window) else {
        return;
    };
    if !draws(window, &s) {
        return;
    }
    let dc = crate::dc::get_dc(window);
    if dc == 0 {
        return;
    }
    let (brush, previous) = ready_dc(window, &s, dc);
    let area = client(window);
    for &(index, action) in &marks.items[..marks.len] {
        // Each item's state read again: an owner's WM_DRAWITEM may have sent messages back.
        let Some(s) = load(window) else {
            break;
        };
        if index >= s.count || item_rect(window, &s, index).intersect(area).is_empty() {
            continue;
        }
        draw_item(window, &s, dc, brush, index, action);
    }
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
    crate::dc::release_dc(window, dc);
}

/// WM_PAINT: each item the update region holds drawn (an owner-drawn one ODA_DRAWENTIRE), the rest
/// of the client area in the background's brush, then an owner-drawn caret's focus (ODA_FOCUS).
fn paint(window: usize) {
    let Some(painting) = paint::Painting::begin(window) else {
        return;
    };
    let Some(s) = load(window) else {
        return;
    };
    if s.flags & NO_REDRAW != 0 {
        return;
    }
    let dc = painting.dc();
    let update = painting.area();
    let area = client(window);
    let (brush, previous) = ready_dc(window, &s, dc);
    if s.multicolumn() {
        crate::draw::fill(dc, update, brush);
    }
    let mut bottom = 0;
    let mut index = s.top;
    // Each item's state read again: an owner's WM_DRAWITEM may have sent messages back.
    while let Some(s) = load(window) {
        if index >= s.count {
            break;
        }
        let rect = item_rect(window, &s, index);
        if (s.multicolumn() && rect.left >= area.right)
            || (!s.multicolumn() && rect.top >= area.bottom)
        {
            break;
        }
        bottom = bottom.max(rect.bottom);
        if !rect.intersect(update).is_empty() {
            draw_item(window, &s, dc, brush, index, ODA_DRAWENTIRE);
        }
        index += 1;
    }
    if !s.multicolumn() && bottom < area.bottom {
        crate::draw::fill(dc, Rect::new(0, bottom, area.right, area.bottom), brush);
    }
    if let Some(s) = load(window) {
        if s.owner_draw() != OwnerDraw::None && s.focused() && (s.caret as u32) < s.count {
            draw_item(window, &s, dc, brush, s.caret as u32, ODA_FOCUS);
        }
    }
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
}

// --- Adding and removing
// -----------------------------------------------------------------------------

/// Where LB_ADDSTRING puts `text` (`data` without strings) in a sorted list box: after the items
/// that sort before it or equal it.
fn sorted_place(window: usize, s: &State, text: &[u16], data: usize) -> u32 {
    let (mut low, mut high) = (0u32, s.count);
    while low < high {
        let middle = low + (high - low) / 2;
        let Some(value) = item(s, middle) else {
            break;
        };
        let order = if s.has_strings() {
            with_item_text(&value, |units| compare(s.locale, text, units))
        } else {
            compare_items(window, data, middle, value.data)
        };
        if order == core::cmp::Ordering::Less {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

/// An item put in at `index` (none: LB_ADDSTRING's place, sorted when LBS_SORT; -1 the end) from
/// the message's lParam (`text` its string, wide): its index, or LB_ERR (ERROR_INVALID_INDEX) for
/// an index past the end, LB_ERRSPACE (LBN_ERRSPACE sent) when there is no room. An
/// LBS_OWNERDRAWVARIABLE list box measures it (WM_MEASUREITEM).
fn insert(window: usize, index: Option<i32>, text: &[u16], lparam: i32) -> i32 {
    let Some(s) = load(window) else {
        return LB_ERR;
    };
    if s.no_data() {
        return LB_ERR;
    }
    let data = if s.has_strings() {
        0
    } else {
        lparam as u32 as usize
    };
    let at = match index {
        None if s.sorted() => sorted_place(window, &s, text, data),
        None | Some(-1) => s.count,
        Some(at) if at < 0 || at as u32 > s.count => {
            imports::set_last_error(ERROR_INVALID_INDEX);
            return LB_ERR;
        }
        Some(at) => at as u32,
    };
    // WM_COMPAREITEM may have changed the items.
    let Some(mut fresh) = load(window) else {
        return LB_ERR;
    };
    let at = at.min(fresh.count);
    let Some(block) = (if fresh.has_strings() {
        keep_units(text)
    } else {
        Some(0)
    }) else {
        notify(window, LBN_ERRSPACE);
        return LB_ERRSPACE;
    };
    let value = Item {
        text: block,
        data,
        length: if fresh.has_strings() {
            text.len() as u32
        } else {
            0
        },
        height: fresh.item_height,
        ..Item::default()
    };
    let old_count = fresh.count;
    if !insert_slot(&mut fresh, at, value) {
        free_item(&value);
        notify(window, LBN_ERRSPACE);
        return LB_ERRSPACE;
    }
    if fresh.selection >= at as i32 {
        fresh.selection += 1;
    }
    if old_count > 0 && fresh.caret >= at as i32 {
        fresh.caret += 1;
    }
    if fresh.anchor >= at as i32 {
        fresh.anchor += 1;
    }
    store(window, &fresh);
    let s = fresh;
    if s.owner_draw() == OwnerDraw::Variable {
        let given = if s.has_strings() {
            lparam as u32 as usize
        } else {
            data
        };
        let height = measure(window, at, given);
        if let Some(s) = load(window) {
            if let Some(mut value) = item(&s, at) {
                value.height = height;
                put_item(&s, at, value);
            }
        }
    }
    invalidate_from(window, at);
    update_scroll(window);
    at as i32
}

/// The item `index` removed (WM_DELETEITEM sent first): the items left, or LB_ERR
/// (ERROR_INVALID_INDEX) for no such item.
fn delete(window: usize, index: u32) -> i32 {
    let Some(s) = load(window) else {
        return LB_ERR;
    };
    let Some(value) = item(&s, index) else {
        imports::set_last_error(ERROR_INVALID_INDEX);
        return LB_ERR;
    };
    if !s.no_data() {
        delete_item_message(window, index, value.data);
    }
    let Some(mut s) = load(window) else {
        return LB_ERR;
    };
    if index >= s.count {
        return s.count as i32;
    }
    let Some(taken) = remove_slot(&mut s, index) else {
        return LB_ERR;
    };
    free_item(&taken);
    let at = index as i32;
    if s.selection == at {
        s.selection = -1;
    } else if s.selection > at {
        s.selection -= 1;
    }
    if s.caret > at || (s.caret == at && s.caret >= s.count as i32) {
        s.caret = (s.caret - 1).max(0);
    }
    if s.anchor > at {
        s.anchor -= 1;
    } else if s.anchor == at {
        s.anchor = -1;
    }
    s.top = s.top.min(most_top(window, &s));
    store(window, &s);
    invalidate_from(window, index.min(s.top));
    update_scroll(window);
    s.count as i32
}

/// Every item removed (WM_DELETEITEM sent for each of an owner-drawn list box's, the last first),
/// the selection, the caret and the top index back to their start.
fn remove_all(window: usize) {
    let Some(s) = load(window) else {
        return;
    };
    if s.owner_draw() != OwnerDraw::None && !s.no_data() {
        let mut index = s.count;
        while index > 0 {
            index -= 1;
            let Some(s) = load(window) else {
                return;
            };
            if let Some(value) = item(&s, index) {
                delete_item_message(window, index, value.data);
            }
        }
    }
    let Some(mut s) = load(window) else {
        return;
    };
    for index in 0..s.count {
        if let Some(value) = item(&s, index) {
            free_item(&value);
        }
    }
    if let Some(mut items) = fixed::<Item>(s.items) {
        items.as_mut_slice().fill(Item::default());
    }
    s.count = 0;
    s.top = 0;
    s.selection = -1;
    s.caret = 0;
    s.anchor = -1;
    store(window, &s);
}

// --- Finding
// -----------------------------------------------------------------------------------------

/// The first item from the one after `start` (-1, or one past the items: from the first), round
/// the end, that `matches`: its index, or LB_ERR.
fn find_from(s: &State, start: i32, mut matches: impl FnMut(u32, &Item) -> bool) -> i32 {
    if s.count == 0 {
        return LB_ERR;
    }
    let first = if start < 0 || start as u32 >= s.count {
        0
    } else {
        (start as u32 + 1) % s.count
    };
    for step in 0..s.count {
        let index = (first + step) % s.count;
        if let Some(value) = item(s, index) {
            if matches(index, &value) {
                return index as i32;
            }
        }
    }
    LB_ERR
}

/// LB_FINDSTRING (`exact` false) and LB_FINDSTRINGEXACT: the item whose text starts with (is)
/// `text`, or without strings whose value is lParam.
fn find(window: usize, start: i32, text: &[u16], lparam: i32, exact: bool) -> i32 {
    let Some(s) = load(window) else {
        return LB_ERR;
    };
    if !s.has_strings() {
        let wanted = lparam as u32 as usize;
        return find_from(&s, start, |_, value| value.data == wanted);
    }
    find_from(&s, start, |_, value| {
        with_item_text(value, |units| {
            if exact {
                equals(s.locale, units, text)
            } else {
                starts_with(s.locale, units, text)
            }
        })
    })
}

// --- The selection
// -----------------------------------------------------------------------------------

/// A single-selection list box's selection moved to `index` (-1: none), the caret with it: the
/// items left and taken drawn (ODA_SELECT), the list scrolled to show it; whether it changed.
fn select_one(window: usize, index: i32) -> bool {
    let Some(mut s) = load(window) else {
        return false;
    };
    let old = s.selection;
    let old_caret = s.caret;
    if old == index && (index < 0 || old_caret == index) {
        return false;
    }
    s.selection = index;
    if index >= 0 {
        s.caret = index;
    }
    store(window, &s);
    let mut marks = Marks::new();
    if s.focused() && old_caret != s.caret {
        marks.add(old_caret, ODA_FOCUS);
    }
    if old != index {
        marks.add(old, ODA_SELECT);
        marks.add(index, ODA_SELECT);
    }
    if s.focused() && old_caret != s.caret {
        marks.add(s.caret, ODA_FOCUS);
    }
    draw_marks(window, &marks);
    if index >= 0 {
        show_item(window, index as u32);
    }
    old != index
}

/// A multiple-selection list box's items `from` to `to` (inclusive) selected or not: the ones that
/// changed drawn; whether any did.
fn select_range(window: usize, from: u32, to: u32, on: bool) -> bool {
    let Some(s) = load(window) else {
        return false;
    };
    if s.count == 0 {
        return false;
    }
    let to = to.min(s.count - 1);
    let mut marks = Marks::new();
    let mut changed = false;
    for index in from..=to {
        if let Some(mut value) = item(&s, index) {
            if (value.selected != 0) != on {
                value.selected = on as u32;
                put_item(&s, index, value);
                marks.add(index as i32, ODA_SELECT);
                changed = true;
            }
        }
    }
    draw_marks(window, &marks);
    changed
}

/// The caret moved to `index` (its old item and its new one redrawn while the list box has the
/// focus), the list scrolled to show it unless `partial`; whether it moved.
fn move_caret(window: usize, index: u32, partial: bool) -> bool {
    let Some(mut s) = load(window) else {
        return false;
    };
    let old = s.caret;
    if old == index as i32 {
        if !partial {
            show_item(window, index);
        }
        return false;
    }
    s.caret = index as i32;
    store(window, &s);
    if s.focused() {
        let mut marks = Marks::new();
        marks.add(old, ODA_FOCUS);
        marks.add(index as i32, ODA_FOCUS);
        draw_marks(window, &marks);
    }
    if !partial {
        show_item(window, index);
    }
    true
}

/// The selected items' indices into the caller's array at `buffer` (as many as `room` holds): how
/// many were written.
fn selected_items(s: &State, room: u32, buffer: i32) -> i32 {
    if buffer == 0 {
        return 0;
    }
    let wanted = (0..s.count)
        .filter(|&index| is_selected(s, index))
        .take(room as usize);
    let count = wanted.clone().count();
    // SAFETY: LB_GETSELITEMS' lParam as its sender hands it over: an array of wParam integers.
    let mut out = unsafe { OutBuf::new(buffer as usize as *mut i32, count) };
    for (slot, index) in wanted.enumerate() {
        out.set(slot, index as i32);
    }
    count as i32
}

// --- The keys and the mouse
// --------------------------------------------------------------------------

/// Whether the key `vk` is down.
fn down(vk: u32) -> bool {
    crate::keyboard::get_key_state(vk as i32) < 0
}

/// The list box's selection taken to the item `target` (the caret's new place) as the keyboard or
/// the mouse takes it (`toggle`: Space, a click in an LBS_MULTIPLESEL list box): see the module
/// notes; whether the caret or the selection changed.
fn go_to(window: usize, target: u32, toggle: bool) -> bool {
    let Some(s) = load(window) else {
        return false;
    };
    if s.count == 0 {
        return false;
    }
    let target = target.min(s.count - 1);
    if s.style & LBS_NOSEL != 0 {
        return move_caret(window, target, false);
    }
    match s.multiple() {
        Selection::Single => select_one(window, target as i32),
        Selection::Multiple => {
            let moved = move_caret(window, target, false);
            let toggled = toggle && {
                let on = !is_selected(&s, target);
                select_range(window, target, target, on)
            };
            moved || toggled
        }
        Selection::Extended => {
            let (shift, control) = (down(VK_SHIFT), down(VK_CONTROL));
            let moved = move_caret(window, target, false);
            let Some(mut s) = load(window) else {
                return moved;
            };
            if control && !shift {
                if toggle {
                    let on = !is_selected(&s, target);
                    s.anchor = target as i32;
                    store(window, &s);
                    return select_range(window, target, target, on) || moved;
                }
                return moved;
            }
            let anchor = if shift && s.anchor >= 0 {
                s.anchor as u32
            } else {
                s.anchor = target as i32;
                store(window, &s);
                target
            };
            let (low, high) = (anchor.min(target), anchor.max(target));
            let mut changed = false;
            if !control {
                if low > 0 {
                    changed |= select_range(window, 0, low - 1, false);
                }
                if high + 1 < s.count {
                    changed |= select_range(window, high + 1, s.count - 1, false);
                }
            }
            changed |= select_range(window, low, high, true);
            changed || moved
        }
    }
}

/// WM_KEYDOWN: the keys of the module notes; LBN_SELCHANGE after a change.
fn key(window: usize, vk: u32) {
    let Some(s) = load(window) else {
        return;
    };
    let mut vk = vk;
    let mut target = None;
    if s.style & LBS_WANTKEYBOARDINPUT != 0 {
        let caret = (s.caret.max(0) as u32) & 0xFFFF;
        let answer = s.owner != 0;
        if answer {
            match message::send(s.owner, WM_VKEYTOITEM, caret << 16 | vk, window as i32)
                .unwrap_or(-1)
            {
                -2 => return,
                -1 => {}
                index => {
                    target = Some(index as u32);
                    vk = 0;
                }
            }
        }
    }
    let Some(s) = load(window) else {
        return;
    };
    if s.count == 0 {
        return;
    }
    let caret = s.caret.clamp(0, s.count as i32 - 1) as u32;
    let last = s.count - 1;
    let shown = page(window, &s);
    let rows = if s.multicolumn() {
        per_column(window, &s)
    } else {
        1
    };
    // A single-selection list box with nothing selected takes the caret's item first.
    let fresh = s.single() && s.selection < 0;
    let toggle = vk == VK_SPACE;
    let target = match (target, vk) {
        (Some(target), _) => target,
        (None, VK_UP) | (None, VK_DOWN) if fresh => caret,
        (None, VK_LEFT) | (None, VK_RIGHT) if fresh && rows == 1 => caret,
        (None, VK_UP) => caret.saturating_sub(1),
        (None, VK_DOWN) => (caret + 1).min(last),
        (None, VK_LEFT) => caret.saturating_sub(rows),
        (None, VK_RIGHT) => (caret + rows).min(last),
        (None, VK_PRIOR) => caret.saturating_sub(shown.saturating_sub(1).max(1)),
        (None, VK_NEXT) => (caret + shown.saturating_sub(1).max(1)).min(last),
        (None, VK_HOME) => 0,
        (None, VK_END) => last,
        (None, VK_SPACE) => {
            if s.multiple() == Selection::Single {
                return;
            }
            caret
        }
        _ => return,
    };
    if go_to(window, target, toggle) {
        notify_if_asked(window, LBN_SELCHANGE);
    }
}

/// WM_CHAR: the next item whose text starts with the character, round the end
/// (LBS_WANTKEYBOARDINPUT: WM_CHARTOITEM first); LBN_SELCHANGE after a change.
fn typed(window: usize, unit: u16) {
    let Some(s) = load(window) else {
        return;
    };
    let mut target = None;
    if s.style & LBS_WANTKEYBOARDINPUT != 0 && s.owner != 0 {
        let caret = (s.caret.max(0) as u32) & 0xFFFF;
        match message::send(
            s.owner,
            WM_CHARTOITEM,
            caret << 16 | u32::from(unit),
            window as i32,
        )
        .unwrap_or(-1)
        {
            -2 => return,
            -1 => {}
            index => target = Some(index as u32),
        }
    }
    let Some(s) = load(window) else {
        return;
    };
    let target = match target {
        Some(target) => target,
        None => {
            if unit < 0x20 || !s.has_strings() {
                return;
            }
            match find(window, s.caret, &[unit], 0, false) {
                LB_ERR => return,
                found => found as u32,
            }
        }
    };
    if go_to(window, target, false) {
        notify_if_asked(window, LBN_SELCHANGE);
    }
}

/// A press (or a double click's, `double`) at the client point (`x`, `y`): the focus and the
/// capture taken, the item under it selected (LBN_SELCHANGE when that changed anything), LBN_DBLCLK
/// for a double click.
fn press(window: usize, x: i32, y: i32, double: bool) {
    if crate::focus::get_focus() != window {
        crate::focus::set_focus(window);
    }
    let Some(mut s) = load(window) else {
        return;
    };
    s.flags |= CAPTURED;
    if double {
        s.flags |= DOUBLE;
    } else {
        s.flags &= !DOUBLE;
    }
    store(window, &s);
    crate::mouse::set_capture(window);
    let Some(s) = load(window) else {
        return;
    };
    if s.count == 0 {
        return;
    }
    let (index, _) = item_at(window, &s, x, y);
    let toggle = s.multiple() == Selection::Multiple || (down(VK_CONTROL) && !double);
    if go_to(window, index, toggle && !double) {
        notify_if_asked(window, LBN_SELCHANGE);
    }
    if double {
        notify_if_asked(window, LBN_DBLCLK);
    }
}

/// A move under the press's capture: the selection follows the item under it (a single-selection or
/// LBS_EXTENDEDSEL list box's).
fn drag(window: usize, x: i32, y: i32) {
    let Some(s) = load(window) else {
        return;
    };
    if s.flags & CAPTURED == 0 || s.count == 0 || s.multiple() == Selection::Multiple {
        return;
    }
    let (index, _) = item_at(window, &s, x, y);
    if index as i32 == s.caret && (!s.single() || s.selection == index as i32) {
        return;
    }
    let changed = if s.single() {
        go_to(window, index, false)
    } else {
        // An extended selection's drag reaches from the anchor, as Shift does.
        let anchor = s.anchor.max(0) as u32;
        let moved = move_caret(window, index, false);
        let (low, high) = (anchor.min(index), anchor.max(index));
        let mut changed = moved;
        if low > 0 {
            changed |= select_range(window, 0, low - 1, false);
        }
        if high + 1 < s.count {
            changed |= select_range(window, high + 1, s.count - 1, false);
        }
        changed | select_range(window, low, high, true)
    };
    if changed {
        notify_if_asked(window, LBN_SELCHANGE);
    }
}

/// The press's end: the capture let go.
fn release(window: usize) {
    let Some(mut s) = load(window) else {
        return;
    };
    if s.flags & CAPTURED == 0 {
        return;
    }
    s.flags &= !(CAPTURED | DOUBLE);
    store(window, &s);
    crate::mouse::release_capture();
}

// --- The scrolling
// -----------------------------------------------------------------------------------

/// WM_VSCROLL (WM_HSCROLL for an LBS_MULTICOLUMN list box, by columns): the top index moved.
fn scroll(window: usize, request: u32, position: u32) {
    let Some(s) = load(window) else {
        return;
    };
    let step = if s.multicolumn() {
        per_column(window, &s)
    } else {
        1
    };
    let shown = page(window, &s);
    let top = s.top;
    let target = match request {
        SB_LINEUP => top.saturating_sub(step),
        SB_LINEDOWN => top + step,
        SB_PAGEUP => top.saturating_sub(shown.max(step)),
        SB_PAGEDOWN => top + shown.max(step),
        SB_THUMBPOSITION | SB_THUMBTRACK => position * step,
        SB_TOP => 0,
        SB_BOTTOM => s.count,
        _ => return,
    };
    set_top(window, target);
}

// --- Creation, size and font
// -------------------------------------------------------------------------

/// WM_NCCREATE: the list box's state made, WS_BORDER turned into WS_EX_CLIENTEDGE; false when there
/// was no room for it.
fn create(window: usize) -> bool {
    let Ok(data) = window::window_data(window) else {
        return false;
    };
    let Some(block) =
        imports::local_alloc(LMEM_FIXED | LMEM_ZEROINIT, core::mem::size_of::<State>())
    else {
        return false;
    };
    if !kept::keep(window, block) {
        imports::local_free(block);
        return false;
    }
    let s = State {
        owner: data.parent as usize,
        selection: -1,
        anchor: -1,
        item_height: 16,
        flags: if data.style & LBS_NOREDRAW != 0 {
            NO_REDRAW
        } else {
            0
        },
        id: data.id,
        locale: imports::thread_locale(),
        style: data.style,
        ..State::default()
    };
    store(window, &s);
    if data.style & WS_BORDER != 0 {
        let _ = imports::set_window_long(window, GWL_STYLE, data.style & !WS_BORDER, false);
        let _ =
            imports::set_window_long(window, GWL_EXSTYLE, data.ex_style | WS_EX_CLIENTEDGE, false);
        window::set_window_pos(
            window,
            0,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
        );
    }
    true
}

/// WM_CREATE: the item height taken from the font (an LBS_OWNERDRAWFIXED list box's from its
/// parent's WM_MEASUREITEM), a multicolumn list box's columns' width set, the list box cut to whole
/// items, its scroll bar set.
fn created(window: usize) {
    let Some(mut s) = load(window) else {
        return;
    };
    s.item_height = font_height(window, s.font);
    s.column_width = 15 * average_width(window, s.font).max(1);
    store(window, &s);
    if s.owner_draw() == OwnerDraw::Fixed {
        let height = measure(window, 0, 0);
        if let Some(mut s) = load(window) {
            s.item_height = height.max(1);
            store(window, &s);
        }
    }
    fit_whole_items(window);
    update_scroll(window);
}

/// The average character width of `font` (0: the System font).
fn average_width(window: usize, font: usize) -> u32 {
    let dc = crate::dc::get_dc(window);
    if dc == 0 {
        return 8;
    }
    let previous = (font != 0)
        .then(|| imports::select_object(dc, font))
        .flatten();
    let width = imports::text_metrics(dc).map_or(8, |metric| metric.ave_char_width.max(1) as u32);
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
    crate::dc::release_dc(window, dc);
    width
}

/// Without LBS_NOINTEGRALHEIGHT, a list box whose items are one height cut to show whole items (its
/// client area's height a multiple of the item height), as Windows 2000's sizes itself.
fn fit_whole_items(window: usize) {
    let Some(mut s) = load(window) else {
        return;
    };
    if s.style & LBS_NOINTEGRALHEIGHT != 0
        || s.owner_draw() == OwnerDraw::Variable
        || s.flags & SIZING != 0
    {
        return;
    }
    let Ok(info) = window::window_info(window) else {
        return;
    };
    let height = info.client.bottom - info.client.top;
    let extra = height % s.height();
    if extra == 0 || height <= s.height() {
        return;
    }
    s.flags |= SIZING;
    store(window, &s);
    let width = info.window.right - info.window.left;
    let whole = info.window.bottom - info.window.top - extra;
    window::set_window_pos(
        window,
        0,
        0,
        0,
        width,
        whole,
        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
    );
    if let Some(mut s) = load(window) {
        s.flags &= !SIZING;
        store(window, &s);
    }
}

/// WM_NCDESTROY: the items removed (an owner-drawn list box's WM_DELETEITEMs), the state freed, its
/// record dropped first.
fn destroy(window: usize) {
    remove_all(window);
    let Some(s) = load(window) else {
        return;
    };
    let Some(block) = kept::forget(window) else {
        return;
    };
    if s.items != 0 {
        imports::local_free(s.items);
    }
    imports::local_free(block);
}

// --- The procedure
// -----------------------------------------------------------------------------------

/// LB_SETITEMHEIGHT: the items' height (the item `index`'s in an LBS_OWNERDRAWVARIABLE list box)
/// set to `height`.
fn set_item_height(window: usize, index: u32, height: u32) -> i32 {
    let Some(mut s) = load(window) else {
        return LB_ERR;
    };
    if height > MOST_HEIGHT {
        imports::set_last_error(ERROR_INVALID_PARAMETER);
        return LB_ERR;
    }
    if s.owner_draw() == OwnerDraw::Variable {
        let Some(mut value) = item(&s, index) else {
            imports::set_last_error(ERROR_INVALID_INDEX);
            return LB_ERR;
        };
        value.height = height;
        put_item(&s, index, value);
    } else {
        s.item_height = height;
        store(window, &s);
        fit_whole_items(window);
    }
    if let Some(mut s) = load(window) {
        s.top = s.top.min(most_top(window, &s));
        store(window, &s);
    }
    invalidate(window);
    update_scroll(window);
    LB_OKAY
}

/// LB_GETITEMRECT: the item's rectangle into the caller's RECT; whether it shows.
fn get_item_rect(window: usize, index: u32, buffer: i32) -> i32 {
    let Some(s) = load(window) else {
        return LB_ERR;
    };
    if index >= s.count && !(index == 0 && s.count == 0) {
        imports::set_last_error(ERROR_INVALID_INDEX);
        return LB_ERR;
    }
    let rect = item_rect(window, &s, index);
    if buffer != 0 {
        // SAFETY: LB_GETITEMRECT's lParam as its sender hands it over: a RECT.
        let mut out = unsafe { OutBuf::new(buffer as usize as *mut Rect, 1) };
        out.set(0, rect);
    }
    (!rect.intersect(client(window)).is_empty()) as i32
}

/// LB_GETTEXT: the item's text into the caller's buffer (an owner-drawn list box's value without
/// strings, four bytes): its length.
fn get_text(window: usize, index: u32, buffer: i32, ansi: bool) -> i32 {
    let Some(s) = load(window) else {
        return LB_ERR;
    };
    let Some(value) = item(&s, index) else {
        imports::set_last_error(ERROR_INVALID_INDEX);
        return LB_ERR;
    };
    if !s.has_strings() {
        if buffer != 0 {
            // SAFETY: LB_GETTEXT's lParam as its sender hands it over: room for a DWORD.
            let mut out = unsafe { OutBuf::new(buffer as usize as *mut u8, 4) };
            out.put(&(value.data as u32).to_le_bytes());
        }
        return 4;
    }
    with_item_text(&value, |units| put_text(buffer, ansi, units))
}

/// LB_GETTEXTLEN: the item's text's length (in bytes for a narrow caller); four for a value.
fn get_text_length(window: usize, index: u32, ansi: bool) -> i32 {
    let Some(s) = load(window) else {
        return LB_ERR;
    };
    let Some(value) = item(&s, index) else {
        imports::set_last_error(ERROR_INVALID_INDEX);
        return LB_ERR;
    };
    if !s.has_strings() {
        return 4;
    }
    with_item_text(&value, |units| {
        if ansi {
            procedure::narrow_length(units) as i32
        } else {
            units.len() as i32
        }
    })
}

/// The list box messages (LB_*): see the module notes.
fn list_message(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    let Some(s) = load(window) else {
        return LB_ERR;
    };
    match message {
        LB_ADDSTRING | LB_ADDFILE => {
            if s.has_strings() {
                with_param_text(lparam, ansi, |text| insert(window, None, text, lparam))
                    .unwrap_or(LB_ERRSPACE)
            } else {
                insert(window, None, &[], lparam)
            }
        }
        LB_INSERTSTRING => {
            let at = Some(wparam as i32);
            if s.has_strings() {
                with_param_text(lparam, ansi, |text| insert(window, at, text, lparam))
                    .unwrap_or(LB_ERRSPACE)
            } else {
                insert(window, at, &[], lparam)
            }
        }
        LB_DELETESTRING => delete(window, wparam),
        LB_RESETCONTENT => {
            remove_all(window);
            invalidate(window);
            update_scroll(window);
            LB_OKAY
        }
        LB_GETCOUNT => s.count as i32,
        LB_GETTEXT => get_text(window, wparam, lparam, ansi),
        LB_GETTEXTLEN => get_text_length(window, wparam, ansi),
        LB_GETITEMDATA => match item(&s, wparam) {
            Some(value) => value.data as i32,
            None => {
                imports::set_last_error(ERROR_INVALID_INDEX);
                LB_ERR
            }
        },
        LB_SETITEMDATA => match item(&s, wparam) {
            Some(mut value) if !s.no_data() => {
                value.data = lparam as u32 as usize;
                put_item(&s, wparam, value);
                1
            }
            _ => {
                imports::set_last_error(ERROR_INVALID_INDEX);
                LB_ERR
            }
        },
        LB_FINDSTRING | LB_FINDSTRINGEXACT => {
            let exact = message == LB_FINDSTRINGEXACT;
            if s.has_strings() {
                with_param_text(lparam, ansi, |text| {
                    find(window, wparam as i32, text, lparam, exact)
                })
                .unwrap_or(LB_ERR)
            } else {
                find(window, wparam as i32, &[], lparam, exact)
            }
        }
        LB_SELECTSTRING => {
            let found = if s.has_strings() {
                with_param_text(lparam, ansi, |text| {
                    find(window, wparam as i32, text, lparam, false)
                })
                .unwrap_or(LB_ERR)
            } else {
                find(window, wparam as i32, &[], lparam, false)
            };
            if found >= 0 {
                if s.single() {
                    select_one(window, found);
                } else {
                    move_caret(window, found as u32, false);
                    select_range(window, found as u32, found as u32, true);
                }
            }
            found
        }
        LB_GETCURSEL => {
            if s.single() {
                s.selection
            } else {
                s.caret
            }
        }
        LB_SETCURSEL => {
            let index = wparam as i32;
            if !s.single() || index < -1 || (index >= 0 && index as u32 >= s.count) {
                return LB_ERR;
            }
            select_one(window, index);
            if index < 0 {
                LB_ERR
            } else {
                index
            }
        }
        LB_GETSEL => {
            if wparam >= s.count {
                LB_ERR
            } else {
                is_selected(&s, wparam) as i32
            }
        }
        LB_SETSEL => {
            let index = lparam;
            if s.single() || (index != -1 && (index < 0 || index as u32 >= s.count)) {
                imports::set_last_error(ERROR_INVALID_PARAMETER);
                return LB_ERR;
            }
            let on = wparam != 0;
            if index == -1 {
                if s.count > 0 {
                    select_range(window, 0, s.count - 1, on);
                }
            } else {
                select_range(window, index as u32, index as u32, on);
                if let Some(mut s) = load(window) {
                    s.anchor = index;
                    store(window, &s);
                }
                move_caret(window, index as u32, true);
            }
            LB_OKAY
        }
        LB_SELITEMRANGE => {
            if s.single() {
                imports::set_last_error(ERROR_INVALID_INDEX);
                return LB_ERR;
            }
            let (first, last) = (lparam as u32 & 0xFFFF, (lparam as u32) >> 16);
            let (low, high) = (first.min(last), first.max(last));
            if low < s.count {
                select_range(window, low, high, wparam != 0);
            }
            LB_OKAY
        }
        LB_SELITEMRANGEEX => {
            if s.single() {
                imports::set_last_error(ERROR_INVALID_LB_MESSAGE);
                return LB_ERR;
            }
            let (first, last) = (wparam, lparam as u32);
            if first <= last {
                if first < s.count {
                    select_range(window, first, last, true);
                }
            } else if last < s.count {
                select_range(window, last, first, false);
            }
            LB_OKAY
        }
        LB_GETSELCOUNT => {
            if s.single() {
                return LB_ERR;
            }
            (0..s.count).filter(|&index| is_selected(&s, index)).count() as i32
        }
        LB_GETSELITEMS => {
            if s.single() {
                return LB_ERR;
            }
            selected_items(&s, wparam, lparam)
        }
        LB_GETCARETINDEX => s.caret,
        LB_SETCARETINDEX => {
            if wparam >= s.count {
                imports::set_last_error(ERROR_INVALID_INDEX);
                return LB_ERR;
            }
            move_caret(window, wparam, lparam != 0);
            LB_OKAY
        }
        LB_GETANCHORINDEX => s.anchor,
        LB_SETANCHORINDEX => {
            if wparam >= s.count {
                imports::set_last_error(ERROR_INVALID_INDEX);
                return LB_ERR;
            }
            let mut s = s;
            s.anchor = wparam as i32;
            store(window, &s);
            LB_OKAY
        }
        LB_GETTOPINDEX => s.top as i32,
        LB_SETTOPINDEX => {
            if wparam >= s.count && !(wparam == 0 && s.count == 0) {
                imports::set_last_error(ERROR_INVALID_INDEX);
                return LB_ERR;
            }
            set_top(window, wparam);
            LB_OKAY
        }
        LB_GETITEMHEIGHT => {
            if s.owner_draw() == OwnerDraw::Variable {
                match item(&s, wparam) {
                    Some(value) => value.height as i32,
                    None if s.count == 0 => s.item_height as i32,
                    None => {
                        imports::set_last_error(ERROR_INVALID_INDEX);
                        LB_ERR
                    }
                }
            } else {
                s.item_height as i32
            }
        }
        LB_SETITEMHEIGHT => set_item_height(window, wparam, lparam as u32 & 0xFFFF),
        LB_GETITEMRECT => get_item_rect(window, wparam, lparam),
        LB_ITEMFROMPOINT => {
            let (x, y) = (lparam as i16 as i32, (lparam >> 16) as i16 as i32);
            let (index, outside) = item_at(window, &s, x, y);
            (index & 0xFFFF | u32::from(outside) << 16) as i32
        }
        LB_GETLISTBOXINFO => {
            if s.multicolumn() {
                per_column(window, &s) as i32
            } else {
                0
            }
        }
        LB_INITSTORAGE => {
            let mut s = s;
            if !reserve(&mut s, wparam as usize) {
                return LB_ERRSPACE;
            }
            store(window, &s);
            capacity(&s) as i32
        }
        LB_SETCOUNT => {
            if !s.no_data() {
                imports::set_last_error(ERROR_SETCOUNT_ON_BAD_LB);
                return LB_ERR;
            }
            let mut s = s;
            let more = wparam.saturating_sub(s.count) as usize;
            if more > 0 && !reserve(&mut s, more) {
                notify(window, LBN_ERRSPACE);
                return LB_ERRSPACE;
            }
            if let Some(mut items) = fixed::<Item>(s.items) {
                let slots = items.as_mut_slice();
                let end = (wparam as usize).min(slots.len());
                slots[end.min(s.count as usize)..s.count as usize].fill(Item::default());
            }
            s.count = wparam;
            s.selection = s.selection.min(wparam as i32 - 1);
            s.caret = s.caret.min((wparam as i32 - 1).max(0));
            s.top = s.top.min(most_top(window, &s));
            store(window, &s);
            invalidate(window);
            update_scroll(window);
            LB_OKAY
        }
        LB_GETLOCALE => s.locale as i32,
        LB_SETLOCALE => {
            let mut s = s;
            let old = s.locale;
            s.locale = wparam;
            store(window, &s);
            old as i32
        }
        LB_SETCOLUMNWIDTH => {
            let mut s = s;
            s.column_width = wparam;
            store(window, &s);
            invalidate(window);
            update_scroll(window);
            LB_OKAY
        }
        LB_GETHORIZONTALEXTENT => s.extent as i32,
        LB_SETHORIZONTALEXTENT => {
            let mut s = s;
            s.extent = wparam;
            store(window, &s);
            unserved(
                message,
                "LB_SETHORIZONTALEXTENT's sideways scroll is not yet served: the extent is kept",
                (window, message, wparam, lparam),
            );
            LB_OKAY
        }
        LB_SETTABSTOPS => {
            if s.style & LBS_USETABSTOPS == 0 {
                imports::set_last_error(ERROR_LB_WITHOUT_TABSTOPS);
                return 0;
            }
            if wparam != 0 {
                unserved(
                    message,
                    "LB_SETTABSTOPS' own stops are not yet served: tabs expand at the default stops",
                    (window, message, wparam, lparam),
                );
            }
            1
        }
        LB_DIR => with_param_text(lparam, ansi, |spec| dir(window, wparam, spec)).unwrap_or(LB_ERR),
        _ => {
            unserved(
                message,
                "a list box message not yet served answers LB_ERR",
                (window, message, wparam, lparam),
            );
            LB_ERR
        }
    }
}

/// The list box's procedure, for a message of the narrow (`ansi`) or wide form.
fn list_box(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    match message {
        WM_NCCREATE => {
            if !create(window) {
                return 0;
            }
            return message::default_procedure(window, message, wparam, lparam, ansi);
        }
        WM_NCDESTROY => {
            destroy(window);
            return message::default_procedure(window, message, wparam, lparam, ansi);
        }
        _ => {}
    }
    let Some(s) = load(window) else {
        return message::default_procedure(window, message, wparam, lparam, ansi);
    };
    match message {
        LB_FIRST..=LB_LAST => list_message(window, message, wparam, lparam, ansi),
        WM_CREATE => {
            created(window);
            0
        }
        WM_GETDLGCODE => (DLGC_WANTARROWS | DLGC_WANTCHARS) as i32,
        WM_SETFONT => {
            let mut s = s;
            s.font = wparam as usize;
            if s.owner_draw() == OwnerDraw::None {
                s.item_height = font_height(window, s.font);
            }
            s.column_width = 15 * average_width(window, s.font).max(1);
            store(window, &s);
            fit_whole_items(window);
            update_scroll(window);
            if lparam != 0 {
                invalidate(window);
            }
            0
        }
        WM_GETFONT => s.font as i32,
        WM_SETREDRAW => {
            let mut s = s;
            if wparam != 0 {
                s.flags &= !NO_REDRAW;
            } else {
                s.flags |= NO_REDRAW;
            }
            store(window, &s);
            if wparam != 0 {
                update_scroll(window);
                invalidate(window);
            }
            0
        }
        WM_SIZE => {
            fit_whole_items(window);
            if let Some(mut s) = load(window) {
                s.top = s.top.min(most_top(window, &s));
                store(window, &s);
            }
            update_scroll(window);
            if s.multicolumn() {
                invalidate(window);
            }
            0
        }
        WM_ENABLE => {
            invalidate(window);
            0
        }
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            paint(window);
            0
        }
        WM_SETFOCUS => {
            let mut s = s;
            s.flags |= FOCUSED;
            store(window, &s);
            let mut marks = Marks::new();
            marks.add(s.caret.min(s.count as i32 - 1), ODA_FOCUS);
            draw_marks(window, &marks);
            notify(window, LBN_SETFOCUS);
            0
        }
        WM_KILLFOCUS => {
            let mut s = s;
            s.flags &= !FOCUSED;
            store(window, &s);
            release(window);
            let mut marks = Marks::new();
            marks.add(s.caret.min(s.count as i32 - 1), ODA_FOCUS);
            draw_marks(window, &marks);
            notify(window, LBN_KILLFOCUS);
            0
        }
        WM_KEYDOWN => {
            key(window, wparam);
            0
        }
        WM_CHAR => {
            let unit = if ansi {
                procedure::char_to_wide(WM_CHAR, wparam)
            } else {
                wparam
            };
            typed(window, unit as u16);
            0
        }
        WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => {
            press(
                window,
                lparam as i16 as i32,
                (lparam >> 16) as i16 as i32,
                message == WM_LBUTTONDBLCLK,
            );
            0
        }
        WM_MOUSEMOVE => {
            drag(window, lparam as i16 as i32, (lparam >> 16) as i16 as i32);
            0
        }
        WM_LBUTTONUP => {
            release(window);
            0
        }
        WM_CAPTURECHANGED => {
            if let Some(mut s) = load(window) {
                s.flags &= !(CAPTURED | DOUBLE);
                store(window, &s);
            }
            0
        }
        WM_VSCROLL if !s.multicolumn() => {
            scroll(window, wparam & 0xFFFF, wparam >> 16);
            0
        }
        WM_HSCROLL if s.multicolumn() => {
            scroll(window, wparam & 0xFFFF, wparam >> 16);
            0
        }
        WM_MOUSEWHEEL => {
            let notches = i32::from((wparam >> 16) as i16) / 120;
            if notches > 0 {
                scroll_by_lines(window, -(3 * notches));
            } else if notches < 0 {
                scroll_by_lines(window, -3 * notches);
            }
            0
        }
        _ => message::default_procedure(window, message, wparam, lparam, ansi),
    }
}

/// The top index moved by `lines` (negative: up).
fn scroll_by_lines(window: usize, lines: i32) {
    let Some(s) = load(window) else {
        return;
    };
    let top = (i64::from(s.top) + i64::from(lines)).max(0) as u32;
    set_top(window, top);
}

/// ListBoxWndProcW: the ListBox class's procedure for a wide message.
pub extern "system" fn list_box_proc_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    list_box(window, message, wparam, lparam, false)
}

/// ListBoxWndProcA: the ListBox class's procedure for a narrow message.
pub extern "system" fn list_box_proc_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    list_box(window, message, wparam, lparam, true)
}

// --- LB_DIR
// --------------------------------------------------------------------------------------------

/// `units` NUL-terminated in a buffer of `N` units; none when they do not fit.
fn terminated<const N: usize>(units: &[u16]) -> Option<[u16; N]> {
    let mut buffer = [0u16; N];
    let length = units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len());
    if length >= N {
        return None;
    }
    buffer[..length].copy_from_slice(&units[..length]);
    Some(buffer)
}

/// The units of a NUL-terminated buffer, without the terminator.
fn until_nul(units: &[u16]) -> &[u16] {
    &units[..units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len())]
}

/// Whether LB_DIR lists a file whose attributes are `attributes` for `wanted`: with DDL_EXCLUSIVE
/// one that has an attribute it names, without it one that is neither hidden nor a system file
/// unless it names those.
fn lists_file(attributes: u32, wanted: u32) -> bool {
    if wanted & DDL_EXCLUSIVE != 0 {
        attributes & wanted & FILE_BITS != 0
    } else {
        attributes & (DDL_HIDDEN | DDL_SYSTEM) & !wanted == 0
    }
}

/// An entry LB_DIR adds: `text` put in at LB_ADDSTRING's place (`sorted`) or the end: its index,
/// or none when there was no room.
fn add_entry(window: usize, text: &[u16], sorted: bool) -> Option<i32> {
    let at = insert(window, if sorted { None } else { Some(-1) }, text, 0);
    (at >= 0).then_some(at)
}

/// LB_DIR: the files `spec` finds as `attributes` asks (see the module notes): the last entry's
/// index, LB_ERR with FindFirstFileW's error when the pattern finds nothing, LB_ERRSPACE when there
/// is no room.
fn dir(window: usize, attributes: u32, spec: &[u16]) -> i32 {
    let Some(pattern) = terminated::<264>(spec) else {
        imports::set_last_error(ERROR_INVALID_PARAMETER);
        return LB_ERR;
    };
    let mut last = LB_ERR;
    let exclusive = attributes & DDL_EXCLUSIVE != 0;
    let files = !exclusive || attributes & FILE_BITS != 0;
    let searches = files || attributes & DDL_DIRECTORY != 0;
    if searches {
        let Some(search) = imports::FileSearch::new(&pattern) else {
            return LB_ERR;
        };
        if files {
            for entry in search {
                if entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                    || !lists_file(entry.attributes, attributes)
                {
                    continue;
                }
                match add_entry(window, until_nul(&entry.file_name), true) {
                    Some(at) => last = at,
                    None => return LB_ERRSPACE,
                }
            }
        } else {
            drop(search);
        }
    }
    if attributes & DDL_DIRECTORY != 0 {
        if let Some(search) = imports::FileSearch::new(&pattern) {
            for entry in search {
                let name = until_nul(&entry.file_name);
                if entry.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 || name == [u16::from(b'.')] {
                    continue;
                }
                let mut bracketed = [0u16; 262];
                let length = name.len().min(259);
                bracketed[0] = u16::from(b'[');
                bracketed[1..=length].copy_from_slice(&name[..length]);
                bracketed[length + 1] = u16::from(b']');
                match add_entry(window, &bracketed[..length + 2], false) {
                    Some(at) => last = at,
                    None => return LB_ERRSPACE,
                }
            }
        }
    }
    if attributes & DDL_DRIVES != 0 {
        let drives = imports::logical_drives();
        for drive in 0..26u16 {
            if drives & 1 << drive == 0 {
                continue;
            }
            let entry = [
                u16::from(b'['),
                u16::from(b'-'),
                u16::from(b'a') + drive,
                u16::from(b'-'),
                u16::from(b']'),
            ];
            match add_entry(window, &entry, false) {
                Some(at) => last = at,
                None => return LB_ERRSPACE,
            }
        }
    }
    last
}

// --- DlgDirList, DlgDirSelectEx, GetListBoxInfo
// ------------------------------------------------------

/// The units of a path's directory part and its file part: split after the last backslash or colon.
fn split_path(path: &[u16]) -> (&[u16], &[u16]) {
    match path
        .iter()
        .rposition(|&unit| unit == u16::from(b'\\') || unit == u16::from(b':'))
    {
        Some(at) => (&path[..=at], &path[at + 1..]),
        None => (&[], path),
    }
}

/// Whether `units` hold a wildcard.
fn has_wildcard(units: &[u16]) -> bool {
    units
        .iter()
        .any(|&unit| unit == u16::from(b'*') || unit == u16::from(b'?'))
}

/// DlgDirList's core over the wide path `path` (the caller's, read): the current directory changed
/// to its directory part, the list box `list_id` of `dialog` filled (LB_DIR of the file part as
/// `attributes` asks for files, then the directories and the drives), the static `static_id` given
/// the current directory. Its answer and the file part to write back into the caller's buffer
/// (uppercased; "*.*" for none), none when the directory could not be entered (the answer 0 then,
/// SetCurrentDirectory's error left).
fn dlg_dir_list(
    dialog: usize,
    path: &[u16],
    list_id: i32,
    static_id: i32,
    attributes: u32,
) -> (i32, Option<[u16; 264]>) {
    let star_dot_star = [u16::from(b'*'), u16::from(b'.'), u16::from(b'*')];
    let (directory, file) = split_path(path);
    if !directory.is_empty() {
        // "C:\": the root itself; "dir\": the directory without its backslash.
        let trimmed = if directory.len() > 1
            && directory.last() == Some(&u16::from(b'\\'))
            && directory[directory.len() - 2] != u16::from(b':')
        {
            &directory[..directory.len() - 1]
        } else {
            directory
        };
        let Some(enter) = terminated::<264>(trimmed) else {
            imports::set_last_error(ERROR_INVALID_PARAMETER);
            return (0, None);
        };
        if !imports::set_current_directory(&enter[..=trimmed.len()]) {
            return (0, None);
        }
    }
    let mut file_part = if file.is_empty() {
        terminated::<264>(&star_dot_star)
    } else {
        terminated::<264>(file)
    };
    // A file part naming a directory (no wildcard) is entered, its files listed.
    if let Some(name) = file_part {
        let length = until_nul(&name).len();
        if !has_wildcard(until_nul(&name))
            && imports::file_attributes(&name[..=length])
                .is_some_and(|found| found & FILE_ATTRIBUTE_DIRECTORY != 0)
            && imports::set_current_directory(&name[..=length])
        {
            file_part = terminated::<264>(&star_dot_star);
        }
    }
    let Some(mut file_part) = file_part else {
        imports::set_last_error(ERROR_INVALID_PARAMETER);
        return (0, None);
    };
    let length = until_nul(&file_part).len();
    // SAFETY: the local buffer, terminated within it.
    unsafe { crate::string::char_upper_buff_w(file_part.as_mut_ptr(), length as u32) };
    if list_id != 0 {
        let list = crate::dialog::get_dlg_item(dialog, list_id);
        if list == 0 {
            imports::set_last_error(ERROR_LISTBOX_ID_NOT_FOUND);
            return (1, Some(file_part));
        }
        let send = |message: u32, wparam: u32, lparam: i32| {
            message::send(list, message, wparam, lparam).unwrap_or(0)
        };
        send(LB_RESETCONTENT, 0, 0);
        send(WM_SETREDRAW, 0, 0);
        let exclusive = attributes & DDL_EXCLUSIVE != 0;
        if !exclusive || attributes & FILE_BITS != 0 {
            send(
                LB_DIR,
                attributes & !(DDL_DIRECTORY | DDL_DRIVES | DDL_POSTMSGS),
                file_part.as_ptr() as usize as i32,
            );
        }
        let star = terminated::<4>(&star_dot_star).unwrap_or_default();
        if attributes & DDL_DIRECTORY != 0 {
            send(
                LB_DIR,
                DDL_DIRECTORY | DDL_EXCLUSIVE,
                star.as_ptr() as usize as i32,
            );
        }
        if attributes & DDL_DRIVES != 0 {
            send(
                LB_DIR,
                DDL_DRIVES | DDL_EXCLUSIVE,
                star.as_ptr() as usize as i32,
            );
        }
        send(WM_SETREDRAW, 1, 0);
    }
    if static_id != 0 {
        let mut current = [0u16; 264];
        let length = imports::current_directory(&mut current[..263]);
        if length > 0 && length < 263 {
            crate::dialog::set_dlg_item_text_w(dialog, static_id, current.as_ptr());
        }
    }
    (1, Some(file_part))
}

/// DlgDirListW: the list box `list_id` of `dialog` filled with the files and directories `path`
/// names, the current directory changed to its directory, the file part written back (see
/// [`dlg_dir_list`]); TRUE, or FALSE with the last error when the directory cannot be entered (a
/// missing list box is ERROR_LISTBOX_ID_NOT_FOUND, the answer TRUE).
///
/// # Safety
///
/// `path` is the caller's NUL-terminated buffer, writable over its length, or null.
#[unsafe(export_name = "f2k_export_DlgDirListW")]
pub unsafe extern "system" fn dlg_dir_list_w(
    dialog: usize,
    path: *mut u16,
    list_id: i32,
    static_id: i32,
    attributes: u32,
) -> i32 {
    if path.is_null() {
        return dlg_dir_list(dialog, &[], list_id, static_id, attributes).0;
    }
    // SAFETY: the caller's terminated buffer (the contract).
    let text = unsafe { InWStr::new(path) }.units();
    let mut whole = [0u16; 1024];
    if text.len() > whole.len() {
        imports::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    text.copy_to(&mut whole[..text.len()]);
    let (answer, written) =
        dlg_dir_list(dialog, &whole[..text.len()], list_id, static_id, attributes);
    if let Some(file) = written {
        let file = until_nul(&file);
        let room = file.len().min(text.len());
        // SAFETY: the caller's buffer, writable over its old length (the file part is no longer).
        let mut out = unsafe { OutBuf::new(path, room + 1) };
        out.put(&file[..room]);
        out.set(room, 0);
    }
    answer
}

/// DlgDirListA: DlgDirListW's over the narrow path, the file part written back narrow.
///
/// # Safety
///
/// As DlgDirListW's, narrow.
#[unsafe(export_name = "f2k_export_DlgDirListA")]
pub unsafe extern "system" fn dlg_dir_list_a(
    dialog: usize,
    path: *mut u8,
    list_id: i32,
    static_id: i32,
    attributes: u32,
) -> i32 {
    if path.is_null() {
        return dlg_dir_list(dialog, &[], list_id, static_id, attributes).0;
    }
    // SAFETY: the caller's terminated buffer (the contract).
    let text = unsafe { InStr::new(path) };
    let room = text.bytes().len();
    let Some((answer, written)) = crate::with_wide(text.bytes(), |units| {
        dlg_dir_list(dialog, units, list_id, static_id, attributes)
    }) else {
        return 0;
    };
    if let Some(file) = written {
        // SAFETY: the caller's buffer, writable over its old length and its terminator.
        let mut out = unsafe { OutBuf::new(path, room + 1) };
        procedure::put_narrow(&mut out, until_nul(&file));
    }
    answer
}

/// DlgDirSelectEx's core: the selected entry of the list box `list_id` of `dialog` as a path into
/// `out` (a directory's "[name]" as "name\", a drive's "[-x-]" as "x:", a file without an extension
/// with a dot after it), cut to the buffer; whether it is a directory or a drive. Nothing selected
/// leaves the buffer as it was and answers FALSE.
fn dlg_dir_select(dialog: usize, out: &mut [u16], list_id: i32) -> i32 {
    let list = crate::dialog::get_dlg_item(dialog, list_id);
    if list == 0 || out.is_empty() {
        return 0;
    }
    let selected = message::send(list, LB_GETCURSEL, 0, 0).unwrap_or(LB_ERR);
    if selected < 0 {
        return 0;
    }
    let length = message::send(list, LB_GETTEXTLEN, selected as u32, 0).unwrap_or(LB_ERR);
    if !(0..260).contains(&length) {
        return 0;
    }
    let mut text = [0u16; 264];
    message::send(
        list,
        LB_GETTEXT,
        selected as u32,
        text.as_mut_ptr() as usize as i32,
    );
    let text = until_nul(&text);
    let mut path = [0u16; 266];
    let (length, directory) = if text.first() == Some(&u16::from(b'[')) && text.len() >= 2 {
        let inner = &text[1..text.len() - usize::from(text.last() == Some(&u16::from(b']')))];
        if inner.len() == 3 && inner[0] == u16::from(b'-') && inner[2] == u16::from(b'-') {
            path[0] = inner[1];
            path[1] = u16::from(b':');
            (2, true)
        } else {
            path[..inner.len()].copy_from_slice(inner);
            path[inner.len()] = u16::from(b'\\');
            (inner.len() + 1, true)
        }
    } else {
        path[..text.len()].copy_from_slice(text);
        if text.contains(&u16::from(b'.')) {
            (text.len(), false)
        } else {
            path[text.len()] = u16::from(b'.');
            (text.len() + 1, false)
        }
    };
    let length = length.min(out.len() - 1);
    out[..length].copy_from_slice(&path[..length]);
    out[length] = 0;
    directory as i32
}

/// DlgDirSelectExW: the list box's selected entry as a path into the caller's buffer of `count`
/// units (see [`dlg_dir_select`]); whether it is a directory or a drive.
///
/// # Safety
///
/// `buffer` holds `count` writable units.
#[unsafe(export_name = "f2k_export_DlgDirSelectExW")]
pub unsafe extern "system" fn dlg_dir_select_ex_w(
    dialog: usize,
    buffer: *mut u16,
    count: i32,
    list_id: i32,
) -> i32 {
    if buffer.is_null() || count <= 0 {
        return 0;
    }
    let mut path = [0u16; 266];
    let room = (count as usize).min(path.len());
    // A copy of the caller's buffer: nothing selected leaves it as it was.
    let answer = dlg_dir_select(dialog, &mut path[..room], list_id);
    let length = until_nul(&path[..room]).len();
    if length > 0 || answer != 0 {
        // SAFETY: the caller's buffer of `count` units (the contract).
        let mut out = unsafe { OutBuf::new(buffer, count as usize) };
        out.put(&path[..length]);
        out.set(length, 0);
    }
    answer
}

/// DlgDirSelectExA: DlgDirSelectExW's into a wide buffer of its own, written back narrow whatever
/// it holds (nothing selected: the empty string).
///
/// # Safety
///
/// `buffer` holds `count` writable bytes.
#[unsafe(export_name = "f2k_export_DlgDirSelectExA")]
pub unsafe extern "system" fn dlg_dir_select_ex_a(
    dialog: usize,
    buffer: *mut u8,
    count: i32,
    list_id: i32,
) -> i32 {
    if buffer.is_null() || count <= 0 {
        return 0;
    }
    let mut path = [0u16; 266];
    let room = (count as usize).min(path.len());
    let answer = dlg_dir_select(dialog, &mut path[..room], list_id);
    // SAFETY: the caller's buffer of `count` bytes (the contract).
    let mut out = unsafe { OutBuf::new(buffer, count as usize) };
    procedure::put_narrow(&mut out, until_nul(&path[..room]));
    answer
}

/// GetListBoxInfo: the items per column of an LBS_MULTICOLUMN list box (LB_GETLISTBOXINFO), 0 for
/// another; 0 with 1400 for a handle naming no window, ERROR_INVALID_PARAMETER for a window that
/// is no list box.
#[unsafe(export_name = "f2k_export_GetListBoxInfo")]
pub extern "system" fn get_list_box_info(window: usize) -> u32 {
    if answered(window::window_info(window)).is_none() {
        return 0;
    }
    if !is_list_box(window) {
        imports::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    message::send(window, LB_GETLISTBOXINFO, 0, 0).unwrap_or(0) as u32
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide;

    use super::*;

    /// A list box's state with no window behind it (its window services fail, which the items'
    /// handling does not need), of the style `style`.
    fn list_with(window: usize, style: u32) {
        let block = imports::local_alloc(LMEM_FIXED | LMEM_ZEROINIT, core::mem::size_of::<State>())
            .unwrap();
        assert!(kept::keep(window, block));
        store(
            window,
            &State {
                selection: -1,
                anchor: -1,
                item_height: 16,
                flags: NO_REDRAW,
                locale: 0x0409,
                style,
                ..State::default()
            },
        );
    }

    fn texts(window: usize) -> std::vec::Vec<std::string::String> {
        let s = load(window).unwrap();
        (0..s.count)
            .map(|index| {
                with_item_text(&item(&s, index).unwrap(), |units| {
                    std::string::String::from_utf16(units).unwrap()
                })
            })
            .collect()
    }

    /// LBS_SORT puts LB_ADDSTRING's strings in order (ignoring case), LB_INSERTSTRING where it is
    /// told; an index past the end is refused.
    #[test]
    fn sorted_strings_go_in_order() {
        let window = 0x7_1010;
        list_with(window, LBS_SORT);
        for (text, at) in [
            ("pear", 0),
            ("apple", 0),
            ("Banana", 1),
            ("cherry", 2),
            ("apricot", 1),
        ] {
            assert_eq!(insert(window, None, &wide(text), 0), at, "{text}");
        }
        assert_eq!(insert(window, Some(0), &wide("zebra"), 0), 0);
        assert_eq!(insert(window, Some(-1), &wide("aardvark"), 0), 6);
        assert_eq!(insert(window, Some(9), &wide("fig"), 0), LB_ERR);
        assert_eq!(
            texts(window),
            ["zebra", "apple", "apricot", "Banana", "cherry", "pear", "aardvark"]
        );
        destroy(window);
    }

    /// LB_FINDSTRING searches from the item after its start, round the end, by prefix; the exact
    /// form matches whole strings.
    #[test]
    fn finding_wraps_round_the_end() {
        let window = 0x7_1020;
        list_with(window, 0);
        for text in ["pear", "cherry", "apple", "banana", "Blueberry"] {
            insert(window, None, &wide(text), 0);
        }
        assert_eq!(find(window, -1, &wide("b"), 0, false), 3);
        assert_eq!(find(window, 3, &wide("b"), 0, false), 4);
        assert_eq!(find(window, 4, &wide("b"), 0, false), 3);
        assert_eq!(find(window, -1, &wide("APP"), 0, false), 2);
        assert_eq!(find(window, -1, &wide("kiwi"), 0, false), LB_ERR);
        assert_eq!(find(window, -1, &wide("BANANA"), 0, true), 3);
        assert_eq!(find(window, -1, &wide("ban"), 0, true), LB_ERR);
        destroy(window);
    }

    /// Deleting an item moves the selection and the caret after it back.
    #[test]
    fn deleting_moves_the_selection_back() {
        let window = 0x7_1030;
        list_with(window, 0);
        for text in ["a", "b", "c"] {
            insert(window, None, &wide(text), 0);
        }
        let mut s = load(window).unwrap();
        s.selection = 2;
        s.caret = 2;
        store(window, &s);
        assert_eq!(delete(window, 0), 2);
        let s = load(window).unwrap();
        assert_eq!((s.selection, s.caret), (1, 1));
        assert_eq!(delete(window, 5), LB_ERR);
        assert_eq!(texts(window), ["b", "c"]);
        destroy(window);
    }

    /// A directory's entry is "name\", a drive's "x:", a file without an extension gets a dot.
    #[test]
    fn paths_split_at_the_last_separator() {
        let path = wide("f2klbdir\\*.txt");
        let (directory, file) = split_path(&path);
        assert_eq!(directory, &wide("f2klbdir\\")[..]);
        assert_eq!(file, &wide("*.txt")[..]);
        let star = wide("*");
        let (directory, file) = split_path(&star);
        assert!(directory.is_empty());
        assert_eq!(file, &wide("*")[..]);
        assert!(has_wildcard(&wide("a?c")) && !has_wildcard(&wide("abc")));
    }

    /// LB_DIR's file filter: hidden and system files only when asked; DDL_EXCLUSIVE only those
    /// with an attribute asked for.
    #[test]
    fn the_directory_listing_filters_files() {
        assert!(lists_file(0x20, DDL_READWRITE));
        assert!(!lists_file(0x22, DDL_READWRITE));
        assert!(lists_file(0x22, DDL_HIDDEN));
        assert!(!lists_file(0x20, DDL_EXCLUSIVE | DDL_READONLY));
        assert!(lists_file(0x21, DDL_EXCLUSIVE | DDL_READONLY));
    }
}
