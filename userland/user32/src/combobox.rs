//! The ComboBox control: the class user32 registers in every process
//! ([`crate::class::register_system_classes`]), its procedure here in its two forms
//! ([`combo_box_proc_w`], [`combo_box_proc_a`]), as Windows 2000's user32 runs it; its drop-down
//! list's class, ComboLBox ([`combo_list_proc_w`], [`combo_list_proc_a`]: the ListBox control's
//! procedure with the mouse of a combo box's list); and the calls over it, GetComboBoxInfo,
//! DlgDirListComboBoxA/W and DlgDirSelectComboBoxExA/W.
//!
//! A combo box is a selection field and a list ([`crate::listbox`], LBS_COMBOBOX), made at its
//! WM_CREATE: CBS_SIMPLE's list is a child of the combo box, always shown below an Edit child;
//! CBS_DROPDOWN's (an Edit child and a button) and CBS_DROPDOWNLIST's (a field the combo box draws
//! itself, and a button) is a hidden child of the desktop, shown below the combo box when it drops
//! down. The list is made first, so a CBS_SIMPLE combo box's first child is its list (the
//! combobox capture's "ComboLBox Edit"); the list tells the combo box its notifications and its
//! owner-draw messages (its owner, which the creation's lpCreateParams names), which the combo box
//! hands its parent as ODT_COMBOBOX ones of its own. Its state is a fixed local block of its own
//! ([`State`], Windows 2000's CBOX), found by its window in a table of the process's ([`kept`]), as
//! a list box's is.
//!
//! As the combobox capture shows Windows 2000's:
//!
//! - the style read back has CBS_HASSTRINGS added to a combo box that is not owner-drawn; the combo
//!   box's own WS_VSCROLL, WS_HSCROLL and WS_BORDER are its list's (taken off the combo box itself,
//!   an F2K choice the capture does not show: it shows the style's low word alone); WM_GETDLGCODE
//!   is DLGC_WANTARROWS | DLGC_WANTCHARS;
//! - a CBS_DROPDOWN or CBS_DROPDOWNLIST combo box is as high as its field, the height it was made
//!   with being its dropped list's: CB_GETDROPPEDCONTROLRECT answers the combo box's rectangle on
//!   the screen down to that height (a CBS_SIMPLE one's, the combo box's own);
//! - the CB_* messages that mirror the list box's are its list's (LB_ERR and ERROR_INVALID_INDEX as
//!   the list answers them); CB_SETCURSEL, CB_SELECTSTRING and CB_RESETCONTENT set the edit's text
//!   to the selection's (none: empty), which leaves the last error 0 (the edit's text lock) or, for
//!   an empty text, as it was; WM_SETTEXT goes to the edit, the selection kept; a CBS_DROPDOWNLIST
//!   combo box's WM_GETTEXT is its selection's text, and WM_SETTEXT, CB_SETEDITSEL, CB_GETEDITSEL
//!   and CB_LIMITTEXT are CB_ERR with ERROR_INVALID_COMBOBOX_MESSAGE; CB_SETEDITSEL is the edit's
//!   EM_SETSEL of lParam's two signed words (the edit without the focus leaves ERROR_ACCESS_DENIED,
//!   its caret's), CB_LIMITTEXT its EM_LIMITTEXT; nothing the messages change is notified, nor the
//!   edit's EN_UPDATE and EN_CHANGE for a text the combo box sets itself;
//! - CB_SHOWDROPDOWN TRUE drops the list down (CBN_DROPDOWN first), FALSE rolls it up
//!   (CBN_SELENDCANCEL, CBN_CLOSEUP), each answering TRUE and doing nothing when it is so already;
//!   a CBS_SIMPLE combo box's is always down (CB_GETDROPPEDSTATE TRUE) and notifies nothing;
//! - the keys: Up and Down (PgUp and PgDn too; Home and End for a combo box without an edit) step
//!   the list's selection, F4 and Alt+Up or Alt+Down drop the list down or roll it up, Enter rolls
//!   it up keeping the selection, Esc rolls it up too (the selection kept as the keys left it); a
//!   selection the keys change while the list is up is CBN_SELCHANGE, while it is down CBN_SELENDOK
//!   then CBN_SELCHANGE; rolling up is CBN_SELENDOK (Enter, F4) or CBN_SELENDCANCEL (Esc), then
//!   CBN_CLOSEUP; a key to a combo box with an edit answers 1, its Enter and Esc while down too, a
//!   combo box without one's the list's answer;
//! - the focus: a combo box with an edit gives it the focus; the first focus is CBN_SETFOCUS, its
//!   loss CBN_SELENDCANCEL (CBN_CLOSEUP after it when the list was down) then CBN_KILLFOCUS;
//! - typing in the edit is CBN_EDITUPDATE then CBN_EDITCHANGE for each change, and moves the list's
//!   caret (not its selection) to the first item the text begins, as Windows 2000's
//!   xxxCBUpdateListBoxWindow does (the next Down selects it);
//! - GetComboBoxInfo answers the field's rectangle and the button's (a CBS_SIMPLE combo box has
//!   none: STATE_SYSTEM_INVISIBLE), the edit (none for CBS_DROPDOWNLIST) and the list; 87 for a
//!   cbSize not the structure's, ERROR_WINDOW_NOT_COMBOBOX for another window, 1400 for no window.
//!
//! What the capture does not show follows Windows 2000's documented behaviour: the list drops
//! below the combo box (above it when it would leave the screen), as wide as the combo box or
//! CB_SETDROPPEDWIDTH's width, cut to its items when they are fewer than its height holds (Wine's
//! and Windows' own list does so: not captured); while it is down the list holds the mouse's
//! capture, an item under the cursor taken as the selection (not notified), a release over the list
//! rolling it up with CBN_SELENDOK, CBN_CLOSEUP and CBN_SELCHANGE when the selection changed, a
//! press outside it rolling it up with CBN_SELENDCANCEL (the selection the mouse moved put back);
//! a press on a CBS_DROPDOWN combo box's button, or anywhere on a CBS_DROPDOWNLIST one, drops it
//! down. CBS_EXTENDEDUI (CB_SETEXTENDEDUI): Down drops the list, F4 does nothing. A CBS_SIMPLE
//! combo box's list takes a click as its selection (CBN_SELCHANGE, CBN_DBLCLK for a double one),
//! the focus kept by the combo box's edit. The field's height is the font's height by 13/8 less
//! the edges (Wine's measure of Windows'), an owner-drawn combo box's its parent's WM_MEASUREITEM
//! answer for the item -1.
//!
//! The combo box paints in WM_PAINT: its sunken edge, its button (DrawFrameControl's
//! DFCS_SCROLLCOMBOBOX, pushed while the mouse holds it), and a CBS_DROPDOWNLIST combo box's field:
//! its background in the brush its parent's WM_CTLCOLOREDIT answers (WM_CTLCOLORSTATIC disabled),
//! the selection's text, in COLOR_HIGHLIGHT and COLOR_HIGHLIGHTTEXT with a focus rectangle while it
//! has the focus and its list is up, or for an owner-drawn one the parent's WM_DRAWITEM with
//! ODS_COMBOBOXEDIT. What is not served is logged once: a press on the dropped list's scroll bar
//! (its non-client area), the CB_* messages not listed here.

use rtl::display::{COLOR_GRAYTEXT, COLOR_HIGHLIGHT, COLOR_HIGHLIGHTTEXT, COLOR_WINDOW};
use rtl::edge::{In, Out, OutBuf};
use rtl::gdi::{Rect, TRANSPARENT};
use rtl::pod::Pod;
use rtl::user::{
    CreateStructW,
    Msg,
    MA_NOACTIVATE,
    VK_DOWN,
    VK_END,
    VK_ESCAPE,
    VK_F4,
    VK_HOME,
    VK_RETURN,
    VK_UP,
    WM_CAPTURECHANGED,
    WM_CHAR,
    WM_CLEAR,
    WM_COMMAND,
    WM_COMPAREITEM,
    WM_COPY,
    WM_CREATE,
    WM_CTLCOLOREDIT,
    WM_CTLCOLORMSGBOX,
    WM_CTLCOLORSTATIC,
    WM_CUT,
    WM_DESTROY,
    WM_DRAWITEM,
    WM_ENABLE,
    WM_ERASEBKGND,
    WM_GETDLGCODE,
    WM_GETFONT,
    WM_GETTEXT,
    WM_GETTEXTLENGTH,
    WM_KEYDOWN,
    WM_KILLFOCUS,
    WM_LBUTTONDBLCLK,
    WM_LBUTTONDOWN,
    WM_LBUTTONUP,
    WM_MOUSEACTIVATE,
    WM_MOUSEMOVE,
    WM_MOUSEWHEEL,
    WM_NCCREATE,
    WM_NCDESTROY,
    WM_PAINT,
    WM_PASTE,
    WM_SETFOCUS,
    WM_SETFONT,
    WM_SETREDRAW,
    WM_SETTEXT,
    WM_SIZE,
    WM_SYSKEYDOWN,
    WM_UNDO,
    WS_BORDER,
    WS_CHILD,
    WS_DISABLED,
    WS_EX_CLIENTEDGE,
    WS_EX_TOOLWINDOW,
    WS_HSCROLL,
    WS_VISIBLE,
    WS_VSCROLL,
};
use rtl::window::{
    GWL_STYLE,
    SWP_FRAMECHANGED,
    SWP_HIDEWINDOW,
    SWP_NOACTIVATE,
    SWP_NOMOVE,
    SWP_NOSIZE,
    SWP_NOZORDER,
    SWP_SHOWWINDOW,
};
use rtl::winerror::ERROR_INVALID_PARAMETER;

use crate::dialog::{DLGC_WANTARROWS, DLGC_WANTCHARS};
use crate::edit::{EM_GETSEL, EM_LIMITTEXT, EM_SETSEL};
use crate::imports::{self, LocalFixed, LMEM_FIXED, LMEM_ZEROINIT};
use crate::listbox::{
    self,
    LBN_DBLCLK,
    LBN_ERRSPACE,
    LBN_SELCANCEL,
    LBN_SELCHANGE,
    LBS_COMBOBOX,
    LBS_DISABLENOSCROLL,
    LBS_HASSTRINGS,
    LBS_NOINTEGRALHEIGHT,
    LBS_NOTIFY,
    LBS_SORT,
    LB_ADDSTRING,
    LB_DELETESTRING,
    LB_DIR,
    LB_FINDSTRING,
    LB_FINDSTRINGEXACT,
    LB_GETCOUNT,
    LB_GETCURSEL,
    LB_GETHORIZONTALEXTENT,
    LB_GETITEMDATA,
    LB_GETITEMHEIGHT,
    LB_GETLOCALE,
    LB_GETTEXT,
    LB_GETTEXTLEN,
    LB_GETTOPINDEX,
    LB_INITSTORAGE,
    LB_INSERTSTRING,
    LB_ITEMFROMPOINT,
    LB_RESETCONTENT,
    LB_SELECTSTRING,
    LB_SETCARETINDEX,
    LB_SETCURSEL,
    LB_SETHORIZONTALEXTENT,
    LB_SETITEMDATA,
    LB_SETITEMHEIGHT,
    LB_SETLOCALE,
    LB_SETTOPINDEX,
};
use crate::{answered, message, paint, procedure, window};

// --- The messages, the styles, the notifications -------------------------------------------------

/// The combo box messages (winuser.h's CB_*).
pub const CB_GETEDITSEL: u32 = 0x0140;
pub const CB_LIMITTEXT: u32 = 0x0141;
pub const CB_SETEDITSEL: u32 = 0x0142;
pub const CB_ADDSTRING: u32 = 0x0143;
pub const CB_DELETESTRING: u32 = 0x0144;
pub const CB_DIR: u32 = 0x0145;
pub const CB_GETCOUNT: u32 = 0x0146;
pub const CB_GETCURSEL: u32 = 0x0147;
pub const CB_GETLBTEXT: u32 = 0x0148;
pub const CB_GETLBTEXTLEN: u32 = 0x0149;
pub const CB_INSERTSTRING: u32 = 0x014A;
pub const CB_RESETCONTENT: u32 = 0x014B;
pub const CB_FINDSTRING: u32 = 0x014C;
pub const CB_SELECTSTRING: u32 = 0x014D;
pub const CB_SETCURSEL: u32 = 0x014E;
pub const CB_SHOWDROPDOWN: u32 = 0x014F;
pub const CB_GETITEMDATA: u32 = 0x0150;
pub const CB_SETITEMDATA: u32 = 0x0151;
pub const CB_GETDROPPEDCONTROLRECT: u32 = 0x0152;
pub const CB_SETITEMHEIGHT: u32 = 0x0153;
pub const CB_GETITEMHEIGHT: u32 = 0x0154;
pub const CB_SETEXTENDEDUI: u32 = 0x0155;
pub const CB_GETEXTENDEDUI: u32 = 0x0156;
pub const CB_GETDROPPEDSTATE: u32 = 0x0157;
pub const CB_FINDSTRINGEXACT: u32 = 0x0158;
pub const CB_SETLOCALE: u32 = 0x0159;
pub const CB_GETLOCALE: u32 = 0x015A;
pub const CB_GETTOPINDEX: u32 = 0x015B;
pub const CB_SETTOPINDEX: u32 = 0x015C;
pub const CB_GETHORIZONTALEXTENT: u32 = 0x015D;
pub const CB_SETHORIZONTALEXTENT: u32 = 0x015E;
pub const CB_GETDROPPEDWIDTH: u32 = 0x015F;
pub const CB_SETDROPPEDWIDTH: u32 = 0x0160;
pub const CB_INITSTORAGE: u32 = 0x0161;
/// The combo box messages' range: one not served answers CB_ERR, logged.
const CB_FIRST: u32 = 0x0140;
const CB_LAST: u32 = 0x0161;

/// The combo box styles (winuser.h's CBS_*).
pub const CBS_SIMPLE: u32 = 0x0001;
pub const CBS_DROPDOWN: u32 = 0x0002;
pub const CBS_DROPDOWNLIST: u32 = 0x0003;
pub const CBS_OWNERDRAWFIXED: u32 = 0x0010;
pub const CBS_OWNERDRAWVARIABLE: u32 = 0x0020;
pub const CBS_AUTOHSCROLL: u32 = 0x0040;
pub const CBS_OEMCONVERT: u32 = 0x0080;
pub const CBS_SORT: u32 = 0x0100;
pub const CBS_HASSTRINGS: u32 = 0x0200;
pub const CBS_NOINTEGRALHEIGHT: u32 = 0x0400;
pub const CBS_DISABLENOSCROLL: u32 = 0x0800;
pub const CBS_UPPERCASE: u32 = 0x2000;
pub const CBS_LOWERCASE: u32 = 0x4000;

/// The notifications (winuser.h's CBN_*), the code in WM_COMMAND's wParam's high word.
pub const CBN_ERRSPACE: u32 = 0xFFFF;
pub const CBN_SELCHANGE: u32 = 1;
pub const CBN_DBLCLK: u32 = 2;
pub const CBN_SETFOCUS: u32 = 3;
pub const CBN_KILLFOCUS: u32 = 4;
pub const CBN_EDITCHANGE: u32 = 5;
pub const CBN_EDITUPDATE: u32 = 6;
pub const CBN_DROPDOWN: u32 = 7;
pub const CBN_CLOSEUP: u32 = 8;
pub const CBN_SELENDOK: u32 = 9;
pub const CBN_SELENDCANCEL: u32 = 10;

/// The answers (winuser.h's CB_OKAY, CB_ERR).
const CB_OKAY: i32 = 0;
const CB_ERR: i32 = -1;

/// The Win32 errors a combo box's refusals leave (winerror.h's).
const ERROR_INVALID_COMBOBOX_MESSAGE: u32 = 1422;
const ERROR_WINDOW_NOT_COMBOBOX: u32 = 1423;

/// The edit's style bit that marks it a combo box's (Windows 2000's private ES_COMBOBOX).
pub const ES_COMBOBOX: u32 = 0x0200;
/// The edit's styles a combo box's carries over (ES_AUTOHSCROLL, ES_OEMCONVERT, ES_UPPERCASE,
/// ES_LOWERCASE).
const ES_AUTOHSCROLL: u32 = 0x0080;
const ES_OEMCONVERT: u32 = 0x0400;
const ES_UPPERCASE: u32 = 0x0008;
const ES_LOWERCASE: u32 = 0x0010;

/// The children's ids, as Windows 2000's combo box gives them (CBLISTBOXID, CBEDITID).
const LIST_ID: u32 = 1000;
const EDIT_ID: u32 = 1001;

/// The owner-draw structures' values (winuser.h's ODT_, ODA_, ODS_).
const ODT_LISTBOX: u32 = 2;
const ODT_COMBOBOX: u32 = 3;
const ODA_DRAWENTIRE: u32 = 0x0001;
const ODS_SELECTED: u32 = 0x0001;
const ODS_DISABLED: u32 = 0x0004;
const ODS_FOCUS: u32 = 0x0010;
const ODS_COMBOBOXEDIT: u32 = 0x1000;

/// The messages and values rtl does not name.
const WM_MEASUREITEM: u32 = 0x002C;
const WM_DELETEITEM: u32 = 0x002D;
const WM_CTLCOLOR_LAST: u32 = 0x0138;
const VK_PRIOR: u32 = 0x21;
const VK_NEXT: u32 = 0x22;
const DLGC_WANTMESSAGE: u32 = 0x0004;
/// SM_CXVSCROLL (the button's width), SM_CXEDGE and SM_CYEDGE (the sunken edge's).
const SM_CXVSCROLL: i32 = 2;
const SM_CXEDGE: i32 = 45;
const SM_CYEDGE: i32 = 46;
/// SetWindowPos's HWND_TOPMOST.
const HWND_TOPMOST: usize = usize::MAX;
/// ExtTextOut's ETO_CLIPPED.
const ETO_CLIPPED: u32 = 0x0004;
/// GetComboBoxInfo's button states (oleacc.h's STATE_SYSTEM_PRESSED, STATE_SYSTEM_INVISIBLE).
const STATE_SYSTEM_PRESSED: u32 = 0x0008;
const STATE_SYSTEM_INVISIBLE: u32 = 0x8000;
/// The highest item CB_SETITEMHEIGHT takes.
const MOST_HEIGHT: u32 = 255;

/// The combo box's extra bytes: Windows 2000's hold the CBOX's address (F2K's state is in
/// [`kept`]).
pub const COMBOBOX_EXTRA: i32 = 4;

/// The cases logged in this process: a message, a case.
static LOGGED: rtl::stub::Logged<16> = rtl::stub::Logged::new();

/// The control's procedure, as its log lines name it.
const COMBOBOX_PROC: rtl::stub::Entry = crate::stub::procedure("ComboBoxWndProc");

/// The children's classes' names, NUL-terminated.
const LIST_CLASS: [u16; 10] = ascii_units::<10>("ComboLBox");
const EDIT_CLASS: [u16; 5] = ascii_units::<5>("Edit");

/// `text` as UTF-16 units, NUL-terminated, in `N` units.
const fn ascii_units<const N: usize>(text: &str) -> [u16; N] {
    let bytes = text.as_bytes();
    let mut units = [0u16; N];
    let mut index = 0;
    while index < bytes.len() {
        units[index] = bytes[index] as u16;
        index += 1;
    }
    units
}

// --- The state -----------------------------------------------------------------------------------

/// [`State::flags`]: the combo box has the focus; its list is down; the edit's EN_UPDATE and
/// EN_CHANGE are the combo box's own (not notified); a key went to the list while it was down
/// (its LBN_SELCHANGE is the keys' alone); the button is drawn pushed; the press that dropped the
/// list is still held (its release outside the list keeps it down); CBS_EXTENDEDUI; the combo box
/// is setting its own size; its redraw is off; a press on the list is held.
const FOCUSED: u32 = 0x1;
const DROPPED: u32 = 0x2;
const NO_EDIT_NOTIFY: u32 = 0x4;
const KEYBOARD: u32 = 0x8;
const PRESSED: u32 = 0x10;
const TRACKING: u32 = 0x20;
const EXTENDED_UI: u32 = 0x40;
const SIZING: u32 = 0x80;
const NO_REDRAW: u32 = 0x100;
const LIST_PRESS: u32 = 0x200;

/// A combo box's state (Windows 2000's CBOX, F2K's layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct State {
    /// The list (ComboLBox) and the edit (0 for CBS_DROPDOWNLIST).
    list: usize,
    edit: usize,
    /// WM_SETFONT's font (0: the System font).
    font: usize,
    /// Its style at its creation (CBS_HASSTRINGS added to one not owner-drawn).
    style: u32,
    /// The control's id, as its creation gave it.
    id: u32,
    flags: u32,
    /// The dropped list's rectangle's height, from the combo box's top: the height it was made
    /// with (or last sized to).
    drop_height: i32,
    /// The selection field's height (CB_SETITEMHEIGHT(-1)).
    field_height: i32,
    /// CB_SETDROPPEDWIDTH's width (0: the combo box's).
    drop_width: i32,
    /// The selection last told to the parent (or set by a message): the one a roll-up cancelled
    /// puts back when the mouse moved it.
    notified: i32,
    reserved: u32,
}

// SAFETY: integers only, with no padding: three words first, then eight 32-bit fields (an even
// count, which ends at a word's boundary).
unsafe impl Pod for State {}

/// The kinds of combo box (the style's low two bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Simple,
    DropDown,
    DropDownList,
}

impl State {
    fn kind(&self) -> Kind {
        kind_of(self.style)
    }

    fn simple(&self) -> bool {
        self.kind() == Kind::Simple
    }

    fn dropped(&self) -> bool {
        self.flags & DROPPED != 0
    }

    fn focused(&self) -> bool {
        self.flags & FOCUSED != 0
    }

    fn owner_drawn(&self) -> bool {
        self.style & (CBS_OWNERDRAWFIXED | CBS_OWNERDRAWVARIABLE) != 0
    }

    fn has_strings(&self) -> bool {
        !self.owner_drawn() || self.style & CBS_HASSTRINGS != 0
    }
}

/// The kind a style makes (0, as Windows 2000 takes it, is CBS_SIMPLE).
fn kind_of(style: u32) -> Kind {
    match style & 3 {
        2 => Kind::DropDown,
        3 => Kind::DropDownList,
        _ => Kind::Simple,
    }
}

/// The combo boxes' state blocks, by window: the process's table (see the module notes).
mod kept {
    use crate::records::Table;

    /// Each combo box's record: its window, its state block.
    static COMBO_BOXES: Table<2> = Table::new();

    /// The state block `block` kept for `window`; false when the heap has no room for its record.
    pub fn keep(window: usize, block: usize) -> bool {
        COMBO_BOXES.with(|boxes| boxes.set([window, block]))
    }

    /// The state block of `window`.
    pub fn block(window: usize) -> Option<usize> {
        COMBO_BOXES
            .with(|boxes| boxes.get(window))
            .map(|[_, block]| block)
    }

    /// The state block of `window`, no longer kept.
    pub fn forget(window: usize) -> Option<usize> {
        COMBO_BOXES
            .with(|boxes| boxes.take(window))
            .map(|[_, block]| block)
    }
}

/// The state of the combo box `window`; none for a window this procedure keeps none for.
fn load(window: usize) -> Option<State> {
    // SAFETY: the state block its window's record names is the combo box's own fixed block, made
    // LMEM_ZEROINIT, freed only once its record is dropped; the value is read and dropped at once.
    unsafe { LocalFixed::<State>::new(kept::block(window)?) }?
        .as_slice()
        .first()
        .copied()
}

/// The state of the combo box `window` written back.
fn store(window: usize, state: &State) {
    let Some(block) = kept::block(window) else {
        return;
    };
    // SAFETY: as in [`load`]: the block is written and dropped at once.
    if let Some(mut block) = unsafe { LocalFixed::<State>::new(block) } {
        if let Some(slot) = block.as_mut_slice().first_mut() {
            *slot = *state;
        }
    }
}

/// The flags `on` set (or cleared) in the combo box's state.
fn set_flags(window: usize, flags: u32, on: bool) {
    if let Some(mut s) = load(window) {
        if on {
            s.flags |= flags;
        } else {
            s.flags &= !flags;
        }
        store(window, &s);
    }
}

/// Whether `window` is a combo box of this process's.
pub fn is_combo_box(window: usize) -> bool {
    kept::block(window).is_some()
}

/// Whether the combo box `window` holds strings: whether a narrow caller's string messages reach
/// its procedure converted (an owner-drawn combo box without CBS_HASSTRINGS holds values).
pub fn holds_strings(window: usize) -> bool {
    load(window).is_some_and(|s| s.has_strings())
}

/// A case the control does not serve, logged once for the message it came with.
fn unserved(key: u32, what: &str, call: (usize, u32, u32, i32)) {
    crate::stub::message_once(&LOGGED, key, &COMBOBOX_PROC, what, call);
}

// --- Sending -------------------------------------------------------------------------------------

/// `message` sent (wide) to `window`: its answer, 0 when it is gone.
fn send(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    message::send(window, message, wparam, lparam).unwrap_or(0)
}

/// The combo box's id: its window's (GWL_ID), the one its creation gave it once the window is gone.
fn id_of(window: usize, s: &State) -> u32 {
    window::window_data(window).map_or(s.id, |data| data.id)
}

/// The combo box's parent: the window its notifications go to (0 for none).
fn parent_of(window: usize) -> usize {
    window::links(window).map_or(0, |links| links.parent as usize)
}

/// The notification `code` sent to the combo box's parent (WM_COMMAND: its id and the code, the
/// combo box's handle).
fn notify(window: usize, code: u32) {
    let Some(s) = load(window) else {
        return;
    };
    let parent = parent_of(window);
    if parent == 0 {
        return;
    }
    let id = id_of(window, &s);
    let _ = message::send(
        parent,
        WM_COMMAND,
        (code & 0xFFFF) << 16 | (id & 0xFFFF),
        window as i32,
    );
}

/// The list's current selection (-1: none).
fn selection(s: &State) -> i32 {
    if s.list == 0 {
        return CB_ERR;
    }
    send(s.list, LB_GETCURSEL, 0, 0)
}

/// Run `f` on the text of the list's item `index` with a terminator after it (`f` gets the units,
/// the terminator included); the empty string's for no item, or for a list that holds values.
fn with_list_text<R>(s: &State, index: i32, f: impl FnOnce(&[u16]) -> R) -> R {
    let length = if index < 0 || !s.has_strings() {
        CB_ERR
    } else {
        send(s.list, LB_GETTEXTLEN, index as u32, 0)
    };
    if length <= 0 {
        return f(&[0]);
    }
    let length = length as usize;
    let mut stack = [0u16; 128];
    if length < stack.len() {
        let got = send(s.list, LB_GETTEXT, index as u32, stack.as_mut_ptr() as i32);
        let got = (got.max(0) as usize).min(length);
        stack[got] = 0;
        return f(&stack[..=got]);
    }
    match imports::HeapBlock::new(2 * (length + 1)) {
        Some(mut block) => {
            let units = block.units_mut();
            let got = send(s.list, LB_GETTEXT, index as u32, units.as_mut_ptr() as i32);
            let got = (got.max(0) as usize).min(length);
            units[got] = 0;
            f(&units[..=got])
        }
        None => f(&[0]),
    }
}

/// Run `f` on the edit's text with a terminator after it (the empty string's for no edit).
fn with_edit_text<R>(s: &State, f: impl FnOnce(&[u16]) -> R) -> R {
    let length = if s.edit == 0 {
        0
    } else {
        send(s.edit, WM_GETTEXTLENGTH, 0, 0).max(0) as usize
    };
    if length == 0 {
        return f(&[0]);
    }
    let mut stack = [0u16; 128];
    if length < stack.len() {
        let got = send(
            s.edit,
            WM_GETTEXT,
            stack.len() as u32,
            stack.as_mut_ptr() as i32,
        );
        let got = (got.max(0) as usize).min(length);
        stack[got] = 0;
        return f(&stack[..=got]);
    }
    match imports::HeapBlock::new(2 * (length + 1)) {
        Some(mut block) => {
            let units = block.units_mut();
            let got = send(
                s.edit,
                WM_GETTEXT,
                (length + 1) as u32,
                units.as_mut_ptr() as i32,
            );
            let got = (got.max(0) as usize).min(length);
            units[got] = 0;
            f(&units[..=got])
        }
        None => f(&[0]),
    }
}

/// The edit's text set to `units` (terminated) by the combo box itself: its EN_UPDATE and EN_CHANGE
/// not notified.
fn set_edit_text(window: usize, edit: usize, units: &[u16]) -> i32 {
    let before = load(window).map_or(0, |s| s.flags & NO_EDIT_NOTIFY);
    set_flags(window, NO_EDIT_NOTIFY, true);
    let answer = send(edit, WM_SETTEXT, 0, units.as_ptr() as i32);
    set_flags(window, NO_EDIT_NOTIFY, before != 0);
    answer
}

// --- The geometry --------------------------------------------------------------------------------

/// The combo box's client area (its origin (0, 0)).
fn client(window: usize) -> Rect {
    window::client_rect(window).unwrap_or_default()
}

/// The sunken edge's width and height (SM_CXEDGE, SM_CYEDGE).
fn edges() -> (i32, i32) {
    (
        crate::display::get_system_metrics(SM_CXEDGE),
        crate::display::get_system_metrics(SM_CYEDGE),
    )
}

/// The parts of the combo box, in its client coordinates: the selection field, the button (empty
/// for CBS_SIMPLE), a CBS_SIMPLE combo box's list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Layout {
    field: Rect,
    button: Rect,
    list: Rect,
}

/// The combo box's parts for a client area `area` (see [`Layout`]).
fn layout_in(
    area: Rect,
    kind: Kind,
    field_height: i32,
    (cx, cy): (i32, i32),
    button: i32,
) -> Layout {
    match kind {
        Kind::Simple => Layout {
            field: Rect::new(cx, cy, area.right - cx, cy + field_height),
            button: Rect::default(),
            list: Rect::new(0, field_height + 2 * cy, area.right, area.bottom),
        },
        _ => {
            let button = Rect::new(
                (area.right - cx - button).max(cx),
                cy,
                area.right - cx,
                area.bottom - cy,
            );
            Layout {
                field: Rect::new(cx, cy, button.left, area.bottom - cy),
                button,
                list: Rect::default(),
            }
        }
    }
}

/// The combo box's parts as it is now.
fn layout(window: usize, s: &State) -> Layout {
    layout_in(
        client(window),
        s.kind(),
        s.field_height,
        edges(),
        crate::display::get_system_metrics(SM_CXVSCROLL),
    )
}

/// The height of a line of `font` (0: the System font), as the combo box's DC measures it.
fn font_height(window: usize, font: usize) -> i32 {
    let dc = crate::dc::get_dc(window);
    if dc == 0 {
        return 16;
    }
    let previous = (font != 0)
        .then(|| imports::select_object(dc, font))
        .flatten();
    let height = imports::text_metrics(dc).map_or(16, |metric| metric.height.max(1));
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
    crate::dc::release_dc(window, dc);
    height
}

/// The field's height for a font `height` high: the whole control's 13/8 of it, less the edges.
fn field_height_for(height: i32, edge: i32) -> i32 {
    (13 * height / 8 - 2 * edge).max(height)
}

/// The field's height: an owner-drawn combo box's from its parent's WM_MEASUREITEM for the item
/// -1, another's from its font.
fn measure_field(window: usize, s: &State) -> i32 {
    let height = font_height(window, s.font);
    if !s.owner_drawn() {
        return field_height_for(height, edges().1);
    }
    let mut item = MeasureItem {
        ctl_type: ODT_COMBOBOX,
        ctl_id: id_of(window, s),
        item_id: u32::MAX,
        item_width: client(window).right.max(0) as u32,
        item_height: height as u32,
        item_data: 0,
    };
    let parent = parent_of(window);
    if parent != 0 {
        let _ = message::send(
            parent,
            WM_MEASUREITEM,
            item.ctl_id,
            &mut item as *mut MeasureItem as usize as i32,
        );
    }
    (item.item_height as i32).max(1)
}

/// The children placed in the combo box (the edit in the field, a CBS_SIMPLE combo box's list
/// below it), and a CBS_DROPDOWN or CBS_DROPDOWNLIST combo box cut to its field's height, the
/// height it had kept as its dropped list's.
fn arrange(window: usize) {
    let Some(mut s) = load(window) else {
        return;
    };
    // Nothing to place before WM_CREATE made the children (a WM_SIZE may come first).
    if s.flags & SIZING != 0 || s.list == 0 {
        return;
    }
    if !s.simple() {
        if let Ok(info) = window::window_info(window) {
            let height = info.window.bottom - info.window.top;
            let wanted = s.field_height + 2 * edges().1;
            if height != wanted {
                // A height past the field's is the dropped list's new one.
                if height > wanted {
                    s.drop_height = height;
                }
                s.flags |= SIZING;
                store(window, &s);
                window::set_window_pos(
                    window,
                    0,
                    0,
                    0,
                    info.window.right - info.window.left,
                    wanted,
                    SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
                );
                set_flags(window, SIZING, false);
            }
        }
    }
    let Some(s) = load(window) else {
        return;
    };
    let parts = layout(window, &s);
    if s.edit != 0 {
        let edit = edit_rect(window, &s, parts.field);
        window::set_window_pos(
            s.edit,
            0,
            edit.left,
            edit.top,
            edit.width().max(0),
            edit.height().max(0),
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
    if s.simple() && s.list != 0 {
        let list = parts.list;
        window::set_window_pos(
            s.list,
            0,
            list.left,
            list.top,
            list.width().max(0),
            list.height().max(0),
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
}

/// Where the edit goes in the field: across it, as high as a line of the font (and a pixel's
/// margin above and below), in its middle.
fn edit_rect(window: usize, s: &State, field: Rect) -> Rect {
    let height = (font_height(window, s.font) + 2).min(field.height().max(0));
    let top = field.top + (field.height() - height).max(0) / 2;
    Rect::new(field.left, top, field.right, top + height)
}

/// CB_GETDROPPEDCONTROLRECT's rectangle, on the screen: the combo box's own, down to the dropped
/// list's height (a CBS_SIMPLE combo box's, its own), as wide as CB_SETDROPPEDWIDTH asks.
fn dropped_rect(window: usize, s: &State) -> Rect {
    let Ok(info) = window::window_info(window) else {
        return Rect::default();
    };
    let own = info.window;
    if s.simple() {
        return own;
    }
    let width = own.width().max(s.drop_width);
    let height = s.drop_height.max(own.height());
    Rect::new(own.left, own.top, own.left + width, own.top + height)
}

// --- Owner draw ----------------------------------------------------------------------------------

/// MEASUREITEMSTRUCT (winuser.h's), as WM_MEASUREITEM's lParam names it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct MeasureItem {
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
struct DrawItem {
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

/// The owner-draw message `message` (WM_MEASUREITEM, WM_DRAWITEM, WM_DELETEITEM, WM_COMPAREITEM)
/// the list sent the combo box, handed to its parent as the combo box's own: ODT_COMBOBOX, the
/// combo box's id and handle in place of the list's. Its parent's answer.
fn owner_draw_to_parent(window: usize, message: u32, lparam: i32) -> i32 {
    let Some(s) = load(window) else {
        return 0;
    };
    let parent = parent_of(window);
    if parent == 0 || lparam == 0 {
        return 0;
    }
    let id = id_of(window, &s);
    let at = lparam as u32 as usize;
    // The handle's place in each structure: DRAWITEMSTRUCT's hwndItem (20), DELETEITEMSTRUCT's
    // (12), COMPAREITEMSTRUCT's (8); MEASUREITEMSTRUCT has none.
    let handle_at = match message {
        WM_DRAWITEM => Some(20),
        WM_DELETEITEM => Some(12),
        WM_COMPAREITEM => Some(8),
        _ => None,
    };
    // SAFETY: the structure the list handed over: its first two DWORDs the control's type and id.
    let ctl_type = unsafe { In::new(at as *const u32) }.read();
    if ctl_type == ODT_LISTBOX {
        // SAFETY: as above, written in place for the parent.
        unsafe {
            Out::new(at as *mut u32).set(ODT_COMBOBOX);
            Out::new((at + 4) as *mut u32).set(id);
            if let Some(offset) = handle_at {
                Out::new((at + offset) as *mut u32).set(window as u32);
            }
        }
    }
    message::send(parent, message, id, lparam).unwrap_or(0)
}

// --- Notifications from the children
// ---------------------------------------------------------------

/// The selection changed (by the keys, the mouse or a click): CBN_SELCHANGE, then the edit's text
/// (or the field) brought up to date.
fn selection_changed(window: usize) {
    notify(window, CBN_SELCHANGE);
    update_text(window);
}

/// The edit's text set to the selection's (none: empty), its EN_ notifications the combo box's own,
/// its text selected while it has the focus; or a CBS_DROPDOWNLIST combo box's field redrawn. The
/// selection is the one told.
fn update_text(window: usize) {
    let Some(mut s) = load(window) else {
        return;
    };
    let index = selection(&s);
    s.notified = index;
    store(window, &s);
    if s.edit == 0 {
        invalidate(window);
        return;
    }
    if s.has_strings() {
        with_list_text(&s, index, |units| set_edit_text(window, s.edit, units));
    }
    if let Some(s) = load(window) {
        if s.focused() {
            send(s.edit, EM_SETSEL, 0, -1);
        }
    }
}

/// The list's caret (and, with `select`, its selection) moved to the first item the edit's text
/// begins, as Windows 2000's xxxCBUpdateListBoxWindow moves it after a change of the edit's text.
fn follow_edit(window: usize, select: bool) {
    let Some(s) = load(window) else {
        return;
    };
    if s.list == 0 || s.edit == 0 {
        return;
    }
    let found = with_edit_text(&s, |units| {
        if units.len() <= 1 {
            CB_ERR
        } else {
            send(s.list, LB_FINDSTRING, u32::MAX, units.as_ptr() as i32)
        }
    });
    send(
        s.list,
        LB_SETCURSEL,
        if select { found as u32 } else { u32::MAX },
        0,
    );
    if send(s.list, LB_GETCOUNT, 0, 0) > 0 {
        let at = found.max(0) as u32;
        send(s.list, LB_SETCARETINDEX, at, 0);
        send(s.list, LB_SETTOPINDEX, at, 0);
    }
}

/// A notification from the edit (`code`, WM_COMMAND's high word).
fn edit_command(window: usize, code: u32) {
    use crate::edit::{EN_CHANGE, EN_ERRSPACE, EN_KILLFOCUS, EN_SETFOCUS, EN_UPDATE};
    let Some(s) = load(window) else {
        return;
    };
    match code {
        EN_SETFOCUS => focus_gained(window),
        EN_KILLFOCUS => {
            // The focus going to the combo box itself comes straight back to the edit.
            let to = crate::focus::get_focus();
            if to != window && (to == 0 || to != s.list) {
                focus_lost(window);
            }
        }
        EN_UPDATE if s.flags & NO_EDIT_NOTIFY == 0 => notify(window, CBN_EDITUPDATE),
        EN_CHANGE if s.flags & NO_EDIT_NOTIFY == 0 => {
            notify(window, CBN_EDITCHANGE);
            let select = load(window).is_some_and(|s| s.dropped() || s.simple());
            follow_edit(window, select);
        }
        EN_ERRSPACE => notify(window, CBN_ERRSPACE),
        _ => {}
    }
}

/// A notification from the list (`code`, WM_COMMAND's high word).
fn list_command(window: usize, code: u32) {
    match code {
        LBN_SELCHANGE | LBN_SELCANCEL => {
            let Some(s) = load(window) else {
                return;
            };
            // A selection the keys change while the list is down keeps it down; one that changes
            // while it is up is the end of a selection.
            if s.flags & KEYBOARD == 0 {
                roll_up(window, code == LBN_SELCHANGE, false);
            }
            selection_changed(window);
        }
        LBN_DBLCLK => notify(window, CBN_DBLCLK),
        LBN_ERRSPACE => notify(window, CBN_ERRSPACE),
        _ => {}
    }
}

// --- The focus -----------------------------------------------------------------------------------

/// The focus come to the combo box (or its edit): CBN_SETFOCUS the first time, the edit's text
/// selected, the field redrawn.
fn focus_gained(window: usize) {
    let Some(mut s) = load(window) else {
        return;
    };
    if s.focused() {
        return;
    }
    s.flags |= FOCUSED;
    store(window, &s);
    if s.edit != 0 {
        send(s.edit, EM_SETSEL, 0, -1);
    }
    invalidate(window);
    notify(window, CBN_SETFOCUS);
}

/// The focus gone from the combo box (and its edit): the list rolled up (CBN_SELENDCANCEL, and
/// CBN_CLOSEUP when it was down), the edit's selection taken off, CBN_KILLFOCUS.
fn focus_lost(window: usize) {
    let Some(s) = load(window) else {
        return;
    };
    if !s.focused() {
        return;
    }
    roll_up(window, false, true);
    let Some(mut s) = load(window) else {
        return;
    };
    s.flags &= !FOCUSED;
    store(window, &s);
    if s.edit != 0 {
        send(s.edit, EM_SETSEL, 0, 0);
    }
    invalidate(window);
    notify(window, CBN_KILLFOCUS);
}

// --- Dropping down and rolling up ----------------------------------------------------------------

/// The list dropped down below the combo box (CBN_DROPDOWN first), on top of the other windows,
/// holding the mouse's capture; `by_press` when a press of the mouse dropped it (its release
/// outside the list keeps it down). A CBS_SIMPLE combo box's, or one already down, is left.
fn drop_down(window: usize, by_press: bool) {
    let Some(s) = load(window) else {
        return;
    };
    if s.simple() || s.dropped() || s.list == 0 {
        return;
    }
    notify(window, CBN_DROPDOWN);
    let Some(mut s) = load(window) else {
        return;
    };
    if s.dropped() || s.list == 0 {
        return;
    }
    if s.edit != 0 {
        follow_edit(window, true);
    }
    let index = selection(&s);
    let rect = list_rect(window, &s);
    s.flags |= DROPPED;
    if by_press {
        s.flags |= PRESSED | TRACKING;
    }
    s.flags &= !(KEYBOARD | LIST_PRESS);
    s.notified = index;
    store(window, &s);
    // Placed while hidden, its first item shown the selection, then shown.
    window::set_window_pos(
        s.list,
        HWND_TOPMOST,
        rect.left,
        rect.top,
        rect.width(),
        rect.height(),
        SWP_NOACTIVATE,
    );
    if index >= 0 {
        send(s.list, LB_SETTOPINDEX, index as u32, 0);
    }
    window::set_window_pos(
        s.list,
        HWND_TOPMOST,
        0,
        0,
        0,
        0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
    );
    crate::mouse::set_capture(s.list);
    invalidate(window);
}

/// Where the list drops: below the combo box (above it when it would leave the screen), as wide as
/// the combo box (or CB_SETDROPPEDWIDTH's width), down to the dropped rectangle's height, cut to
/// its items when they are fewer.
fn list_rect(window: usize, s: &State) -> Rect {
    let dropped = dropped_rect(window, s);
    let own = window::window_info(window).map_or(dropped, |info| info.window);
    let mut height = (dropped.bottom - own.bottom).max(0);
    let count = send(s.list, LB_GETCOUNT, 0, 0).max(0);
    let border = 2 * crate::display::get_system_metrics(rtl::display::SM_CXBORDER).max(1);
    let item = send(s.list, LB_GETITEMHEIGHT, 0, 0).max(1);
    let items = if s.style & CBS_OWNERDRAWVARIABLE != 0 {
        (0..count)
            .map(|index| send(s.list, LB_GETITEMHEIGHT, index as u32, 0).max(1))
            .sum()
    } else {
        count * item
    };
    let fewest = item + border;
    if count > 0 && items + border < height {
        height = items + border;
    }
    let height = height.max(fewest);
    let screen = crate::display::get_system_metrics(rtl::display::SM_CYSCREEN);
    let top = if own.bottom + height > screen && own.top - height >= 0 {
        own.top - height
    } else {
        own.bottom
    };
    Rect::new(dropped.left, top, dropped.right, top + height)
}

/// The list rolled up: CBN_SELENDOK (`ok`) or CBN_SELENDCANCEL, sent whether or not it was down
/// (a CBS_SIMPLE combo box sends neither); a list that was down hidden, its capture let go,
/// CBN_CLOSEUP. A cancel puts back the selection the mouse moved; with `commit`, an end that keeps
/// a selection the mouse moved is CBN_SELCHANGE after CBN_CLOSEUP.
fn roll_up(window: usize, ok: bool, commit: bool) {
    let Some(s) = load(window) else {
        return;
    };
    if s.simple() {
        return;
    }
    let was_dropped = s.dropped();
    if was_dropped && !ok && selection(&s) != s.notified {
        send(
            s.list,
            LB_SETCURSEL,
            if s.notified < 0 {
                u32::MAX
            } else {
                s.notified as u32
            },
            0,
        );
    }
    notify(window, if ok { CBN_SELENDOK } else { CBN_SELENDCANCEL });
    let Some(mut s) = load(window) else {
        return;
    };
    if s.dropped() {
        s.flags &= !(DROPPED | PRESSED | TRACKING | KEYBOARD | LIST_PRESS);
        store(window, &s);
        if crate::mouse::get_capture() == s.list {
            crate::mouse::release_capture();
        }
        window::set_window_pos(
            s.list,
            0,
            0,
            0,
            0,
            0,
            SWP_HIDEWINDOW | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
        );
        invalidate(window);
        notify(window, CBN_CLOSEUP);
    }
    if commit && was_dropped && ok {
        if let Some(s) = load(window) {
            if selection(&s) != s.notified {
                selection_changed(window);
            }
        }
    }
}

/// F4 or Alt+Up or Alt+Down: the list rolled up (keeping the selection) when it is down, dropped
/// down otherwise.
fn toggle(window: usize) {
    let Some(s) = load(window) else {
        return;
    };
    if s.simple() {
        return;
    }
    if s.dropped() {
        roll_up(window, true, true);
    } else {
        drop_down(window, false);
    }
}

// --- The keys and the mouse ----------------------------------------------------------------------

/// Whether `vk` steps the list (Home and End too in a combo box without an edit, whose field takes
/// no text).
fn steps_list(vk: u32, has_edit: bool) -> bool {
    matches!(vk, VK_UP | VK_DOWN | VK_PRIOR | VK_NEXT)
        || (!has_edit && matches!(vk, VK_HOME | VK_END))
}

/// The key `vk` sent to the list, marked as the keys' while it is down: the list's answer.
fn key_to_list(window: usize, message: u32, vk: u32, lparam: i32, ansi: bool) -> i32 {
    let Some(s) = load(window) else {
        return 0;
    };
    let dropped = s.dropped();
    if dropped {
        set_flags(window, KEYBOARD, true);
    }
    let answer = message::send_as(s.list, message, vk, lparam, ansi).unwrap_or(0);
    if dropped {
        set_flags(window, KEYBOARD, false);
    }
    answer
}

/// A key the combo box takes itself (F4, the arrows and the page keys, Enter and Esc while the list
/// is down): its answer; none for a key that goes on to the edit or the list.
fn combo_key(window: usize, vk: u32, lparam: i32, ansi: bool) -> Option<i32> {
    let s = load(window)?;
    let has_edit = s.edit != 0;
    let edit_answer = |answer: i32| if has_edit { 1 } else { answer };
    match vk {
        VK_F4 if !s.simple() => {
            if s.flags & EXTENDED_UI == 0 {
                toggle(window);
            }
            Some(0)
        }
        VK_RETURN | VK_ESCAPE if s.dropped() => {
            roll_up(window, vk == VK_RETURN, true);
            Some(1)
        }
        VK_DOWN if !s.simple() && !s.dropped() && s.flags & EXTENDED_UI != 0 => {
            drop_down(window, false);
            Some(edit_answer(0))
        }
        _ if steps_list(vk, has_edit) => {
            let answer = key_to_list(window, WM_KEYDOWN, vk, lparam, ansi);
            Some(edit_answer(answer))
        }
        _ => None,
    }
}

/// WM_KEYDOWN: the combo box's keys ([`combo_key`]), the others to the edit or the list.
fn key_down(window: usize, vk: u32, lparam: i32, ansi: bool) -> i32 {
    if let Some(answer) = combo_key(window, vk, lparam, ansi) {
        return answer;
    }
    let Some(s) = load(window) else {
        return 0;
    };
    if s.edit != 0 {
        message::send_as(s.edit, WM_KEYDOWN, vk, lparam, ansi).unwrap_or(0)
    } else {
        key_to_list(window, WM_KEYDOWN, vk, lparam, ansi)
    }
}

/// WM_SYSKEYDOWN: Alt+Up and Alt+Down drop the list down or roll it up; whether it was one.
fn sys_key_down(window: usize, vk: u32) -> bool {
    if !matches!(vk, VK_UP | VK_DOWN) || load(window).is_none_or(|s| s.simple()) {
        return false;
    }
    toggle(window);
    true
}

/// The combo box of `edit` when it is one's edit (ES_COMBOBOX, its parent's edit).
fn combo_of_edit(edit: usize) -> Option<usize> {
    if window::style_of(edit).unwrap_or(0) & ES_COMBOBOX == 0 {
        return None;
    }
    let combo = parent_of(edit);
    load(combo).filter(|s| s.edit == edit).map(|_| combo)
}

/// The edit's WM_KEYDOWN of `vk`, when it is a combo box's: the combo box's own keys handled there
/// (its answer); none for a key the edit takes.
pub fn edit_key(edit: usize, vk: u32, lparam: i32) -> Option<i32> {
    let combo = combo_of_edit(edit)?;
    combo_key(combo, vk, lparam, false)
}

/// The edit's WM_SYSKEYDOWN of `vk`, when it is a combo box's: whether the combo box took it.
pub fn edit_sys_key(edit: usize, vk: u32) -> bool {
    combo_of_edit(edit).is_some_and(|combo| sys_key_down(combo, vk))
}

/// What a combo box's edit adds to its WM_GETDLGCODE: DLGC_WANTMESSAGE while the list is down
/// (its Enter and Esc are the combo box's, not the dialog's).
pub fn edit_dialog_code(edit: usize) -> u32 {
    match combo_of_edit(edit).and_then(load) {
        Some(s) if s.dropped() => DLGC_WANTMESSAGE,
        _ => 0,
    }
}

/// A press (or a double click's) on the combo box at the client point (`x`, `y`): the focus taken;
/// a press on a CBS_DROPDOWN combo box's button, or anywhere on a CBS_DROPDOWNLIST one, drops the
/// list down (rolls it up when it is down).
fn press(window: usize, x: i32, y: i32) {
    let Some(s) = load(window) else {
        return;
    };
    let focus = crate::focus::get_focus();
    if focus != window && (s.edit == 0 || focus != s.edit) {
        crate::focus::set_focus(window);
    }
    let Some(s) = load(window) else {
        return;
    };
    if s.simple() {
        return;
    }
    let hot = s.kind() == Kind::DropDownList || layout(window, &s).button.contains(x, y);
    if !hot {
        return;
    }
    if s.dropped() {
        roll_up(window, true, true);
    } else {
        drop_down(window, true);
    }
}

/// The list's item under its client point (`x`, `y`); none outside its items.
fn item_under(list: usize, x: i32, y: i32) -> Option<u32> {
    let point = (x as u16 as u32 | (y as u16 as u32) << 16) as i32;
    let answer = send(list, LB_ITEMFROMPOINT, 0, point) as u32;
    (answer >> 16 == 0 && send(list, LB_GETCOUNT, 0, 0) > 0).then_some(answer & 0xFFFF)
}

/// The list's selection moved to the item under (`x`, `y`) without a notification: whether it
/// changed.
fn select_under(list: usize, x: i32, y: i32) -> bool {
    let Some(index) = item_under(list, x, y) else {
        return false;
    };
    if send(list, LB_GETCURSEL, 0, 0) == index as i32 {
        return false;
    }
    send(list, LB_SETCURSEL, index, 0);
    true
}

/// The mouse's message `message` to a combo box's list (`list`, of the combo box `window`, `s` its
/// state): its answer; none for a message the list box takes as its own.
fn list_mouse(window: usize, list: usize, message: u32, wparam: u32, lparam: i32) -> Option<i32> {
    let s = load(window)?;
    let (x, y) = (lparam as i16 as i32, (lparam >> 16) as i16 as i32);
    let area = window::client_rect(list).unwrap_or_default();
    let inside = area.contains(x, y);
    if s.simple() {
        return Some(simple_list_mouse(window, list, message, x, y, inside));
    }
    match message {
        WM_MOUSEACTIVATE => Some(MA_NOACTIVATE as i32),
        _ if !s.dropped() => None,
        WM_MOUSEMOVE => {
            if inside {
                select_under(list, x, y);
            }
            Some(0)
        }
        WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => {
            if inside {
                set_flags(window, LIST_PRESS, true);
                select_under(list, x, y);
                return Some(0);
            }
            if on_list_frame(list, x, y) {
                unserved(
                    message,
                    "a press on the dropped list's scroll bar is not yet served: it is ignored",
                    (list, message, wparam, lparam),
                );
                return Some(0);
            }
            // A press outside the list rolls it up; one on the combo box's button or field is
            // taken by that (it does not drop the list again).
            roll_up(window, false, true);
            Some(0)
        }
        WM_LBUTTONUP => {
            set_flags(window, TRACKING | PRESSED | LIST_PRESS, false);
            if s.flags & PRESSED != 0 {
                invalidate(window);
            }
            if inside {
                select_under(list, x, y);
                roll_up(window, true, true);
            }
            Some(0)
        }
        WM_CAPTURECHANGED => {
            if lparam as u32 as usize != list {
                roll_up(window, false, true);
            }
            Some(0)
        }
        _ => None,
    }
}

/// Whether the list's client point (`x`, `y`) is on its frame (its border, its scroll bar): inside
/// its window, outside its client area.
fn on_list_frame(list: usize, x: i32, y: i32) -> bool {
    let Ok(info) = window::window_info(list) else {
        return false;
    };
    let (sx, sy) = (x + info.client.left, y + info.client.top);
    info.window.contains(sx, sy) && !info.client.contains(sx, sy)
}

/// A CBS_SIMPLE combo box's list's mouse message: a press takes the item under it as the selection
/// (CBN_SELCHANGE; a double click's CBN_DBLCLK too) and the capture, the focus going to the combo
/// box; a move while it is held follows; the release lets the capture go.
fn simple_list_mouse(
    window: usize,
    list: usize,
    message: u32,
    x: i32,
    y: i32,
    inside: bool,
) -> i32 {
    match message {
        WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => {
            crate::focus::set_focus(window);
            set_flags(window, LIST_PRESS, true);
            crate::mouse::set_capture(list);
            if inside && select_under(list, x, y) {
                selection_changed(window);
            }
            if message == WM_LBUTTONDBLCLK {
                notify(window, CBN_DBLCLK);
            }
            0
        }
        WM_MOUSEMOVE => {
            if load(window).is_some_and(|s| s.flags & LIST_PRESS != 0)
                && inside
                && select_under(list, x, y)
            {
                selection_changed(window);
            }
            0
        }
        WM_LBUTTONUP => {
            if load(window).is_some_and(|s| s.flags & LIST_PRESS != 0) {
                set_flags(window, LIST_PRESS, false);
                crate::mouse::release_capture();
            }
            0
        }
        WM_CAPTURECHANGED => {
            set_flags(window, LIST_PRESS, false);
            0
        }
        WM_MOUSEACTIVATE => MA_NOACTIVATE as i32,
        _ => listbox::list_box_procedure(list, message, 0, 0, false),
    }
}

// --- The drawing ---------------------------------------------------------------------------------

/// The whole combo box to be repainted.
fn invalidate(window: usize) {
    if load(window).is_some_and(|s| s.flags & NO_REDRAW == 0) {
        let _ = imports::invalidate_rect(window, 0, true);
    }
}

/// WM_PAINT: the sunken edge, the button, a CBS_DROPDOWNLIST combo box's field.
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
    let area = client(window);
    let parts = layout(window, &s);
    let disabled = window::style_of(window).unwrap_or(0) & WS_DISABLED != 0;
    let (_, cy) = edges();
    let framed = if s.simple() {
        Rect::new(0, 0, area.right, parts.field.bottom + cy)
    } else {
        area
    };
    crate::draw::draw_edge_in(dc, framed, crate::draw::EDGE_SUNKEN, crate::draw::BF_RECT);
    if !s.simple() {
        // The column between the field and the button, in the field's color.
        let gap = Rect::new(parts.field.right, cy, parts.button.left, area.bottom - cy);
        if !gap.is_empty() {
            crate::draw::fill(dc, gap, COLOR_WINDOW as usize + 1);
        }
        crate::scrollbar::draw_combo_button(dc, parts.button, s.flags & PRESSED != 0, disabled);
    }
    if s.edit == 0 {
        draw_field(window, &s, dc, parts.field, disabled);
    } else {
        // The field above and below the edit, in the edit's background.
        let edit = edit_rect(window, &s, parts.field);
        let brush = field_brush(window, dc, disabled);
        for strip in [
            Rect::new(
                parts.field.left,
                parts.field.top,
                parts.field.right,
                edit.top,
            ),
            Rect::new(
                parts.field.left,
                edit.bottom,
                parts.field.right,
                parts.field.bottom,
            ),
        ] {
            if !strip.is_empty() {
                crate::draw::fill(dc, strip, brush);
            }
        }
    }
}

/// The field's brush: the one the parent's WM_CTLCOLOREDIT answers (WM_CTLCOLORSTATIC when the
/// combo box is disabled), the default procedure's for none; the DC's colors set by it.
fn field_brush(window: usize, dc: usize, disabled: bool) -> usize {
    let parent = parent_of(window);
    let color_message = if disabled {
        WM_CTLCOLORSTATIC
    } else {
        WM_CTLCOLOREDIT
    };
    let brush = if parent != 0 {
        message::send(parent, color_message, dc as u32, window as i32).unwrap_or(0) as usize
    } else {
        0
    };
    if brush != 0 {
        return brush;
    }
    message::default_procedure(window, color_message, dc as u32, window as i32, false) as usize
}

/// A CBS_DROPDOWNLIST combo box's field drawn into `dc` at `field`: see the module notes.
fn draw_field(window: usize, s: &State, dc: usize, field: Rect, disabled: bool) {
    let parent = parent_of(window);
    let previous = (s.font != 0)
        .then(|| imports::select_object(dc, s.font))
        .flatten();
    let brush = field_brush(window, dc, disabled);
    let index = selection(s);
    let lit = s.focused() && !s.dropped();
    if s.owner_drawn() {
        crate::draw::fill(dc, field, brush);
        let mut state = ODS_COMBOBOXEDIT;
        if lit {
            state |= ODS_SELECTED | ODS_FOCUS;
        }
        if disabled {
            state |= ODS_DISABLED;
        }
        let data = if index >= 0 {
            send(s.list, LB_GETITEMDATA, index as u32, 0) as u32
        } else {
            0
        };
        let mut drawn = DrawItem {
            ctl_type: ODT_COMBOBOX,
            ctl_id: id_of(window, s),
            item_id: index as u32,
            item_action: ODA_DRAWENTIRE,
            item_state: state,
            hwnd_item: window as u32,
            hdc: dc as u32,
            rc_item: field.inflate(-1, -1),
            item_data: data,
        };
        if parent != 0 {
            let _ = message::send(
                parent,
                WM_DRAWITEM,
                drawn.ctl_id,
                &mut drawn as *mut DrawItem as usize as i32,
            );
        }
    } else {
        crate::draw::fill(dc, field, brush);
        let inner = field.inflate(-1, -1);
        let text_color = imports::text_color(dc);
        if lit {
            crate::draw::fill(dc, inner, COLOR_HIGHLIGHT as usize + 1);
            imports::set_text_color(
                dc,
                crate::display::get_sys_color(COLOR_HIGHLIGHTTEXT as i32),
            );
        }
        if disabled {
            imports::set_text_color(dc, crate::display::get_sys_color(COLOR_GRAYTEXT as i32));
        }
        imports::set_bk_mode(dc, TRANSPARENT);
        let line = imports::text_metrics(dc).map_or(16, |metric| metric.height);
        let top = inner.top + (inner.height() - line).max(0) / 2;
        with_list_text(s, index, |units| {
            let text = &units[..units.len() - 1];
            if !text.is_empty() {
                imports::ext_text_out(dc, inner.left + 1, top, ETO_CLIPPED, Some(&inner), text);
            }
        });
        imports::set_text_color(dc, text_color);
        if lit {
            crate::draw::focus_rect_in(dc, inner);
        }
    }
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
}

// --- Creation, size and font ---------------------------------------------------------------------

/// WM_NCCREATE: the combo box's state made, CBS_HASSTRINGS added to one not owner-drawn, its own
/// scroll bars and border taken off (they are its list's); false when there was no room for it.
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
    let mut style = data.style;
    if style & (CBS_OWNERDRAWFIXED | CBS_OWNERDRAWVARIABLE) == 0 {
        style |= CBS_HASSTRINGS;
    }
    let s = State {
        style,
        id: data.id,
        notified: CB_ERR,
        // The list's styles the combo box carries for it.
        reserved: data.style & (WS_VSCROLL | WS_HSCROLL | WS_BORDER),
        ..State::default()
    };
    store(window, &s);
    let own = style & !(WS_VSCROLL | WS_HSCROLL | WS_BORDER);
    if own != data.style {
        let _ = imports::set_window_long(window, GWL_STYLE, own, false);
        if data.style & (WS_VSCROLL | WS_HSCROLL | WS_BORDER) != 0 {
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
    }
    true
}

/// The list's style for a combo box of style `style` (`carried` the combo box's own WS_VSCROLL,
/// WS_HSCROLL and WS_BORDER).
fn list_style(style: u32, carried: u32) -> u32 {
    let mut list = WS_CHILD | LBS_COMBOBOX | LBS_NOTIFY | (carried & (WS_VSCROLL | WS_HSCROLL));
    list |= style & (CBS_OWNERDRAWFIXED | CBS_OWNERDRAWVARIABLE);
    if style & CBS_SORT != 0 {
        list |= LBS_SORT;
    }
    if style & CBS_HASSTRINGS != 0 {
        list |= LBS_HASSTRINGS;
    }
    if style & CBS_NOINTEGRALHEIGHT != 0 {
        list |= LBS_NOINTEGRALHEIGHT;
    }
    if style & CBS_DISABLENOSCROLL != 0 {
        list |= LBS_DISABLENOSCROLL;
    }
    if kind_of(style) == Kind::Simple {
        list |= WS_VISIBLE;
    } else {
        list |= WS_BORDER;
    }
    list
}

/// The edit's style for a combo box of style `style`.
fn edit_style(style: u32) -> u32 {
    let mut edit = WS_CHILD | WS_VISIBLE | ES_COMBOBOX;
    if style & CBS_AUTOHSCROLL != 0 {
        edit |= ES_AUTOHSCROLL;
    }
    if style & CBS_OEMCONVERT != 0 {
        edit |= ES_OEMCONVERT;
    }
    if style & CBS_UPPERCASE != 0 {
        edit |= ES_UPPERCASE;
    }
    if style & CBS_LOWERCASE != 0 {
        edit |= ES_LOWERCASE;
    }
    edit
}

/// WM_CREATE: the field's height measured, the list made (a CBS_SIMPLE combo box's child, another's
/// hidden child of the desktop), then the edit (none for CBS_DROPDOWNLIST) with the window's text,
/// the combo box cut to its field and its children placed; -1 when a child cannot be made.
fn created(window: usize, lparam: i32) -> i32 {
    let Some(mut s) = load(window) else {
        return -1;
    };
    let Ok(data) = window::window_data(window) else {
        return -1;
    };
    let (height, name) = if lparam != 0 {
        // SAFETY: WM_CREATE's lParam as the window manager hands it over (or translated for a
        // narrow procedure): a CREATESTRUCT.
        let create = unsafe { In::new(lparam as u32 as usize as *const CreateStructW) }.read();
        (create.cy, create.name as usize)
    } else {
        (0, 0)
    };
    s.drop_height = height.max(0);
    s.field_height = measure_field(window, &s);
    store(window, &s);
    let simple = s.simple();
    let area = client(window);
    let parts = layout_in(
        area,
        s.kind(),
        s.field_height,
        edges(),
        crate::display::get_system_metrics(SM_CXVSCROLL),
    );
    let (list_parent, list_place) = if simple {
        (window, parts.list)
    } else {
        (
            window::get_desktop_window(),
            Rect::new(0, 0, area.right.max(1), 1),
        )
    };
    let list = window::create(&imports::Creation {
        ex_style: if simple {
            WS_EX_CLIENTEDGE
        } else {
            WS_EX_TOOLWINDOW
        },
        class: LIST_CLASS.as_ptr() as usize,
        name: 0,
        style: list_style(s.style, s.reserved),
        x: list_place.left,
        y: list_place.top,
        cx: list_place.width().max(0),
        cy: list_place.height().max(0),
        parent: list_parent,
        menu: LIST_ID as usize,
        instance: data.instance as usize,
        param: window,
        version: window::EXPECTED_VERSION,
    });
    if list == 0 {
        return -1;
    }
    if let Some(mut s) = load(window) {
        s.list = list;
        store(window, &s);
    }
    if s.kind() != Kind::DropDownList {
        let field = parts.field;
        let edit = window::create(&imports::Creation {
            ex_style: 0,
            class: EDIT_CLASS.as_ptr() as usize,
            name: if name >> 16 != 0 { name } else { 0 },
            style: edit_style(s.style),
            x: field.left,
            y: field.top,
            cx: field.width().max(0),
            cy: field.height().max(0),
            parent: window,
            menu: EDIT_ID as usize,
            instance: data.instance as usize,
            param: 0,
            version: window::EXPECTED_VERSION,
        });
        if edit == 0 {
            return -1;
        }
        if let Some(mut s) = load(window) {
            s.edit = edit;
            store(window, &s);
        }
    }
    arrange(window);
    0
}

/// WM_SETFONT: the font kept and handed to the edit and the list, the field measured anew (not an
/// owner-drawn one's), the combo box cut to it.
fn set_font(window: usize, font: usize, redraw: bool) {
    let Some(mut s) = load(window) else {
        return;
    };
    s.font = font;
    store(window, &s);
    if s.edit != 0 {
        send(s.edit, WM_SETFONT, font as u32, 0);
    }
    if s.list != 0 {
        send(s.list, WM_SETFONT, font as u32, 0);
    }
    let Some(mut s) = load(window) else {
        return;
    };
    if !s.owner_drawn() {
        s.field_height = measure_field(window, &s);
        store(window, &s);
    }
    arrange(window);
    if redraw {
        invalidate(window);
    }
}

/// WM_NCDESTROY: the list destroyed (a CBS_SIMPLE combo box's is gone with it already), the state
/// freed, its record dropped first.
fn destroy(window: usize) {
    let Some(s) = load(window) else {
        return;
    };
    if s.list != 0 && window::is_window_alive(s.list) {
        if crate::mouse::get_capture() == s.list {
            set_flags(window, DROPPED, false);
            crate::mouse::release_capture();
        }
        let _ = imports::destroy_window(s.list);
    }
    if let Some(block) = kept::forget(window) {
        imports::local_free(block);
    }
}

// --- The procedure -------------------------------------------------------------------------------

/// The combo box's WM_GETTEXT for a combo box without an edit: the selection's text into the buffer
/// of `max` units (bytes for `ansi`), cut to leave room for the terminator: the units copied.
fn get_text(s: &State, max: u32, buffer: i32, ansi: bool) -> i32 {
    if max == 0 || buffer == 0 {
        return 0;
    }
    let index = selection(s);
    with_list_text(s, index, |units| {
        let text = &units[..units.len() - 1];
        if ansi {
            // SAFETY: WM_GETTEXT's lParam as its sender hands it over: a buffer of wParam bytes.
            let mut out = unsafe { OutBuf::new(buffer as u32 as usize as *mut u8, max as usize) };
            procedure::put_narrow(&mut out, text) as i32
        } else {
            // SAFETY: as above, of wParam units.
            let mut out = unsafe { OutBuf::new(buffer as u32 as usize as *mut u16, max as usize) };
            let length = text.len().min(max as usize - 1);
            out.put(&text[..length]);
            out.set(length, 0);
            length as i32
        }
    })
}

/// The combo box's WM_GETTEXTLENGTH for a combo box without an edit: the selection's text's length
/// (in bytes for `ansi`).
fn get_text_length(s: &State, ansi: bool) -> i32 {
    let index = selection(s);
    with_list_text(s, index, |units| {
        let text = &units[..units.len() - 1];
        if ansi {
            procedure::narrow_length(text) as i32
        } else {
            text.len() as i32
        }
    })
}

/// The CB_ messages that go to the list as their LB_ twins: the twin.
fn list_twin(message: u32) -> Option<u32> {
    Some(match message {
        CB_ADDSTRING => LB_ADDSTRING,
        CB_INSERTSTRING => LB_INSERTSTRING,
        CB_DELETESTRING => LB_DELETESTRING,
        CB_GETCOUNT => LB_GETCOUNT,
        CB_GETCURSEL => LB_GETCURSEL,
        CB_GETLBTEXT => LB_GETTEXT,
        CB_GETLBTEXTLEN => LB_GETTEXTLEN,
        CB_FINDSTRING => LB_FINDSTRING,
        CB_FINDSTRINGEXACT => LB_FINDSTRINGEXACT,
        CB_GETITEMDATA => LB_GETITEMDATA,
        CB_SETITEMDATA => LB_SETITEMDATA,
        CB_DIR => LB_DIR,
        CB_SETLOCALE => LB_SETLOCALE,
        CB_GETLOCALE => LB_GETLOCALE,
        CB_GETTOPINDEX => LB_GETTOPINDEX,
        CB_SETTOPINDEX => LB_SETTOPINDEX,
        CB_GETHORIZONTALEXTENT => LB_GETHORIZONTALEXTENT,
        CB_SETHORIZONTALEXTENT => LB_SETHORIZONTALEXTENT,
        CB_INITSTORAGE => LB_INITSTORAGE,
        _ => return None,
    })
}

/// The combo box messages (CB_*): see the module notes.
fn combo_message(
    window: usize,
    s: State,
    message: u32,
    wparam: u32,
    lparam: i32,
    ansi: bool,
) -> i32 {
    let to_list = |message: u32, wparam: u32, lparam: i32| {
        message::send_as(s.list, message, wparam, lparam, ansi).unwrap_or(CB_ERR)
    };
    let no_edit = || {
        imports::set_last_error(ERROR_INVALID_COMBOBOX_MESSAGE);
        CB_ERR
    };
    match message {
        CB_SETCURSEL => {
            let answer = to_list(LB_SETCURSEL, wparam, 0);
            if answer >= 0 {
                to_list(LB_SETTOPINDEX, wparam, 0);
            }
            update_text(window);
            answer
        }
        CB_SELECTSTRING => {
            let answer = to_list(LB_SELECTSTRING, wparam, lparam);
            update_text(window);
            answer
        }
        CB_DELETESTRING => {
            let answer = to_list(LB_DELETESTRING, wparam, lparam);
            if s.edit == 0 {
                invalidate(window);
            }
            answer
        }
        CB_RESETCONTENT => {
            to_list(LB_RESETCONTENT, 0, 0);
            if s.edit != 0 && s.has_strings() {
                set_edit_text(window, s.edit, &[0]);
            }
            if let Some(mut s) = load(window) {
                s.notified = CB_ERR;
                store(window, &s);
            }
            invalidate(window);
            1
        }
        CB_SHOWDROPDOWN => {
            if !s.simple() {
                if wparam != 0 {
                    drop_down(window, false);
                } else if s.dropped() {
                    roll_up(window, false, true);
                }
            }
            1
        }
        CB_GETDROPPEDSTATE => (s.simple() || s.dropped()) as i32,
        CB_GETDROPPEDCONTROLRECT => {
            if lparam != 0 {
                // SAFETY: CB_GETDROPPEDCONTROLRECT's lParam as its sender hands it over: a RECT.
                unsafe { Out::new(lparam as u32 as usize as *mut Rect) }
                    .set(dropped_rect(window, &s));
            }
            1
        }
        CB_GETDROPPEDWIDTH => dropped_rect(window, &s).width(),
        CB_SETDROPPEDWIDTH => {
            let mut s = s;
            s.drop_width = wparam as i32;
            store(window, &s);
            dropped_rect(window, &s).width()
        }
        CB_SETITEMHEIGHT => {
            let height = lparam as u32 & 0xFFFF;
            if wparam == u32::MAX {
                if height == 0 || height > MOST_HEIGHT {
                    imports::set_last_error(ERROR_INVALID_PARAMETER);
                    return CB_ERR;
                }
                let mut s = s;
                s.field_height = height as i32;
                store(window, &s);
                arrange(window);
                invalidate(window);
                CB_OKAY
            } else {
                to_list(LB_SETITEMHEIGHT, wparam, lparam)
            }
        }
        CB_GETITEMHEIGHT => {
            if wparam == u32::MAX {
                s.field_height
            } else {
                to_list(LB_GETITEMHEIGHT, wparam, 0)
            }
        }
        CB_SETEXTENDEDUI => {
            set_flags(window, EXTENDED_UI, wparam != 0);
            CB_OKAY
        }
        CB_GETEXTENDEDUI => (s.flags & EXTENDED_UI != 0) as i32,
        CB_GETEDITSEL => {
            if s.edit == 0 {
                return no_edit();
            }
            send(s.edit, EM_GETSEL, wparam, lparam)
        }
        CB_SETEDITSEL => {
            if s.edit == 0 {
                return no_edit();
            }
            let start = i32::from(lparam as u16 as i16);
            let end = i32::from((lparam >> 16) as u16 as i16);
            send(s.edit, EM_SETSEL, start as u32, end);
            1
        }
        CB_LIMITTEXT => {
            if s.edit == 0 {
                return no_edit();
            }
            send(s.edit, EM_LIMITTEXT, wparam, 0);
            1
        }
        _ => match list_twin(message) {
            Some(twin) => {
                let answer = to_list(twin, wparam, lparam);
                if s.edit == 0 && matches!(twin, LB_ADDSTRING | LB_INSERTSTRING | LB_DIR) {
                    invalidate(window);
                }
                answer
            }
            None => {
                unserved(
                    message,
                    "a combo box message not yet served answers CB_ERR",
                    (window, message, wparam, lparam),
                );
                CB_ERR
            }
        },
    }
}

/// The combo box's procedure, for a message of the narrow (`ansi`) or wide form.
fn combo_box(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
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
        CB_FIRST..=CB_LAST => combo_message(window, s, message, wparam, lparam, ansi),
        WM_CREATE => created(window, lparam),
        WM_DESTROY => {
            if s.dropped() {
                set_flags(window, DROPPED, false);
                if crate::mouse::get_capture() == s.list {
                    crate::mouse::release_capture();
                }
            }
            0
        }
        WM_GETDLGCODE => {
            let mut code = DLGC_WANTARROWS | DLGC_WANTCHARS;
            if s.dropped() && lparam != 0 {
                // SAFETY: WM_GETDLGCODE's lParam as the dialog manager hands it over: a MSG.
                let msg = unsafe { In::new(lparam as u32 as usize as *const Msg) }.read();
                if msg.message == WM_KEYDOWN && matches!(msg.wparam, VK_RETURN | VK_ESCAPE) {
                    code |= DLGC_WANTMESSAGE;
                }
            }
            code as i32
        }
        WM_SETTEXT => {
            if s.edit == 0 {
                imports::set_last_error(ERROR_INVALID_COMBOBOX_MESSAGE);
                return CB_ERR;
            }
            let before = s.flags & NO_EDIT_NOTIFY;
            set_flags(window, NO_EDIT_NOTIFY, true);
            let answer = message::send_as(s.edit, WM_SETTEXT, wparam, lparam, ansi).unwrap_or(0);
            set_flags(window, NO_EDIT_NOTIFY, before != 0);
            answer
        }
        WM_GETTEXT => {
            if s.edit != 0 {
                message::send_as(s.edit, WM_GETTEXT, wparam, lparam, ansi).unwrap_or(0)
            } else {
                get_text(&s, wparam, lparam, ansi)
            }
        }
        WM_GETTEXTLENGTH => {
            if s.edit != 0 {
                message::send_as(s.edit, WM_GETTEXTLENGTH, wparam, lparam, ansi).unwrap_or(0)
            } else {
                get_text_length(&s, ansi)
            }
        }
        WM_CUT | WM_COPY | WM_PASTE | WM_CLEAR | WM_UNDO => {
            if s.edit != 0 {
                message::send_as(s.edit, message, wparam, lparam, ansi).unwrap_or(0)
            } else {
                0
            }
        }
        WM_SETFONT => {
            set_font(window, wparam as usize, lparam != 0);
            0
        }
        WM_GETFONT => s.font as i32,
        WM_SETREDRAW => {
            set_flags(window, NO_REDRAW, wparam == 0);
            if s.list != 0 {
                send(s.list, WM_SETREDRAW, wparam, 0);
            }
            if wparam != 0 {
                invalidate(window);
            }
            0
        }
        WM_SIZE => {
            arrange(window);
            invalidate(window);
            0
        }
        WM_ENABLE => {
            for child in [s.edit, s.list] {
                if child != 0 {
                    crate::focus::enable_window(child, wparam);
                }
            }
            invalidate(window);
            0
        }
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            paint(window);
            0
        }
        WM_SETFOCUS => {
            if s.edit != 0 {
                crate::focus::set_focus(s.edit);
            } else {
                focus_gained(window);
            }
            0
        }
        WM_KILLFOCUS => {
            // A combo box with an edit loses the focus with its edit (EN_KILLFOCUS); the focus
            // going to its own children stays its.
            let to = wparam as usize;
            if s.edit == 0 && to != s.list {
                focus_lost(window);
            }
            0
        }
        WM_KEYDOWN => key_down(window, wparam, lparam, ansi),
        WM_SYSKEYDOWN => {
            if sys_key_down(window, wparam) {
                0
            } else {
                message::default_procedure(window, message, wparam, lparam, ansi)
            }
        }
        WM_CHAR => {
            if s.edit != 0 {
                message::send_as(s.edit, WM_CHAR, wparam, lparam, ansi).unwrap_or(0)
            } else {
                key_to_list(window, WM_CHAR, wparam, lparam, ansi)
            }
        }
        WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => {
            press(window, lparam as i16 as i32, (lparam >> 16) as i16 as i32);
            0
        }
        WM_LBUTTONUP => {
            if s.flags & PRESSED != 0 && !s.dropped() {
                set_flags(window, PRESSED, false);
                invalidate(window);
            }
            0
        }
        WM_MOUSEWHEEL if s.dropped() => send(s.list, WM_MOUSEWHEEL, wparam, lparam),
        WM_COMMAND => {
            let from = lparam as u32 as usize;
            let code = wparam >> 16;
            if from != 0 && from == s.edit {
                edit_command(window, code);
            } else if from != 0 && from == s.list {
                list_command(window, code);
            }
            0
        }
        WM_MEASUREITEM | WM_DRAWITEM | WM_DELETEITEM | WM_COMPAREITEM => {
            owner_draw_to_parent(window, message, lparam)
        }
        WM_CTLCOLORMSGBOX..=WM_CTLCOLOR_LAST => {
            let parent = parent_of(window);
            let brush = if parent != 0 {
                message::send(parent, message, wparam, lparam).unwrap_or(0)
            } else {
                0
            };
            if brush != 0 {
                brush
            } else {
                message::default_procedure(window, message, wparam, lparam, ansi)
            }
        }
        _ => message::default_procedure(window, message, wparam, lparam, ansi),
    }
}

/// ComboBoxWndProcW: the ComboBox class's procedure for a wide message.
pub extern "system" fn combo_box_proc_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    combo_box(window, message, wparam, lparam, false)
}

/// ComboBoxWndProcA: the ComboBox class's procedure for a narrow message.
pub extern "system" fn combo_box_proc_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    combo_box(window, message, wparam, lparam, true)
}

/// The ComboLBox class's procedure: the list box's, but for the mouse of a combo box's list.
fn combo_list(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    if matches!(
        message,
        WM_MOUSEMOVE
            | WM_LBUTTONDOWN
            | WM_LBUTTONDBLCLK
            | WM_LBUTTONUP
            | WM_CAPTURECHANGED
            | WM_MOUSEACTIVATE
    ) {
        let combo = listbox::owner_of(window);
        if load(combo).is_some_and(|s| s.list == window) {
            if let Some(answer) = list_mouse(combo, window, message, wparam, lparam) {
                return answer;
            }
        }
    }
    listbox::list_box_procedure(window, message, wparam, lparam, ansi)
}

/// ComboLBoxWndProcW: the ComboLBox class's procedure for a wide message.
pub extern "system" fn combo_list_proc_w(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    combo_list(window, message, wparam, lparam, false)
}

/// ComboLBoxWndProcA: the ComboLBox class's procedure for a narrow message.
pub extern "system" fn combo_list_proc_a(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    combo_list(window, message, wparam, lparam, true)
}

// --- GetComboBoxInfo, DlgDirListComboBox, DlgDirSelectComboBoxEx ---------------------------------

/// COMBOBOXINFO (winuser.h's).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ComboBoxInfo {
    size: u32,
    item: Rect,
    button: Rect,
    button_state: u32,
    combo: u32,
    item_window: u32,
    list: u32,
}

/// GetComboBoxInfo: the combo box's field and button rectangles (client coordinates), the button's
/// state, its edit and its list into the caller's COMBOBOXINFO; TRUE, or FALSE with 1400 for a
/// handle naming no window, ERROR_INVALID_PARAMETER for a cbSize not the structure's,
/// ERROR_WINDOW_NOT_COMBOBOX for a window that is no combo box.
///
/// # Safety
///
/// `info` is the caller's COMBOBOXINFO, as for the platform's.
#[unsafe(export_name = "f2k_export_GetComboBoxInfo")]
pub unsafe extern "system" fn get_combo_box_info(window: usize, info: *mut u8) -> u32 {
    if answered(window::window_info(window)).is_none() {
        return 0;
    }
    let size = core::mem::size_of::<ComboBoxInfo>();
    if info.is_null() {
        imports::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's structure, whose first DWORD is its cbSize (the contract).
    let given = unsafe { In::new(info as *const u32) }.read();
    if given as usize != size {
        imports::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let Some(s) = load(window) else {
        imports::set_last_error(ERROR_WINDOW_NOT_COMBOBOX);
        return 0;
    };
    let parts = layout(window, &s);
    let answer = ComboBoxInfo {
        size: given,
        item: parts.field,
        button: parts.button,
        button_state: if s.simple() {
            STATE_SYSTEM_INVISIBLE
        } else if s.flags & PRESSED != 0 {
            STATE_SYSTEM_PRESSED
        } else {
            0
        },
        combo: window as u32,
        item_window: s.edit as u32,
        list: s.list as u32,
    };
    // SAFETY: as above, the whole structure written.
    unsafe { Out::new(info as *mut ComboBoxInfo) }.set(answer);
    1
}

/// DlgDirListComboBoxW: the combo box `combo_id` of `dialog` filled with the files and directories
/// `path` names (CB_DIR), the current directory changed to its directory, the file part written
/// back, as DlgDirListW fills a list box ([`listbox::dlg_dir_list_with`]).
///
/// # Safety
///
/// `path` is the caller's NUL-terminated buffer, writable over its length, or null.
#[unsafe(export_name = "f2k_export_DlgDirListComboBoxW")]
pub unsafe extern "system" fn dlg_dir_list_combo_box_w(
    dialog: usize,
    path: *mut u16,
    combo_id: i32,
    static_id: i32,
    attributes: u32,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe {
        listbox::dlg_dir_list_with_w(
            &listbox::COMBO_DIR_MESSAGES,
            dialog,
            path,
            combo_id,
            static_id,
            attributes,
        )
    }
}

/// DlgDirListComboBoxA: DlgDirListComboBoxW's over the narrow path, the file part written back
/// narrow.
///
/// # Safety
///
/// As DlgDirListComboBoxW's, narrow.
#[unsafe(export_name = "f2k_export_DlgDirListComboBoxA")]
pub unsafe extern "system" fn dlg_dir_list_combo_box_a(
    dialog: usize,
    path: *mut u8,
    combo_id: i32,
    static_id: i32,
    attributes: u32,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe {
        listbox::dlg_dir_list_with_a(
            &listbox::COMBO_DIR_MESSAGES,
            dialog,
            path,
            combo_id,
            static_id,
            attributes,
        )
    }
}

/// DlgDirSelectComboBoxExW: the combo box's selected entry as a path into the caller's buffer of
/// `count` units, as DlgDirSelectExW's; whether it is a directory or a drive.
///
/// # Safety
///
/// `buffer` holds `count` writable units.
#[unsafe(export_name = "f2k_export_DlgDirSelectComboBoxExW")]
pub unsafe extern "system" fn dlg_dir_select_combo_box_ex_w(
    dialog: usize,
    buffer: *mut u16,
    count: i32,
    combo_id: i32,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe {
        listbox::dlg_dir_select_with_w(
            &listbox::COMBO_DIR_MESSAGES,
            dialog,
            buffer,
            count,
            combo_id,
        )
    }
}

/// DlgDirSelectComboBoxExA: DlgDirSelectComboBoxExW's, written back narrow.
///
/// # Safety
///
/// `buffer` holds `count` writable bytes.
#[unsafe(export_name = "f2k_export_DlgDirSelectComboBoxExA")]
pub unsafe extern "system" fn dlg_dir_select_combo_box_ex_a(
    dialog: usize,
    buffer: *mut u8,
    count: i32,
    combo_id: i32,
) -> i32 {
    // SAFETY: the caller's contract.
    unsafe {
        listbox::dlg_dir_select_with_a(
            &listbox::COMBO_DIR_MESSAGES,
            dialog,
            buffer,
            count,
            combo_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kinds the style's low bits make (0 is CBS_SIMPLE).
    #[test]
    fn the_style_makes_the_kind() {
        assert_eq!(kind_of(0), Kind::Simple);
        assert_eq!(kind_of(CBS_SIMPLE), Kind::Simple);
        assert_eq!(kind_of(CBS_DROPDOWN | CBS_SORT), Kind::DropDown);
        assert_eq!(kind_of(CBS_DROPDOWNLIST), Kind::DropDownList);
    }

    /// The list's style carries the combo box's sort, strings, owner draw, integral height and
    /// scroll styles; a drop-down one's has a border, a simple one's shows.
    #[test]
    fn the_list_style_follows_the_combo_box() {
        let list = list_style(
            CBS_DROPDOWNLIST | CBS_SORT | CBS_HASSTRINGS | CBS_OWNERDRAWFIXED,
            WS_VSCROLL,
        );
        assert_eq!(
            list,
            WS_CHILD
                | WS_BORDER
                | WS_VSCROLL
                | LBS_COMBOBOX
                | LBS_NOTIFY
                | LBS_SORT
                | LBS_HASSTRINGS
                | CBS_OWNERDRAWFIXED
        );
        let simple = list_style(CBS_SIMPLE | CBS_NOINTEGRALHEIGHT | CBS_DISABLENOSCROLL, 0);
        assert_eq!(
            simple,
            WS_CHILD
                | WS_VISIBLE
                | LBS_COMBOBOX
                | LBS_NOTIFY
                | LBS_NOINTEGRALHEIGHT
                | LBS_DISABLENOSCROLL
        );
        assert_eq!(
            edit_style(CBS_DROPDOWN | CBS_AUTOHSCROLL | CBS_UPPERCASE),
            WS_CHILD | WS_VISIBLE | ES_COMBOBOX | ES_AUTOHSCROLL | ES_UPPERCASE
        );
    }

    /// A drop-down combo box's field runs to its button, the button down its right inside the
    /// edges; a simple one's field is at its top, its list below.
    #[test]
    fn the_parts_of_the_combo_box() {
        let drop = layout_in(Rect::new(0, 0, 150, 26), Kind::DropDown, 22, (2, 2), 16);
        assert_eq!(drop.button, Rect::new(132, 2, 148, 24));
        assert_eq!(drop.field, Rect::new(2, 2, 132, 24));
        assert!(drop.list.is_empty());
        let simple = layout_in(Rect::new(0, 0, 150, 120), Kind::Simple, 22, (2, 2), 16);
        assert_eq!(simple.field, Rect::new(2, 2, 148, 24));
        assert!(simple.button.is_empty());
        assert_eq!(simple.list, Rect::new(0, 26, 150, 120));
        // MS Sans Serif 8 (13 pixels): a 21-pixel control; the System font (16): 26.
        assert_eq!(field_height_for(13, 2) + 4, 21);
        assert_eq!(field_height_for(16, 2) + 4, 26);
    }

    /// The keys the list steps: the page keys and the arrows, Home and End without an edit.
    #[test]
    fn the_keys_that_step_the_list() {
        assert!(steps_list(VK_DOWN, true) && steps_list(VK_PRIOR, true));
        assert!(!steps_list(VK_HOME, true) && steps_list(VK_HOME, false));
        assert!(!steps_list(VK_RETURN, false));
    }

    /// The CB_ messages the list answers are its LB_ twins.
    #[test]
    fn the_list_twins() {
        assert_eq!(list_twin(CB_ADDSTRING), Some(LB_ADDSTRING));
        assert_eq!(list_twin(CB_GETLBTEXT), Some(LB_GETTEXT));
        assert_eq!(list_twin(CB_DIR), Some(LB_DIR));
        assert_eq!(list_twin(CB_SHOWDROPDOWN), None);
    }
}
