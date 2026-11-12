//! The Edit control: the class user32 registers in every process
//! ([`crate::class::register_system_classes`]), its procedure here in its two forms
//! ([`edit_proc_w`], [`edit_proc_a`]), as Windows 2000's user32 runs it, single-line and
//! ES_MULTILINE.
//!
//! An edit's state is a fixed local block of its own ([`State`], Windows 2000's PED), found by its
//! window in a table of the process's ([`kept`]): F2K's window manager frees a window before its
//! WM_NCDESTROY reaches the procedure, so the window's extra bytes cannot name it then. Its text is
//! a movable local block of UTF-16 units (Windows 2000's hText; an ANSI edit's text is kept wide
//! too, converted where a narrow message reads or writes it), locked for each step that reads it;
//! as kernel32's LocalUnlock leaves the last error NO_ERROR when the last lock goes, each such step
//! leaves it so, as Windows 2000's do (the editctl capture's err=0 after a text was read or
//! written). A multiline edit keeps its lines' starts in a fixed block, rebuilt with each change of
//! the text; a line ends at CR LF (a lone CR or LF is text). Its undo record (the text an operation
//! put in, and the text it took out, kept in a fixed block) is undone by EM_UNDO, which records
//! its own undoing: a second EM_UNDO redoes.
//!
//! As the editctl capture shows Windows 2000's:
//!
//! - WS_BORDER becomes WS_EX_CLIENTEDGE at WM_NCCREATE (the style read back has no WS_BORDER);
//!   WM_GETDLGCODE is DLGC_WANTCHARS | DLGC_HASSETSEL | DLGC_WANTARROWS, DLGC_WANTALLKEYS added for
//!   a multiline edit; the text limit is 30000 units, EM_LIMITTEXT(0) 0x7FFFFFFE for a single-line
//!   edit and 0xFFFFFFFF for a multiline one;
//! - WM_SETTEXT replaces the text whatever the limit, empties the undo record and the modify flag,
//!   and notifies EN_UPDATE then EN_CHANGE for a single-line edit (an empty or unchanged text too),
//!   nothing for a multiline one; creation sets a nonempty title the same way;
//! - EM_SETSEL orders its ends, takes -1 for the end as the text's end and -1 for the start as no
//!   selection (at the caret), clamps both to the text, and puts the caret at its end argument;
//!   EM_GETSEL answers both ends in one word and through its two pointers;
//! - EM_REPLACESEL puts its text in place of the selection, the caret after it, cut to the limit
//!   (EN_MAXTEXT first, then EN_UPDATE and EN_CHANGE if anything changed); its undo flag FALSE
//!   empties the undo record; it works on a read-only edit;
//! - typing (WM_CHAR) inserts a character in place of the selection, EN_UPDATE then EN_CHANGE for
//!   each; one past the limit is refused with EN_MAXTEXT; Enter puts CR LF in a multiline edit (two
//!   units against the limit); Backspace takes the selection or the character before the caret; a
//!   read-only edit takes nothing; ES_NUMBER takes digits alone; ES_UPPERCASE and ES_LOWERCASE fold
//!   typed text, WM_SETTEXT's and EM_REPLACESEL's (the style read at each);
//! - EM_UNDO takes out what the record put in and puts back what it took out, selecting what it put
//!   back (an insertion undone leaves the selection at 0: its record holds no deletion); a
//!   single-line edit answers TRUE whether or not there was anything to undo; consecutive typing is
//!   one record;
//! - EM_GETLINE copies a line with no terminator, a single-line edit's with one when there is room,
//!   and answers 0 with ERROR_INVALID_PARAMETER for a line past the last, as EM_LINEINDEX answers
//!   -1; EM_LINELENGTH(-1) is the length of the caret's line less the selection's part of it, or
//!   for a selection over several lines what its first and last lines hold outside it.
//!
//! The caret is the thread's ([`crate::caret`]): made at WM_SETFOCUS (a border's width, a line's
//! height) and shown, destroyed at WM_KILLFOCUS, then EN_SETFOCUS or EN_KILLFOCUS. Each change of
//! the text or the selection hides it, moves it (when the edit has the focus), redraws the control
//! and shows it again: an edit without the focus calls HideCaret and ShowCaret for nothing, which
//! fail (ERROR_ACCESS_DENIED) when the thread has no caret, as the capture's err=5 shows Windows
//! 2000's do. WM_SETTEXT moves no caret of an edit without the focus.
//!
//! The control paints in WM_PAINT: its background with the brush its parent's WM_CTLCOLOREDIT
//! answers (WM_CTLCOLORSTATIC for a read-only or disabled edit), its text in its font (WM_SETFONT;
//! the system font without one) from a one-pixel margin, ES_RIGHT and ES_CENTER lines aligned, the
//! selection in COLOR_HIGHLIGHT and COLOR_HIGHLIGHTTEXT while the edit has the focus (or
//! ES_NOHIDESEL), ES_PASSWORD's text as its password character, disabled text in COLOR_GRAYTEXT.
//! A line longer than the edit scrolls sideways to keep the caret in view (ES_AUTOHSCROLL), a
//! multiline edit's lines up and down; a single-line edit without ES_AUTOHSCROLL takes no more text
//! than its width shows (EN_MAXTEXT).
//!
//! The arrows, Home and End move the caret (Shift extends the selection, Ctrl moves by words and to
//! the text's ends), Delete takes the selection or the character after the caret; Ctrl+Z undoes;
//! WM_CUT, WM_COPY and WM_PASTE (Ctrl+X, Ctrl+C, Ctrl+V, Shift+Delete, Ctrl+Insert, Shift+Insert)
//! go through the clipboard's CF_UNICODETEXT. What is not served logs through the debug port and
//! answers 0: the scroll bars (WS_HSCROLL, WS_VSCROLL), a multiline edit's word wrap (one without
//! ES_AUTOHSCROLL), the EM_ messages not listed here, the mouse (F2K has none), IME.

use core::ffi::CStr;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use rtl::edge::{In, InStr, InWStr, Out, OutBuf};
use rtl::gdi::{Rect, ETO_OPAQUE, OPAQUE, TRANSPARENT};
use rtl::nonclient::{WS_BORDER, WS_EX_CLIENTEDGE};
use rtl::pod::Pod;
use rtl::user::{
    CreateStructW,
    Msg,
    WM_CHAR,
    WM_CREATE,
    WM_ENABLE,
    WM_ERASEBKGND,
    WM_GETTEXT,
    WM_GETTEXTLENGTH,
    WM_KEYDOWN,
    WM_KILLFOCUS,
    WM_NCCREATE,
    WM_NCDESTROY,
    WM_PAINT,
    WM_SETFOCUS,
    WM_SETTEXT,
    WM_SIZE,
};
use rtl::window::{GWL_EXSTYLE, GWL_STYLE};

use crate::dialog::{
    DLGC_HASSETSEL,
    DLGC_WANTALLKEYS,
    DLGC_WANTARROWS,
    DLGC_WANTCHARS,
    WM_COMMAND,
    WM_GETDLGCODE,
    WM_GETFONT,
    WM_SETFONT,
    WS_CHILD,
    WS_DISABLED,
};
use crate::imports::{self, LocalFixed, LocalLocked, LMEM_FIXED, LMEM_MOVEABLE, LMEM_ZEROINIT};
use crate::message::{WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC};
use crate::{caret, clipboard, message, paint, procedure, window};

/// The edit messages (winuser.h's EM_*).
pub const EM_GETSEL: u32 = 0x00B0;
pub const EM_SETSEL: u32 = 0x00B1;
pub const EM_GETRECT: u32 = 0x00B2;
pub const EM_SCROLLCARET: u32 = 0x00B7;
pub const EM_GETMODIFY: u32 = 0x00B8;
pub const EM_SETMODIFY: u32 = 0x00B9;
pub const EM_GETLINECOUNT: u32 = 0x00BA;
pub const EM_LINEINDEX: u32 = 0x00BB;
pub const EM_GETHANDLE: u32 = 0x00BD;
pub const EM_LINELENGTH: u32 = 0x00C1;
pub const EM_REPLACESEL: u32 = 0x00C2;
pub const EM_GETLINE: u32 = 0x00C4;
pub const EM_LIMITTEXT: u32 = 0x00C5;
pub const EM_CANUNDO: u32 = 0x00C6;
pub const EM_UNDO: u32 = 0x00C7;
pub const EM_LINEFROMCHAR: u32 = 0x00C9;
pub const EM_SETPASSWORDCHAR: u32 = 0x00CC;
pub const EM_EMPTYUNDOBUFFER: u32 = 0x00CD;
pub const EM_GETFIRSTVISIBLELINE: u32 = 0x00CE;
pub const EM_SETREADONLY: u32 = 0x00CF;
pub const EM_GETPASSWORDCHAR: u32 = 0x00D2;
pub const EM_GETLIMITTEXT: u32 = 0x00D5;
pub const EM_POSFROMCHAR: u32 = 0x00D6;
/// The edit messages' range, EM_GETSEL to EM_GETIMESTATUS: one not served is logged.
const EM_FIRST: u32 = 0x00B0;
const EM_LAST: u32 = 0x00DA;

/// The edit styles (winuser.h's ES_*).
pub const ES_LEFT: u32 = 0x0000;
pub const ES_CENTER: u32 = 0x0001;
pub const ES_RIGHT: u32 = 0x0002;
pub const ES_MULTILINE: u32 = 0x0004;
pub const ES_UPPERCASE: u32 = 0x0008;
pub const ES_LOWERCASE: u32 = 0x0010;
pub const ES_PASSWORD: u32 = 0x0020;
pub const ES_AUTOVSCROLL: u32 = 0x0040;
pub const ES_AUTOHSCROLL: u32 = 0x0080;
pub const ES_NOHIDESEL: u32 = 0x0100;
pub const ES_READONLY: u32 = 0x0800;
pub const ES_NUMBER: u32 = 0x2000;
const ES_ALIGN: u32 = ES_CENTER | ES_RIGHT;

/// The edit notifications (winuser.h's EN_*), WM_COMMAND's code to the parent.
pub const EN_SETFOCUS: u32 = 0x0100;
pub const EN_KILLFOCUS: u32 = 0x0200;
pub const EN_CHANGE: u32 = 0x0300;
pub const EN_UPDATE: u32 = 0x0400;
pub const EN_ERRSPACE: u32 = 0x0500;
pub const EN_MAXTEXT: u32 = 0x0501;

/// The clipboard messages and WM_CLEAR, WM_UNDO (winuser.h).
pub const WM_CUT: u32 = 0x0300;
pub const WM_COPY: u32 = 0x0301;
pub const WM_PASTE: u32 = 0x0302;
pub const WM_CLEAR: u32 = 0x0303;
pub const WM_UNDO: u32 = 0x0304;

/// The window styles an edit's scroll bars would take (winuser.h).
const WS_HSCROLL: u32 = 0x0010_0000;
const WS_VSCROLL: u32 = 0x0020_0000;

/// The text limit an edit starts with, and EM_LIMITTEXT(0)'s for each kind (the capture's).
const DEFAULT_LIMIT: u32 = 30000;
const SINGLE_MOST: u32 = 0x7FFF_FFFE;
const MULTI_MOST: u32 = 0xFFFF_FFFF;

/// The units the text block grows by beyond what a change needs.
const GROW: usize = 32;

/// The character ES_PASSWORD shows in place of each of the text's.
const PASSWORD_CHAR: u32 = 0x2A;

/// The margin, in pixels, between the client area's edges and the text.
const MARGIN: i32 = 1;

const CR: u16 = 0x0D;
const LF: u16 = 0x0A;
const TAB: u16 = 0x09;
const SPACE: u16 = 0x20;

/// The keys an edit acts on (winuser.h's VK_*).
const VK_TAB: u32 = 0x09;
const VK_SHIFT: i32 = 0x10;
const VK_CONTROL: i32 = 0x11;
const VK_ESCAPE: u32 = 0x1B;
const VK_END: u32 = 0x23;
const VK_HOME: u32 = 0x24;
const VK_LEFT: u32 = 0x25;
const VK_UP: u32 = 0x26;
const VK_RIGHT: u32 = 0x27;
const VK_DOWN: u32 = 0x28;
const VK_INSERT: u32 = 0x2D;
const VK_DELETE: u32 = 0x2E;

/// The system colors an edit's selection and disabled text take (winuser.h's COLOR_*).
const COLOR_HIGHLIGHT: i32 = 13;
const COLOR_HIGHLIGHTTEXT: i32 = 14;
const COLOR_GRAYTEXT: i32 = 17;

/// GetSystemMetrics' border width: the caret's.
const SM_CXBORDER: i32 = 5;

/// The clipboard's Unicode text format, and the global memory it is handed in.
const CF_UNICODETEXT: u32 = 13;
const GMEM_MOVEABLE: u32 = 0x0002;

/// SetWindowPos's flags for a frame change alone.
const SWP_FRAME_ONLY: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020;

// --- The state -----------------------------------------------------------------------------------

/// [`State::flags`]: the edit is multiline (its style at creation), has the focus, was modified.
const MULTILINE: u32 = 0x1;
const FOCUSED: u32 = 0x2;
const MODIFIED: u32 = 0x4;

/// An edit's state (Windows 2000's PED, F2K's layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct State {
    /// The text: a movable local block of UTF-16 units, `length` of them used.
    text: usize,
    /// A multiline edit's line starts: a fixed local block of u32, `lines` of them used.
    starts: usize,
    /// The undo record's text taken out: a fixed local block of `deleted_length` units (0: none).
    deleted: usize,
    /// WM_SETFONT's font (0: the system font).
    font: usize,
    length: u32,
    lines: u32,
    /// The selection, and the end of it the caret is at.
    sel_min: u32,
    sel_max: u32,
    caret: u32,
    limit: u32,
    flags: u32,
    /// The character ES_PASSWORD shows (0: the text as it is).
    password: u32,
    /// How far the lines are scrolled sideways, in pixels, and the first line shown.
    scroll_x: i32,
    top_line: u32,
    /// The undo record: what it put in (`inserted_start` to `inserted_end`), and where what it
    /// took out was (`deleted_at`; 0 when it took nothing out).
    inserted_start: u32,
    inserted_end: u32,
    deleted_at: u32,
    deleted_length: u32,
}

// SAFETY: integers only, with no padding: the four words first, then fourteen 32-bit fields (an
// even count, which ends at a word's boundary).
unsafe impl Pod for State {}

impl State {
    fn multiline(&self) -> bool {
        self.flags & MULTILINE != 0
    }

    fn focused(&self) -> bool {
        self.flags & FOCUSED != 0
    }

    fn can_undo(&self) -> bool {
        self.inserted_start != self.inserted_end || self.deleted_length != 0
    }

    /// The lines it has.
    fn line_count(&self) -> u32 {
        if self.multiline() {
            self.lines.max(1)
        } else {
            1
        }
    }
}

/// The edits' state blocks, by window: the process's table (see the module notes).
mod kept {
    use super::*;

    /// How many edits a process keeps at once; past them an edit has no state (and logs).
    const KEPT: usize = 256;

    static WINDOWS: [AtomicU32; KEPT] = [const { AtomicU32::new(0) }; KEPT];
    static BLOCKS: [AtomicUsize; KEPT] = [const { AtomicUsize::new(0) }; KEPT];

    fn slot(window: usize) -> Option<usize> {
        let window = window as u32;
        (window != 0)
            .then(|| {
                WINDOWS
                    .iter()
                    .position(|w| w.load(Ordering::Acquire) == window)
            })
            .flatten()
    }

    /// The state block `block` kept for `window`; false when the table is full.
    pub fn keep(window: usize, block: usize) -> bool {
        for (index, slot) in WINDOWS.iter().enumerate() {
            if slot
                .compare_exchange(0, window as u32, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                BLOCKS[index].store(block, Ordering::Release);
                return true;
            }
        }
        false
    }

    /// The state block of `window`.
    pub fn block(window: usize) -> Option<usize> {
        slot(window).map(|index| BLOCKS[index].load(Ordering::Acquire))
    }

    /// The state block of `window`, no longer kept.
    pub fn forget(window: usize) -> Option<usize> {
        let index = slot(window)?;
        let block = BLOCKS[index].swap(0, Ordering::AcqRel);
        WINDOWS[index].store(0, Ordering::Release);
        Some(block)
    }
}

/// The fixed block `block` (one of an edit's: its state, its line starts, its undo text) as values
/// of `T`; none for no block.
fn fixed<T: Pod>(block: usize) -> Option<LocalFixed<T>> {
    // SAFETY: the blocks an edit's state names, and the state block its window's record names, are
    // its own fixed blocks, made LMEM_ZEROINIT or written whole before they are read, freed only
    // once nothing names them; the value returned is read or written and dropped within one step of
    // the edit's, which sends no message meanwhile, so no other value names the block.
    unsafe { LocalFixed::new(block) }
}

/// The state of the edit `window`; none for a window this procedure keeps none for.
fn load(window: usize) -> Option<State> {
    fixed::<State>(kept::block(window)?)?
        .as_slice()
        .first()
        .copied()
}

/// The state of the edit `window` written back.
fn store(window: usize, state: &State) {
    if let Some(mut block) = kept::block(window).and_then(fixed::<State>) {
        if let Some(slot) = block.as_mut_slice().first_mut() {
            *slot = *state;
        }
    }
}

/// A line to the debug port for a path the control does not serve (as the stub routine's lines,
/// with no export to name).
fn unsupported(what: &CStr) {
    imports::debug_print(what);
}

// --- The text ------------------------------------------------------------------------------------

/// Run `f` on the edit's text, its block locked (see the module notes on the last error); none
/// when the block cannot be locked.
fn with_text<R>(s: &State, f: impl FnOnce(&[u16]) -> R) -> Option<R> {
    let locked = LocalLocked::new(s.text)?;
    let units = locked.units();
    Some(f(&units[..(s.length as usize).min(units.len())]))
}

/// A fixed block holding `units` (0 for none); none when there is no room.
fn keep_units(units: &[u16]) -> Option<usize> {
    if units.is_empty() {
        return Some(0);
    }
    let block = imports::local_alloc(LMEM_FIXED, 2 * units.len())?;
    let mut held = fixed::<u16>(block)?;
    held.as_mut_slice()[..units.len()].copy_from_slice(units);
    Some(block)
}

/// The starts of `text`'s lines into `out` (as many as fit): 0, then the unit after each CR LF;
/// how many lines there are.
fn line_starts(text: &[u16], out: &mut [u32]) -> usize {
    let mut count = 1;
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    let mut at = 0;
    while at + 1 < text.len() {
        if text[at] == CR && text[at + 1] == LF {
            if let Some(slot) = out.get_mut(count) {
                *slot = (at + 2) as u32;
            }
            count += 1;
            at += 2;
        } else {
            at += 1;
        }
    }
    count
}

/// A multiline edit's line starts rebuilt from its text (`text`, as it now is).
fn rebuild_lines(s: &mut State, text: &[u16]) {
    let count = line_starts(text, &mut []);
    let room = imports::local_size(s.starts) / 4;
    if count > room {
        let wanted = 4 * (count + count / 4 + 8);
        match imports::local_realloc(s.starts, wanted, LMEM_MOVEABLE | LMEM_ZEROINIT) {
            Some(block) => s.starts = block,
            None => return,
        }
    }
    if let Some(mut starts) = fixed::<u32>(s.starts) {
        line_starts(text, starts.as_mut_slice());
        s.lines = count as u32;
    }
}

/// The text's units from `start` to `end` replaced by `new`, the text's block grown as it needs
/// (locked to write: see the module notes); false when it could not grow (the text as it was).
fn splice(s: &mut State, start: u32, end: u32, new: &[u16]) -> bool {
    if start == end && new.is_empty() {
        return true;
    }
    let (start, end, length) = (start as usize, end as usize, s.length as usize);
    let grown = length - (end - start) + new.len();
    if grown + 1 > imports::local_size(s.text) / 2 {
        let wanted = grown + grown / 4 + GROW;
        match imports::local_realloc(s.text, 2 * wanted, LMEM_MOVEABLE | LMEM_ZEROINIT) {
            Some(block) => s.text = block,
            None => return false,
        }
    }
    let Some(mut locked) = LocalLocked::new(s.text) else {
        return false;
    };
    let units = locked.units_mut();
    units.copy_within(end..length, start + new.len());
    units[start..start + new.len()].copy_from_slice(new);
    s.length = grown as u32;
    if s.multiline() {
        rebuild_lines(s, &units[..grown]);
    }
    true
}

/// The text emptied, its block not read (as WM_SETTEXT empties it: the capture's err=- for an
/// empty text).
fn empty_text(s: &mut State) {
    s.length = 0;
    s.lines = 1;
    if let Some(mut starts) = fixed::<u32>(s.starts) {
        if let Some(first) = starts.as_mut_slice().first_mut() {
            *first = 0;
        }
    }
}

/// The start of line `line`.
fn line_start(s: &State, line: u32) -> u32 {
    if !s.multiline() || line == 0 {
        return 0;
    }
    fixed::<u32>(s.starts)
        .and_then(|starts| starts.as_slice().get(line as usize).copied())
        .unwrap_or(s.length)
}

/// The line unit `at` is on (the last line for one past the text).
fn line_of(s: &State, at: u32) -> u32 {
    if !s.multiline() {
        return 0;
    }
    let Some(starts) = fixed::<u32>(s.starts) else {
        return 0;
    };
    let lines = &starts.as_slice()[..(s.line_count() as usize).min(starts.as_slice().len())];
    match lines.binary_search(&at) {
        Ok(line) => line as u32,
        Err(after) => after.saturating_sub(1) as u32,
    }
}

/// The length of line `line`, its CR LF left out: the last line's needs no text (what follows its
/// start), another's is read from the text (Windows 2000's MLLine reads the line's end: the
/// capture's err=0 for every line but the last).
fn line_length(s: &State, line: u32) -> u32 {
    if !s.multiline() {
        return s.length;
    }
    let start = line_start(s, line);
    if line + 1 >= s.line_count() {
        return s.length - start;
    }
    let next = line_start(s, line + 1);
    with_text(s, |text| {
        let end = next as usize;
        if end >= 2 && text.get(end - 2) == Some(&CR) && text.get(end - 1) == Some(&LF) {
            next - 2 - start
        } else {
            next - start
        }
    })
    .unwrap_or(next - start)
}

/// The text a message's lParam names (WM_SETTEXT's, EM_REPLACESEL's, a CREATESTRUCT's name), in the
/// narrow form for `ansi`, handed to `f` wide; the empty text for none. None when its conversion
/// found no room.
fn with_param_text<R>(lparam: usize, ansi: bool, f: impl FnOnce(&[u16]) -> R) -> Option<R> {
    if lparam == 0 {
        return Some(f(&[]));
    }
    if ansi {
        // SAFETY: the message's lParam as its sender hands it over: a NUL-terminated string,
        // narrow in this form.
        let text = unsafe { InStr::new(lparam as *const u8) };
        return crate::with_wide(text.bytes(), |units| f(&units[..units.len() - 1]));
    }
    // SAFETY: as above, wide in this form.
    let text = unsafe { InWStr::new(lparam as *const u16) }.units();
    if let Some(units) = text.aligned() {
        return Some(f(units));
    }
    let mut block = imports::HeapBlock::new(2 * text.len())?;
    let units = block.units_mut();
    text.copy_to(units);
    Some(f(&units[..text.len()]))
}

/// Run `f` on `units` as the style folds them (ES_UPPERCASE, ES_LOWERCASE), copied when it does;
/// none when the copy found no room.
fn with_case<R>(style: u32, units: &[u16], f: impl FnOnce(&[u16]) -> R) -> Option<R> {
    let upper = match style & (ES_UPPERCASE | ES_LOWERCASE) {
        0 => return Some(f(units)),
        ES_LOWERCASE => false,
        _ => true,
    };
    let mut block = imports::HeapBlock::new(2 * units.len())?;
    let folded = block.units_mut();
    for (slot, &unit) in folded.iter_mut().zip(units) {
        *slot = rtl::cp1252::map_case(unit, upper);
    }
    Some(f(&folded[..units.len()]))
}

// --- The undo record -----------------------------------------------------------------------------

/// The undo record emptied.
fn empty_undo(s: &mut State) {
    if s.deleted != 0 {
        imports::local_free(s.deleted);
    }
    s.deleted = 0;
    s.deleted_length = 0;
    s.deleted_at = 0;
    s.inserted_start = 0;
    s.inserted_end = 0;
}

/// The units of the undo record's text taken out.
fn with_deleted<R>(s: &State, f: impl FnOnce(&[u16]) -> R) -> R {
    match fixed::<u16>(s.deleted) {
        Some(held) => {
            let units = held.as_slice();
            f(&units[..(s.deleted_length as usize).min(units.len())])
        }
        None => f(&[]),
    }
}

/// An operation recorded: at `start`, the text `taken` (a fixed block of `taken_length` units, now
/// the record's or freed) taken out and `put` units put in. Typing (`coalesce`) carries the record
/// on when it continues it: an insertion where the record's insertion ends, a deletion that ends
/// (Backspace) or starts (Delete) where the record's deletion is.
fn record(s: &mut State, start: u32, taken: usize, taken_length: u32, put: u32, coalesce: bool) {
    let recorded_deletion = s.inserted_start == s.inserted_end && s.deleted_length != 0;
    if coalesce && s.can_undo() {
        if taken_length == 0
            && put != 0
            && s.inserted_end > s.inserted_start
            && start == s.inserted_end
        {
            s.inserted_end += put;
            return;
        }
        if put == 0 && taken_length != 0 && recorded_deletion {
            let before = start + taken_length == s.deleted_at;
            let after = start == s.deleted_at;
            if before || after {
                let joined = with_deleted(s, |old| {
                    with_deleted(
                        &State {
                            deleted: taken,
                            deleted_length: taken_length,
                            ..*s
                        },
                        |new| join(if before { (new, old) } else { (old, new) }),
                    )
                });
                if let Some(joined) = joined {
                    imports::local_free(taken);
                    imports::local_free(s.deleted);
                    s.deleted = joined;
                    s.deleted_length += taken_length;
                    if before {
                        s.deleted_at = start;
                        s.inserted_start = start;
                        s.inserted_end = start;
                    }
                    return;
                }
            }
        }
    }
    empty_undo(s);
    s.inserted_start = start;
    s.inserted_end = start + put;
    s.deleted = taken;
    s.deleted_length = taken_length;
    s.deleted_at = if taken_length != 0 { start } else { 0 };
}

/// A fixed block holding `first` then `second`; none when there is no room.
fn join((first, second): (&[u16], &[u16])) -> Option<usize> {
    let length = first.len() + second.len();
    let block = imports::local_alloc(LMEM_FIXED, 2 * length.max(1))?;
    let mut held = fixed::<u16>(block)?;
    let units = held.as_mut_slice();
    units[..first.len()].copy_from_slice(first);
    units[first.len()..length].copy_from_slice(second);
    Some(block)
}

// --- Measuring -----------------------------------------------------------------------------------

/// A DC of the edit's client area in its font, to measure the text with; released when dropped
/// (a painting's DC, lent, is not).
struct Measure {
    window: usize,
    dc: usize,
    previous: Option<usize>,
    owned: bool,
}

impl Measure {
    /// A DC of `window` in `font` (0: the DC's own); none when the window has none.
    fn new(window: usize, font: usize) -> Option<Measure> {
        let dc = crate::dc::get_dc(window);
        if dc == 0 {
            return None;
        }
        let previous = (font != 0)
            .then(|| imports::select_object(dc, font))
            .flatten();
        Some(Measure {
            window,
            dc,
            previous,
            owned: true,
        })
    }

    /// The painting's DC `dc`, its font already selected.
    fn lent(window: usize, dc: usize) -> Measure {
        Measure {
            window,
            dc,
            previous: None,
            owned: false,
        }
    }

    /// The width of `units` as the edit shows them (its password character for each, when it has
    /// one).
    fn width(&self, s: &State, units: &[u16]) -> i32 {
        if units.is_empty() {
            return 0;
        }
        if s.password != 0 {
            let one = imports::text_width(self.dc, &[s.password as u16]).unwrap_or(0);
            return one * units.len() as i32;
        }
        imports::text_width(self.dc, units).unwrap_or(0)
    }

    /// A line's height: the font's.
    fn line_height(&self) -> i32 {
        imports::text_metrics(self.dc).map_or(16, |metric| metric.height.max(1))
    }
}

impl Drop for Measure {
    fn drop(&mut self) {
        if let Some(previous) = self.previous {
            imports::select_object(self.dc, previous);
        }
        if self.owned {
            crate::dc::release_dc(self.window, self.dc);
        }
    }
}

/// The rectangle the text is formatted in (client coordinates), and a line's height.
#[derive(Clone, Copy, Debug)]
struct Layout {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    line: i32,
}

impl Layout {
    fn of(window: usize, measure: &Measure) -> Layout {
        let client = window::client_rect(window).unwrap_or_default();
        Layout {
            left: client.left + MARGIN,
            top: client.top + MARGIN,
            right: (client.right - MARGIN).max(client.left + MARGIN),
            bottom: client.bottom,
            line: measure.line_height(),
        }
    }

    fn width(&self) -> i32 {
        self.right - self.left
    }

    /// The lines it shows whole (one at least).
    fn visible_lines(&self) -> u32 {
        ((self.bottom - self.top) / self.line).max(1) as u32
    }

    /// Where a line `width` wide starts, as the style aligns it (a line wider than the rectangle
    /// starts at its left, and scrolls).
    fn origin(&self, style: u32, width: i32) -> i32 {
        if width >= self.width() {
            return self.left;
        }
        match style & ES_ALIGN {
            ES_RIGHT => self.right - width,
            ES_CENTER => self.left + (self.width() - width) / 2,
            _ => self.left,
        }
    }
}

/// The point (client coordinates) of the unit `at`, the edit's scrolling brought to show it when
/// `scroll`, and the line it is on: `text` is the edit's text.
fn point_of(
    s: &mut State,
    style: u32,
    measure: &Measure,
    layout: &Layout,
    text: &[u16],
    at: u32,
    scroll: bool,
) -> (i32, i32) {
    let line = line_of(s, at);
    let start = line_start(s, line) as usize;
    let end = (start + line_length_in(s, line, text) as usize).min(text.len());
    let units = &text[start..end];
    let width = measure.width(s, units);
    let before = measure.width(s, &units[..(at as usize - start).min(units.len())]);
    let origin = layout.origin(style, width);
    if scroll {
        let x = origin + before;
        let view = layout.width();
        if !s.multiline() && width < view {
            s.scroll_x = 0;
        } else if x - s.scroll_x >= layout.right {
            s.scroll_x = x - layout.left - view * 2 / 3;
        } else if x - s.scroll_x < layout.left {
            s.scroll_x = (x - layout.left - view / 3).max(0);
        }
        s.scroll_x = s.scroll_x.max(0);
        if s.multiline() {
            let shown = layout.visible_lines();
            if line < s.top_line {
                s.top_line = line;
            } else if line >= s.top_line + shown {
                s.top_line = line + 1 - shown;
            }
        }
    }
    (
        origin + before - s.scroll_x,
        layout.top + (line as i32 - s.top_line as i32) * layout.line,
    )
}

/// [`line_length`] from the text already read (no lock of its own).
fn line_length_in(s: &State, line: u32, text: &[u16]) -> u32 {
    if !s.multiline() {
        return s.length;
    }
    let start = line_start(s, line);
    if line + 1 >= s.line_count() {
        return s.length - start;
    }
    let next = line_start(s, line + 1) as usize;
    if next >= 2 && text.get(next - 2) == Some(&CR) && text.get(next - 1) == Some(&LF) {
        next as u32 - 2 - start
    } else {
        next as u32 - start
    }
}

// --- The view ------------------------------------------------------------------------------------

fn style(window: usize) -> u32 {
    window::style_of(window).unwrap_or(0)
}

fn invalidate(window: usize) {
    let _ = imports::invalidate_rect(window, 0, false);
}

/// The caret moved to the selection's caret end, the edit scrolled to show it (the text read when
/// it has any, as Windows 2000's caret placement reads it: the capture's err=0).
fn place_caret(window: usize, s: &mut State) {
    let Some(measure) = Measure::new(window, s.font) else {
        return;
    };
    let layout = Layout::of(window, &measure);
    let style = style(window);
    let at = s.caret;
    let point = if s.length == 0 {
        let origin = layout.origin(style, 0);
        s.scroll_x = 0;
        s.top_line = 0;
        (origin, layout.top)
    } else {
        let mut state = *s;
        let point = with_text(s, |text| {
            point_of(&mut state, style, &measure, &layout, text, at, true)
        });
        s.scroll_x = state.scroll_x;
        s.top_line = state.top_line;
        point.unwrap_or((layout.left, layout.top))
    };
    caret::set_caret_pos(point.0, point.1);
}

/// The view brought to the state: the caret hidden, placed (when the edit has the focus), the
/// control redrawn, the caret shown (see the module notes on an edit without the focus).
fn update_view(window: usize) {
    caret::show_or_hide(window, false);
    if let Some(mut s) = load(window) {
        if s.focused() {
            place_caret(window, &mut s);
            store(window, &s);
        }
    }
    invalidate(window);
    caret::show_or_hide(window, true);
}

/// The edit's parent: the window its notifications go to (0 for none).
fn parent_of(window: usize) -> usize {
    if style(window) & WS_CHILD == 0 {
        return 0;
    }
    window::links(window).map_or(0, |links| links.parent as usize)
}

/// The notification `code` sent to the edit's parent (WM_COMMAND: its id and the code, the edit's
/// handle).
fn notify(window: usize, code: u32) {
    let parent = parent_of(window);
    if parent == 0 {
        return;
    }
    let id = window::window_data(window).map_or(0, |data| data.id);
    let _ = message::send(
        parent,
        WM_COMMAND,
        code << 16 | (id & 0xFFFF),
        window as i32,
    );
}

/// The notifications of a change, sent once the state is stored: EN_MAXTEXT when it was cut, then
/// (when anything changed) EN_UPDATE, the view brought up to date, EN_CHANGE.
fn changed(window: usize, change: Change) {
    if change.cut {
        notify(window, EN_MAXTEXT);
    }
    if change.done {
        notify(window, EN_UPDATE);
        update_view(window);
        notify(window, EN_CHANGE);
    }
}

// --- Changes -------------------------------------------------------------------------------------

/// What a change did: whether it was cut short (EN_MAXTEXT), whether it changed the text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Change {
    cut: bool,
    done: bool,
}

/// How many of `new`'s units fit in place of `taken` units of a text `length` long under `limit`
/// (a CR LF kept whole).
fn fitting(new: &[u16], length: u32, taken: u32, limit: u32) -> usize {
    let base = length - taken;
    let room = limit.saturating_sub(base) as usize;
    let mut fit = new.len().min(room);
    if fit < new.len() && fit > 0 && new[fit - 1] == CR && new[fit] == LF {
        fit -= 1;
    }
    fit
}

/// The selection replaced by `new`, cut to the limit (and, for a single-line edit without
/// ES_AUTOHSCROLL, to its width), recorded for EM_UNDO when `undoable` (`coalesce`: typing) and
/// the record emptied otherwise, the caret after what went in, the edit modified.
fn replace(window: usize, s: &mut State, new: &[u16], undoable: bool, coalesce: bool) -> Change {
    let (start, end) = (s.sel_min, s.sel_max);
    let mut fit = fitting(new, s.length, end - start, s.limit);
    if !s.multiline() && style(window) & ES_AUTOHSCROLL == 0 && fit > 0 {
        fit = fitting_width(window, s, start, end, &new[..fit]);
    }
    let cut = fit < new.len();
    if start == end && fit == 0 {
        return Change { cut, done: false };
    }
    let taken = if end > start {
        match with_text(s, |text| keep_units(&text[start as usize..end as usize])).flatten() {
            Some(block) => block,
            None => return Change { cut, done: false },
        }
    } else {
        0
    };
    if !splice(s, start, end, &new[..fit]) {
        if taken != 0 {
            imports::local_free(taken);
        }
        notify(window, EN_ERRSPACE);
        return Change { cut, done: false };
    }
    if undoable {
        record(s, start, taken, end - start, fit as u32, coalesce);
    } else {
        if taken != 0 {
            imports::local_free(taken);
        }
        empty_undo(s);
    }
    let at = start + fit as u32;
    s.sel_min = at;
    s.sel_max = at;
    s.caret = at;
    s.flags |= MODIFIED;
    Change { cut, done: true }
}

/// How many of `new`'s units fit the single-line edit's width in place of its text from `start` to
/// `end`.
fn fitting_width(window: usize, s: &State, start: u32, end: u32, new: &[u16]) -> usize {
    let Some(measure) = Measure::new(window, s.font) else {
        return new.len();
    };
    let room = Layout::of(window, &measure).width();
    let kept = with_text(s, |text| {
        measure.width(s, &text[..start as usize]) + measure.width(s, &text[end as usize..])
    })
    .unwrap_or(0);
    let mut fit = new.len();
    while fit > 0 && kept + measure.width(s, &new[..fit]) > room {
        fit -= 1;
    }
    fit
}

/// The edit's text set (WM_SETTEXT, the creation's title): `units`, folded as the style asks, in
/// place of the whole text, the undo record and the modify flag emptied, the selection at 0;
/// EN_UPDATE and EN_CHANGE for a single-line edit. TRUE; FALSE (EN_ERRSPACE) when there is no
/// room for it.
fn set_text(window: usize, units: &[u16]) -> bool {
    let Some(mut s) = load(window) else {
        return false;
    };
    let style = style(window);
    empty_text(&mut s);
    empty_undo(&mut s);
    s.flags &= !MODIFIED;
    s.sel_min = 0;
    s.sel_max = 0;
    s.caret = 0;
    s.scroll_x = 0;
    s.top_line = 0;
    let set = units.is_empty()
        || with_case(style, units, |units| splice(&mut s, 0, 0, units)).unwrap_or(false);
    store(window, &s);
    if !set {
        notify(window, EN_ERRSPACE);
        return false;
    }
    if !s.multiline() {
        notify(window, EN_UPDATE);
    }
    if s.focused() {
        update_view(window);
    } else {
        invalidate(window);
    }
    if !s.multiline() {
        notify(window, EN_CHANGE);
    }
    true
}

/// EM_REPLACESEL (and a paste): `units`, folded as the style asks, in place of the selection.
fn replace_selection(window: usize, units: &[u16], undoable: bool) {
    let Some(mut s) = load(window) else {
        return;
    };
    let style = style(window);
    let change = with_case(style, units, |units| {
        replace(window, &mut s, units, undoable, false)
    })
    .unwrap_or_default();
    store(window, &s);
    changed(window, change);
}

/// The units from `start` to `end` taken out (Backspace, Delete, WM_CLEAR, WM_CUT), recorded
/// (`coalesce`: a key's).
fn delete(window: usize, start: u32, end: u32, coalesce: bool) {
    let Some(mut s) = load(window) else {
        return;
    };
    if start >= end {
        return;
    }
    s.sel_min = start;
    s.sel_max = end;
    let change = replace(window, &mut s, &[], true, coalesce);
    store(window, &s);
    changed(window, change);
}

/// EM_UNDO and WM_UNDO: the record undone (see the module notes), what it put back selected;
/// TRUE for a single-line edit, whether a multiline one undid anything.
fn undo(window: usize) -> i32 {
    let Some(mut s) = load(window) else {
        return 0;
    };
    if !s.can_undo() {
        return !s.multiline() as i32;
    }
    let (start, end) = (s.inserted_start, s.inserted_end.min(s.length));
    let removed = if end > start {
        match with_text(&s, |text| keep_units(&text[start as usize..end as usize])).flatten() {
            Some(block) => block,
            None => return 0,
        }
    } else {
        0
    };
    let at = s.deleted_at.min(s.length - (end - start));
    let put_back = s.deleted_length;
    let done = splice(&mut s, start, end, &[])
        && with_deleted(&s.clone(), |deleted| splice(&mut s, at, at, deleted));
    if s.deleted != 0 {
        imports::local_free(s.deleted);
    }
    s.inserted_start = at;
    s.inserted_end = at + put_back;
    s.deleted = removed;
    s.deleted_length = end - start;
    s.deleted_at = if end > start { start } else { 0 };
    s.sel_min = s.inserted_start;
    s.sel_max = s.inserted_end;
    s.caret = s.inserted_end;
    s.flags |= MODIFIED;
    store(window, &s);
    if !done {
        notify(window, EN_ERRSPACE);
    }
    changed(
        window,
        Change {
            cut: false,
            done: true,
        },
    );
    1
}

// --- Selection and keys --------------------------------------------------------------------------

/// EM_SETSEL's selection of `s` (see the module notes).
fn select(s: &mut State, start: i32, end: i32) {
    if start == -1 {
        s.sel_min = s.caret;
        s.sel_max = s.caret;
        return;
    }
    let start = (start as u32).min(s.length);
    let end = (end as u32).min(s.length);
    s.sel_min = start.min(end);
    s.sel_max = start.max(end);
    s.caret = end;
}

/// The unit before `at`, a CR LF taken whole.
fn step_back(text: &[u16], at: u32) -> u32 {
    let at = at as usize;
    if at >= 2 && text[at - 2] == CR && text[at - 1] == LF {
        (at - 2) as u32
    } else {
        at.saturating_sub(1) as u32
    }
}

/// The unit after `at`, a CR LF taken whole.
fn step_on(text: &[u16], at: u32) -> u32 {
    let at = at as usize;
    if at + 1 < text.len() && text[at] == CR && text[at + 1] == LF {
        (at + 2) as u32
    } else {
        (at + 1).min(text.len()) as u32
    }
}

/// Whether `unit` separates words.
fn is_space(unit: u16) -> bool {
    matches!(unit, SPACE | TAB | CR | LF)
}

/// The start of the word before `at`.
fn word_back(text: &[u16], at: u32) -> u32 {
    let mut at = at as usize;
    while at > 0 && is_space(text[at - 1]) {
        at -= 1;
    }
    while at > 0 && !is_space(text[at - 1]) {
        at -= 1;
    }
    at as u32
}

/// The start of the word after `at`.
fn word_on(text: &[u16], at: u32) -> u32 {
    let mut at = at as usize;
    while at < text.len() && !is_space(text[at]) {
        at += 1;
    }
    while at < text.len() && is_space(text[at]) {
        at += 1;
    }
    at as u32
}

/// Whether the key `vk` is down.
fn down(vk: i32) -> bool {
    crate::keyboard::get_key_state(vk) < 0
}

/// The caret moved to `to`, the selection extended from its other end when `extend`, collapsed
/// there otherwise.
fn move_caret(window: usize, s: &mut State, to: u32, extend: bool) {
    let to = to.min(s.length);
    if extend {
        let anchor = if s.caret == s.sel_min {
            s.sel_max
        } else {
            s.sel_min
        };
        s.sel_min = anchor.min(to);
        s.sel_max = anchor.max(to);
    } else {
        s.sel_min = to;
        s.sel_max = to;
    }
    s.caret = to;
    store(window, s);
    update_view(window);
}

/// The unit on line `line` nearest the caret's x on its own line (Up and Down).
fn same_column(window: usize, s: &State, line: u32) -> u32 {
    let Some(measure) = Measure::new(window, s.font) else {
        return line_start(s, line);
    };
    let layout = Layout::of(window, &measure);
    let style = style(window);
    with_text(s, |text| {
        let mut state = *s;
        let (x, _) = point_of(&mut state, style, &measure, &layout, text, s.caret, false);
        let start = line_start(s, line) as usize;
        let length = line_length_in(s, line, text) as usize;
        let units = &text[start..start + length];
        let origin = layout.origin(style, measure.width(s, units)) - s.scroll_x;
        let mut best = 0;
        for at in 0..=length {
            if origin + measure.width(s, &units[..at]) <= x {
                best = at;
            }
        }
        (start + best) as u32
    })
    .unwrap_or_else(|| line_start(s, line))
}

/// WM_KEYDOWN: the caret keys and Delete; whether the key was the edit's.
fn key(window: usize, vk: u32) -> bool {
    let Some(mut s) = load(window) else {
        return false;
    };
    let (shift, control) = (down(VK_SHIFT), down(VK_CONTROL));
    let line = line_of(&s, s.caret);
    let to = match vk {
        VK_LEFT | VK_RIGHT if !shift && s.sel_min != s.sel_max && !control => {
            if vk == VK_LEFT {
                s.sel_min
            } else {
                s.sel_max
            }
        }
        VK_LEFT | VK_RIGHT => with_text(&s, |text| match (vk, control) {
            (VK_LEFT, false) => step_back(text, s.caret),
            (VK_LEFT, true) => word_back(text, s.caret),
            (_, false) => step_on(text, s.caret),
            _ => word_on(text, s.caret),
        })
        .unwrap_or(s.caret),
        VK_UP | VK_DOWN if !s.multiline() => {
            return key(window, if vk == VK_UP { VK_LEFT } else { VK_RIGHT });
        }
        VK_UP if line == 0 => s.caret,
        VK_UP => same_column(window, &s, line - 1),
        VK_DOWN if line + 1 >= s.line_count() => s.caret,
        VK_DOWN => same_column(window, &s, line + 1),
        VK_HOME if control => 0,
        VK_HOME => line_start(&s, line),
        VK_END if control => s.length,
        VK_END => line_start(&s, line) + line_length(&s, line),
        VK_DELETE => {
            if shift {
                cut(window);
            } else if style(window) & ES_READONLY == 0 {
                let (start, end) = if s.sel_min != s.sel_max {
                    (s.sel_min, s.sel_max)
                } else {
                    let next = with_text(&s, |text| step_on(text, s.caret)).unwrap_or(s.caret);
                    (s.caret, next)
                };
                delete(window, start, end, true);
            }
            return true;
        }
        VK_INSERT if shift => {
            paste(window);
            return true;
        }
        VK_INSERT if control => {
            copy(window);
            return true;
        }
        _ => return false,
    };
    move_caret(window, &mut s, to, shift);
    true
}

/// WM_CHAR: a typed character (see the module notes); Backspace; Ctrl+Z, Ctrl+X, Ctrl+C and
/// Ctrl+V.
fn typed(window: usize, unit: u16) {
    let style = style(window);
    match unit {
        0x1A => {
            undo(window);
            return;
        }
        0x18 => return cut(window),
        0x03 => return copy(window),
        0x16 => return paste(window),
        _ => {}
    }
    if style & ES_READONLY != 0 {
        return;
    }
    let Some(mut s) = load(window) else {
        return;
    };
    if unit == 0x08 {
        let (start, end) = if s.sel_min != s.sel_max {
            (s.sel_min, s.sel_max)
        } else {
            let before = with_text(&s, |text| step_back(text, s.caret)).unwrap_or(s.caret);
            (before, s.caret)
        };
        delete(window, start, end, true);
        return;
    }
    let crlf = [CR, LF];
    let one = [unit];
    let new: &[u16] = match unit {
        CR | LF if s.multiline() => &crlf,
        TAB if s.multiline() => &one,
        0x00..=0x1F | 0x7F => return,
        _ if style & ES_NUMBER != 0 && !(0x30..=0x39).contains(&unit) => return,
        _ => &one,
    };
    let change =
        with_case(style, new, |new| replace(window, &mut s, new, true, true)).unwrap_or_default();
    store(window, &s);
    changed(window, change);
}

// --- The clipboard -------------------------------------------------------------------------------

/// WM_COPY: the selection put on the clipboard as CF_UNICODETEXT (not a password's).
fn copy(window: usize) {
    let Some(s) = load(window) else {
        return;
    };
    if s.sel_min == s.sel_max || s.password != 0 {
        return;
    }
    let count = (s.sel_max - s.sel_min) as usize;
    let Some(memory) = imports::global_alloc(GMEM_MOVEABLE, 2 * (count + 1)) else {
        return;
    };
    if let Some(mut locked) = imports::GlobalLocked::new(memory) {
        let out = locked.units_mut();
        let _ = with_text(&s, |text| {
            out[..count].copy_from_slice(&text[s.sel_min as usize..s.sel_max as usize]);
            out[count] = 0;
        });
    }
    if clipboard::open_clipboard(window) == 0 {
        imports::global_free(memory);
        return;
    }
    clipboard::empty_clipboard();
    if clipboard::set_clipboard_data(CF_UNICODETEXT, memory) == 0 {
        imports::global_free(memory);
    }
    clipboard::close_clipboard();
}

/// WM_CUT: the selection copied, then taken out (not from a read-only edit).
fn cut(window: usize) {
    copy(window);
    clear(window);
}

/// WM_CLEAR: the selection taken out (not from a read-only edit).
fn clear(window: usize) {
    if style(window) & ES_READONLY != 0 {
        return;
    }
    if let Some(s) = load(window) {
        delete(window, s.sel_min, s.sel_max, false);
    }
}

/// WM_PASTE: the clipboard's CF_UNICODETEXT in place of the selection (a single-line edit takes
/// it to its first line break), as EM_REPLACESEL puts it.
fn paste(window: usize) {
    if style(window) & ES_READONLY != 0 || clipboard::open_clipboard(window) == 0 {
        return;
    }
    let memory = clipboard::get_clipboard_data(CF_UNICODETEXT);
    let multiline = load(window).is_some_and(|s| s.multiline());
    if let Some(locked) = (memory != 0)
        .then(|| imports::GlobalLocked::new(memory))
        .flatten()
    {
        let units = locked.units();
        let mut length = rtl::cstr::nul_len(units);
        if !multiline {
            length = units[..length]
                .iter()
                .position(|&unit| unit == CR || unit == LF)
                .unwrap_or(length);
        }
        replace_selection(window, &units[..length], true);
    }
    clipboard::close_clipboard();
}

// --- Painting ------------------------------------------------------------------------------------

/// The edit drawn into its painting's DC (see the module notes).
fn draw_edit(window: usize, dc: usize) {
    let Some(s) = load(window) else {
        return;
    };
    let style = style(window);
    let client = window::client_rect(window).unwrap_or_default();
    let quiet = style & (ES_READONLY | WS_DISABLED) != 0;
    let kind = if quiet {
        WM_CTLCOLORSTATIC
    } else {
        WM_CTLCOLOREDIT
    };
    let parent = parent_of(window);
    let mut brush = if parent != 0 {
        message::send(parent, kind, dc as u32, window as i32).unwrap_or(0) as usize
    } else {
        0
    };
    if brush == 0 {
        brush = message::default_procedure(window, kind, dc as u32, window as i32, false) as usize;
    }
    crate::draw::fill(dc, client, brush);
    if style & WS_DISABLED != 0 {
        imports::set_text_color(dc, crate::display::get_sys_color(COLOR_GRAYTEXT));
    }
    let previous = (s.font != 0)
        .then(|| imports::select_object(dc, s.font))
        .flatten();
    imports::set_bk_mode(dc, TRANSPARENT);
    let measure = Measure::lent(window, dc);
    let layout = Layout::of(window, &measure);
    let show_selection = s.sel_min != s.sel_max && (s.focused() || style & ES_NOHIDESEL != 0);
    let _ = with_text(&s, |text| {
        let mut line = s.top_line;
        let mut y = layout.top;
        while line < s.line_count() && y < layout.bottom {
            let start = line_start(&s, line);
            let length = line_length_in(&s, line, text);
            let units = &text[start as usize..(start + length) as usize];
            let x = layout.origin(style, measure.width(&s, units)) - s.scroll_x;
            let selection = if show_selection {
                (
                    s.sel_min.clamp(start, start + length) - start,
                    s.sel_max.clamp(start, start + length) - start,
                )
            } else {
                (0, 0)
            };
            draw_line(dc, &s, &measure, x, y, layout.line, units, selection);
            line += 1;
            y += layout.line;
        }
    });
    drop(measure);
    if let Some(previous) = previous {
        imports::select_object(dc, previous);
    }
}

/// One line's `units` drawn at (`x`, `y`), its part from `selection.0` to `selection.1` in the
/// selection's colors.
#[allow(clippy::too_many_arguments)]
fn draw_line(
    dc: usize,
    s: &State,
    measure: &Measure,
    x: i32,
    y: i32,
    height: i32,
    units: &[u16],
    selection: (u32, u32),
) {
    let (from, to) = (selection.0 as usize, selection.1 as usize);
    let mut pen = x;
    for (part, selected) in [
        (&units[..from], false),
        (&units[from..to], true),
        (&units[to..], false),
    ] {
        if part.is_empty() {
            continue;
        }
        let width = measure.width(s, part);
        if selected {
            let text = imports::text_color(dc);
            imports::set_text_color(dc, crate::display::get_sys_color(COLOR_HIGHLIGHTTEXT));
            imports::set_bk_color(dc, crate::display::get_sys_color(COLOR_HIGHLIGHT));
            imports::set_bk_mode(dc, OPAQUE);
            let rect = Rect {
                left: pen,
                top: y,
                right: pen + width,
                bottom: y + height,
            };
            draw_units(dc, s, pen, y, ETO_OPAQUE, Some(&rect), part);
            imports::set_bk_mode(dc, TRANSPARENT);
            imports::set_text_color(dc, text);
        } else {
            draw_units(dc, s, pen, y, 0, None, part);
        }
        pen += width;
    }
}

/// `units` drawn at (`x`, `y`), as the edit shows them (its password character for each).
fn draw_units(
    dc: usize,
    s: &State,
    x: i32,
    y: i32,
    options: u32,
    rect: Option<&Rect>,
    units: &[u16],
) {
    if s.password == 0 {
        imports::ext_text_out(dc, x, y, options, rect, units);
        return;
    }
    let stars = [s.password as u16; 64];
    let one = imports::text_width(dc, &stars[..1]).unwrap_or(0);
    let mut pen = x;
    for chunk in units.chunks(stars.len()) {
        imports::ext_text_out(dc, pen, y, options, rect, &stars[..chunk.len()]);
        pen += one * chunk.len() as i32;
    }
}

// --- Creation and destruction --------------------------------------------------------------------

/// WM_NCCREATE: the edit's state made (its text empty, its limit the default), WS_BORDER turned
/// into WS_EX_CLIENTEDGE; what it does not serve logged. False when there was no room for it.
fn create(window: usize) -> bool {
    let style = style(window);
    let state = imports::local_alloc(LMEM_FIXED | LMEM_ZEROINIT, core::mem::size_of::<State>());
    let text = imports::local_alloc(LMEM_MOVEABLE | LMEM_ZEROINIT, 2 * GROW);
    let starts = imports::local_alloc(LMEM_FIXED | LMEM_ZEROINIT, 4 * 8);
    let (Some(block), Some(text), Some(starts)) = (state, text, starts) else {
        for block in [state, text, starts].into_iter().flatten() {
            imports::local_free(block);
        }
        return false;
    };
    let multiline = style & ES_MULTILINE != 0;
    let s = State {
        text,
        starts,
        lines: 1,
        limit: DEFAULT_LIMIT,
        flags: if multiline { MULTILINE } else { 0 },
        password: if style & ES_PASSWORD != 0 && !multiline {
            PASSWORD_CHAR
        } else {
            0
        },
        ..State::default()
    };
    if !kept::keep(window, block) {
        unsupported(c"user32 Edit: more edits than a process keeps not yet implemented\n");
        for block in [block, text, starts] {
            imports::local_free(block);
        }
        return false;
    }
    store(window, &s);
    if style & WS_BORDER != 0 {
        let ex_style = window::window_data(window).map_or(0, |data| data.ex_style);
        let _ = imports::set_window_long(window, GWL_STYLE, style & !WS_BORDER, false);
        let _ = imports::set_window_long(window, GWL_EXSTYLE, ex_style | WS_EX_CLIENTEDGE, false);
        window::set_window_pos(window, 0, 0, 0, 0, 0, SWP_FRAME_ONLY);
    }
    if style & (WS_HSCROLL | WS_VSCROLL) != 0 {
        unsupported(c"user32 Edit: scroll bars (WS_HSCROLL, WS_VSCROLL) not yet implemented\n");
    }
    if multiline && style & ES_AUTOHSCROLL == 0 {
        unsupported(c"user32 Edit: a multiline edit's word wrap not yet implemented\n");
    }
    true
}

/// WM_NCDESTROY: the edit's state and its blocks freed.
fn destroy(window: usize) {
    if let Some(s) = load(window) {
        for block in [s.text, s.starts, s.deleted] {
            if block != 0 {
                imports::local_free(block);
            }
        }
    }
    if let Some(block) = kept::forget(window) {
        imports::local_free(block);
    }
}

// --- The procedure -------------------------------------------------------------------------------

/// WM_GETDLGCODE: what the edit wants of the keyboard (`msg` the address of the MSG asked about,
/// 0 for none): a multiline edit wants every key but Tab and Esc, which move the dialog's focus
/// and cancel it.
fn dialog_code(s: Option<State>, msg: usize) -> u32 {
    let code = DLGC_WANTCHARS | DLGC_HASSETSEL | DLGC_WANTARROWS;
    if !s.is_some_and(|s| s.multiline()) {
        return code;
    }
    if msg != 0 {
        // SAFETY: WM_GETDLGCODE's lParam as the dialog manager hands it over: a MSG.
        let msg = unsafe { In::new(msg as *const Msg) }.read();
        if msg.message == WM_KEYDOWN && matches!(msg.wparam, VK_TAB | VK_ESCAPE) {
            return code;
        }
    }
    code | DLGC_WANTALLKEYS
}

/// WM_GETTEXT: the text into the buffer of `max` units (bytes for `ansi`), cut to leave room for
/// the terminator, terminated: the units (bytes) copied; nothing into an empty buffer.
fn get_text(window: usize, max: u32, buffer: usize, ansi: bool) -> i32 {
    let Some(s) = load(window) else {
        return 0;
    };
    if max == 0 || buffer == 0 {
        return 0;
    }
    with_text(&s, |text| {
        if ansi {
            // SAFETY: WM_GETTEXT's lParam as its sender hands it over: a buffer of wParam bytes.
            let mut out = unsafe { OutBuf::new(buffer as *mut u8, max as usize) };
            procedure::put_narrow(&mut out, text) as i32
        } else {
            // SAFETY: as above, of wParam units.
            let mut out = unsafe { OutBuf::new(buffer as *mut u16, max as usize) };
            let length = text.len().min(max as usize - 1);
            out.put(&text[..length]);
            out.set(length, 0);
            length as i32
        }
    })
    .unwrap_or(0)
}

/// EM_GETLINE: line `line` (a single-line edit's text, whatever the line) into the buffer at
/// `buffer`, whose first unit (byte pair, for `ansi`) is its size: the units (bytes) copied; see
/// the module notes.
fn get_line(s: &State, line: u32, buffer: usize, ansi: bool) -> i32 {
    if buffer == 0 {
        return 0;
    }
    let (start, length) = if s.multiline() {
        if line >= s.line_count() {
            imports::set_last_error(crate::ERROR_INVALID_PARAMETER);
            return 0;
        }
        (line_start(s, line), line_length(s, line))
    } else {
        (0, s.length)
    };
    if length == 0 {
        return 0;
    }
    // SAFETY: EM_GETLINE's lParam as its sender hands it over: a buffer whose first unit holds its
    // size.
    let room = unsafe { In::new(buffer as *const u16) }.read() as usize;
    let terminated = !s.multiline();
    with_text(s, |text| {
        let units = &text[start as usize..(start + length) as usize];
        if ansi {
            // SAFETY: as above, of `room` bytes.
            let mut out = unsafe { OutBuf::new(buffer as *mut u8, room) };
            let mut bytes = [0u8; 512];
            let mut written = 0;
            for chunk in units.chunks(bytes.len() / 2) {
                if written == room {
                    break;
                }
                let made = imports::unicode_to_multi_byte(&mut bytes, chunk);
                let count = made.min(room - written);
                out.put_at(written, &bytes[..count]);
                written += count;
            }
            if terminated && written < room {
                out.set(written, 0);
            }
            written as i32
        } else {
            // SAFETY: as above, of `room` units.
            let mut out = unsafe { OutBuf::new(buffer as *mut u16, room) };
            let count = units.len().min(room);
            out.put(&units[..count]);
            if terminated && count < room {
                out.set(count, 0);
            }
            count as i32
        }
    })
    .unwrap_or(0)
}

/// EM_LINELENGTH of `at` (see the module notes; -1: the selection's lines).
fn length_of_line(s: &State, at: u32) -> u32 {
    if !s.multiline() {
        return s.length;
    }
    if at != u32::MAX {
        return line_length(s, line_of(s, at.min(s.length)));
    }
    let (first, last) = (line_of(s, s.sel_min), line_of(s, s.sel_max));
    if first == last {
        return line_length(s, first) - (s.sel_max - s.sel_min);
    }
    let before = s.sel_min - line_start(s, first);
    let after = line_length(s, last) - (s.sel_max - line_start(s, last));
    before + after
}

/// The edit's procedure, for a message of the narrow (`ansi`) or wide form.
fn edit_control(window: usize, message: u32, wparam: u32, lparam: i32, ansi: bool) -> i32 {
    let state = load(window);
    let lp = lparam as u32 as usize;
    match message {
        WM_NCCREATE => {
            if !create(window) {
                return 0;
            }
            message::default_procedure(window, message, wparam, lparam, ansi)
        }
        WM_CREATE => {
            if lp != 0 {
                // SAFETY: WM_CREATE's lParam as the window manager hands it over (or translated
                // for a narrow procedure): a CREATESTRUCT.
                let create = unsafe { In::new(lp as *const CreateStructW) }.read();
                let name = create.name as usize;
                if name >> 16 != 0 {
                    let _ = with_param_text(name, ansi, |units| {
                        if !units.is_empty() {
                            set_text(window, units);
                        }
                    });
                }
            }
            0
        }
        WM_NCDESTROY => {
            destroy(window);
            0
        }
        _ if state.is_none() => message::default_procedure(window, message, wparam, lparam, ansi),
        WM_GETDLGCODE => dialog_code(state, lp) as i32,
        WM_SETTEXT => {
            with_param_text(lp, ansi, |units| set_text(window, units)).unwrap_or(false) as i32
        }
        WM_GETTEXT => get_text(window, wparam, lp, ansi),
        WM_GETTEXTLENGTH => match state {
            Some(s) if ansi => {
                with_text(&s, |text| procedure::narrow_length(text) as i32).unwrap_or(0)
            }
            Some(s) => s.length as i32,
            None => 0,
        },
        WM_SETFONT => {
            if let Some(mut s) = state {
                s.font = wparam as usize;
                store(window, &s);
                if s.focused() {
                    focus_gained(window);
                }
                if lparam != 0 {
                    invalidate(window);
                }
            }
            0
        }
        WM_GETFONT => state.map_or(0, |s| s.font as i32),
        WM_SETFOCUS => {
            focus_gained(window);
            notify(window, EN_SETFOCUS);
            0
        }
        WM_KILLFOCUS => {
            if let Some(mut s) = state {
                s.flags &= !FOCUSED;
                store(window, &s);
            }
            caret::destroy_caret();
            invalidate(window);
            notify(window, EN_KILLFOCUS);
            0
        }
        WM_CHAR => {
            let unit = if ansi && wparam > 0x7F {
                let mut unit = [0u16; 1];
                imports::multi_byte_to_unicode(&mut unit, &[wparam as u8]);
                unit[0]
            } else {
                wparam as u16
            };
            typed(window, unit);
            0
        }
        WM_KEYDOWN => {
            if key(window, wparam) {
                0
            } else {
                message::default_procedure(window, message, wparam, lparam, ansi)
            }
        }
        WM_SIZE => {
            if state.is_some_and(|s| s.focused()) {
                update_view(window);
            } else {
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
            if let Some(painting) = paint::Painting::begin(window) {
                draw_edit(window, painting.dc());
            }
            0
        }
        WM_CLEAR => {
            clear(window);
            0
        }
        WM_CUT => {
            cut(window);
            0
        }
        WM_COPY => {
            copy(window);
            0
        }
        WM_PASTE => {
            paste(window);
            0
        }
        WM_UNDO | EM_UNDO => undo(window),
        _ => match state {
            Some(s) => edit_message(window, s, message, wparam, lparam, ansi),
            None => 0,
        },
    }
}

/// The focus come to the edit: its caret made (a border's width, a line's height), placed and
/// shown, its selection redrawn.
fn focus_gained(window: usize) {
    let Some(mut s) = load(window) else {
        return;
    };
    s.flags |= FOCUSED;
    store(window, &s);
    let height = Measure::new(window, s.font).map_or(16, |measure| measure.line_height());
    let width = crate::display::get_system_metrics(SM_CXBORDER);
    caret::create_caret(window, 0, width, height);
    place_caret(window, &mut s);
    store(window, &s);
    caret::show_or_hide(window, true);
    invalidate(window);
}

/// The EM_ messages (and the rest, to the default procedure).
fn edit_message(
    window: usize,
    mut s: State,
    message: u32,
    wparam: u32,
    lparam: i32,
    ansi: bool,
) -> i32 {
    let lp = lparam as u32 as usize;
    match message {
        EM_GETSEL => {
            for (at, value) in [(wparam as usize, s.sel_min), (lp, s.sel_max)] {
                if at != 0 {
                    // SAFETY: EM_GETSEL's wParam and lParam as their sender hands them over: the
                    // addresses of DWORDs (or none).
                    unsafe { Out::new(at as *mut u32) }.set(value);
                }
            }
            if s.sel_max > 0xFFFF {
                -1
            } else {
                (s.sel_max << 16 | s.sel_min) as i32
            }
        }
        EM_SETSEL => {
            select(&mut s, wparam as i32, lparam);
            store(window, &s);
            update_view(window);
            1
        }
        EM_REPLACESEL => {
            let _ = with_param_text(lp, ansi, |units| {
                replace_selection(window, units, wparam != 0)
            });
            1
        }
        EM_LIMITTEXT => {
            s.limit = match (wparam, s.multiline()) {
                (0, true) => MULTI_MOST,
                (0, false) => SINGLE_MOST,
                (limit, _) => limit,
            };
            store(window, &s);
            1
        }
        EM_GETLIMITTEXT => s.limit as i32,
        EM_GETLINECOUNT => s.line_count() as i32,
        EM_LINEINDEX => {
            if !s.multiline() {
                return 0;
            }
            let line = if wparam == u32::MAX {
                line_of(&s, s.caret)
            } else {
                wparam
            };
            if line >= s.line_count() {
                imports::set_last_error(crate::ERROR_INVALID_PARAMETER);
                return -1;
            }
            line_start(&s, line) as i32
        }
        EM_LINELENGTH => length_of_line(&s, wparam) as i32,
        EM_LINEFROMCHAR => {
            let at = if wparam == u32::MAX {
                if s.sel_min == s.sel_max {
                    s.caret
                } else {
                    s.sel_min
                }
            } else {
                wparam.min(s.length)
            };
            line_of(&s, at) as i32
        }
        EM_GETLINE => get_line(&s, wparam, lp, ansi),
        EM_CANUNDO => s.can_undo() as i32,
        EM_EMPTYUNDOBUFFER => {
            empty_undo(&mut s);
            store(window, &s);
            1
        }
        EM_GETMODIFY => (s.flags & MODIFIED != 0) as i32,
        EM_SETMODIFY => {
            if wparam != 0 {
                s.flags |= MODIFIED;
            } else {
                s.flags &= !MODIFIED;
            }
            store(window, &s);
            1
        }
        EM_SETREADONLY => {
            let style = style(window);
            let style = if wparam != 0 {
                style | ES_READONLY
            } else {
                style & !ES_READONLY
            };
            let _ = imports::set_window_long(window, GWL_STYLE, style, false);
            invalidate(window);
            1
        }
        EM_SETPASSWORDCHAR => {
            if !s.multiline() {
                s.password = wparam & 0xFFFF;
                store(window, &s);
                invalidate(window);
            }
            1
        }
        EM_GETPASSWORDCHAR => s.password as i32,
        EM_GETFIRSTVISIBLELINE => s.top_line as i32,
        EM_SCROLLCARET => {
            update_view(window);
            1
        }
        EM_GETHANDLE => {
            // The text's block, terminated past its text, as Windows 2000 hands it over.
            let length = s.length;
            if splice(&mut s, length, length, &[0]) {
                s.length -= 1;
            }
            store(window, &s);
            s.text as i32
        }
        EM_GETRECT => {
            if lp != 0 {
                let rect = Measure::new(window, s.font).map(|measure| {
                    let layout = Layout::of(window, &measure);
                    Rect {
                        left: layout.left,
                        top: layout.top,
                        right: layout.right,
                        bottom: layout.bottom,
                    }
                });
                // SAFETY: EM_GETRECT's lParam as its sender hands it over: a RECT.
                unsafe { Out::new(lp as *mut Rect) }.set(rect.unwrap_or_default());
            }
            0
        }
        EM_POSFROMCHAR => {
            let Some(measure) = Measure::new(window, s.font) else {
                return -1;
            };
            if wparam > s.length {
                return -1;
            }
            let layout = Layout::of(window, &measure);
            let style = style(window);
            let point = with_text(&s, |text| {
                let mut state = s;
                point_of(&mut state, style, &measure, &layout, text, wparam, false)
            })
            .unwrap_or((layout.left, layout.top));
            ((point.1 as u32 & 0xFFFF) << 16 | (point.0 as u32 & 0xFFFF)) as i32
        }
        EM_FIRST..=EM_LAST => {
            let mut line = [0u8; 80];
            let text = b"user32 Edit: EM_ message 0x00?? not yet implemented\n";
            line[..text.len()].copy_from_slice(text);
            let hex = b"0123456789ABCDEF";
            line[29] = hex[(message >> 4 & 0xF) as usize];
            line[30] = hex[(message & 0xF) as usize];
            if let Ok(text) = CStr::from_bytes_until_nul(&line) {
                unsupported(text);
            }
            0
        }
        _ => message::default_procedure(window, message, wparam, lparam, ansi),
    }
}

/// EditWndProcW: the Edit class's procedure for a wide message.
pub extern "system" fn edit_proc_w(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    edit_control(window, message, wparam, lparam, false)
}

/// EditWndProcA: the Edit class's procedure for a narrow message.
pub extern "system" fn edit_proc_a(window: usize, message: u32, wparam: u32, lparam: i32) -> i32 {
    edit_control(window, message, wparam, lparam, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// Lines start after each CR LF; a lone CR or LF is text.
    #[test]
    fn lines_break_at_cr_lf() {
        let mut starts = [0u32; 8];
        assert_eq!(
            line_starts(&units("one\r\ntwo two\r\n\r\nfour"), &mut starts),
            4
        );
        assert_eq!(&starts[..4], &[0, 5, 14, 16]);
        assert_eq!(line_starts(&units("a\nb"), &mut starts), 1);
        assert_eq!(line_starts(&units("one\rnew\r\ntwo"), &mut starts), 2);
        assert_eq!(line_starts(&units("a\r\n"), &mut starts), 2);
        assert_eq!(starts[1], 3);
        assert_eq!(line_starts(&[], &mut starts), 1);
    }

    /// What fits the limit: the room the selection leaves, a CR LF kept whole.
    #[test]
    fn the_limit_cuts_what_goes_in() {
        assert_eq!(fitting(&units("XYZW"), 3, 0, 5), 2);
        assert_eq!(fitting(&units("123"), 5, 1, 5), 1);
        assert_eq!(fitting(&units("z"), 11, 0, 3), 0);
        assert_eq!(fitting(&[CR, LF], 7, 0, 8), 0, "a CR LF is not split");
        assert_eq!(fitting(&[CR, LF], 6, 0, 8), 2);
        assert_eq!(fitting(&units("abc"), 0, 0, MULTI_MOST), 3);
    }

    /// EM_SETSEL's ends: ordered, -1 as the end, a start of -1 deselecting at the caret.
    #[test]
    fn selections_are_ordered_and_clamped() {
        let mut s = State {
            length: 11,
            ..State::default()
        };
        select(&mut s, 4, 1);
        assert_eq!((s.sel_min, s.sel_max, s.caret), (1, 4, 1));
        select(&mut s, 0, -1);
        assert_eq!((s.sel_min, s.sel_max, s.caret), (0, 11, 11));
        select(&mut s, -1, 0);
        assert_eq!((s.sel_min, s.sel_max), (11, 11));
        select(&mut s, 2, 99);
        assert_eq!((s.sel_min, s.sel_max), (2, 11));
    }

    /// The caret keys step over a CR LF whole, and by words with Ctrl.
    #[test]
    fn steps_and_words() {
        let text = units("ab\r\ncd ef");
        assert_eq!(step_back(&text, 4), 2);
        assert_eq!(step_on(&text, 2), 4);
        assert_eq!(step_on(&text, 9), 9);
        assert_eq!(word_back(&text, 9), 7);
        assert_eq!(word_on(&text, 4), 7);
    }

    /// The text of the edit `window`, as its state holds it.
    fn text_of(window: usize) -> std::string::String {
        let s = load(window).unwrap();
        std::string::String::from_utf16(&with_text(&s, |text| text.to_vec()).unwrap()).unwrap()
    }

    /// An edit's state with no window behind it (its messages' window services fail, which the
    /// text's handling does not need): made, then `text` set.
    fn edit_with(window: usize, text: &str) {
        assert!(create(window));
        assert!(set_text(window, &units(text)));
    }

    /// EM_REPLACESEL's insertion undone leaves the selection at 0; the undo redone selects what it
    /// put back, and a replacement without undo empties the record (the editctl capture's undo
    /// block).
    #[test]
    fn undo_undoes_and_redoes() {
        let window = 0x7_0010;
        edit_with(window, "Hello");
        let mut s = load(window).unwrap();
        select(&mut s, 5, 5);
        store(window, &s);
        replace_selection(window, &units(" world"), true);
        assert_eq!(text_of(window), "Hello world");
        assert!(load(window).unwrap().can_undo());
        assert_eq!(undo(window), 1);
        assert_eq!(text_of(window), "Hello");
        let s = load(window).unwrap();
        assert_eq!((s.sel_min, s.sel_max), (0, 0));
        assert_eq!(undo(window), 1);
        assert_eq!(text_of(window), "Hello world");
        let s = load(window).unwrap();
        assert_eq!((s.sel_min, s.sel_max), (5, 11));
        replace_selection(window, &units("!"), false);
        assert_eq!(text_of(window), "Hello!");
        assert!(!load(window).unwrap().can_undo());
        destroy(window);
        assert!(load(window).is_none());
    }

    /// Typed text past the limit is cut; Backspace takes a CR LF whole; the lines follow.
    #[test]
    fn typing_against_the_limit() {
        let window = 0x7_0020;
        edit_with(window, "");
        let mut s = load(window).unwrap();
        s.limit = 5;
        store(window, &s);
        for unit in units("abcdefg") {
            typed(window, unit);
        }
        assert_eq!(text_of(window), "abcde");
        destroy(window);

        let window = 0x7_0030;
        assert!(create(window));
        let mut s = load(window).unwrap();
        s.flags |= MULTILINE;
        store(window, &s);
        for unit in units("ab\rcd") {
            typed(window, unit);
        }
        assert_eq!(text_of(window), "ab\r\ncd");
        let s = load(window).unwrap();
        assert_eq!(s.line_count(), 2);
        assert_eq!(line_length(&s, 0), 2);
        assert_eq!(length_of_line(&s, u32::MAX), 2);
        typed(window, 0x08);
        typed(window, 0x08);
        typed(window, 0x08);
        assert_eq!(text_of(window), "ab");
        assert_eq!(load(window).unwrap().line_count(), 1);
        assert_eq!(undo(window), 1, "the Backspaces are one record");
        assert_eq!(text_of(window), "ab\r\ncd");
        destroy(window);
    }

    /// Typing carries the record on; a new insertion elsewhere starts another.
    #[test]
    fn typing_is_one_record() {
        let mut s = State::default();
        record(&mut s, 5, 0, 0, 1, true);
        record(&mut s, 6, 0, 0, 1, true);
        assert_eq!((s.inserted_start, s.inserted_end, s.deleted_at), (5, 7, 0));
        record(&mut s, 0, 0, 0, 1, true);
        assert_eq!((s.inserted_start, s.inserted_end), (0, 1));
        record(&mut s, 0, 0, 0, 3, false);
        assert_eq!((s.inserted_start, s.inserted_end), (0, 3));
    }
}
