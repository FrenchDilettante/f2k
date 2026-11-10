//! The clipboard: the window station's store of data by format, and the services user32's clipboard
//! calls come through.
//!
//! Windows 2000 keeps a clipboard in each window station: the thread that has it open and the
//! window it opened it with, its owner (the window that last emptied it), and its formats in the
//! order they were put, each a clipboard data object of win32k's. F2K has one window station,
//! WinSta0 ([`super::winsta`]), so the window manager holds its one clipboard ([`Clipboard`],
//! under the window manager's lock as Windows 2000's is under its user lock), and its owner is
//! the window registry's `clipboard_owner`, which a window's destruction already reaches.
//!
//! The data crosses as Windows 2000's does: SetClipboardData hands win32k a global memory block's
//! bytes (NtUserConvertMemHandle copies them into a data object of the kernel's, then
//! NtUserSetClipboardData puts that object under a format), and GetClipboardData gets a data
//! object's handle (NtUserGetClipboardData), whose bytes user32 copies into a global memory block
//! of its own (NtUserCreateLocalMemHandle). The objects' bytes are blocks of the nonpaged pool,
//! copied from and to the caller in chunks at the passive level, outside the lock.
//!
//! The text formats stand in for one another, as Windows 2000's do: when the clipboard closes
//! after a change, every text format missing from CF_TEXT, CF_OEMTEXT and CF_UNICODETEXT, and
//! CF_LOCALE, joins the formats as a synthesised one, with no data yet. The first
//! GetClipboardData of one renders it from the text put (CF_UNICODETEXT first, then CF_TEXT,
//! then CF_OEMTEXT), through the ANSI code page (1252) or the OEM one (437); CF_LOCALE renders
//! as the language of the keyboard layout (`rtl::user::KEYBOARD_LAYOUT`, the one F2K has).
//!
//! The owner hears of the clipboard's end: an EmptyClipboard sends it WM_DESTROYCLIPBOARD, and
//! its own destruction WM_RENDERALLFORMATS (the window manager's `disown_clipboard` seam), after
//! which the clipboard has no owner and keeps its data, as the clipbrd capture shows. Delayed
//! rendering (a format put with no data, rendered by its owner's WM_RENDERFORMAT) is not
//! written: user32 refuses a put with no data.
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtUserOpenClipboard(handle Window): open it for the calling thread, with the window (0 for
//!   none);
//! - NtUserCloseClipboard(), NtUserEmptyClipboard();
//! - NtUserConvertMemHandle(ptr Data, u32 Length, ptr<u32> Handle): a data object of the bytes;
//! - NtUserSetClipboardData(u32 Format, u32 Data): the data object put under the format;
//! - NtUserGetClipboardData(u32 Format, ptr<u32> Data, ptr<u32> Length): the format's data object
//!   and its length (0 for a format the clipboard has none of);
//! - NtUserCreateLocalMemHandle(u32 Data, ptr Buffer, u32 Length, ptr<u32> Needed): the data
//!   object's bytes;
//! - NtUserIsClipboardFormatAvailable(u32 Format, ptr<u32> Available),
//!   NtUserCountClipboardFormats(ptr<u32> Count), NtUserGetClipboardOwner(ptr<u32> Window),
//!   NtUserGetOpenClipboardWindow(ptr<u32> Window);
//! - NtUserRegisterWindowMessage(ptr Name, ptr<u32> Atom), NtUserGetClipboardFormatName(u32 Format,
//!   ptr Name, u32 MaxCount, ptr<u32> Copied): the registered names' atoms.
//!
//! EnumClipboardFormats comes through NtUserCallOneParam ([`super::queue`]).

use rtl::codepage::{decode_byte, encode_unit, CodePage};

use super::class;
use super::window::{Message, Payload, WindowId, Windows};
use crate::sched::thread::ThreadId;
use crate::status::*;

/// The predefined formats the clipboard synthesises (winuser.h's CF_*).
pub const CF_TEXT: u32 = 1;
pub const CF_OEMTEXT: u32 = 7;
pub const CF_UNICODETEXT: u32 = 13;
pub const CF_LOCALE: u32 = 16;

/// The text formats, in the order a close adds the missing ones.
const TEXT_FORMATS: [u32; 3] = [CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT];

/// The first registered format: registered names are string atoms (0xC000..=0xFFFF).
pub const FIRST_REGISTERED: u32 = 0xC000;

/// The messages the clipboard sends its owner (winuser.h).
pub const WM_RENDERALLFORMATS: u32 = 0x0306;
pub const WM_DESTROYCLIPBOARD: u32 = 0x0307;

/// How many formats the clipboard holds at once.
const FORMATS: usize = 32;
/// How many data objects can wait between NtUserConvertMemHandle and NtUserSetClipboardData.
const CONVERTED: usize = 8;
/// The largest data object: 4 MiB.
pub const MAX_DATA: usize = 4 << 20;
/// The byte a code page writes for a character it has nothing for (the code pages' default).
const DEFAULT_CHAR: u8 = b'?';
/// The bytes copied to or from the caller at a time.
const CHUNK: usize = 512;

/// A data object's bytes: a block of the nonpaged pool (on the host, a vector).
#[cfg(target_arch = "x86")]
pub use crate::mem::pool::Block;
#[cfg(not(target_arch = "x86"))]
pub type Block = std::vec::Vec<u8>;

/// A zeroed block of `bytes` bytes; none when the pool has no room.
pub fn allocate(bytes: usize) -> Option<Block> {
    #[cfg(target_arch = "x86")]
    {
        crate::mem::pool::allocate(bytes)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        Some(std::vec![0; bytes])
    }
}

/// A block's bytes.
fn bytes(block: &Block) -> &[u8] {
    block.as_ref()
}

/// A block's bytes, to write.
fn bytes_mut(block: &mut Block) -> &mut [u8] {
    block.as_mut()
}

/// Why a clipboard call is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// ERROR_CLIPBOARD_NOT_OPEN (1418): the calling thread does not have the clipboard open.
    NotOpen,
    /// ERROR_ACCESS_DENIED (5): another thread has it open.
    AccessDenied,
    /// ERROR_INVALID_PARAMETER (87): no such format or data object.
    InvalidParameter,
    /// ERROR_NOT_ENOUGH_MEMORY (8): the clipboard's formats or the pool are full.
    NoMemory,
}

impl Refusal {
    /// The NTSTATUS the service answers. ERROR_CLIPBOARD_NOT_OPEN has no NTSTATUS counterpart
    /// (nothing maps to it in RtlNtStatusToDosError's table), so STATUS_UNSUCCESSFUL stands in,
    /// which user32's clipboard calls map back to it.
    pub const fn status(self) -> NtStatus {
        match self {
            Refusal::NotOpen => STATUS_UNSUCCESSFUL,
            Refusal::AccessDenied => STATUS_ACCESS_DENIED,
            Refusal::InvalidParameter => STATUS_INVALID_PARAMETER,
            Refusal::NoMemory => STATUS_NO_MEMORY,
        }
    }
}

/// One format on the clipboard.
struct Entry {
    format: u32,
    /// The data object's handle: the clipboard's own number for it.
    id: u32,
    /// The data; none for a synthesised format not rendered yet.
    data: Option<Block>,
    /// Whether the system made it (at a close) rather than a SetClipboardData.
    synthesized: bool,
}

impl Entry {
    const EMPTY: Self = Entry {
        format: 0,
        id: 0,
        data: None,
        synthesized: false,
    };
}

/// A data object between NtUserConvertMemHandle and NtUserSetClipboardData: its bytes, and the
/// process that made it (which alone may put it, and whose end frees it).
struct Converted {
    id: u32,
    owner: class::Owner,
    data: Option<Block>,
}

impl Converted {
    const EMPTY: Self = Converted {
        id: 0,
        owner: 0,
        data: None,
    };
}

/// What GetClipboardData finds for a format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// The clipboard has no such format (or nothing to render it from).
    Nothing,
    /// The format's data object and its length.
    Data { id: u32, length: usize },
    /// A synthesised format not rendered yet: the block `length` bytes long its rendering takes,
    /// from the text format `source`'s data object (none for CF_LOCALE). See
    /// [`Clipboard::render`].
    Render { source: Option<u32>, length: usize },
}

/// The window station's clipboard (see the module notes).
pub struct Clipboard {
    /// The thread that has it open, and the window it opened it with.
    opener: Option<ThreadId>,
    open_window: Option<WindowId>,
    /// Whether an EmptyClipboard or a SetClipboardData changed it since it was opened (the
    /// close synthesises the text formats only then).
    changed: bool,
    /// The formats, in the order they were put; `count` of them.
    entries: [Entry; FORMATS],
    count: usize,
    converted: [Converted; CONVERTED],
    /// The next data object's number (never 0).
    next_id: u32,
}

impl Clipboard {
    /// Write an empty, closed clipboard at `clipboard`, field by field (by value it would pass
    /// through the stack).
    ///
    /// # Safety
    ///
    /// `clipboard` is valid for writes and aligned; its previous contents are overwritten, not
    /// dropped.
    pub unsafe fn write_empty(clipboard: *mut Clipboard) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written, the arrays element by element.
        unsafe {
            addr_of_mut!((*clipboard).opener).write(None);
            addr_of_mut!((*clipboard).open_window).write(None);
            addr_of_mut!((*clipboard).changed).write(false);
            let entries = addr_of_mut!((*clipboard).entries) as *mut Entry;
            for index in 0..FORMATS {
                entries.add(index).write(Entry::EMPTY);
            }
            addr_of_mut!((*clipboard).count).write(0);
            let converted = addr_of_mut!((*clipboard).converted) as *mut Converted;
            for index in 0..CONVERTED {
                converted.add(index).write(Converted::EMPTY);
            }
            addr_of_mut!((*clipboard).next_id).write(1);
        }
    }

    // --- Opening and closing

    /// OpenClipboard: the clipboard open for `caller`, with `window` (none for NULL). A thread
    /// that has it open already may open it again, with another window; another thread may not
    /// (ERROR_ACCESS_DENIED).
    pub fn open(&mut self, caller: ThreadId, window: Option<WindowId>) -> Result<(), Refusal> {
        match self.opener {
            Some(opener) if opener != caller => return Err(Refusal::AccessDenied),
            Some(_) => {}
            None => {
                self.opener = Some(caller);
                self.changed = false;
            }
        }
        self.open_window = window;
        Ok(())
    }

    /// Whether `caller` has the clipboard open; ERROR_CLIPBOARD_NOT_OPEN otherwise.
    fn check_open(&self, caller: ThreadId) -> Result<(), Refusal> {
        if self.opener == Some(caller) {
            Ok(())
        } else {
            Err(Refusal::NotOpen)
        }
    }

    /// CloseClipboard: the clipboard closed, the text formats synthesised when it changed.
    pub fn close(&mut self, caller: ThreadId) -> Result<(), Refusal> {
        self.check_open(caller)?;
        self.release();
        Ok(())
    }

    /// The close's work: the text formats synthesised when the clipboard changed, then no opener.
    fn release(&mut self) {
        if self.changed {
            self.synthesize();
        }
        self.opener = None;
        self.open_window = None;
        self.changed = false;
    }

    /// The formats a close adds when there is text: CF_LOCALE, then each text format missing,
    /// with no data yet (what a full clipboard has no room for is left out).
    fn synthesize(&mut self) {
        if !TEXT_FORMATS.iter().any(|&f| self.position(f).is_some()) {
            return;
        }
        for format in core::iter::once(CF_LOCALE).chain(TEXT_FORMATS) {
            if self.position(format).is_none() {
                let _ = self.push(format, None, true);
            }
        }
    }

    /// The window the clipboard was opened with, while it lives (GetOpenClipboardWindow).
    pub fn open_window(&self, windows: &Windows) -> Option<WindowId> {
        self.open_window.filter(|&w| windows.is_live(w))
    }

    /// The clipboard's owner, while it lives (GetClipboardOwner).
    pub fn owner(windows: &Windows) -> Option<WindowId> {
        windows.clipboard_owner.filter(|&w| windows.is_live(w))
    }

    // --- The formats

    /// EmptyClipboard: every format gone, the window the clipboard was opened with its owner (none
    /// for none). The answer is the owner before, which the service sends WM_DESTROYCLIPBOARD (the
    /// window emptying it included).
    pub fn empty(
        &mut self,
        windows: &mut Windows,
        caller: ThreadId,
    ) -> Result<Option<WindowId>, Refusal> {
        self.check_open(caller)?;
        let previous = Self::owner(windows);
        for entry in &mut self.entries[..self.count] {
            *entry = Entry::EMPTY;
        }
        self.count = 0;
        windows.clipboard_owner = self.open_window(windows);
        self.changed = true;
        Ok(previous)
    }

    /// SetClipboardData: the data object `data` (as [`Clipboard::park`] numbered it for the
    /// process `owner`) put under `format`, in the place of the format's data if it had some,
    /// after the others otherwise. The object is consumed whatever the answer. A text format
    /// put takes the synthesised ones with it, which the next close makes again from it.
    pub fn set(
        &mut self,
        caller: ThreadId,
        owner: class::Owner,
        format: u32,
        data: u32,
    ) -> Result<(), Refusal> {
        let block = self.take_converted(data, owner);
        self.check_open(caller)?;
        let block = block.ok_or(Refusal::InvalidParameter)?;
        if format == 0 {
            return Err(Refusal::InvalidParameter);
        }
        if TEXT_FORMATS.contains(&format) {
            self.drop_synthesized();
        }
        let id = self.new_id();
        let entry = Entry {
            format,
            id,
            data: Some(block),
            synthesized: false,
        };
        match self.position(format) {
            Some(index) => self.entries[index] = entry,
            None => {
                if self.count == FORMATS {
                    return Err(Refusal::NoMemory);
                }
                self.entries[self.count] = entry;
                self.count += 1;
            }
        }
        self.changed = true;
        Ok(())
    }

    /// GetClipboardData's look-up of `format` (see [`Found`]).
    pub fn get(&self, caller: ThreadId, format: u32) -> Result<Found, Refusal> {
        self.check_open(caller)?;
        let Some(index) = self.position(format) else {
            return Ok(Found::Nothing);
        };
        let entry = &self.entries[index];
        if let Some(data) = &entry.data {
            return Ok(Found::Data {
                id: entry.id,
                length: bytes(data).len(),
            });
        }
        if format == CF_LOCALE {
            return Ok(Found::Render {
                source: None,
                length: 4,
            });
        }
        let Some(source) = self.text_source() else {
            return Ok(Found::Nothing);
        };
        let text = text_units(source.format, source.bytes());
        let unit = if format == CF_UNICODETEXT { 2 } else { 1 };
        Ok(Found::Render {
            source: Some(source.id),
            length: unit * (text + 1),
        })
    }

    /// Render the synthesised `format` into `block` (zeroed, as long as [`Clipboard::get`]
    /// answered), from the data object `source`: the rendered data object and its length. None
    /// when the clipboard changed since the look-up (the format or its source gone).
    pub fn render(
        &mut self,
        format: u32,
        source: Option<u32>,
        mut block: Block,
    ) -> Option<(u32, usize)> {
        let index = self.position(format)?;
        if let Some(data) = &self.entries[index].data {
            // Rendered meanwhile: that rendering stands.
            return Some((self.entries[index].id, bytes(data).len()));
        }
        match source {
            None => {
                let language = rtl::user::KEYBOARD_LAYOUT & 0xFFFF;
                bytes_mut(&mut block)
                    .get_mut(..4)?
                    .copy_from_slice(&language.to_le_bytes());
            }
            Some(source) => {
                let source = self.entries[..self.count]
                    .iter()
                    .find(|e| e.id == source && e.data.is_some())?;
                convert(source.format, source.bytes(), format, bytes_mut(&mut block));
            }
        }
        let length = bytes(&block).len();
        let entry = &mut self.entries[index];
        entry.data = Some(block);
        Some((entry.id, length))
    }

    /// IsClipboardFormatAvailable: whether the clipboard has `format`, put or synthesised.
    pub fn available(&self, format: u32) -> bool {
        self.position(format).is_some()
    }

    /// CountClipboardFormats: how many formats the clipboard has.
    pub fn count(&self) -> usize {
        self.count
    }

    /// EnumClipboardFormats: the format after `format` (the first for 0) in the order they were
    /// put; 0 past the last, or for a format the clipboard has none of.
    pub fn next_format(&self, caller: ThreadId, format: u32) -> Result<u32, Refusal> {
        self.check_open(caller)?;
        let next = match format {
            0 => 0,
            _ => match self.position(format) {
                Some(index) => index + 1,
                None => return Ok(0),
            },
        };
        Ok(self.entries[..self.count]
            .get(next)
            .map_or(0, |entry| entry.format))
    }

    // --- The data objects

    /// A data object of `block`'s bytes, made by the process `owner`, waiting for its
    /// SetClipboardData: its handle; none when too many wait already.
    pub fn park(&mut self, owner: class::Owner, block: Block) -> Option<u32> {
        let index = self.converted.iter().position(|c| c.id == 0)?;
        let id = self.new_id();
        self.converted[index] = Converted {
            id,
            owner,
            data: Some(block),
        };
        Some(id)
    }

    /// The waiting data object `id` of the process `owner`, taken.
    fn take_converted(&mut self, id: u32, owner: class::Owner) -> Option<Block> {
        if id == 0 {
            return None;
        }
        let slot = self
            .converted
            .iter_mut()
            .find(|c| c.id == id && c.owner == owner)?;
        let data = slot.data.take();
        *slot = Converted::EMPTY;
        data
    }

    /// The length of the data object `id` on the clipboard; none for one it does not have.
    pub fn length_of(&self, id: u32) -> Option<usize> {
        self.data_of(id).map(|data| data.len())
    }

    /// The bytes of the data object `id` from `offset` into `out`, as many as fit: how many; none
    /// for an object the clipboard does not have.
    pub fn copy_out(&self, id: u32, offset: usize, out: &mut [u8]) -> Option<usize> {
        let data = self.data_of(id)?;
        let rest = data.get(offset..).unwrap_or(&[]);
        let count = rest.len().min(out.len());
        out[..count].copy_from_slice(&rest[..count]);
        Some(count)
    }

    fn data_of(&self, id: u32) -> Option<&[u8]> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.id == id)
            .and_then(|e| e.data.as_ref())
            .map(bytes)
    }

    /// The process `owner`'s end: the clipboard closed if one of its threads had it open, its
    /// waiting data objects freed. (Its windows go with the process, the owner with them.)
    pub fn process_gone(&mut self, windows: &Windows, owner: class::Owner) {
        if self
            .opener
            .is_some_and(|thread| windows.thread_process(thread) == owner)
        {
            self.release();
        }
        for slot in &mut self.converted {
            if slot.id != 0 && slot.owner == owner {
                *slot = Converted::EMPTY;
            }
        }
    }

    // --- The table

    fn position(&self, format: u32) -> Option<usize> {
        self.entries[..self.count]
            .iter()
            .position(|e| e.format == format)
    }

    fn push(&mut self, format: u32, data: Option<Block>, synthesized: bool) -> Option<()> {
        if self.count == FORMATS {
            return None;
        }
        let id = self.new_id();
        self.entries[self.count] = Entry {
            format,
            id,
            data,
            synthesized,
        };
        self.count += 1;
        Some(())
    }

    /// The synthesised formats taken out, the others kept in their order.
    fn drop_synthesized(&mut self) {
        let mut kept = 0;
        for index in 0..self.count {
            if !self.entries[index].synthesized {
                self.entries.swap(kept, index);
                kept += 1;
            }
        }
        for entry in &mut self.entries[kept..self.count] {
            *entry = Entry::EMPTY;
        }
        self.count = kept;
    }

    /// The text put that the synthesised text formats render from: CF_UNICODETEXT, else CF_TEXT,
    /// else CF_OEMTEXT.
    fn text_source(&self) -> Option<&Entry> {
        [CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT].iter().find_map(|&f| {
            self.entries[..self.count]
                .iter()
                .find(|e| e.format == f && !e.synthesized && e.data.is_some())
        })
    }

    fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }
}

impl Entry {
    fn bytes(&self) -> &[u8] {
        self.data.as_ref().map_or(&[], bytes)
    }
}

/// How many characters the text of `format` in `bytes` has before its NUL (or its block's end).
fn text_units(format: u32, bytes: &[u8]) -> usize {
    if format == CF_UNICODETEXT {
        bytes
            .chunks_exact(2)
            .position(|pair| pair == [0, 0])
            .unwrap_or(bytes.len() / 2)
    } else {
        bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())
    }
}

/// The text of the format `from` in `source` written into `out` in the format `to`, through
/// UTF-16: the ANSI code page's characters for CF_TEXT, the OEM code page's for CF_OEMTEXT
/// (best-fit, the default character for what neither has). `out` is zeroed and long enough for
/// the text and its NUL.
fn convert(from: u32, source: &[u8], to: u32, out: &mut [u8]) {
    let page = |format| {
        if format == CF_OEMTEXT {
            CodePage::Oem
        } else {
            CodePage::Ansi
        }
    };
    for index in 0..text_units(from, source) {
        let unit = match from {
            CF_UNICODETEXT => u16::from_le_bytes([source[2 * index], source[2 * index + 1]]),
            _ => decode_byte(page(from), source[index]),
        };
        match to {
            CF_UNICODETEXT => out[2 * index..2 * index + 2].copy_from_slice(&unit.to_le_bytes()),
            _ => out[index] = encode_unit(page(to), unit, true).unwrap_or(DEFAULT_CHAR),
        }
    }
}

/// The owner's destruction (the window manager's `disown_clipboard` seam): WM_RENDERALLFORMATS
/// sent it, which every destruction of the owner sends (the clipbrd capture's owner section has
/// no format left to render), then the clipboard has no owner; its formats stay.
pub fn disown(windows: &mut Windows, owner: WindowId) {
    send(windows, owner, WM_RENDERALLFORMATS);
    windows.clipboard_owner = None;
}

/// `message` sent to `target` as the window manager sends: queued for its thread, delivered by
/// the thread's next read (`super::queue::defer`).
pub fn send(windows: &mut Windows, target: WindowId, message: u32) {
    let message = Message {
        message,
        wparam: 0,
        lparam: 0,
        payload: Payload::None,
    };
    super::queue::defer(windows, target, &message, 0);
}

// --- The services
// ---------------------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::queue::with_manager;
    use crate::win32k::window::{lock, Failure, WindowManager};
    use crate::win32k::winsta::gui_thread;

    /// NtUserOpenClipboard(Window): the clipboard open for the calling thread, with the window (0
    /// for none; STATUS_INVALID_HANDLE for a handle naming no window); STATUS_ACCESS_DENIED while
    /// another thread has it open.
    pub fn open_clipboard(call: &mut NtCall, window: Handle) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let mut manager = lock(call.passive());
        let WindowManager {
            windows, clipboard, ..
        } = &mut *manager;
        let window = match window.raw() {
            0 => None,
            handle => Some(windows.window_of(handle).map_err(Failure::status)?),
        };
        clipboard.open(caller, window).map_err(Refusal::status)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCloseClipboard(): the clipboard closed.
    pub fn close_clipboard(call: &mut NtCall) -> NtResult {
        let caller = gui_thread(call)?.thread;
        lock(call.passive())
            .clipboard
            .close(caller)
            .map_err(Refusal::status)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserEmptyClipboard(): the clipboard emptied, its owner before sent WM_DESTROYCLIPBOARD.
    pub fn empty_clipboard(call: &mut NtCall) -> NtResult {
        let caller = gui_thread(call)?.thread;
        with_manager(call.passive(), |m| {
            let previous = m.clipboard.empty(&mut m.windows, caller)?;
            if let Some(previous) = previous {
                send(&mut m.windows, previous, WM_DESTROYCLIPBOARD);
            }
            Ok(())
        })
        .map_err(Refusal::status)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserConvertMemHandle(Data, Length, Handle): a data object of the caller's `length` bytes
    /// at `data`, waiting for its NtUserSetClipboardData, into `handle`. STATUS_NO_MEMORY past
    /// [`MAX_DATA`] or when the pool or the waiting objects are full.
    pub fn convert_mem_handle(
        call: &mut NtCall,
        data: UserAddr,
        length: u32,
        handle: UserPtr<u32>,
    ) -> NtResult {
        let owner = gui_thread(call)?.owner;
        if length as usize > MAX_DATA {
            return Err(STATUS_NO_MEMORY);
        }
        let mut block = allocate(length as usize).ok_or(STATUS_NO_MEMORY)?;
        for (index, chunk) in bytes_mut(&mut block).chunks_mut(CHUNK).enumerate() {
            data.offset((index * CHUNK) as u32).read(chunk)?;
        }
        let id = lock(call.passive())
            .clipboard
            .park(owner, block)
            .ok_or(STATUS_NO_MEMORY)?;
        handle.write(id)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserSetClipboardData(Format, Data): the data object `data` put under `format`.
    pub fn set_clipboard_data(call: &mut NtCall, format: u32, data: u32) -> NtResult {
        let thread = gui_thread(call)?;
        lock(call.passive())
            .clipboard
            .set(thread.thread, thread.owner, format, data)
            .map_err(Refusal::status)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetClipboardData(Format, Data, Length): the format's data object and its length into
    /// `data` and `length` (0 and 0 for a format the clipboard has none of), a synthesised format
    /// rendered first, its block taken from the pool outside the lock.
    pub fn get_clipboard_data(
        call: &mut NtCall,
        format: u32,
        data: UserPtr<u32>,
        length: UserPtr<u32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let found = lock(call.passive())
            .clipboard
            .get(caller, format)
            .map_err(Refusal::status)?;
        let (id, bytes) = match found {
            Found::Nothing => (0, 0),
            Found::Data { id, length } => (id, length),
            Found::Render { source, length } => {
                let block = allocate(length).ok_or(STATUS_NO_MEMORY)?;
                lock(call.passive())
                    .clipboard
                    .render(format, source, block)
                    .unwrap_or((0, 0))
            }
        };
        data.write(id)?;
        length.write(bytes as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCreateLocalMemHandle(Data, Buffer, Length, Needed): the data object's length into
    /// `needed`, and its bytes into the caller's buffer when `length` holds them
    /// (STATUS_BUFFER_TOO_SMALL otherwise); STATUS_INVALID_PARAMETER for an object the clipboard
    /// does not have. The bytes go a chunk at a time, each copied out of the lock first.
    pub fn create_local_mem_handle(
        call: &mut NtCall,
        data: u32,
        buffer: UserAddr,
        length: u32,
        needed: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let total = lock(call.passive())
            .clipboard
            .length_of(data)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        needed.write(total as u32)?;
        if (length as usize) < total {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        let mut chunk = [0u8; CHUNK];
        let mut offset = 0;
        while offset < total {
            let count = lock(call.passive())
                .clipboard
                .copy_out(data, offset, &mut chunk)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            if count == 0 {
                break;
            }
            buffer.offset(offset as u32).write(&chunk[..count])?;
            offset += count;
        }
        Ok(STATUS_SUCCESS)
    }

    /// NtUserIsClipboardFormatAvailable(Format, Available): whether the clipboard has the format.
    pub fn is_clipboard_format_available(
        call: &mut NtCall,
        format: u32,
        available: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let answer = lock(call.passive()).clipboard.available(format);
        available.write(answer as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserCountClipboardFormats(Count): how many formats the clipboard has.
    pub fn count_clipboard_formats(call: &mut NtCall, count: UserPtr<u32>) -> NtResult {
        gui_thread(call)?;
        let answer = lock(call.passive()).clipboard.count();
        count.write(answer as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetClipboardOwner(Window): the owner's handle, 0 for none.
    pub fn get_clipboard_owner(call: &mut NtCall, window: UserPtr<u32>) -> NtResult {
        gui_thread(call)?;
        let answer = {
            let manager = lock(call.passive());
            Clipboard::owner(&manager.windows).map_or(0, |w| manager.windows.handle_of(w))
        };
        window.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetOpenClipboardWindow(Window): the window the clipboard is open with, 0 for none.
    pub fn get_open_clipboard_window(call: &mut NtCall, window: UserPtr<u32>) -> NtResult {
        gui_thread(call)?;
        let answer = {
            let manager = lock(call.passive());
            manager
                .clipboard
                .open_window(&manager.windows)
                .map_or(0, |w| manager.windows.handle_of(w))
        };
        window.write(answer)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserRegisterWindowMessage(Name, Atom): the atom of the NUL-terminated name at `name`,
    /// registered (RegisterClipboardFormat's format); STATUS_INVALID_PARAMETER for an empty name
    /// or one longer than an atom's, STATUS_NO_MEMORY when the atom table is full.
    pub fn register_window_message(
        call: &mut NtCall,
        name: UserAddr,
        atom: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        let mut units = [0u16; class::MAX_ATOM_NAME + 1];
        let mut len = 0;
        loop {
            let unit = name.offset(2 * len as u32).cast::<u16>().read()?;
            if unit == 0 {
                break;
            }
            if len == class::MAX_ATOM_NAME {
                return Err(STATUS_INVALID_PARAMETER);
            }
            units[len] = unit;
            len += 1;
        }
        if len == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let answer = lock(call.passive()).classes.register_name(&units[..len]);
        if answer == 0 {
            return Err(STATUS_NO_MEMORY);
        }
        atom.write(answer as u32)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetClipboardFormatName(Format, Name, MaxCount, Copied): the registered format's name,
    /// at most `max` units into `name` with its NUL (the name cut to fit), the units copied before
    /// the NUL into `copied`; STATUS_INVALID_PARAMETER for a predefined format or an atom with no
    /// name.
    pub fn get_clipboard_format_name(
        call: &mut NtCall,
        format: u32,
        name: UserAddr,
        max: u32,
        copied: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        if !(FIRST_REGISTERED..=0xFFFF).contains(&format) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut units = [0u16; class::MAX_ATOM_NAME];
        let len = lock(call.passive())
            .classes
            .atom_name(format as class::Atom, &mut units);
        if len == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let count = len.min((max as usize).saturating_sub(1));
        if max > 0 {
            let mut bytes = [0u8; 2 * (class::MAX_ATOM_NAME + 1)];
            for (pair, unit) in bytes.chunks_exact_mut(2).zip(&units[..count]) {
                pair.copy_from_slice(&unit.to_le_bytes());
            }
            name.write(&bytes[..2 * (count + 1)])?;
        }
        copied.write(count as u32)?;
        Ok(STATUS_SUCCESS)
    }
}

#[cfg(target_arch = "x86")]
pub use services::*;

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the clipboard itself).
#[cfg(not(target_arch = "x86"))]
mod services {
    use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
    use crate::status::*;

    pub fn open_clipboard(_: &mut NtCall, _: Handle) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn close_clipboard(_: &mut NtCall) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn empty_clipboard(_: &mut NtCall) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn convert_mem_handle(_: &mut NtCall, _: UserAddr, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn set_clipboard_data(_: &mut NtCall, _: u32, _: u32) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_clipboard_data(
        _: &mut NtCall,
        _: u32,
        _: UserPtr<u32>,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn create_local_mem_handle(
        _: &mut NtCall,
        _: u32,
        _: UserAddr,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn is_clipboard_format_available(_: &mut NtCall, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn count_clipboard_formats(_: &mut NtCall, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_clipboard_owner(_: &mut NtCall, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_open_clipboard_window(_: &mut NtCall, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn register_window_message(_: &mut NtCall, _: UserAddr, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_clipboard_format_name(
        _: &mut NtCall,
        _: u32,
        _: UserAddr,
        _: u32,
        _: UserPtr<u32>,
    ) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

#[cfg(not(target_arch = "x86"))]
pub use services::*;

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;
    use crate::win32k::queue::rig;
    use crate::win32k::window::WindowManager;

    /// The rig's window manager, with an empty clipboard, a thread and two of its windows.
    fn setup() -> (&'static mut WindowManager, ThreadId, WindowId, WindowId) {
        let (m, atom) = rig::manager();
        let t = rig::thread(m, 1, 0x10);
        let first = rig::popup(m, atom, t);
        let second = rig::popup(m, atom, t);
        rig::deliver(m, t);
        let id = |m: &WindowManager, h| m.windows.window_from_handle(h).unwrap();
        let (first, second) = (id(m, first), id(m, second));
        (m, t, first, second)
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }

    /// Put `bytes` under `format` as user32 does: converted, then set.
    fn put(m: &mut WindowManager, t: ThreadId, format: u32, bytes: &[u8]) -> Result<(), Refusal> {
        let id = m.clipboard.park(rig::OWNER, bytes.to_vec()).unwrap();
        m.clipboard.set(t, rig::OWNER, format, id)
    }

    /// Get `format`'s bytes as the service does: rendered first when synthesised.
    fn get(m: &mut WindowManager, t: ThreadId, format: u32) -> Option<Vec<u8>> {
        let id = match m.clipboard.get(t, format).unwrap() {
            Found::Nothing => return None,
            Found::Data { id, .. } => id,
            Found::Render { source, length } => {
                m.clipboard
                    .render(format, source, allocate(length).unwrap())?
                    .0
            }
        };
        let mut out = std::vec![0; m.clipboard.length_of(id)?];
        m.clipboard.copy_out(id, 0, &mut out)?;
        Some(out)
    }

    fn formats(m: &WindowManager, t: ThreadId) -> Vec<u32> {
        let mut list = Vec::new();
        let mut format = 0;
        loop {
            format = m.clipboard.next_format(t, format).unwrap();
            if format == 0 {
                return list;
            }
            list.push(format);
        }
    }

    /// Open, close, and the calls a closed clipboard refuses (the open section).
    #[test]
    fn the_open_rules() {
        let (m, t, first, _) = setup();
        let other = rig::thread(m, 2, 0x14);
        let c = &mut m.clipboard;
        assert_eq!(c.open(t, Some(first)), Ok(()));
        assert_eq!(c.open_window(&m.windows), Some(first));
        assert_eq!(c.open(t, Some(first)), Ok(()), "open again by its thread");
        assert_eq!(c.open(other, None), Err(Refusal::AccessDenied));
        assert_eq!(c.close(t), Ok(()));
        assert_eq!(c.open_window(&m.windows), None);
        assert_eq!(c.close(t), Err(Refusal::NotOpen));
        assert_eq!(c.empty(&mut m.windows, t), Err(Refusal::NotOpen));
        assert_eq!(
            put(m, t, CF_UNICODETEXT, &utf16("closed")),
            Err(Refusal::NotOpen)
        );
        assert_eq!(m.clipboard.get(t, CF_UNICODETEXT), Err(Refusal::NotOpen));
        assert_eq!(m.clipboard.next_format(t, 0), Err(Refusal::NotOpen));
        assert!(!m.clipboard.available(CF_UNICODETEXT));
        assert!(m.clipboard.converted.iter().all(|c| c.id == 0), "consumed");
    }

    /// EmptyClipboard makes the open window the owner (none for NULL) and names the owner before,
    /// which hears WM_DESTROYCLIPBOARD (the owner section).
    #[test]
    fn emptying_changes_the_owner() {
        let (m, t, first, second) = setup();
        m.clipboard.open(t, None).unwrap();
        assert_eq!(m.clipboard.empty(&mut m.windows, t), Ok(None));
        assert_eq!(Clipboard::owner(&m.windows), None);
        m.clipboard.close(t).unwrap();
        m.clipboard.open(t, Some(first)).unwrap();
        assert_eq!(m.clipboard.empty(&mut m.windows, t), Ok(None));
        assert_eq!(Clipboard::owner(&m.windows), Some(first));
        put(m, t, CF_UNICODETEXT, &utf16("first's")).unwrap();
        m.clipboard.close(t).unwrap();
        m.clipboard.open(t, Some(second)).unwrap();
        assert_eq!(m.clipboard.empty(&mut m.windows, t), Ok(Some(first)));
        assert_eq!(Clipboard::owner(&m.windows), Some(second));
        assert!(!m.clipboard.available(CF_UNICODETEXT));
        assert_eq!(m.clipboard.empty(&mut m.windows, t), Ok(Some(second)));
    }

    /// WM_DESTROYCLIPBOARD reaches the owner as the window manager's own send, which InSendMessage
    /// does not count as another thread's (the clipbrd procedure records it only then).
    #[test]
    fn the_owner_hears_of_the_empty_from_its_own_thread() {
        use crate::win32k::queue::{end_sent, in_send, Filter, Taken};
        let (m, t, first, second) = setup();
        m.clipboard.open(t, Some(first)).unwrap();
        m.clipboard.empty(&mut m.windows, t).unwrap();
        m.clipboard.open(t, Some(second)).unwrap();
        let previous = m.clipboard.empty(&mut m.windows, t).unwrap().unwrap();
        send(&mut m.windows, previous, WM_DESTROYCLIPBOARD);
        let only_sent = Filter::new(0, 0, 0, rtl::user::PM_QS_SENDMESSAGE);
        assert!(matches!(rig::read(m, t, &only_sent, 0), Taken::Sent(_)));
        assert!(!in_send(&m.windows, t));
        assert!(end_sent(&mut m.windows, t, 0));
        assert!(!in_send(&m.windows, t), "nothing being delivered");
    }

    /// The owner's destruction sends it WM_RENDERALLFORMATS and leaves the clipboard ownerless,
    /// its text still there.
    #[test]
    fn the_owner_destroyed_leaves_the_data() {
        let (m, t, first, _) = setup();
        m.clipboard.open(t, Some(first)).unwrap();
        m.clipboard.empty(&mut m.windows, t).unwrap();
        put(m, t, CF_UNICODETEXT, &utf16("kept")).unwrap();
        m.clipboard.close(t).unwrap();
        let handle = m.windows.handle_of(first);
        let WindowManager {
            windows, classes, ..
        } = m;
        windows
            .destroy_window_handle(classes, t, handle, &mut crate::win32k::queue::QueuePump)
            .unwrap();
        let delivered = rig::deliver(m, t);
        assert_eq!(delivered.first(), Some(&(handle, WM_RENDERALLFORMATS)));
        assert_eq!(Clipboard::owner(&m.windows), None);
        assert!(m.clipboard.available(CF_UNICODETEXT));
    }

    /// CF_UNICODETEXT put: the close synthesises CF_LOCALE, CF_TEXT and CF_OEMTEXT after it, each
    /// rendered through its code page at its first get (the unicode section).
    #[test]
    fn unicode_text_synthesises_the_others() {
        let (m, t, first, _) = setup();
        m.clipboard.open(t, Some(first)).unwrap();
        m.clipboard.empty(&mut m.windows, t).unwrap();
        put(m, t, CF_UNICODETEXT, &utf16("caf\u{e9} \u{4e00}!\r\n")).unwrap();
        assert_eq!(m.clipboard.count(), 1, "nothing synthesised while open");
        assert_eq!(formats(m, t), [CF_UNICODETEXT]);
        m.clipboard.close(t).unwrap();
        assert_eq!(m.clipboard.count(), 4);
        for format in [CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT, CF_LOCALE] {
            assert!(m.clipboard.available(format));
        }
        assert!(!m.clipboard.available(2), "CF_BITMAP");
        m.clipboard.open(t, Some(first)).unwrap();
        assert_eq!(
            formats(m, t),
            [CF_UNICODETEXT, CF_LOCALE, CF_TEXT, CF_OEMTEXT]
        );
        assert_eq!(get(m, t, CF_TEXT).unwrap(), b"caf\xe9 ?!\r\n\0");
        assert_eq!(get(m, t, CF_OEMTEXT).unwrap(), b"caf\x82 ?!\r\n\0");
        assert_eq!(get(m, t, CF_LOCALE).unwrap(), 0x0409u32.to_le_bytes());
        assert_eq!(
            get(m, t, CF_TEXT).unwrap(),
            b"caf\xe9 ?!\r\n\0",
            "rendered once"
        );
        assert_eq!(get(m, t, 2), None);
    }

    /// CF_TEXT and CF_OEMTEXT put: the others render from them (the text section); with
    /// CF_UNICODETEXT put too, CF_OEMTEXT renders from it (the formats section).
    #[test]
    fn narrow_text_synthesises_the_others() {
        let (m, t, first, _) = setup();
        m.clipboard.open(t, Some(first)).unwrap();
        m.clipboard.empty(&mut m.windows, t).unwrap();
        put(m, t, CF_OEMTEXT, b"Caf\x82 oem\0").unwrap();
        m.clipboard.close(t).unwrap();
        m.clipboard.open(t, Some(first)).unwrap();
        assert_eq!(get(m, t, CF_TEXT).unwrap(), b"Caf\xe9 oem\0");
        assert_eq!(get(m, t, CF_UNICODETEXT).unwrap(), utf16("Caf\u{e9} oem"));
        m.clipboard.empty(&mut m.windows, t).unwrap();
        put(m, t, CF_TEXT, b"ansi\0").unwrap();
        put(m, t, CF_UNICODETEXT, &utf16("wide")).unwrap();
        put(m, t, 0xC123, &[1, 2, 3, 4]).unwrap();
        assert_eq!(formats(m, t), [CF_TEXT, CF_UNICODETEXT, 0xC123]);
        m.clipboard.close(t).unwrap();
        m.clipboard.open(t, Some(first)).unwrap();
        assert_eq!(
            formats(m, t),
            [CF_TEXT, CF_UNICODETEXT, 0xC123, CF_LOCALE, CF_OEMTEXT]
        );
        assert_eq!(get(m, t, CF_TEXT).unwrap(), b"ansi\0");
        assert_eq!(get(m, t, CF_OEMTEXT).unwrap(), b"wide\0");
        assert_eq!(get(m, t, 0xC123).unwrap(), [1, 2, 3, 4]);
    }

    /// A put replaces the format's data in its place; a put of text drops the synthesised formats.
    #[test]
    fn a_put_replaces_in_place() {
        let (m, t, first, _) = setup();
        m.clipboard.open(t, Some(first)).unwrap();
        m.clipboard.empty(&mut m.windows, t).unwrap();
        put(m, t, CF_TEXT, b"one\0").unwrap();
        m.clipboard.close(t).unwrap();
        m.clipboard.open(t, Some(first)).unwrap();
        put(m, t, CF_TEXT, b"two\0").unwrap();
        assert_eq!(formats(m, t), [CF_TEXT]);
        m.clipboard.close(t).unwrap();
        m.clipboard.open(t, Some(first)).unwrap();
        assert_eq!(get(m, t, CF_UNICODETEXT).unwrap(), utf16("two"));
    }

    /// A data object is put only by its own process, and once.
    #[test]
    fn a_data_object_is_its_process_s() {
        let (m, t, _, _) = setup();
        m.clipboard.open(t, None).unwrap();
        let id = m.clipboard.park(rig::OTHER_OWNER, b"x\0".to_vec()).unwrap();
        assert_eq!(
            m.clipboard.set(t, rig::OWNER, CF_TEXT, id),
            Err(Refusal::InvalidParameter)
        );
        let id = m.clipboard.park(rig::OWNER, b"x\0".to_vec()).unwrap();
        assert_eq!(m.clipboard.set(t, rig::OWNER, CF_TEXT, id), Ok(()));
        assert_eq!(
            m.clipboard.set(t, rig::OWNER, CF_TEXT, id),
            Err(Refusal::InvalidParameter)
        );
    }

    /// A process's end closes the clipboard its thread had open and frees its waiting objects.
    #[test]
    fn a_process_end_closes_it() {
        let (m, t, _, _) = setup();
        m.clipboard.open(t, None).unwrap();
        m.clipboard.park(rig::OWNER, b"x\0".to_vec()).unwrap();
        m.clipboard.process_gone(&m.windows, rig::OWNER);
        assert!(m.clipboard.converted.iter().all(|c| c.id == 0));
        let other = rig::thread(m, 2, 0x14);
        assert_eq!(m.clipboard.open(other, None), Ok(()));
    }

    /// Registered names: one atom whatever their case, in the string atoms' range.
    #[test]
    fn registered_names_ignore_case() {
        let (m, _, _, _) = setup();
        let name: Vec<u16> = "F2K Clipbrd Format".encode_utf16().collect();
        let lower: Vec<u16> = "f2k clipbrd format".encode_utf16().collect();
        let atom = m.classes.register_name(&name);
        assert!(atom as u32 >= FIRST_REGISTERED);
        assert_eq!(m.classes.register_name(&lower), atom);
        let mut out = [0u16; 64];
        let len = m.classes.atom_name(atom, &mut out);
        assert_eq!(&out[..len], &name[..]);
        assert_eq!(m.classes.register_name(&[]), 0);
    }
}
