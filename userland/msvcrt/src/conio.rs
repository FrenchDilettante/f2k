//! Console input, conio.h's: `_kbhit` and `_getch`, over the console's input records (kernel32's
//! console input calls, on the console's input buffer opened as `CONIN$`).
//!
//! A key counts when it goes down and gives a character, or is one of the extended keys (the
//! function keys, the arrows and the navigation keys): the rest of the records (key releases,
//! a lone Shift, mouse and focus events) are passed over. `_getch` answers an extended key in two
//! calls, as the PC BIOS reports it: 0xE0 for one of the enhanced keys (the separate arrow and
//! navigation keys, ENHANCED_KEY) or 0 for the others (the function keys, the keypad's), then its
//! code (fd's capture: Up `0xE0 0x48`, F1 `0x00 0x3B`), which `_kbhit` counts as waiting.
//!
//! The console input has a lock of its own, apart from the C runtime's: a `_getch` waiting for a
//! key keeps other threads from the console's input, not from the rest of the C runtime.

use crate::data::Global;
use crate::imports;

/// The console's input buffer, opened on the first need (none yet: 0; not to be had:
/// INVALID_HANDLE_VALUE).
static INPUT: Global<usize> = Global::new(0);

/// An extended key's code, answered by the next `_getch` (none: 0x100).
static PENDING: Global<u16> = Global::new(NONE);
const NONE: u16 = 0x100;

/// The console input's lock: a CRITICAL_SECTION (24 bytes), initialized with the DLL.
static LOCK: Global<[usize; 8]> = Global::new([0; 8]);

/// EOF: `_getch`'s answer when there is no console input to read.
const EOF: i32 = -1;

/// An INPUT_RECORD: its size and a key event's fields (KEY_EVENT_RECORD at 4).
const RECORD_SIZE: usize = 20;
const KEY_EVENT: u16 = 1;

/// dwControlKeyState's flags.
const RIGHT_ALT_PRESSED: u32 = 0x0001;
const LEFT_ALT_PRESSED: u32 = 0x0002;
const RIGHT_CTRL_PRESSED: u32 = 0x0004;
const LEFT_CTRL_PRESSED: u32 = 0x0008;
const SHIFT_PRESSED: u32 = 0x0010;
const ENHANCED_KEY: u32 = 0x0100;

/// CreateFileA's arguments for `CONIN$`: read and write access, shared both ways, the device as it
/// is.
const GENERIC_READ_WRITE: u32 = 0xC000_0000;
const FILE_SHARE_READ_WRITE: u32 = 3;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE: usize = usize::MAX;

/// The extended keys, by virtual-key code: the codes the PC BIOS gives each alone, with Shift,
/// with Ctrl and with Alt.
const EXTENDED: [(u16, [u8; 4]); 22] = [
    (0x21, [0x49, 0x49, 0x84, 0x99]), // Page Up
    (0x22, [0x51, 0x51, 0x76, 0xA1]), // Page Down
    (0x23, [0x4F, 0x4F, 0x75, 0x9F]), // End
    (0x24, [0x47, 0x47, 0x77, 0x97]), // Home
    (0x25, [0x4B, 0x4B, 0x73, 0x9B]), // Left
    (0x26, [0x48, 0x48, 0x8D, 0x98]), // Up
    (0x27, [0x4D, 0x4D, 0x74, 0x9D]), // Right
    (0x28, [0x50, 0x50, 0x91, 0xA0]), // Down
    (0x2D, [0x52, 0x52, 0x92, 0xA2]), // Insert
    (0x2E, [0x53, 0x53, 0x93, 0xA3]), // Delete
    (0x70, [0x3B, 0x54, 0x5E, 0x68]), // F1
    (0x71, [0x3C, 0x55, 0x5F, 0x69]), // F2
    (0x72, [0x3D, 0x56, 0x60, 0x6A]), // F3
    (0x73, [0x3E, 0x57, 0x61, 0x6B]), // F4
    (0x74, [0x3F, 0x58, 0x62, 0x6C]), // F5
    (0x75, [0x40, 0x59, 0x63, 0x6D]), // F6
    (0x76, [0x41, 0x5A, 0x64, 0x6E]), // F7
    (0x77, [0x42, 0x5B, 0x65, 0x6F]), // F8
    (0x78, [0x43, 0x5C, 0x66, 0x70]), // F9
    (0x79, [0x44, 0x5D, 0x67, 0x71]), // F10
    (0x7A, [0x85, 0x87, 0x89, 0x8B]), // F11
    (0x7B, [0x86, 0x88, 0x8A, 0x8C]), // F12
];

/// What a record gives `_getch`: a character, or an extended key's prefix and code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Character(u8),
    Extended(u8, u8),
}

/// The key an input record (an INPUT_RECORD from ReadConsoleInputA) gives, or none for a record
/// that does not count (not a key, a release, a key of neither a character nor an extended code).
pub fn key(record: &[u8; RECORD_SIZE]) -> Option<Key> {
    let half = |at: usize| u16::from_le_bytes([record[at], record[at + 1]]);
    let word = |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().unwrap());
    if half(0) != KEY_EVENT || word(4) == 0 {
        return None;
    }
    let (virtual_key, character, state) = (half(10), record[14], word(16));
    if character != 0 {
        return Some(Key::Character(character));
    }
    let (_, codes) = EXTENDED.iter().find(|(key, _)| *key == virtual_key)?;
    let code = if state & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0 {
        codes[3]
    } else if state & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0 {
        codes[2]
    } else if state & SHIFT_PRESSED != 0 {
        codes[1]
    } else {
        codes[0]
    };
    let prefix = if state & ENHANCED_KEY != 0 { 0xE0 } else { 0 };
    Some(Key::Extended(prefix, code))
}

/// The DLL's process attach: the console input's lock.
pub fn initialize() {
    // SAFETY: kernel32's export; the lock's storage is the DLL's own.
    unsafe { imports::InitializeCriticalSection(LOCK.get().cast()) };
}

/// The console input's lock, held for the guard's life.
struct Held(());

impl Held {
    fn take() -> Held {
        // SAFETY: kernel32's export, over the DLL's own critical section.
        unsafe { imports::EnterCriticalSection(LOCK.get().cast()) };
        Held(())
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        // SAFETY: as above; the guard took it.
        unsafe { imports::LeaveCriticalSection(LOCK.get().cast()) };
    }
}

/// The console's input buffer, opened as `CONIN$` on the first call; none when there is no console.
fn input() -> Option<usize> {
    if INPUT.read() == 0 {
        // SAFETY: kernel32's export, over a NUL-terminated name.
        let handle = unsafe {
            imports::CreateFileA(
                c"CONIN$".as_ptr().cast(),
                GENERIC_READ_WRITE,
                FILE_SHARE_READ_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        INPUT.write(handle);
    }
    Some(INPUT.read()).filter(|&handle| handle != INVALID_HANDLE)
}

/// _kbhit: nonzero when a key is waiting, a record that counts or an extended key's code; the
/// waiting records stay as they are, for `_getch` (or ReadConsoleInput) to read.
#[unsafe(export_name = "f2k_export__kbhit")]
pub extern "C" fn kbhit() -> i32 {
    let _lock = Held::take();
    if PENDING.read() != NONE {
        return 1;
    }
    let Some(handle) = input() else {
        return 0;
    };
    let mut count = 0u32;
    // SAFETY: kernel32's export, over a dword.
    if unsafe { imports::GetNumberOfConsoleInputEvents(handle, &mut count) } == 0 || count == 0 {
        return 0;
    }
    let records = crate::heap::allocate(count as usize * RECORD_SIZE, false);
    if records.is_null() {
        return 0;
    }
    let mut peeked = 0u32;
    // SAFETY: kernel32's export, over the block of `count` records.
    let waiting = if unsafe { imports::PeekConsoleInputA(handle, records, count, &mut peeked) } != 0
    {
        // SAFETY: the block holds the `peeked` records PeekConsoleInputA copied.
        let bytes = unsafe {
            core::slice::from_raw_parts(records, peeked.min(count) as usize * RECORD_SIZE)
        };
        bytes
            .as_chunks::<RECORD_SIZE>()
            .0
            .iter()
            .any(|record| key(record).is_some())
    } else {
        false
    };
    // SAFETY: the block from the C runtime's heap, given back.
    unsafe { crate::heap::release(records) };
    i32::from(waiting)
}

/// _getch: the next key's character, read without echo (the console's input in raw mode for the
/// read), waiting for one; an extended key's prefix (0 or 0xE0), its code at the next call. The
/// records that do not count are read and dropped. EOF when there is no console input to read.
#[unsafe(export_name = "f2k_export__getch")]
pub extern "C" fn getch() -> i32 {
    let _lock = Held::take();
    let pending = PENDING.read();
    if pending != NONE {
        PENDING.write(NONE);
        return i32::from(pending);
    }
    let Some(handle) = input() else {
        return EOF;
    };
    let mut mode = 0u32;
    // SAFETY: kernel32's exports, over the console's input buffer.
    let restore = unsafe { imports::GetConsoleMode(handle, &mut mode) } != 0;
    if restore {
        // SAFETY: as above.
        unsafe { imports::SetConsoleMode(handle, 0) };
    }
    let mut record = [0u8; RECORD_SIZE];
    let answer = loop {
        let mut read = 0u32;
        // SAFETY: kernel32's export, over one record.
        if unsafe { imports::ReadConsoleInputA(handle, record.as_mut_ptr(), 1, &mut read) } == 0
            || read == 0
        {
            break EOF;
        }
        match key(&record) {
            Some(Key::Character(character)) => break i32::from(character),
            Some(Key::Extended(prefix, code)) => {
                PENDING.write(u16::from(code));
                break i32::from(prefix);
            }
            None => {}
        }
    };
    if restore {
        // SAFETY: kernel32's export, the mode as it was.
        unsafe { imports::SetConsoleMode(handle, mode) };
    }
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key event's record, as fd's fixture queues them.
    fn record(down: bool, virtual_key: u16, scan: u16, character: u8, state: u32) -> [u8; 20] {
        let mut record = [0u8; RECORD_SIZE];
        record[0..2].copy_from_slice(&KEY_EVENT.to_le_bytes());
        record[4..8].copy_from_slice(&u32::from(down).to_le_bytes());
        record[8..10].copy_from_slice(&1u16.to_le_bytes());
        record[10..12].copy_from_slice(&virtual_key.to_le_bytes());
        record[12..14].copy_from_slice(&scan.to_le_bytes());
        record[14] = character;
        record[16..20].copy_from_slice(&state.to_le_bytes());
        record
    }

    /// fd's capture: each key pressed and released, the presses with a character or an extended
    /// code counting (Up, an enhanced key, `0xE0 0x48`; F1 `0x00 0x3B`), the releases and a lone
    /// Shift not.
    #[test]
    fn the_keys_count_as_the_capture_reads_them() {
        let keys = [
            (0x41, 0x1E, b'a', 0, Some(Key::Character(0x61))),
            (0x10, 0x2A, 0, SHIFT_PRESSED, None),
            (0x5A, 0x2C, b'Z', SHIFT_PRESSED, Some(Key::Character(0x5A))),
            (0x0D, 0x1C, b'\r', 0, Some(Key::Character(0x0D))),
            (0x1B, 0x01, 0x1B, 0, Some(Key::Character(0x1B))),
            (0x26, 0x48, 0, ENHANCED_KEY, Some(Key::Extended(0xE0, 0x48))),
            (0x70, 0x3B, 0, 0, Some(Key::Extended(0, 0x3B))),
        ];
        for (virtual_key, scan, character, state, expected) in keys {
            assert_eq!(
                key(&record(true, virtual_key, scan, character, state)),
                expected,
                "{virtual_key:#x} down"
            );
            assert_eq!(
                key(&record(false, virtual_key, scan, character, state)),
                None,
                "{virtual_key:#x} up"
            );
        }
    }

    /// The modifiers choose an extended key's code (Alt over Ctrl over Shift); a record that is
    /// not a key event never counts.
    #[test]
    fn the_modifiers_choose_the_code() {
        assert_eq!(
            key(&record(true, 0x70, 0x3B, 0, SHIFT_PRESSED)),
            Some(Key::Extended(0, 0x54))
        );
        assert_eq!(
            key(&record(
                true,
                0x25,
                0x4B,
                0,
                LEFT_CTRL_PRESSED | ENHANCED_KEY
            )),
            Some(Key::Extended(0xE0, 0x73))
        );
        assert_eq!(
            key(&record(
                true,
                0x7B,
                0x58,
                0,
                RIGHT_ALT_PRESSED | LEFT_CTRL_PRESSED
            )),
            Some(Key::Extended(0, 0x8C))
        );
        let mut mouse = record(true, 0x41, 0x1E, b'a', 0);
        mouse[0] = 2;
        assert_eq!(key(&mouse), None);
    }
}
