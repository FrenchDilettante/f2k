//! The runtime library's calls (strings, version, time, bitmaps, messages, handle tables,
//! environment), as ntdll runs them over rtl.

use std::cell::RefCell;

use rtl::host::string_block;

/// ntdll's string calls, over the stand-in heap (rtl::string, as ntdll runs them).
pub unsafe extern "system" fn RtlInitAnsiString(
    destination: *mut crate::nt::AnsiString,
    source: *const u8,
) {
    // SAFETY: the caller's string and structure.
    unsafe { destination.write(rtl::string::init_ansi_string(source)) };
}

pub unsafe extern "system" fn RtlUpcaseUnicodeString(
    destination: *mut crate::nt::UnicodeString,
    source: *const crate::nt::UnicodeString,
    allocate: u32,
) -> u32 {
    // SAFETY: the caller's strings, the source read whole first (the two may be one).
    unsafe {
        let source = source.read();
        rtl::string::upcase_unicode_string(
            &mut *destination,
            &source,
            allocate as u8 != 0,
            string_block,
        )
    }
}

pub unsafe extern "system" fn RtlUnicodeStringToInteger(
    text: *const crate::nt::UnicodeString,
    base: u32,
    value: *mut u32,
) -> u32 {
    // SAFETY: the caller's string, its buffer holding its length.
    match rtl::string::unicode_string_to_integer(unsafe { (*text).units() }, base) {
        Ok(number) => {
            // SAFETY: the caller's place.
            unsafe { value.write(number) };
            0
        }
        Err(status) => status,
    }
}

/// ntdll's version check (rtl::version, as ntdll runs it) against Windows 2000 service pack 4,
/// a workstation.
pub unsafe extern "system" fn RtlVerifyVersionInfo(
    info: *const crate::nt::OsVersionInfoExW,
    types: u32,
    mask: u64,
) -> u32 {
    use rtl::version::{verify, Refusal, VersionInfo};
    // SAFETY: the caller's structure.
    let info = unsafe { info.read() };
    let system = VersionInfo {
        major: 5,
        minor: 0,
        build: 2195,
        platform: 2,
        service_pack_major: 4,
        service_pack_minor: 0,
        suite_mask: 0,
        product_type: 1,
    };
    let wanted = VersionInfo {
        major: info.major,
        minor: info.minor,
        build: info.build,
        platform: info.platform,
        service_pack_major: info.service_pack_major,
        service_pack_minor: info.service_pack_minor,
        suite_mask: info.suite_mask,
        product_type: info.product_type,
    };
    match verify(&system, &wanted, types, mask) {
        Ok(()) => 0,
        Err(Refusal::NoType) => 0xC000_000D,
        Err(Refusal::Mismatch) => 0xC000_0059,
    }
}

/// ntdll's time conversions (rtl::time, as ntdll runs them).
pub unsafe extern "system" fn RtlTimeToTimeFields(
    time: *const i64,
    fields: *mut crate::nt::TimeFields,
) {
    // SAFETY: the caller's time and structure.
    unsafe { fields.write(rtl::time::time_to_time_fields(time.read_unaligned())) };
}

pub unsafe extern "system" fn RtlTimeFieldsToTime(
    fields: *const crate::nt::TimeFields,
    time: *mut i64,
) -> u8 {
    // SAFETY: the caller's structure and time.
    match rtl::time::time_fields_to_time(unsafe { &*fields }) {
        Some(converted) => {
            unsafe { time.write_unaligned(converted) };
            1
        }
        None => 0,
    }
}

/// The RTL_BITMAP at `header`'s dwords and size: the PEB's TLS bitmaps' headers as the stand-in
/// process keeps them.
fn bitmap_bits(header: *const crate::nt::RtlBitmap) -> (&'static mut [u32], u32) {
    // SAFETY: one of the stand-in process's headers, over its PEB's bit arrays, its size's
    // bits.
    unsafe {
        let size = (*header).size_of_bit_map;
        let bits = core::slice::from_raw_parts_mut((*header).buffer, rtl::bitmap::words(size));
        (bits, size)
    }
}

/// ntdll's bitmap calls (rtl::bitmap, as ntdll runs them).
pub unsafe extern "system" fn RtlFindClearBitsAndSet(
    bitmap: *mut crate::nt::RtlBitmap,
    count: u32,
    hint: u32,
) -> u32 {
    let (bits, size) = bitmap_bits(bitmap);
    rtl::bitmap::find_clear_and_set(bits, size, count, hint)
}

pub unsafe extern "system" fn RtlClearBits(
    bitmap: *mut crate::nt::RtlBitmap,
    start: u32,
    count: u32,
) {
    let (bits, size) = bitmap_bits(bitmap);
    rtl::bitmap::clear(bits, size, start, count);
}

pub unsafe extern "system" fn RtlAreBitsSet(
    bitmap: *const crate::nt::RtlBitmap,
    start: u32,
    length: u32,
) -> u8 {
    let (bits, size) = bitmap_bits(bitmap);
    u8::from(rtl::bitmap::are_set(bits, size, start, length))
}

/// kernel32's message table, as its build makes it from messages.txt (the bytes it links into
/// the DLL as its RT_MESSAGETABLE resource), dword-aligned as in the image.
#[repr(C, align(4))]
struct Aligned<T: ?Sized>(T);
static MESSAGE_TABLE: &Aligned<[u8]> =
    &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/messages.bin")));

/// The table's bytes, read by offset (`rtl::resource`'s reads, the table at offset zero).
struct TableBytes;

impl rtl::modules::Memory for TableBytes {
    fn byte(&self, at: u32) -> u8 {
        MESSAGE_TABLE.0[at as usize]
    }
}

/// RtlFindMessage, over kernel32's own table whatever the module (the resource walk is
/// `rtl::resource`'s, tested there): the table is US English, so a language whose search does
/// not reach US English is STATUS_RESOURCE_LANG_NOT_FOUND.
pub unsafe extern "system" fn RtlFindMessage(
    _module: usize,
    table: u32,
    language: u32,
    id: u32,
    entry: *mut *const u8,
) -> u32 {
    use rtl::resource::{self, Defaults, LANG_ENGLISH_US};
    if table != resource::RT_MESSAGETABLE {
        return rtl::status::STATUS_RESOURCE_TYPE_NOT_FOUND;
    }
    let (languages, count, any) = resource::languages(language as u16, Defaults::F2K);
    if !any && !languages[..count].contains(&LANG_ENGLISH_US) {
        return rtl::status::STATUS_RESOURCE_LANG_NOT_FOUND;
    }
    let size = MESSAGE_TABLE.0.len() as u32;
    match resource::message_entry(&TableBytes, 0, size, id) {
        Ok(offset) => {
            // SAFETY: the caller's pointer place.
            unsafe { entry.write(MESSAGE_TABLE.0.as_ptr().add(offset as usize)) };
            0
        }
        Err(status) => status,
    }
}

/// RtlFormatMessage (rtl::message, as ntdll runs it).
pub unsafe extern "system" fn RtlFormatMessage(
    format: *const u16,
    width: u32,
    ignore_inserts: u32,
    ansi: u32,
    array: u32,
    arguments: *const u8,
    buffer: *mut u16,
    length: u32,
    return_length: *mut u32,
) -> u32 {
    let mut units = std::vec::Vec::new();
    // SAFETY: the caller's string, read to its NUL.
    while let unit @ 1.. = unsafe { (format as *const u16).add(units.len()).read_unaligned() } {
        units.push(unit);
    }
    let arguments = (!arguments.is_null()).then(|| rtl::message::Arguments {
        slots: if array as u8 != 0 {
            arguments as *const usize
        } else {
            // SAFETY: a va_list's address.
            unsafe { (arguments as *const *const usize).read_unaligned() }
        },
        ansi: ansi as u8 != 0,
    });
    // SAFETY: the caller's buffer, `length` bytes.
    let out = unsafe { core::slice::from_raw_parts_mut(buffer, length as usize / 2) };
    match rtl::message::format(&units, width, ignore_inserts as u8 != 0, arguments, out) {
        Ok(written) => {
            if !return_length.is_null() {
                // SAFETY: the caller's count.
                unsafe { return_length.write(2 * (written as u32 + 1)) };
            }
            0
        }
        Err(status) => status,
    }
}

/// The handle tables' memory: page-aligned host allocations, never given back.
struct HostVm;

impl rtl::heap::Vm for HostVm {
    fn reserve(&self, size: usize) -> Option<usize> {
        let layout = std::alloc::Layout::from_size_align(size, rtl::heap::PAGE).ok()?;
        // SAFETY: a nonzero, page-aligned layout.
        Some(unsafe { std::alloc::alloc_zeroed(layout) } as usize).filter(|&base| base != 0)
    }

    fn commit(&self, _base: usize, _size: usize) -> bool {
        true
    }

    fn release(&self, _base: usize) {}
}

/// ntdll's handle-table calls (rtl::handles, as ntdll runs them), over host memory.
pub unsafe extern "system" fn RtlInitializeHandleTable(
    maximum: u32,
    size: u32,
    table: *mut crate::nt::HandleTable,
) {
    // SAFETY: the caller's table.
    unsafe { &mut *table }.initialize(maximum, size);
}

pub unsafe extern "system" fn RtlAllocateHandle(
    table: *mut crate::nt::HandleTable,
    index: *mut u32,
) -> usize {
    // SAFETY: the caller's table.
    match unsafe { &mut *table }.allocate(&HostVm) {
        Some((entry, number)) => {
            if !index.is_null() {
                // SAFETY: the caller's index.
                unsafe { index.write(number) };
            }
            entry
        }
        None => 0,
    }
}

pub unsafe extern "system" fn RtlFreeHandle(
    table: *mut crate::nt::HandleTable,
    entry: usize,
) -> u8 {
    // SAFETY: the caller's table.
    u8::from(unsafe { &mut *table }.free(entry))
}

pub unsafe extern "system" fn RtlIsValidHandle(
    table: *const crate::nt::HandleTable,
    entry: usize,
) -> u8 {
    // SAFETY: the caller's table.
    u8::from(unsafe { &*table }.is_valid(entry))
}

/// RtlLockHeap and RtlUnlockHeap: the stand-in heap is the host's allocator, its own lock.
pub unsafe extern "system" fn RtlLockHeap(_heap: usize) -> u8 {
    1
}

pub unsafe extern "system" fn RtlUnlockHeap(_heap: usize) -> u8 {
    1
}

std::thread_local! {
    /// The environment block, as ntdll keeps it (an empty one to start; room for the tests).
    pub static ENVIRONMENT: RefCell<std::vec::Vec<u16>> = RefCell::new(std::vec![0; 4096]);
}

/// The environment block's address.
pub fn environment_block() -> *mut u16 {
    ENVIRONMENT.with(|block| block.borrow_mut().as_mut_ptr())
}

/// ntdll's environment functions over the stand-in's block (rtl::env, as ntdll runs them).
pub unsafe extern "system" fn RtlQueryEnvironmentVariable_U(
    _environment: *mut u16,
    name: *const crate::nt::UnicodeString,
    value: *mut crate::nt::UnicodeString,
) -> u32 {
    ENVIRONMENT.with(|block| {
        let block = block.borrow();
        // SAFETY: the caller's strings.
        let Some(found) = rtl::env::query(&block, unsafe { (*name).units() }) else {
            return rtl::status::STATUS_VARIABLE_NOT_FOUND;
        };
        let value = unsafe { &mut *value };
        value.length = (2 * found.len()) as u16;
        if 2 * found.len() > value.maximum_length as usize {
            return rtl::status::STATUS_BUFFER_TOO_SMALL;
        }
        // SAFETY: the caller's buffer.
        unsafe {
            value
                .buffer
                .copy_from_nonoverlapping(found.as_ptr(), found.len())
        };
        0
    })
}

pub unsafe extern "system" fn RtlSetEnvironmentVariable(
    _environment: *mut *mut u16,
    name: *const crate::nt::UnicodeString,
    value: *const crate::nt::UnicodeString,
) -> u32 {
    ENVIRONMENT.with(|block| {
        // SAFETY: the caller's strings.
        let (name, value) = unsafe {
            (
                (*name).units(),
                (!value.is_null()).then(|| (*value).units()),
            )
        };
        match rtl::env::set(&mut block.borrow_mut(), name, value) {
            Ok(()) => 0,
            Err(rtl::env::EnvError::InvalidName) => rtl::status::STATUS_INVALID_PARAMETER,
            Err(rtl::env::EnvError::NotFound) => rtl::status::STATUS_VARIABLE_NOT_FOUND,
            Err(rtl::env::EnvError::NeedsRoom(_)) => rtl::status::STATUS_NO_MEMORY,
        }
    })
}

pub unsafe extern "system" fn RtlExpandEnvironmentStrings_U(
    _environment: *mut u16,
    source: *const crate::nt::UnicodeString,
    destination: *mut crate::nt::UnicodeString,
    returned: *mut u32,
) -> u32 {
    ENVIRONMENT.with(|block| {
        let block = block.borrow();
        let mut out = std::vec::Vec::new();
        // SAFETY: the caller's strings.
        rtl::env::expand(&block, unsafe { (*source).units() }, |unit| out.push(unit));
        let destination = unsafe { &mut *destination };
        // SAFETY: the caller's count.
        unsafe { returned.write((2 * (out.len() + 1)) as u32) };
        if out.len() >= destination.maximum_length as usize / 2 {
            return rtl::status::STATUS_BUFFER_TOO_SMALL;
        }
        // SAFETY: the caller's buffer holds the expansion and its terminator.
        unsafe {
            destination
                .buffer
                .copy_from_nonoverlapping(out.as_ptr(), out.len());
            destination.buffer.add(out.len()).write(0);
        }
        destination.length = (2 * out.len()) as u16;
        0
    })
}
