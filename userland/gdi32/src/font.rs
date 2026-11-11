//! Fonts: the font files a program loads (AddFontResource and AddFontResourceEx, their
//! removals), the font objects (CreateFont, CreateFontIndirect, GetObject of one), what a DC's
//! font answers (its face name, its outline metrics, its characters' widths and ABC spacing, its
//! tables' bytes, its glyphs), and the enumeration of the faces loaded, each over its win32k
//! service ([`imports`]); the kernel's fonts module (kernel/src/win32k/fonts) does the work. The
//! narrow forms convert their strings in the ANSI code page, as the text calls do.
//!
//! A font file's name is resolved here, before the kernel sees it, through kernel32's SearchPathW
//! as Windows 2000's gdi32 imports it: a bare file name is looked for in the system's Fonts
//! directory first, then along the search path (the current directory on it); a name with a path
//! along the search path alone. The file found is opened for reading through ntdll
//! (RtlDosPathNameToNtPathName_U and NtOpenFile, which touch no last error) and its handle handed
//! to the kernel, which reads the file and keeps its bytes; the handle is closed before the call
//! returns. The capture of Windows 2000 shows the look in the Fonts directory: every load and
//! removal of the fixture's file, which is not there, leaves ERROR_FILE_NOT_FOUND as the last
//! error, whether it succeeds or not (an assumption: the look is how the capture's last error
//! comes about).

use rtl::edge::{In, InStr, InWStr, OutBuf};
use rtl::gdi::*;
use rtl::pod::Pod;

use crate::imports::{self, Caller, OpenFile};
use crate::{answered, failed, stub, ERROR_INVALID_PARAMETER};

/// MAX_PATH: the longest font file name, its terminator included.
const MAX_PATH: usize = 260;

/// The Fonts directory, under the system root.
const FONTS: &str = "\\Fonts";

/// AddFontResourceEx's flag the kernel takes: FR_PRIVATE.
const FR_PRIVATE: u32 = 0x10;

/// NtGdiEnumFontChunk's flag for EnumFontFamilies' enumeration: each face once.
const ENUM_FAMILIES: u32 = 1;

/// GetGlyphOutline's GGO_GLYPH_INDEX.
const GGO_GLYPH_INDEX: u32 = 0x80;

/// The identity MAT2: eM11 and eM22 1.0 (a FIXED is a 16-bit fraction under a 16-bit value).
const IDENTITY: [u32; 4] = [0x0001_0000, 0, 0, 0x0001_0000];

/// An enumeration's callback, as EnumFontFamilies and EnumFontFamiliesEx take it: the face's
/// ENUMLOGFONT(EX), its NEWTEXTMETRIC(EX), its FontType, and the caller's value.
pub type EnumProc = unsafe extern "system" fn(*const u8, *const u8, u32, isize) -> i32;

// --- Loading -------------------------------------------------------------------------------------

/// The file `name` (no terminator, shorter than MAX_PATH) found and opened for reading, as a font
/// load looks for it (see the module notes); none, with SearchPathW's last error when it cannot be
/// found, or the open's when it cannot be opened.
fn open_font_file(name: &[u16]) -> Option<OpenFile> {
    let mut terminated = [0u16; MAX_PATH];
    terminated[..name.len()].copy_from_slice(name);
    let terminated = &terminated[..=name.len()];
    let mut found = [0u16; MAX_PATH];
    let mut length = 0;
    let separator = |unit: &u16| {
        b"\\/:"
            .iter()
            .any(|&byte| *unit == u16::from(byte))
    };
    if !name.iter().any(separator) {
        let mut fonts = [0u16; MAX_PATH];
        let root = imports::system_windows_directory(&mut fonts);
        let end = root + FONTS.len();
        if root != 0 && end < MAX_PATH {
            for (slot, unit) in fonts[root..end].iter_mut().zip(FONTS.encode_utf16()) {
                *slot = unit;
            }
            fonts[end] = 0;
            length = imports::search_path(Some(&fonts[..=end]), terminated, &mut found);
        }
    }
    if length == 0 {
        length = imports::search_path(None, terminated, &mut found);
    }
    if length == 0 {
        return None;
    }
    answered(OpenFile::open(&found[..=length]))
}

/// The units of the caller's wide name into `units` (no terminator): none for no name or one
/// longer than MAX_PATH allows.
fn wide_name<'a>(name: Option<InWStr>, units: &'a mut [u16; MAX_PATH]) -> Option<&'a [u16]> {
    let name = name?;
    let length = name.len();
    if length >= MAX_PATH {
        return None;
    }
    name.units().copy_to(&mut units[..length]);
    Some(&units[..length])
}

/// The caller's narrow name, converted, into `units` (no terminator): none for no name or one
/// longer than MAX_PATH allows.
fn narrow_name<'a>(name: Option<InStr>, units: &'a mut [u16; MAX_PATH]) -> Option<&'a [u16]> {
    let bytes = name?.bytes_within(MAX_PATH - 1)?;
    let length = imports::multi_byte_to_unicode(&mut units[..MAX_PATH - 1], bytes);
    Some(&units[..length])
}

/// A load of the font file `name` with `flags`: the faces added, or 0 with the last error.
fn add_named(name: Option<&[u16]>, flags: u32) -> i32 {
    let Some(name) = name.filter(|name| !name.is_empty()) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let Some(file) = open_font_file(name) else {
        return 0;
    };
    answered(imports::add_font_resource(&file, flags & FR_PRIVATE)).map_or(0, |faces| faces as i32)
}

/// A removal of a load of the font file `name` with `flags`: whether there was one (FALSE leaves
/// the last error as the look for the file left it).
fn remove_named(name: Option<&[u16]>, flags: u32) -> u32 {
    let Some(name) = name.filter(|name| !name.is_empty()) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let Some(file) = open_font_file(name) else {
        return 0;
    };
    answered(imports::remove_font_resource(&file, flags & FR_PRIVATE)).map_or(0, u32::from)
}

/// AddFontResourceExW: the TrueType font file `name` loaded, for every process, or for this one
/// alone (FR_PRIVATE): the faces it holds; 0 with the last error for a file that cannot be found
/// or is no font, or a reserved pointer that is not null (ERROR_INVALID_PARAMETER).
///
/// # Safety
///
/// The caller's NUL-terminated name, as for the platform's.
#[unsafe(export_name = "f2k_export_AddFontResourceExW")]
pub unsafe extern "system" fn add_font_resource_ex_w(
    name: *const u16,
    flags: u32,
    reserved: usize,
) -> i32 {
    if reserved != 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let mut units = [0u16; MAX_PATH];
    // SAFETY: the caller's string, or null.
    let name = wide_name(unsafe { InWStr::optional(name) }, &mut units);
    add_named(name, flags)
}

/// AddFontResourceExA: the name converted, then AddFontResourceExW's load.
///
/// # Safety
///
/// The caller's NUL-terminated name, as for the platform's.
#[unsafe(export_name = "f2k_export_AddFontResourceExA")]
pub unsafe extern "system" fn add_font_resource_ex_a(
    name: *const u8,
    flags: u32,
    reserved: usize,
) -> i32 {
    if reserved != 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let mut units = [0u16; MAX_PATH];
    // SAFETY: the caller's string, or null.
    let name = narrow_name(unsafe { InStr::optional(name) }, &mut units);
    add_named(name, flags)
}

/// AddFontResourceW: AddFontResourceExW's public load.
///
/// # Safety
///
/// The caller's NUL-terminated name, as for the platform's.
#[unsafe(export_name = "f2k_export_AddFontResourceW")]
pub unsafe extern "system" fn add_font_resource_w(name: *const u16) -> i32 {
    // SAFETY: the caller's contract, passed on.
    unsafe { add_font_resource_ex_w(name, 0, 0) }
}

/// AddFontResourceA: AddFontResourceExA's public load.
///
/// # Safety
///
/// The caller's NUL-terminated name, as for the platform's.
#[unsafe(export_name = "f2k_export_AddFontResourceA")]
pub unsafe extern "system" fn add_font_resource_a(name: *const u8) -> i32 {
    // SAFETY: the caller's contract, passed on.
    unsafe { add_font_resource_ex_a(name, 0, 0) }
}

/// RemoveFontResourceExW: one load of the font file `name` removed, the public one or this
/// process's (FR_PRIVATE); FALSE when there is none, or with the last error for a file that cannot
/// be found.
///
/// # Safety
///
/// The caller's NUL-terminated name, as for the platform's.
#[unsafe(export_name = "f2k_export_RemoveFontResourceExW")]
pub unsafe extern "system" fn remove_font_resource_ex_w(
    name: *const u16,
    flags: u32,
    reserved: usize,
) -> u32 {
    if reserved != 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let mut units = [0u16; MAX_PATH];
    // SAFETY: the caller's string, or null.
    let name = wide_name(unsafe { InWStr::optional(name) }, &mut units);
    remove_named(name, flags)
}

/// RemoveFontResourceExA: the name converted, then RemoveFontResourceExW's removal.
///
/// # Safety
///
/// The caller's NUL-terminated name, as for the platform's.
#[unsafe(export_name = "f2k_export_RemoveFontResourceExA")]
pub unsafe extern "system" fn remove_font_resource_ex_a(
    name: *const u8,
    flags: u32,
    reserved: usize,
) -> u32 {
    if reserved != 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let mut units = [0u16; MAX_PATH];
    // SAFETY: the caller's string, or null.
    let name = narrow_name(unsafe { InStr::optional(name) }, &mut units);
    remove_named(name, flags)
}

/// RemoveFontResourceW: RemoveFontResourceExW's removal of a public load.
///
/// # Safety
///
/// The caller's NUL-terminated name, as for the platform's.
#[unsafe(export_name = "f2k_export_RemoveFontResourceW")]
pub unsafe extern "system" fn remove_font_resource_w(name: *const u16) -> u32 {
    // SAFETY: the caller's contract, passed on.
    unsafe { remove_font_resource_ex_w(name, 0, 0) }
}

/// RemoveFontResourceA: RemoveFontResourceExA's removal of a public load.
///
/// # Safety
///
/// The caller's NUL-terminated name, as for the platform's.
#[unsafe(export_name = "f2k_export_RemoveFontResourceA")]
pub unsafe extern "system" fn remove_font_resource_a(name: *const u8) -> u32 {
    // SAFETY: the caller's contract, passed on.
    unsafe { remove_font_resource_ex_a(name, 0, 0) }
}

// --- Font objects --------------------------------------------------------------------------------

/// A font object of `log_font`: its handle, or NULL with the last error.
fn create(log_font: &LogFontW) -> usize {
    answered(imports::create_font(Caller::of(log_font))).map_or(0, |font| font as usize)
}

/// CreateFontIndirectW: a font object of the caller's LOGFONTW, as it is (GetObject answers it
/// back); NULL with ERROR_INVALID_PARAMETER for none.
#[unsafe(export_name = "f2k_export_CreateFontIndirectW")]
pub extern "system" fn create_font_indirect_w(log_font: *const LogFontW) -> usize {
    if log_font.is_null() {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    answered(imports::create_font(Caller(log_font as usize))).map_or(0, |font| font as usize)
}

/// CreateFontIndirectA: the LOGFONTA's face name converted, then CreateFontIndirectW's font.
///
/// # Safety
///
/// The caller's LOGFONTA (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_CreateFontIndirectA")]
pub unsafe extern "system" fn create_font_indirect_a(log_font: *const LogFontA) -> usize {
    // SAFETY: the caller's structure, or null.
    let Some(log_font) = (unsafe { In::optional(log_font) }) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    create(&wide_log_font(
        &log_font.read(),
        imports::multi_byte_to_unicode,
    ))
}

/// The LOGFONTW CreateFont's arguments make, its face name `face` (cut to LF_FACESIZE - 1 units).
#[allow(clippy::too_many_arguments)]
fn log_font_of(
    height: i32,
    width: i32,
    escapement: i32,
    orientation: i32,
    weight: i32,
    italic: u32,
    underline: u32,
    strike_out: u32,
    char_set: u32,
    out_precision: u32,
    clip_precision: u32,
    quality: u32,
    pitch_and_family: u32,
    face: &[u16],
) -> LogFontW {
    let mut face_name = [0u16; LF_FACESIZE];
    let length = face.len().min(LF_FACESIZE - 1);
    face_name[..length].copy_from_slice(&face[..length]);
    LogFontW {
        height,
        width,
        escapement,
        orientation,
        weight,
        italic: italic as u8,
        underline: underline as u8,
        strike_out: strike_out as u8,
        char_set: char_set as u8,
        out_precision: out_precision as u8,
        clip_precision: clip_precision as u8,
        quality: quality as u8,
        pitch_and_family: pitch_and_family as u8,
        face_name,
    }
}

/// CreateFontW: a font object of the LOGFONTW its arguments make.
///
/// # Safety
///
/// The caller's NUL-terminated face name (or null), as for the platform's.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_CreateFontW")]
pub unsafe extern "system" fn create_font_w(
    height: i32,
    width: i32,
    escapement: i32,
    orientation: i32,
    weight: i32,
    italic: u32,
    underline: u32,
    strike_out: u32,
    char_set: u32,
    out_precision: u32,
    clip_precision: u32,
    quality: u32,
    pitch_and_family: u32,
    face: *const u16,
) -> usize {
    let mut units = [0u16; LF_FACESIZE];
    // SAFETY: the caller's string, or null.
    let face = match unsafe { InWStr::optional(face) } {
        Some(name) => {
            let length = name.len().min(LF_FACESIZE - 1);
            for (slot, unit) in units.iter_mut().zip(name.units().iter().take(length)) {
                *slot = unit;
            }
            &units[..length]
        }
        None => &units[..0],
    };
    create(&log_font_of(
        height,
        width,
        escapement,
        orientation,
        weight,
        italic,
        underline,
        strike_out,
        char_set,
        out_precision,
        clip_precision,
        quality,
        pitch_and_family,
        face,
    ))
}

/// CreateFontA: the face name converted, then CreateFontW's font.
///
/// # Safety
///
/// The caller's NUL-terminated face name (or null), as for the platform's.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_CreateFontA")]
pub unsafe extern "system" fn create_font_a(
    height: i32,
    width: i32,
    escapement: i32,
    orientation: i32,
    weight: i32,
    italic: u32,
    underline: u32,
    strike_out: u32,
    char_set: u32,
    out_precision: u32,
    clip_precision: u32,
    quality: u32,
    pitch_and_family: u32,
    face: *const u8,
) -> usize {
    let mut units = [0u16; LF_FACESIZE];
    // SAFETY: the caller's string, or null.
    let face = match unsafe { InStr::optional(face) } {
        Some(name) => {
            let bytes = name.bytes();
            let bytes = &bytes[..bytes.len().min(LF_FACESIZE - 1)];
            let length = imports::multi_byte_to_unicode(&mut units[..LF_FACESIZE - 1], bytes);
            &units[..length]
        }
        None => &units[..0],
    };
    create(&log_font_of(
        height,
        width,
        escapement,
        orientation,
        weight,
        italic,
        underline,
        strike_out,
        char_set,
        out_precision,
        clip_precision,
        quality,
        pitch_and_family,
        face,
    ))
}

/// GetObjectW and GetObjectA of a stock object: not served yet.
fn stock_get_object(entry: &rtl::stub::Entry, object: usize, size: i32, buffer: usize) -> i32 {
    let args = [object as u64, size as u32 as u64, buffer as u64];
    // SAFETY: the arguments as GetObject's kinds read them (no string).
    unsafe {
        stub::stubbed(
            entry,
            "a stock object's description not yet implemented",
            &args,
        ) as i32
    }
}

/// GetObjectW: a font object's LOGFONTW, its first `size` bytes into `buffer`, their number (the
/// whole size for no buffer); 0 with the last error for a handle that names no font. A stock
/// object goes to the stub routine.
#[unsafe(export_name = "f2k_export_GetObjectW")]
pub extern "system" fn get_object_w(object: usize, size: i32, buffer: usize) -> i32 {
    if stock_object(object as u32).is_some() {
        return stock_get_object(&crate::spec::GetObjectW, object, size, buffer);
    }
    if size < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    answered(imports::object(object, size as u32, Caller(buffer))).map_or(0, |size| size as i32)
}

/// GetObjectA: a font object's LOGFONTA (GetObjectW's, its face name converted), its first `size`
/// bytes into `buffer`, their number (the whole size for no buffer).
///
/// # Safety
///
/// The caller's buffer of `size` bytes (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_GetObjectA")]
pub unsafe extern "system" fn get_object_a(object: usize, size: i32, buffer: *mut u8) -> i32 {
    if stock_object(object as u32).is_some() {
        return stock_get_object(&crate::spec::GetObjectA, object, size, buffer as usize);
    }
    if size < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let mut wide = LogFontW::zeroed();
    if answered(imports::object(
        object,
        size_of::<LogFontW>() as u32,
        Caller::of_mut(&mut wide),
    ))
    .is_none()
    {
        return 0;
    }
    let narrow = narrow_log_font(&wide, imports::unicode_to_multi_byte);
    let bytes = narrow.as_bytes();
    if buffer.is_null() {
        return bytes.len() as i32;
    }
    let length = bytes.len().min(size as usize);
    // SAFETY: the caller's buffer of `size` bytes.
    let mut out = unsafe { OutBuf::new(buffer, length) };
    out.put(&bytes[..length]);
    length as i32
}

// --- What the DC's font answers ------------------------------------------------------------------

/// GetTextFaceW: the DC's font's face name, at most `count` units with its terminator, into
/// `buffer`; the units written (the name's length and its terminator for no buffer); 0 with the
/// last error for a DC that is none or a negative count.
#[unsafe(export_name = "f2k_export_GetTextFaceW")]
pub extern "system" fn get_text_face_w(dc: usize, count: i32, buffer: *mut u16) -> i32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let count = if buffer.is_null() { 0 } else { count as u32 };
    answered(imports::text_face(dc, count, Caller(buffer as usize)))
        .map_or(0, |length| length as i32)
}

/// GetTextFaceA: the face name converted, at most `count` bytes with its terminator, into
/// `buffer`; the bytes written before the terminator (for no buffer, GetTextFaceW's count, as the
/// capture of Windows 2000 answers it).
///
/// # Safety
///
/// The caller's buffer of `count` bytes (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_GetTextFaceA")]
pub unsafe extern "system" fn get_text_face_a(dc: usize, count: i32, buffer: *mut u8) -> i32 {
    if count < 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    let mut units = [0u16; LF_FACESIZE];
    let Some(length) = answered(imports::text_face(
        dc,
        LF_FACESIZE as u32,
        Caller::of_mut(&mut units),
    )) else {
        return 0;
    };
    if buffer.is_null() {
        return length as i32;
    }
    if count == 0 {
        return 0;
    }
    let name = &units[..(length as usize).saturating_sub(1)];
    let mut bytes = [0u8; 2 * LF_FACESIZE];
    let written = imports::unicode_to_multi_byte(&mut bytes, name).min(count as usize - 1);
    bytes[written] = 0;
    // SAFETY: the caller's buffer of `count` bytes, `written` + 1 of them written.
    let mut out = unsafe { OutBuf::new(buffer, written + 1) };
    out.put(&bytes[..=written]);
    written as i32
}

/// GetOutlineTextMetricsW: the DC's TrueType font's OUTLINETEXTMETRICW and its names, at most
/// `size` bytes of them into `metric`, the bytes written (their size for no buffer); 0 for the
/// built-in font, and with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_GetOutlineTextMetricsW")]
pub extern "system" fn get_outline_text_metrics_w(dc: usize, size: u32, metric: usize) -> u32 {
    let size = if metric == 0 { 0 } else { size };
    answered(imports::outline_text_metrics(dc, size, Caller(metric))).unwrap_or(0)
}

/// The room GetOutlineTextMetricsW's answer takes at most: the structure and four names of 64
/// units with their terminators.
const OUTLINE_W: usize = 216 + 4 * 2 * 64;

/// GetOutlineTextMetricsA: GetOutlineTextMetricsW's answer converted: OUTLINETEXTMETRICA, its
/// TEXTMETRICA as GetTextMetricsA's, its names in the ANSI code page after it.
///
/// # Safety
///
/// The caller's buffer of `size` bytes (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_GetOutlineTextMetricsA")]
pub unsafe extern "system" fn get_outline_text_metrics_a(
    dc: usize,
    size: u32,
    metric: *mut u8,
) -> u32 {
    let mut wide = [0u32; OUTLINE_W / 4];
    let Some(got) = answered(imports::outline_text_metrics(
        dc,
        OUTLINE_W as u32,
        Caller::of_mut(&mut wide),
    )) else {
        return 0;
    };
    let bytes = &wide.as_bytes()[..(got as usize).min(OUTLINE_W)];
    let Some(outline) = OutlineTextMetricW::from_bytes(bytes) else {
        return 0;
    };
    let mut narrow = [0u8; 212 + 4 * 2 * 64];
    let mut fields = outline.fields;
    let mut at = size_of::<OutlineTextMetricA>();
    let names = [
        &mut fields.family_name,
        &mut fields.face_name,
        &mut fields.style_name,
        &mut fields.full_name,
    ];
    for offset in names {
        let start = *offset as usize;
        let name = bytes.get(start..).unwrap_or(&[]);
        let mut units = [0u16; 64];
        let mut length = 0;
        for &pair in name.as_chunks::<2>().0.iter().take(63) {
            let unit = u16::from_le_bytes(pair);
            if unit == 0 {
                break;
            }
            units[length] = unit;
            length += 1;
        }
        let written = imports::unicode_to_multi_byte(&mut narrow[at..at + 127], &units[..length]);
        narrow[at + written] = 0;
        *offset = at as u32;
        at += written + 1;
    }
    let head = OutlineTextMetricA {
        size: at as u32,
        text_metrics: narrow_truetype_metric(&outline.text_metrics),
        filler: 0,
        panose: outline.panose,
        padding: 0,
        fields,
    };
    narrow[..size_of::<OutlineTextMetricA>()].copy_from_slice(head.as_bytes());
    if metric.is_null() || size == 0 {
        return at as u32;
    }
    let length = at.min(size as usize);
    // SAFETY: the caller's buffer of `size` bytes, `length` of them written.
    let mut out = unsafe { OutBuf::new(metric, length) };
    out.put(&narrow[..length]);
    length as u32
}

/// The characters of the narrow range `first` to `last`, converted to their wide forms into
/// `units`; none for a range that is empty or reaches past a byte.
fn narrow_range(first: u32, last: u32, units: &mut [u16; 256]) -> Option<&[u16]> {
    if last < first || last > 0xFF {
        return None;
    }
    let bytes: [u8; 256] = core::array::from_fn(|index| index as u8);
    let length = imports::multi_byte_to_unicode(units, &bytes[first as usize..=last as usize]);
    Some(&units[..length])
}

/// GetCharWidth32W: the advances of the characters `first` to `last` into `widths`; FALSE with
/// ERROR_INVALID_PARAMETER for a range that runs backwards or no buffer, with the last error for
/// a DC that is none.
#[unsafe(export_name = "f2k_export_GetCharWidth32W")]
pub extern "system" fn get_char_width32_w(dc: usize, first: u32, last: u32, widths: usize) -> u32 {
    if last < first || widths == 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    answered(imports::char_widths(
        dc,
        first,
        last - first + 1,
        Caller::NONE,
        Caller(widths),
    ))
    .map_or(0, |()| 1)
}

/// GetCharWidth32A: the advances of the ANSI characters `first` to `last` (each converted to its
/// wide form).
#[unsafe(export_name = "f2k_export_GetCharWidth32A")]
pub extern "system" fn get_char_width32_a(dc: usize, first: u32, last: u32, widths: usize) -> u32 {
    let mut units = [0u16; 256];
    let Some(units) = narrow_range(first, last, &mut units).filter(|_| widths != 0) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let count = units.len() as u32;
    answered(imports::char_widths(
        dc,
        0,
        count,
        Caller(units.as_ptr() as usize),
        Caller(widths),
    ))
    .map_or(0, |()| 1)
}

/// GetCharABCWidthsW: the ABC spacing of the characters `first` to `last` into `abc`; FALSE
/// with the last error for the built-in font (it has none) or a DC that is none.
#[unsafe(export_name = "f2k_export_GetCharABCWidthsW")]
pub extern "system" fn get_char_abc_widths_w(dc: usize, first: u32, last: u32, abc: usize) -> u32 {
    if last < first || abc == 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    answered(imports::char_abc_widths(
        dc,
        first,
        last - first + 1,
        Caller::NONE,
        Caller(abc),
    ))
    .map_or(0, |()| 1)
}

/// GetCharABCWidthsA: the ABC spacing of the ANSI characters `first` to `last`.
#[unsafe(export_name = "f2k_export_GetCharABCWidthsA")]
pub extern "system" fn get_char_abc_widths_a(dc: usize, first: u32, last: u32, abc: usize) -> u32 {
    let mut units = [0u16; 256];
    let Some(units) = narrow_range(first, last, &mut units).filter(|_| abc != 0) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let count = units.len() as u32;
    answered(imports::char_abc_widths(
        dc,
        0,
        count,
        Caller(units.as_ptr() as usize),
        Caller(abc),
    ))
    .map_or(0, |()| 1)
}

/// GetFontData: the bytes of the DC's TrueType font's table `table` (0: the whole file) from
/// `offset`, at most `size` of them into `buffer`, their number (the table's size for no buffer);
/// GDI_ERROR for a table the font lacks, an offset past its end or the built-in font (the last
/// error left), and with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_GetFontData")]
pub extern "system" fn get_font_data(
    dc: usize,
    table: u32,
    offset: u32,
    buffer: usize,
    size: u32,
) -> u32 {
    answered(imports::font_data(dc, table, offset, Caller(buffer), size)).unwrap_or(GDI_ERROR)
}

/// GetGlyphOutlineW: GGO_METRICS (the glyph's GLYPHMETRICS, its cached size answered) or
/// GGO_BITMAP (its monochrome bitmap's rows too, their size answered) of character `character`
/// (or glyph, with GGO_GLYPH_INDEX) of the DC's TrueType font, under the identity matrix;
/// GDI_ERROR for the built-in font or a buffer too small, with ERROR_INVALID_PARAMETER for no
/// GLYPHMETRICS. Another format, or another matrix, goes to the stub routine.
///
/// # Safety
///
/// The caller's MAT2 (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_GetGlyphOutlineW")]
pub unsafe extern "system" fn get_glyph_outline_w(
    dc: usize,
    character: u32,
    format: u32,
    metrics: usize,
    size: u32,
    buffer: usize,
    matrix: *const [u32; 4],
) -> u32 {
    // SAFETY: the caller's matrix, or null.
    let matrix = unsafe { In::optional(matrix) }.map(|matrix| matrix.read());
    let kind = format & !GGO_GLYPH_INDEX;
    if matrix != Some(IDENTITY) || (kind != GGO_METRICS && kind != GGO_BITMAP) {
        let args = [
            dc as u64,
            character as u64,
            format as u64,
            metrics as u64,
            size as u64,
            buffer as u64,
            matrix.map_or(0, |_| 1),
        ];
        // SAFETY: the arguments as GetGlyphOutlineW's kinds read them (no string).
        return unsafe {
            stub::stubbed(
                &crate::spec::GetGlyphOutlineW,
                "outlines and transformed glyphs not yet implemented",
                &args,
            )
        };
    }
    if metrics == 0 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(GDI_ERROR);
    }
    answered(imports::glyph_outline(
        dc,
        character,
        format,
        Caller(metrics),
        size,
        Caller(buffer),
    ))
    .unwrap_or(GDI_ERROR)
}

/// GetGlyphOutlineA: an ANSI character converted to its wide form (a glyph index as it is), then
/// GetGlyphOutlineW's answer.
///
/// # Safety
///
/// As GetGlyphOutlineW's.
#[unsafe(export_name = "f2k_export_GetGlyphOutlineA")]
pub unsafe extern "system" fn get_glyph_outline_a(
    dc: usize,
    character: u32,
    format: u32,
    metrics: usize,
    size: u32,
    buffer: usize,
    matrix: *const [u32; 4],
) -> u32 {
    let mut wide = character;
    if format & GGO_GLYPH_INDEX == 0 && character < 0x100 {
        let mut unit = [0u16];
        if imports::multi_byte_to_unicode(&mut unit, &[character as u8]) == 1 {
            wide = unit[0] as u32;
        }
    }
    // SAFETY: the caller's contract, passed on.
    unsafe { get_glyph_outline_w(dc, wide, format, metrics, size, buffer, matrix) }
}

// --- The enumeration ----------------------------------------------------------------------------

/// Run the enumeration of the faces named `face` (every face for none) in `char_set` (with
/// `flags`) through `each`, a face at a time: the last answer of `each`, which stops it at 0 (1
/// when no face is enumerated); 0 with the last error for a DC that is none.
fn enumerate(
    dc: usize,
    face: Option<&[u16; LF_FACESIZE]>,
    char_set: u8,
    flags: u32,
    mut each: impl FnMut(&FontEnumRecord) -> i32,
) -> i32 {
    let mut answer = 1;
    for index in 0.. {
        let mut record = FontEnumRecord::zeroed();
        match answered(imports::enum_font(
            dc,
            face,
            char_set,
            flags,
            index,
            &mut record,
        )) {
            None => return 0,
            Some(false) => break,
            Some(true) => {}
        }
        answer = each(&record);
        if answer == 0 {
            break;
        }
    }
    answer
}

/// A face name's units, terminated and padded: none for an empty name.
fn face_array(units: &[u16]) -> Option<[u16; LF_FACESIZE]> {
    let end = units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len());
    let units = &units[..end.min(LF_FACESIZE - 1)];
    if units.is_empty() {
        return None;
    }
    let mut face = [0u16; LF_FACESIZE];
    face[..units.len()].copy_from_slice(units);
    Some(face)
}

/// The narrow form of the wide, NUL-terminated `units`, into `bytes` (terminated, zero-padded).
fn narrow_into<const N: usize>(bytes: &mut [u8; N], units: &[u16]) {
    let end = units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len());
    let written = imports::unicode_to_multi_byte(&mut bytes[..N - 1], &units[..end]);
    bytes[written..].fill(0);
}

/// The narrow forms of an enumeration's record: ENUMLOGFONTEXA and NEWTEXTMETRICEXA (its
/// TEXTMETRICA as GetTextMetricsA's: a TrueType face's characters as the ANSI code page sees the
/// font, a raster font's converted).
fn narrow_record(record: &FontEnumRecord) -> (EnumLogFontExA, NewTextMetricExA) {
    let mut log_font = EnumLogFontExA::zeroed();
    log_font.log_font = narrow_log_font(&record.log_font.log_font, imports::unicode_to_multi_byte);
    narrow_into(&mut log_font.full_name, &record.log_font.full_name);
    narrow_into(&mut log_font.style, &record.log_font.style);
    narrow_into(&mut log_font.script, &record.log_font.script);
    let wide = &record.metric.metric;
    let text_metric = if record.font_type == TRUETYPE_FONTTYPE {
        narrow_truetype_metric(&wide.text_metric)
    } else {
        narrow_text_metric(&wide.text_metric, |unit| {
            let mut byte = [0u8];
            imports::unicode_to_multi_byte(&mut byte, &[unit]);
            byte[0]
        })
    };
    let metric = NewTextMetricExA {
        metric: NewTextMetricA {
            text_metric,
            flags: wide.flags,
            size_em: wide.size_em,
            cell_height: wide.cell_height,
            avg_width: wide.avg_width,
        },
        signature: record.metric.signature,
    };
    (log_font, metric)
}

/// Call the caller's `callback` with a face's two structures, its FontType and the caller's
/// `value`: its answer.
fn call_back<L: Pod, M: Pod>(
    callback: EnumProc,
    log_font: &L,
    metric: &M,
    font_type: u32,
    value: isize,
) -> i32 {
    // SAFETY: the caller's callback, of the type the platform documents for it; the structures
    // are ours, alive for the call, which reads them alone.
    unsafe {
        callback(
            log_font as *const L as *const u8,
            metric as *const M as *const u8,
            font_type,
            value,
        )
    }
}

/// EnumFontFamiliesExW: the faces the LOGFONTW's face name names (every face for an empty one)
/// in its character set (each one a face covers for DEFAULT_CHARSET), each passed to `callback`
/// with its ENUMLOGFONTEXW, NEWTEXTMETRICEXW and FontType: the callback's last answer (it stops
/// the enumeration at 0), 1 when no face is enumerated; 0 with ERROR_INVALID_PARAMETER for no
/// LOGFONT or callback.
///
/// # Safety
///
/// The caller's LOGFONTW (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_EnumFontFamiliesExW")]
pub unsafe extern "system" fn enum_font_families_ex_w(
    dc: usize,
    log_font: *const LogFontW,
    callback: Option<EnumProc>,
    value: isize,
    _flags: u32,
) -> i32 {
    // SAFETY: the caller's structure, or null.
    let (Some(log_font), Some(callback)) = (unsafe { In::optional(log_font) }, callback) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let log_font = log_font.read();
    let face = face_array(&log_font.face_name);
    enumerate(dc, face.as_ref(), log_font.char_set, 0, |record| {
        call_back(
            callback,
            &record.log_font,
            &record.metric,
            record.font_type,
            value,
        )
    })
}

/// EnumFontFamiliesExA: the LOGFONTA's face name converted, then EnumFontFamiliesExW's
/// enumeration, each face's structures converted for `callback`.
///
/// # Safety
///
/// The caller's LOGFONTA (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_EnumFontFamiliesExA")]
pub unsafe extern "system" fn enum_font_families_ex_a(
    dc: usize,
    log_font: *const LogFontA,
    callback: Option<EnumProc>,
    value: isize,
    _flags: u32,
) -> i32 {
    // SAFETY: the caller's structure, or null.
    let (Some(log_font), Some(callback)) = (unsafe { In::optional(log_font) }, callback) else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let wide = wide_log_font(&log_font.read(), imports::multi_byte_to_unicode);
    let face = face_array(&wide.face_name);
    enumerate(dc, face.as_ref(), wide.char_set, 0, |record| {
        let (log_font, metric) = narrow_record(record);
        call_back(callback, &log_font, &metric, record.font_type, value)
    })
}

/// EnumFontFamiliesW: the faces named `family` (every face for none), each once, in its first
/// character set, passed to `callback` with its ENUMLOGFONTW and NEWTEXTMETRICW (the first members
/// of EnumFontFamiliesExW's structures); as EnumFontFamiliesExW answers.
///
/// # Safety
///
/// The caller's NUL-terminated family name (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_EnumFontFamiliesW")]
pub unsafe extern "system" fn enum_font_families_w(
    dc: usize,
    family: *const u16,
    callback: Option<EnumProc>,
    value: isize,
) -> i32 {
    let Some(callback) = callback else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let mut units = [0u16; LF_FACESIZE];
    // SAFETY: the caller's string, or null.
    if let Some(name) = unsafe { InWStr::optional(family) } {
        let length = name.len().min(LF_FACESIZE - 1);
        for (slot, unit) in units.iter_mut().zip(name.units().iter().take(length)) {
            *slot = unit;
        }
    }
    let face = face_array(&units);
    enumerate(
        dc,
        face.as_ref(),
        DEFAULT_CHARSET,
        ENUM_FAMILIES,
        |record| {
            call_back(
                callback,
                &record.log_font,
                &record.metric,
                record.font_type,
                value,
            )
        },
    )
}

/// EnumFontFamiliesA: the family name converted, then EnumFontFamiliesW's enumeration, each
/// face's structures converted for `callback`.
///
/// # Safety
///
/// The caller's NUL-terminated family name (or null), as for the platform's.
#[unsafe(export_name = "f2k_export_EnumFontFamiliesA")]
pub unsafe extern "system" fn enum_font_families_a(
    dc: usize,
    family: *const u8,
    callback: Option<EnumProc>,
    value: isize,
) -> i32 {
    let Some(callback) = callback else {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    };
    let mut units = [0u16; LF_FACESIZE];
    // SAFETY: the caller's string, or null.
    if let Some(name) = unsafe { InStr::optional(family) } {
        let bytes = name.bytes();
        let bytes = &bytes[..bytes.len().min(LF_FACESIZE - 1)];
        imports::multi_byte_to_unicode(&mut units[..LF_FACESIZE - 1], bytes);
    }
    let face = face_array(&units);
    enumerate(
        dc,
        face.as_ref(),
        DEFAULT_CHARSET,
        ENUM_FAMILIES,
        |record| {
            let (log_font, metric) = narrow_record(record);
            call_back(callback, &log_font, &metric, record.font_type, value)
        },
    )
}

#[cfg(test)]
mod tests;
