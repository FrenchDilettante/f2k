//! Fonts: TrueType faces loaded from the volume ([`table`]), the font objects programs make
//! (LOGFONTs, objects of the object manager's Font type), the mapper that realises a font object's
//! LOGFONT as a face at a size ([`mapper`]), and the services gdi32's font calls come through. The
//! TrueType reading and rendering is rtl's ([`rtl::truetype`]); a DC's text drawn in a TrueType
//! font goes through the realised font's glyph cache ([`draw_run`]).
//!
//! Where the faces come from:
//! - the boot loads the faces of [`BOOT_FONTS`] once the boot volume is mounted
//!   ([`load_boot_fonts`]), public to every process: Windows 2000 loads the faces its registry's
//!   `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts` key lists at logon, and F2K, with no
//!   registry on disk yet, keeps a built-in list standing in for the key (a deviation);
//! - AddFontResource and AddFontResourceEx load a font file a program names, gdi32 opening it and
//!   handing the kernel its handle: the kernel reads the whole file, at the passive level, into a
//!   block of the nonpaged pool (Windows 2000's TrueType driver maps its files as section views
//!   instead; F2K maps sections into processes' address spaces alone, with no view in system space
//!   to map a file into, and the pool, 16 MiB, holds a file of a few hundred KiB);
//! - FR_PRIVATE loads a face for the calling process alone, which it goes with.
//!
//! A font object is the LOGFONT its creation gave (as GetObject answers it). Its handle carries
//! the font kind above the handle table's handle, as a brush's carries its own
//! ([`rtl::gdi::object_handle`]), so gdi32 and the DC services tell a font from another object by
//! its handle alone ([`font_table_handle`]). A DC selects one by its handle, the font's object id
//! beside it; the DC's text calls realise it each time, through
//! the mapper, against the faces the calling process sees: a font whose face is gone, or a font
//! object deleted while selected, realises as the built-in font. (Windows 2000 keeps a deleted
//! font selected in a DC alive until it is deselected; here the DC's id of it goes stale.) The
//! stock fonts stay the built-in font ([`super::font`]).
//!
//! The services (F2K's argument lists, see [`crate::win32k`]):
//!
//! - NtGdiHfontCreate(ptr LogFont, ptr<u32> Font): a font object of the LOGFONTW, its handle;
//! - NtGdiExtGetObjectW(handle Object, u32 Count, ptr Buffer, ptr<u32> Size): a font's LOGFONTW,
//!   the first `Count` bytes of it, their number (the whole size for a null buffer);
//! - NtGdiAddFontResourceW(handle File, u32 Flags, ptr<u32> Faces) and
//!   NtGdiRemoveFontResourceW(handle File, u32 Flags, ptr<u32> Removed): a load of the open file's
//!   face, the faces it holds, or a removal of one, whether there was one (FR_PRIVATE: the calling
//!   process's own);
//! - NtGdiGetTextFaceW(handle Dc, u32 Count, ptr Buffer, ptr<u32> Length): the selected font's face
//!   name, cut to `Count` units with its terminator, the units written (all of them, the
//!   terminator's included, for a null buffer);
//! - NtGdiGetOutlineTextMetricsInternalW(handle Dc, u32 Size, ptr Buffer, ptr<u32> Needed):
//!   OUTLINETEXTMETRICW and its four names after it, its size (0 for the built-in font);
//! - NtGdiGetCharWidthW(handle Dc, u32 First, u32 Count, ptr Characters, ptr Widths) and
//!   NtGdiGetCharABCWidthsW(handle Dc, u32 First, u32 Count, ptr Characters, ptr Abc): `Count`
//!   characters' advances (INTs) or ABCs, from `First` on, or the characters at `Characters` when
//!   it is not null (the built-in font has no ABC widths: STATUS_INVALID_PARAMETER);
//! - NtGdiGetFontData(handle Dc, u32 Table, u32 Offset, ptr Buffer, u32 Count, ptr<u32> Answer):
//!   GetFontData's answer, GDI_ERROR included;
//! - NtGdiGetGlyphOutline(handle Dc, u32 Character, u32 Format, ptr Metrics, u32 Size, ptr Buffer,
//!   ptr<u32> Answer): GetGlyphOutlineW's answer for GGO_METRICS and GGO_BITMAP (with
//!   GGO_GLYPH_INDEX), GDI_ERROR included, the GLYPHMETRICS into `Metrics`;
//! - NtGdiEnumFontChunk(handle Dc, ptr Face, u32 CharSet, u32 Flags, u32 Index, ptr Record): the
//!   enumeration's `Index`th face (an [`rtl::gdi::FontEnumRecord`]), STATUS_NO_MORE_ENTRIES past
//!   the last: the faces named `Face` (every face for a null one) the process sees, in each
//!   character set they cover (DEFAULT_CHARSET) or in `CharSet`, or once each in its first
//!   ([`ENUM_FAMILIES`], EnumFontFamilies' enumeration).
//!
//! A DC that is none is STATUS_INVALID_HANDLE throughout; GetFontData's and GetGlyphOutline's
//! GDI_ERROR is an answer, as the capture's calls leave the last error untouched.

pub mod mapper;
pub mod table;

use rtl::gdi::*;
use rtl::pod::Pod;
use rtl::truetype::glyph::GlyphMetrics;
use rtl::truetype::metrics::{self, Size as MetricSize};
use rtl::truetype::{Font, Tag};

use self::mapper::{FaceName, Name};
use self::table::{FileIdentity, FontTable, Key, Owner, Realization, Storage};
use super::dc::Dc;
use super::raster::TextOut;
use crate::hw::vbe::{Framebuffer, PixelMemory};
use crate::nt::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use crate::status::*;

/// The access a font's handle carries: STANDARD_RIGHTS_REQUIRED.
pub const FONT_ACCESS: u32 = 0x000F_0000;

/// The faces the boot loads, by their paths under the volume's root: the list standing in for
/// `...\CurrentVersion\Fonts` (see the module notes).
pub const BOOT_FONTS: [&str; 1] = ["WINNT\\Fonts\\tahoma.ttf"];

/// The largest font file a load reads: 4 MiB of the pool.
pub const MAX_FONT_FILE: u32 = 4 << 20;

/// AddFontResourceEx's FR_PRIVATE: the face is the calling process's alone.
pub const FR_PRIVATE: u32 = 0x10;

/// NtGdiEnumFontChunk's flag: each face once, in its first character set (EnumFontFamilies'
/// enumeration, which lists families rather than character sets).
pub const ENUM_FAMILIES: u32 = 1;

/// GetGlyphOutline's GGO_GLYPH_INDEX: the character is the glyph's index.
pub const GGO_GLYPH_INDEX: u32 = 0x80;

/// EnumFontFamilies' LOGFONT precisions and quality for a TrueType face: OUT_STROKE_PRECIS,
/// CLIP_STROKE_PRECIS, DRAFT_QUALITY (the capture's 3, 2 and 1).
const ENUM_OUT_PRECISION: u8 = 3;
const ENUM_CLIP_PRECISION: u8 = 2;
const ENUM_QUALITY: u8 = 1;

/// The units, widths or bytes a service copies to or from the caller at a time.
const CHUNK: usize = 64;
const BYTES_CHUNK: usize = 512;

/// The handle-table handle under a font object's handle (its kind's bits taken off); none for a
/// handle that is no font's ([`rtl::gdi::object_of`]).
pub fn font_table_handle(handle: Handle) -> Option<u32> {
    match object_of(handle.raw()) {
        Some((OBJ_FONT, table)) => Some(table),
        _ => None,
    }
}

/// A font object's body: the LOGFONTW its creation gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FontObject {
    pub log_font: LogFontW,
}

impl FontObject {
    /// A record holding no font (a pool's fresh record).
    pub fn none() -> Self {
        FontObject {
            log_font: LogFontW::zeroed(),
        }
    }
}

// --- The text a DC draws in a TrueType font ------------------------------------------------------

/// What a DC's selected font is for a text call: the built-in font, or a font object's LOGFONT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selected {
    BuiltIn,
    Font(LogFontW),
}

/// A realised TrueType font's metrics a run of text needs: its ascent and its cell's height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ascent: i32,
    pub height: i32,
}

impl<B: Storage> FontTable<B> {
    /// The TEXTMETRICW of the realised font `key` in `char_set`; none when its face is gone.
    pub fn text_metric(&self, key: Key, char_set: u8) -> Option<TextMetricW> {
        let font = self.face(key.face)?.font()?;
        metrics::text_metric(&font, MetricSize::Em(key.ppem), key.bold, char_set).ok()
    }

    /// The cell of the realised font `key`.
    pub fn cell(&self, key: Key) -> Option<Cell> {
        let metric = self.text_metric(key, ANSI_CHARSET)?;
        Some(Cell {
            ascent: metric.ascent,
            height: metric.height,
        })
    }
}

/// Draw `units` in the realised font `key` on `screen` (none: the graphics mode is not set, and
/// only the pen moves) from the pen's column `pen`, as `text` draws (its clip, its colors, the
/// cells' top its row): each glyph's black box placed by its origin from the baseline, `cell`'s
/// ascent below the row; under OPAQUE, the run's cells (each character's advance wide, the cell
/// high) filled with the background first. Each character's advance is `advances[i]`, or its
/// glyph's. The pen's column after the run.
#[allow(clippy::too_many_arguments)]
pub fn draw_run<B: Storage, M: PixelMemory>(
    table: &mut FontTable<B>,
    mut screen: Option<&mut Framebuffer<M>>,
    text: &TextOut,
    key: Key,
    cell: Cell,
    pen: i32,
    units: &[u16],
    advances: Option<&[i32]>,
) -> i32 {
    let mut glyphs = [0u16; CHUNK];
    let mut widths = [0i32; CHUNK];
    let mut end = pen;
    for (start, units) in units
        .chunks(CHUNK)
        .enumerate()
        .map(|(n, run)| (n * CHUNK, run))
    {
        let glyphs = &mut glyphs[..units.len()];
        if table.glyph_indices(key.face, units, glyphs).is_none() {
            glyphs.fill(0);
        }
        for (index, (&glyph, width)) in glyphs.iter().zip(widths.iter_mut()).enumerate() {
            *width = match advances {
                Some(advances) => advances[start + index],
                None => table.advance(key, glyph),
            };
        }
        let widths = &widths[..units.len()];
        let run_start = end;
        let run_end = widths
            .iter()
            .fold(run_start, |pen, &width| pen.saturating_add(width));
        if let Some(screen) = screen.as_deref_mut() {
            text.fill_run(screen, run_start, run_end, cell.height);
            let mut at = run_start;
            for (&glyph, &width) in glyphs.iter().zip(widths) {
                table.with_glyph(key, glyph, |metrics, bits| {
                    let top = text.row() + cell.ascent - metrics.origin_y;
                    text.draw_bits(screen, at + metrics.origin_x, top, metrics, bits);
                });
                at = at.saturating_add(width);
            }
        }
        end = run_end;
    }
    end
}

/// The width of `units` in the realised font `key`: their advances summed.
pub fn extent<B: Storage>(table: &mut FontTable<B>, key: Key, units: &[u16]) -> i32 {
    let mut glyphs = [0u16; CHUNK];
    let mut width = 0i32;
    for units in units.chunks(CHUNK) {
        let glyphs = &mut glyphs[..units.len()];
        if table.glyph_indices(key.face, units, glyphs).is_none() {
            return width;
        }
        for &glyph in glyphs.iter() {
            width = width.saturating_add(table.advance(key, glyph));
        }
    }
    width
}

/// The `index`th face an enumeration of `process`'s faces answers (see NtGdiEnumFontChunk in the
/// module notes): those named `name` (every one for none), in `char_set` (each it covers for
/// DEFAULT_CHARSET), or each once in its first character set when `families`.
pub fn enumerated<B: Storage>(
    table: &FontTable<B>,
    process: u16,
    name: Option<&[u16]>,
    char_set: u8,
    families: bool,
    index: usize,
) -> Option<FontEnumRecord> {
    let mut seen = 0;
    for (_, face) in table.visible(process) {
        if name.is_some_and(|name| !mapper::same_name(face.family.units(), name)) {
            continue;
        }
        let Some(font) = face.font() else {
            continue;
        };
        let Ok(signature) = metrics::signature(&font) else {
            continue;
        };
        for (set, script) in metrics::char_sets(&signature) {
            if !families && char_set != DEFAULT_CHARSET && set != char_set {
                continue;
            }
            if seen == index {
                return enumeration_record(&font, face, signature, set, script);
            }
            seen += 1;
            if families {
                break;
            }
        }
    }
    None
}

/// The enumeration's record of `face` in `char_set` (its script `script`): its metrics at the
/// enumeration's cell ([`metrics::ENUMERATION_CELL`]).
fn enumeration_record<B: Storage>(
    font: &Font,
    face: &table::Face<B>,
    signature: FontSignature,
    char_set: u8,
    script: &str,
) -> Option<FontEnumRecord> {
    let metric = metrics::text_metric(
        font,
        MetricSize::Cell(metrics::ENUMERATION_CELL),
        false,
        char_set,
    )
    .ok()?;
    let os2 = font.os2().ok().flatten();
    let post = font.post().ok().flatten();
    let pitch = if metrics::fixed_pitch(post.as_ref()) {
        FIXED_PITCH
    } else {
        VARIABLE_PITCH
    };
    let mut log_font = LogFontW::zeroed();
    log_font.height = metric.height;
    log_font.width = metric.ave_char_width;
    log_font.weight = metric.weight;
    log_font.italic = metric.italic;
    log_font.char_set = char_set;
    log_font.out_precision = ENUM_OUT_PRECISION;
    log_font.clip_precision = ENUM_CLIP_PRECISION;
    log_font.quality = ENUM_QUALITY;
    log_font.pitch_and_family = metrics::family(os2.as_ref()) | pitch;
    log_font.face_name = face.family.padded();
    let selection = os2.as_ref().map_or(0, |os2| os2.fs_selection);
    let mut flags = 0;
    if selection & 0x01 != 0 {
        flags |= NTM_ITALIC;
    }
    if selection & 0x20 != 0 {
        flags |= NTM_BOLD;
    }
    if selection & 0x40 != 0 {
        flags |= NTM_REGULAR;
    }
    let (ascent, descent) = match &os2 {
        Some(os2) => (os2.us_win_ascent as u32, os2.us_win_descent as u32),
        None => (
            font.hhea.ascender as u32,
            font.hhea.descender.unsigned_abs() as u32,
        ),
    };
    Some(FontEnumRecord {
        log_font: EnumLogFontExW {
            log_font,
            full_name: face.full.padded(),
            style: face.style.padded(),
            script: Name::<LF_FACESIZE>::ascii(script).padded(),
        },
        metric: NewTextMetricExW {
            metric: NewTextMetricW {
                text_metric: metric,
                flags,
                size_em: font.head.units_per_em as u32,
                cell_height: ascent + descent,
                avg_width: os2.as_ref().map_or(0, |os2| os2.x_avg_char_width as u32),
            },
            signature,
        },
        font_type: TRUETYPE_FONTTYPE,
    })
}

/// The bytes GetFontData reads for `table_tag` (0: the whole file) of the font file `bytes`, from
/// `offset` to the table's end; none (GDI_ERROR) for a table the font lacks or an offset at or
/// past its end.
pub fn font_data(bytes: &[u8], table_tag: u32, offset: u32) -> Option<&[u8]> {
    let data = if table_tag == 0 {
        bytes
    } else {
        // GetFontData's tag is the four characters read little-endian.
        Font::new(bytes).ok()?.table(Tag(table_tag.swap_bytes()))?
    };
    data.get(offset as usize..).filter(|rest| !rest.is_empty())
}

/// The OUTLINETEXTMETRICW of the realised font `key`, and its four names (family, face, style
/// and full name), as GetOutlineTextMetricsW lays them out: the structure, then the names one
/// after another, each with its terminator, the structure's members their offsets.
pub fn outline_metric<B: Storage>(
    table: &FontTable<B>,
    key: Key,
    char_set: u8,
) -> Option<(OutlineTextMetricW, [Name<64>; 4])> {
    let face = table.face(key.face)?;
    let font = face.font()?;
    let text_metric = table.text_metric(key, char_set)?;
    let mut fields = metrics::outline_fields(&font, MetricSize::Em(key.ppem)).ok()?;
    let names = [
        Name::of(face.family.units().iter().copied()),
        face.full,
        Name::of(face.style.units().iter().copied()),
        face.unique,
    ];
    let mut at = core::mem::size_of::<OutlineTextMetricW>() as u32;
    let mut offsets = [0u32; 4];
    for (offset, name) in offsets.iter_mut().zip(&names) {
        *offset = at;
        at += 2 * (name.units().len() as u32 + 1);
    }
    [
        fields.family_name,
        fields.face_name,
        fields.style_name,
        fields.full_name,
    ] = offsets;
    Some((
        OutlineTextMetricW {
            size: at,
            text_metrics: text_metric,
            filler: 0,
            panose: metrics::panose(&font).ok()?,
            padding: 0,
            fields,
        },
        names,
    ))
}

// --- The services --------------------------------------------------------------------------------

/// NtGdiHfontCreate(LogFont, Font): a font object of the caller's LOGFONTW, its handle into `out`.
pub fn hfont_create(call: &mut NtCall, log_font: UserAddr, out: UserPtr<u32>) -> NtResult {
    let log_font = log_font.cast::<LogFontW>().read()?;
    let handle = publish_font(call, FontObject { log_font })?;
    if out.write(handle).is_err() {
        close_font(call, Handle(handle))?;
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(STATUS_SUCCESS)
}

/// NtGdiExtGetObjectW(Object, Count, Buffer, Size): a font's LOGFONTW (see the module notes);
/// STATUS_INVALID_HANDLE for a handle that names no font.
pub fn ext_get_object_w(
    _call: &mut NtCall,
    object: Handle,
    count: u32,
    buffer: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let log_font = font_of(object).ok_or(STATUS_INVALID_HANDLE)?;
    let bytes = log_font.as_bytes();
    let written = if buffer.is_null() {
        bytes.len()
    } else {
        let length = bytes.len().min(count as usize);
        buffer.write(&bytes[..length])?;
        length
    };
    out.write(written as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiAddFontResourceW(File, Flags, Faces): the open file's face loaded once more for every
/// process, or for the calling one (FR_PRIVATE), the faces it holds into `out`;
/// STATUS_INVALID_IMAGE_FORMAT for a file that is no TrueType font, STATUS_INSUFFICIENT_RESOURCES
/// when the table or the pool is full.
pub fn add_font_resource_w(
    call: &mut NtCall,
    file: Handle,
    flags: u32,
    out: UserPtr<u32>,
) -> NtResult {
    let owner = owner_for(call, flags);
    let faces = load_file(file, owner)?;
    out.write(faces)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiRemoveFontResourceW(File, Flags, Removed): one load of the open file's face for every
/// process, or for the calling one (FR_PRIVATE), removed; whether there was one into `out` (none
/// is no failure of the service: RemoveFontResource's FALSE leaves the last error).
pub fn remove_font_resource_w(
    call: &mut NtCall,
    file: Handle,
    flags: u32,
    out: UserPtr<u32>,
) -> NtResult {
    let owner = owner_for(call, flags);
    let identity = file_identity(file)?;
    let removed = with_table(|table| table.remove(identity, owner)).unwrap_or(false);
    out.write(removed as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetTextFaceW(Dc, Count, Buffer, Length): see the module notes.
pub fn get_text_face_w(
    call: &mut NtCall,
    dc: Handle,
    count: u32,
    buffer: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let realization = realize(call, dc)?;
    let name = realization.name();
    let units = name.units();
    let written = if buffer.is_null() {
        units.len() + 1
    } else if count == 0 {
        0
    } else {
        let length = (count as usize).min(units.len() + 1);
        let mut terminated = name.padded();
        terminated[length - 1] = 0;
        buffer.write(&terminated.as_bytes()[..2 * length])?;
        length
    };
    out.write(written as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetOutlineTextMetricsInternalW(Dc, Size, Buffer, Needed): see the module notes; at most
/// `size` bytes are written, the bytes written answered (the whole size for a null buffer).
pub fn get_outline_text_metrics_internal_w(
    call: &mut NtCall,
    dc: Handle,
    size: u32,
    buffer: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let Realization::TrueType { key, char_set, .. } = realize(call, dc)? else {
        out.write(0)?;
        return Ok(STATUS_SUCCESS);
    };
    let (metric, names) = with_table(|table| outline_metric(table, key, char_set))
        .flatten()
        .ok_or(STATUS_INVALID_HANDLE)?;
    if buffer.is_null() || size == 0 {
        out.write(metric.size)?;
        return Ok(STATUS_SUCCESS);
    }
    let limit = size.min(metric.size) as usize;
    let head = metric.as_bytes();
    buffer.write(&head[..head.len().min(limit)])?;
    let mut at = head.len();
    for name in &names {
        let mut units = name.padded();
        units[name.units().len()] = 0;
        let bytes = &units.as_bytes()[..2 * (name.units().len() + 1)];
        if at < limit {
            let length = bytes.len().min(limit - at);
            buffer.offset(at as u32).write(&bytes[..length])?;
        }
        at += bytes.len();
    }
    out.write(limit as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetCharWidthW(Dc, First, Count, Characters, Widths): see the module notes.
pub fn get_char_width_w(
    call: &mut NtCall,
    dc: Handle,
    first: u32,
    count: u32,
    characters: UserAddr,
    widths: UserAddr,
) -> NtResult {
    let realization = realize(call, dc)?;
    let mut buffer = [0u16; CHUNK];
    let mut answers = [0i32; CHUNK];
    let mut done = 0usize;
    while done < count as usize {
        let length = (count as usize - done).min(CHUNK);
        let units = characters_at(characters, first, done, &mut buffer[..length])?;
        match realization {
            Realization::BuiltIn { .. } => answers.fill(super::font::WIDTH),
            Realization::TrueType { key, .. } => {
                with_table(|table| {
                    let mut glyphs = [0u16; CHUNK];
                    let glyphs = &mut glyphs[..length];
                    table.glyph_indices(key.face, units, glyphs);
                    for (answer, &glyph) in answers.iter_mut().zip(glyphs.iter()) {
                        *answer = table.advance(key, glyph);
                    }
                })
                .ok_or(STATUS_INVALID_HANDLE)?;
            }
        }
        widths
            .offset(4 * done as u32)
            .write(&answers.as_bytes()[..4 * length])?;
        done += length;
    }
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetCharABCWidthsW(Dc, First, Count, Characters, Abc): see the module notes.
pub fn get_char_abc_widths_w(
    call: &mut NtCall,
    dc: Handle,
    first: u32,
    count: u32,
    characters: UserAddr,
    abc: UserAddr,
) -> NtResult {
    const ABCS: usize = 32;
    let Realization::TrueType { key, .. } = realize(call, dc)? else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let mut buffer = [0u16; ABCS];
    let mut answers = [Abc::default(); ABCS];
    let mut done = 0usize;
    while done < count as usize {
        let length = (count as usize - done).min(ABCS);
        let units = characters_at(characters, first, done, &mut buffer[..length])?;
        with_table(|table| {
            let mut glyphs = [0u16; ABCS];
            let glyphs = &mut glyphs[..length];
            table.glyph_indices(key.face, units, glyphs);
            for (answer, &glyph) in answers.iter_mut().zip(glyphs.iter()) {
                *answer = table
                    .with_glyph(key, glyph, |metrics, _| metrics::abc(metrics))
                    .unwrap_or_default();
            }
        })
        .ok_or(STATUS_INVALID_HANDLE)?;
        abc.offset(12 * done as u32)
            .write(&answers.as_bytes()[..12 * length])?;
        done += length;
    }
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetFontData(Dc, Table, Offset, Buffer, Count, Answer): see the module notes. The bytes
/// are copied a chunk at a time, each through a buffer of the stack, the table not held while the
/// caller's memory is written.
pub fn get_font_data(
    call: &mut NtCall,
    dc: Handle,
    table_tag: u32,
    offset: u32,
    buffer: UserAddr,
    count: u32,
    out: UserPtr<u32>,
) -> NtResult {
    let Realization::TrueType { key, .. } = realize(call, dc)? else {
        out.write(GDI_ERROR)?;
        return Ok(STATUS_SUCCESS);
    };
    let available = with_table(|table| {
        let face = table.face(key.face)?;
        font_data(face.bytes(), table_tag, offset).map(|rest| rest.len())
    })
    .flatten();
    let Some(available) = available else {
        out.write(GDI_ERROR)?;
        return Ok(STATUS_SUCCESS);
    };
    if buffer.is_null() || count == 0 {
        out.write((available + offset as usize) as u32)?;
        return Ok(STATUS_SUCCESS);
    }
    let length = available.min(count as usize);
    let mut chunk = [0u8; BYTES_CHUNK];
    let mut done = 0usize;
    while done < length {
        let take = (length - done).min(BYTES_CHUNK);
        let copied = with_table(|table| {
            let face = table.face(key.face)?;
            let rest = font_data(face.bytes(), table_tag, offset)?;
            chunk[..take].copy_from_slice(rest.get(done..done + take)?);
            Some(())
        })
        .flatten();
        if copied.is_none() {
            out.write(GDI_ERROR)?;
            return Ok(STATUS_SUCCESS);
        }
        buffer.offset(done as u32).write(&chunk[..take])?;
        done += take;
    }
    out.write(length as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiGetGlyphOutline(Dc, Character, Format, Metrics, Size, Buffer, Answer): see the module
/// notes. A GGO_BITMAP's rows are rendered into a block of the pool of their size, then copied to
/// the caller a chunk at a time.
#[allow(clippy::too_many_arguments)]
pub fn get_glyph_outline(
    call: &mut NtCall,
    dc: Handle,
    character: u32,
    format: u32,
    metrics_out: UserAddr,
    size: u32,
    buffer: UserAddr,
    out: UserPtr<u32>,
) -> NtResult {
    let kind = format & !GGO_GLYPH_INDEX;
    let Realization::TrueType { key, .. } = realize(call, dc)? else {
        out.write(GDI_ERROR)?;
        return Ok(STATUS_SUCCESS);
    };
    if kind != GGO_METRICS && kind != GGO_BITMAP {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let measured = with_table(|table| {
        let glyph = if format & GGO_GLYPH_INDEX != 0 {
            character.min(u16::MAX as u32) as u16
        } else {
            let mut glyph = [0u16];
            table.glyph_indices(key.face, &[character.min(0xFFFF) as u16], &mut glyph)?;
            glyph[0]
        };
        let rendered = table.render(key, glyph, &mut [])?.ok()?;
        Some((glyph, rendered))
    })
    .flatten();
    let Some((glyph, rendered)) = measured else {
        out.write(GDI_ERROR)?;
        return Ok(STATUS_SUCCESS);
    };
    let write_metrics = |metrics: &GlyphMetrics| -> Result<(), NtStatus> {
        if !metrics_out.is_null() {
            metrics_out.write(metrics.as_bytes())?;
        }
        Ok(())
    };
    if kind == GGO_METRICS {
        write_metrics(&rendered.metrics)?;
        out.write(metrics::metrics_size(&rendered.metrics))?;
        return Ok(STATUS_SUCCESS);
    }
    if buffer.is_null() || size == 0 || rendered.size == 0 {
        write_metrics(&rendered.metrics)?;
        out.write(rendered.size as u32)?;
        return Ok(STATUS_SUCCESS);
    }
    if (size as usize) < rendered.size {
        out.write(GDI_ERROR)?;
        return Ok(STATUS_SUCCESS);
    }
    let Some(mut bits) = allocate(rendered.size) else {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    let drawn = with_table(|table| table.render(key, glyph, bits.as_mut())?.ok()).flatten();
    let Some(drawn) = drawn else {
        out.write(GDI_ERROR)?;
        return Ok(STATUS_SUCCESS);
    };
    write_metrics(&drawn.metrics)?;
    for (index, chunk) in bits.as_ref()[..drawn.size].chunks(BYTES_CHUNK).enumerate() {
        buffer.offset((index * BYTES_CHUNK) as u32).write(chunk)?;
    }
    out.write(drawn.size as u32)?;
    Ok(STATUS_SUCCESS)
}

/// NtGdiEnumFontChunk(Dc, Face, CharSet, Flags, Index, Record): see the module notes.
pub fn enum_font_chunk(
    call: &mut NtCall,
    dc: Handle,
    face: UserAddr,
    char_set: u32,
    flags: u32,
    index: u32,
    record: UserAddr,
) -> NtResult {
    dc_state(call, dc)?;
    let mut name = [0u16; LF_FACESIZE];
    let name = if face.is_null() {
        None
    } else {
        face.read_units(&mut name)?;
        let end = name
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(LF_FACESIZE);
        Some(&name[..end]).filter(|name| !name.is_empty())
    };
    let process = process_index(call);
    let found = with_table(|table| {
        enumerated(
            table,
            process,
            name,
            char_set as u8,
            flags & ENUM_FAMILIES != 0,
            index as usize,
        )
    })
    .flatten()
    .ok_or(STATUS_NO_MORE_ENTRIES)?;
    record.write(found.as_bytes())?;
    Ok(STATUS_SUCCESS)
}

// --- What the DC services ask of the fonts -------------------------------------------------------

/// What the DC `dc`'s selected font realises to for the calling process.
pub fn realize(call: &mut NtCall, dc: Handle) -> Result<Realization, NtStatus> {
    let state = dc_state(call, dc)?;
    Ok(realize_selected(call, &state))
}

/// What the DC state `dc`'s selected font realises to for the calling process.
pub fn realize_selected(call: &mut NtCall, dc: &Dc) -> Realization {
    let built_in = Realization::BuiltIn {
        name: FaceName::ascii(mapper::BUILT_IN_FACE),
    };
    match selected(dc) {
        Selected::BuiltIn => built_in,
        Selected::Font(log_font) => {
            let process = process_index(call);
            with_table(|table| table.map(&log_font, process)).unwrap_or(built_in)
        }
    }
}

/// The characters a widths call asks for, `units.len()` of them from the `done`th: the caller's
/// array at `characters`, or the run from `first`.
fn characters_at(
    characters: UserAddr,
    first: u32,
    done: usize,
    units: &mut [u16],
) -> Result<&[u16], NtStatus> {
    if characters.is_null() {
        for (index, unit) in units.iter_mut().enumerate() {
            *unit = (first as usize + done + index).min(0xFFFF) as u16;
        }
    } else {
        characters.offset(2 * done as u32).read_units(units)?;
    }
    Ok(units)
}

/// Whom a load or removal with `flags` is for.
fn owner_for(call: &mut NtCall, flags: u32) -> Owner {
    if flags & FR_PRIVATE != 0 {
        Owner::Private(process_index(call))
    } else {
        Owner::Public
    }
}

// --- The target's side: the table behind its lock, the objects, the files ------------------------

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::fs::fat32::lookup::File;
    use crate::fs::file::rights::FILE_READ_DATA;
    use crate::mem::pool::{self, Block};
    use crate::sync::ShortLock;

    impl Storage for Block {
        fn allocate(bytes: usize) -> Option<Self> {
            pool::allocate(bytes)
        }
    }

    /// The kernel's one font table, behind its short lock (Windows 2000 guards its font tables
    /// with a semaphore of their own). The rasteriser's buffers inside it make it a few dozen KiB:
    /// a static's, never a stack's.
    static TABLE: ShortLock<FontTable<Block>> = ShortLock::new(FontTable::new());

    /// Run `f` on the locked font table (the bridge for code without a passive token: see
    /// `crate::win32k::window::locked`). Never with the caller's memory: copies to and from it go
    /// outside.
    pub fn with_table<R>(f: impl FnOnce(&mut FontTable<Block>) -> R) -> Option<R> {
        assert_eq!(
            crate::pcr::pcr().current(),
            crate::interrupt::irql::PASSIVE,
            "the font table's bridge entered above the passive level"
        );
        // SAFETY: a passive entry (see `At::enter`): the ledger reads the passive level, and the
        // token stays on this thread, dropped with this frame.
        let mut passive = unsafe { crate::level::At::<crate::level::Passive>::enter() };
        let mut table = TABLE.lock(&mut passive);
        Some(f(&mut table))
    }

    /// A pool block of `bytes` bytes, for a call's own copy.
    pub fn allocate(bytes: usize) -> Option<Block> {
        pool::allocate(bytes)
    }

    /// The calling process, as the table names an owner: its object's index.
    pub fn process_index(call: &mut NtCall) -> u16 {
        call.process().object().index
    }

    /// The selected font of the DC state `dc`.
    pub fn selected(dc: &Dc) -> Selected {
        dc.font_object
            .and_then(|id| {
                crate::ob::locked(|directory| directory.font(id).map(|font| font.log_font))
            })
            .map_or(Selected::BuiltIn, Selected::Font)
    }

    /// The DC `handle` names, its state as it is now.
    pub fn dc_state(call: &mut NtCall, handle: Handle) -> Result<Dc, NtStatus> {
        super::super::dc::dc_of(call, handle).map(|(_reference, dc)| dc)
    }

    /// The LOGFONT of the font object `handle` names in the calling process.
    pub fn font_of(handle: Handle) -> Option<LogFontW> {
        let table = font_table_handle(handle)?;
        let reference = crate::ob::reference_by_handle(table, Some(crate::ob::ObjectType::Font))?;
        crate::ob::locked(|directory| directory.font(reference.id()).map(|font| font.log_font))
    }

    /// The object id of the font object `handle` names in the calling process.
    pub fn font_id(handle: Handle) -> Option<crate::ob::ObjectId> {
        crate::process::current()
            .lookup_handle(font_table_handle(handle)?)
            .and_then(|entry| entry.object_id())
            .filter(|id| id.kind == crate::ob::ObjectType::Font)
    }

    /// A font object holding `font`, its handle in the calling process (not inheritable) under
    /// the font kind's bits ([`rtl::gdi::object_handle`]); STATUS_INSUFFICIENT_RESOURCES when the
    /// pool or the handle table is full.
    pub fn publish_font(call: &mut NtCall, font: FontObject) -> Result<u32, NtStatus> {
        let id = crate::ob::locked(|directory| directory.create_font(font))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        crate::ob::publish(call.process(), id, FONT_ACCESS, false)
            .map(|table| object_handle(OBJ_FONT, table.get()))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)
    }

    /// Close the calling process's handle `handle` when it names a font; STATUS_INVALID_HANDLE
    /// otherwise.
    pub fn close_font(call: &mut NtCall, handle: Handle) -> Result<(), NtStatus> {
        let process = call.process();
        let table = font_table_handle(handle).filter(|_| font_id(handle).is_some());
        if table.is_some_and(|table| process.close_handle(table)) {
            Ok(())
        } else {
            Err(STATUS_INVALID_HANDLE)
        }
    }

    /// The open disk file `handle` names, read access checked.
    fn open_file(handle: Handle) -> Result<File, NtStatus> {
        let object = crate::fs::io::object_of(handle.raw()).ok_or(STATUS_INVALID_HANDLE)?;
        let record = object.disk().ok_or(STATUS_INVALID_PARAMETER)?;
        if object.granted & FILE_READ_DATA == 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(crate::fs::io::file_at(record))
    }

    fn identity(file: &File) -> FileIdentity {
        FileIdentity {
            parent_cluster: file.parent_cluster,
            index: file.index,
        }
    }

    /// The identity of the open disk file `handle` names.
    pub fn file_identity(handle: Handle) -> Result<FileIdentity, NtStatus> {
        open_file(handle).map(|file| identity(&file))
    }

    /// A load of the open file `handle` names for `owner`: the faces it holds (see
    /// NtGdiAddFontResourceW).
    pub fn load_file(handle: Handle, owner: Owner) -> Result<u32, NtStatus> {
        let file = open_file(handle)?;
        if file.directory {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let identity = identity(&file);
        if with_table(|table| table.load_again(identity, owner)) == Some(true) {
            return Ok(1);
        }
        let block = read_whole(&file)?;
        add(block, identity, owner)
    }

    /// The whole of `file`, read off the volume into a block of the pool, outside any lock but
    /// the volume's (the disk's reads may block: a critical region, as the file services' reads).
    fn read_whole(file: &File) -> Result<Block, NtStatus> {
        if file.size == 0 || file.size > MAX_FONT_FILE {
            return Err(STATUS_INVALID_IMAGE_FORMAT);
        }
        let mut block = pool::allocate(file.size as usize).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let read = crate::process::threads::critical_region(|| {
            crate::fs::io::read_file_at(file, 0, block.as_mut())
        });
        read.ok_or(STATUS_IO_DEVICE_ERROR)?;
        Ok(block)
    }

    fn add(block: Block, identity: FileIdentity, owner: Owner) -> Result<u32, NtStatus> {
        match with_table(|table| table.add(block, identity, owner)) {
            Some(Ok(faces)) => Ok(faces),
            Some(Err(table::AddError::NotAFont)) => Err(STATUS_INVALID_IMAGE_FORMAT),
            _ => Err(STATUS_INSUFFICIENT_RESOURCES),
        }
    }

    /// The boot's load (see the module notes): each face of [`BOOT_FONTS`] the volume has, public;
    /// a file the volume lacks is passed over without a word.
    pub fn load_boot_fonts() {
        for path in BOOT_FONTS {
            let found = crate::fs::fat32::volume::with_boot_volume(|volume| {
                crate::fs::fat32::lookup::lookup(volume, path.as_bytes())
            });
            let Some(Ok(file)) = found else {
                continue;
            };
            let loaded =
                read_whole(&file).and_then(|block| add(block, identity(&file), Owner::Public));
            match loaded {
                Ok(_) => {
                    crate::serial_println!("F2K: win32k: font loaded: \\{}", path);
                }
                Err(status) => {
                    crate::serial_println!(
                        "F2K: win32k: font not loaded: \\{} ({:#010x})",
                        path,
                        status.0
                    );
                }
            }
        }
    }

    /// The process whose object's index is `process` ended: its private faces go.
    pub fn end_process(process: u16) {
        with_table(|table| table.end_process(process));
    }
}

#[cfg(target_arch = "x86")]
use target::*;
#[cfg(target_arch = "x86")]
pub use target::{end_process, load_boot_fonts};

// The host builds have no table, no objects and no files: the services' helpers answer none (the
// host tests drive the table, the mapper and the text runs directly).

#[cfg(not(target_arch = "x86"))]
mod host {
    use super::*;

    /// The host's storage: none to be had.
    pub struct Store;

    impl AsRef<[u8]> for Store {
        fn as_ref(&self) -> &[u8] {
            &[]
        }
    }

    impl AsMut<[u8]> for Store {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut []
        }
    }

    impl Storage for Store {
        fn allocate(_: usize) -> Option<Self> {
            None
        }
    }

    pub fn with_table<R>(_: impl FnOnce(&mut FontTable<Store>) -> R) -> Option<R> {
        None
    }

    pub fn allocate(_: usize) -> Option<Store> {
        None
    }

    pub fn process_index(_: &mut NtCall) -> u16 {
        0
    }

    pub fn selected(_: &Dc) -> Selected {
        Selected::BuiltIn
    }

    pub fn dc_state(_: &mut NtCall, _: Handle) -> Result<Dc, NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn font_of(_: Handle) -> Option<LogFontW> {
        None
    }

    pub fn font_id(_: Handle) -> Option<crate::ob::ObjectId> {
        None
    }

    pub fn publish_font(_: &mut NtCall, _: FontObject) -> Result<u32, NtStatus> {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn close_font(_: &mut NtCall, _: Handle) -> Result<(), NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn file_identity(_: Handle) -> Result<FileIdentity, NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }

    pub fn load_file(_: Handle, _: Owner) -> Result<u32, NtStatus> {
        Err(STATUS_INVALID_HANDLE)
    }
}

#[cfg(not(target_arch = "x86"))]
use host::*;

pub use self::selection::*;

/// What dc.rs asks: whether a handle is a font object's, and closing one.
mod selection {
    use super::*;

    /// The object id of the font object `handle` names in the calling process: what a DC's
    /// selection keeps beside the handle.
    pub fn font_object(handle: Handle) -> Option<crate::ob::ObjectId> {
        font_id(handle)
    }

    /// DeleteObject of a font: its handle closed; STATUS_INVALID_HANDLE for a handle that names
    /// no font.
    pub fn delete_font(call: &mut NtCall, handle: Handle) -> Result<(), NtStatus> {
        close_font(call, handle)
    }

    /// The table's realised font `key`'s cell, and a run of text drawn in it on `screen` (see
    /// [`draw_run`]); the pen's column after it. The run's pen alone moves when the face is gone.
    pub fn draw_text<M: PixelMemory>(
        screen: Option<&mut Framebuffer<M>>,
        text: &TextOut,
        key: Key,
        pen: i32,
        units: &[u16],
        advances: Option<&[i32]>,
    ) -> i32 {
        with_table(|table| {
            let cell = table.cell(key)?;
            Some(draw_run(
                table, screen, text, key, cell, pen, units, advances,
            ))
        })
        .flatten()
        .unwrap_or(pen)
    }

    /// The TEXTMETRICW of the realised font `key` in `char_set`.
    pub fn text_metric(key: Key, char_set: u8) -> Option<TextMetricW> {
        with_table(|table| table.text_metric(key, char_set)).flatten()
    }

    /// The width of `units` in the realised font `key`.
    pub fn text_width(key: Key, units: &[u16]) -> i32 {
        with_table(|table| extent(table, key, units)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests;
