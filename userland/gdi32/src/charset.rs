//! Character sets: the DC's font's (GetTextCharset, GetTextCharsetInfo, through win32k's
//! NtGdiGetTextCharsetInfo, and GetFontLanguageInfo over it), and TranslateCharsetInfo's table of
//! the character sets, their ANSI code pages and their font-signature code-page bits, as Windows
//! 2000's gdi32 keeps it (the txlayout capture's charset block: OEM_CHARSET, code page 437 and a
//! signature of two bits are none of its entries).

use rtl::edge::Out;
use rtl::gdi::*;

use crate::imports::{self, Caller};
use crate::{answered, failed, ERROR_INVALID_PARAMETER};

/// DEFAULT_CHARSET: GetTextCharset's and GetTextCharsetInfo's failure.
const DEFAULT_CHARSET: i32 = 1;

/// TranslateCharsetInfo's sources: a character set, a code page, a font signature's code pages.
pub const TCI_SRCCHARSET: u32 = 1;
pub const TCI_SRCCODEPAGE: u32 = 2;
pub const TCI_SRCFONTSIG: u32 = 3;

/// GetFontLanguageInfo's flags: the font's double-byte characters (GCP_DBCS), its right-to-left
/// order (GCP_REORDER), its glyph shaping (GCP_GLYPHSHAPE); GCP_ERROR for a DC that is none.
pub const GCP_DBCS: u32 = 0x0001;
pub const GCP_REORDER: u32 = 0x0002;
pub const GCP_GLYPHSHAPE: u32 = 0x0010;
pub const GCP_ERROR: u32 = 0x8000;

/// The code-page bits that make each of GetFontLanguageInfo's flags (Wine's reading of Windows'):
/// the double-byte code pages (Thai's bit with them), Hebrew and Arabic's order, Arabic's shapes.
const DBCS_PAGES: u32 = 0x003F_0000;
const REORDER_PAGES: u32 = 0x0000_0060;
const GLYPHSHAPE_PAGES: u32 = 0x0000_0040;

/// CHARSETINFO: a character set, its ANSI code page, and its font signature (its code-page bit).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CharsetInfo {
    pub char_set: u32,
    pub acp: u32,
    pub signature: FontSignature,
}

/// The character sets TranslateCharsetInfo knows: each one's code page and code-page bit.
pub const CHARSETS: [(u32, u32, u32); 16] = [
    (0, 1252, 0x0000_0001),   // ANSI_CHARSET, Latin 1
    (238, 1250, 0x0000_0002), // EASTEUROPE_CHARSET, Latin 2
    (204, 1251, 0x0000_0004), // RUSSIAN_CHARSET, Cyrillic
    (161, 1253, 0x0000_0008), // GREEK_CHARSET
    (162, 1254, 0x0000_0010), // TURKISH_CHARSET
    (177, 1255, 0x0000_0020), // HEBREW_CHARSET
    (178, 1256, 0x0000_0040), // ARABIC_CHARSET
    (186, 1257, 0x0000_0080), // BALTIC_CHARSET
    (163, 1258, 0x0000_0100), // VIETNAMESE_CHARSET
    (222, 874, 0x0001_0000),  // THAI_CHARSET
    (128, 932, 0x0002_0000),  // SHIFTJIS_CHARSET, Japanese
    (134, 936, 0x0004_0000),  // GB2312_CHARSET, simplified Chinese
    (129, 949, 0x0008_0000),  // HANGEUL_CHARSET, Korean Wansung
    (136, 950, 0x0010_0000),  // CHINESEBIG5_CHARSET, traditional Chinese
    (130, 1361, 0x0020_0000), // JOHAB_CHARSET, Korean Johab
    (2, 42, 0x8000_0000),     // SYMBOL_CHARSET, CP_SYMBOL
];

/// The CHARSETINFO of the entry whose `flags` source (TCI_SRC*) is `source` (a font signature's
/// first code-page DWORD for TCI_SRCFONTSIG, which must name one bit exactly); none for no entry.
pub fn translate(source: u32, flags: u32) -> Option<CharsetInfo> {
    let column = |&(char_set, acp, bit): &(u32, u32, u32)| match flags {
        TCI_SRCCHARSET => char_set,
        TCI_SRCCODEPAGE => acp,
        _ => bit,
    };
    let &(char_set, acp, bit) = CHARSETS.iter().find(|entry| column(entry) == source)?;
    Some(CharsetInfo {
        char_set,
        acp,
        signature: FontSignature {
            usb: [0; 4],
            csb: [bit, 0],
        },
    })
}

/// GetFontLanguageInfo's flags for a font of `signature`, laid out under the alignment `align`.
pub fn language_flags(signature: &FontSignature, align: u32) -> u32 {
    let pages = signature.csb[0];
    let mut flags = 0;
    if pages & DBCS_PAGES != 0 {
        flags |= GCP_DBCS;
    }
    if pages & REORDER_PAGES != 0 || align & TA_RTLREADING != 0 {
        flags |= GCP_REORDER;
    }
    if pages & GLYPHSHAPE_PAGES != 0 {
        flags |= GCP_GLYPHSHAPE;
    }
    flags
}

/// GetTextCharsetInfo: the DC's font's character set, its FONTSIGNATURE into `signature` (when
/// not null); DEFAULT_CHARSET with the last error for a DC that is none.
#[unsafe(export_name = "f2k_export_GetTextCharsetInfo")]
pub extern "system" fn get_text_charset_info(
    dc: usize,
    signature: *mut FontSignature,
    flags: u32,
) -> i32 {
    answered(imports::text_charset_info(
        dc,
        Caller(signature as usize),
        flags,
    ))
    .map_or(DEFAULT_CHARSET, |char_set| char_set as i32)
}

/// GetTextCharset: GetTextCharsetInfo's character set.
#[unsafe(export_name = "f2k_export_GetTextCharset")]
pub extern "system" fn get_text_charset(dc: usize) -> i32 {
    get_text_charset_info(dc, core::ptr::null_mut(), 0)
}

/// GetFontLanguageInfo: the flags the DC's font's code pages and the DC's TA_RTLREADING make
/// ([`language_flags`]); GCP_ERROR for a DC that is none, the last error untouched. (No
/// GCP_USEKERNING: F2K reads no kerning pairs yet.)
#[unsafe(export_name = "f2k_export_GetFontLanguageInfo")]
pub extern "system" fn get_font_language_info(dc: usize) -> u32 {
    let mut signature = FontSignature::default();
    if imports::text_charset_info(dc, Caller::of_mut(&mut signature), 0).is_err() {
        return GCP_ERROR;
    }
    let align = imports::dc_dword(dc, DC_TEXT_ALIGN).unwrap_or(0);
    language_flags(&signature, align)
}

/// TranslateCharsetInfo: the CHARSETINFO of the entry `source` names ([`translate`]: the value
/// itself for a character set or a code page, a pointer to a font signature's code pages for
/// TCI_SRCFONTSIG) into `info`; FALSE for none, the last error untouched, and FALSE with
/// ERROR_INVALID_PARAMETER for another flag.
///
/// # Safety
///
/// For TCI_SRCFONTSIG, the caller's code-page DWORDs at `source`; the caller's CHARSETINFO.
#[unsafe(export_name = "f2k_export_TranslateCharsetInfo")]
pub unsafe extern "system" fn translate_charset_info(
    source: usize,
    info: *mut CharsetInfo,
    flags: u32,
) -> u32 {
    let source = match flags {
        TCI_SRCCHARSET | TCI_SRCCODEPAGE => source as u32,
        // SAFETY: the caller's font signature's first code-page DWORD.
        TCI_SRCFONTSIG => unsafe { rtl::edge::In::new(source as *const u32) }.read(),
        _ => return failed(ERROR_INVALID_PARAMETER).unwrap_or(0),
    };
    let Some(found) = translate(source, flags) else {
        return 0;
    };
    // SAFETY: the caller's CHARSETINFO, or null.
    match unsafe { Out::optional(info) } {
        Some(mut info) => {
            info.set(found);
            1
        }
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{BAD, DC, LAST_ERROR};
    use crate::ERROR_INVALID_HANDLE;

    fn info(char_set: u32, acp: u32, bit: u32) -> Option<CharsetInfo> {
        Some(CharsetInfo {
            char_set,
            acp,
            signature: FontSignature {
                usb: [0; 4],
                csb: [bit, 0],
            },
        })
    }

    /// The txlayout capture's translations: from character sets, code pages and font
    /// signatures; OEM_CHARSET, 99, code pages 437 and 0, and a signature of two bits or none
    /// are no entry.
    #[test]
    fn the_capture_s_translations() {
        assert_eq!(translate(0, TCI_SRCCHARSET), info(0, 1252, 1));
        assert_eq!(translate(2, TCI_SRCCHARSET), info(2, 42, 0x8000_0000));
        assert_eq!(translate(128, TCI_SRCCHARSET), info(128, 932, 0x0002_0000));
        assert_eq!(translate(161, TCI_SRCCHARSET), info(161, 1253, 8));
        assert_eq!(translate(204, TCI_SRCCHARSET), info(204, 1251, 4));
        assert_eq!(translate(238, TCI_SRCCHARSET), info(238, 1250, 2));
        assert_eq!(translate(255, TCI_SRCCHARSET), None);
        assert_eq!(translate(99, TCI_SRCCHARSET), None);
        assert_eq!(translate(1252, TCI_SRCCODEPAGE), info(0, 1252, 1));
        assert_eq!(translate(1250, TCI_SRCCODEPAGE), info(238, 1250, 2));
        assert_eq!(translate(932, TCI_SRCCODEPAGE), info(128, 932, 0x0002_0000));
        assert_eq!(translate(437, TCI_SRCCODEPAGE), None);
        assert_eq!(translate(0, TCI_SRCCODEPAGE), None);
        assert_eq!(translate(1, TCI_SRCFONTSIG), info(0, 1252, 1));
        assert_eq!(translate(2, TCI_SRCFONTSIG), info(238, 1250, 2));
        assert_eq!(
            translate(0x0002_0000, TCI_SRCFONTSIG),
            info(128, 932, 0x0002_0000)
        );
        assert_eq!(translate(6, TCI_SRCFONTSIG), None);
        assert_eq!(translate(0, TCI_SRCFONTSIG), None);
    }

    /// The export: a signature read through its pointer; an unknown flag ERROR_INVALID_PARAMETER;
    /// no entry FALSE, the structure and the last error untouched.
    ///
    /// Pins: gdi32.TranslateCharsetInfo
    #[test]
    fn translate_charset_info_reads_its_source() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
        let mut out = CharsetInfo::default();
        let pages = [0x0000_0002u32, 0];
        // SAFETY: the tests' own signature and structure.
        unsafe {
            assert_eq!(
                translate_charset_info(pages.as_ptr() as usize, &mut out, TCI_SRCFONTSIG),
                1
            );
            assert_eq!(Some(out), info(238, 1250, 2));
            out = CharsetInfo::default();
            assert_eq!(translate_charset_info(437, &mut out, TCI_SRCCODEPAGE), 0);
            assert_eq!(out, CharsetInfo::default());
            assert_eq!(LAST_ERROR.with(|error| error.get()), 0xF2F2);
            assert_eq!(translate_charset_info(0, &mut out, 7), 0);
        }
        assert_eq!(
            LAST_ERROR.with(|error| error.get()),
            ERROR_INVALID_PARAMETER
        );
    }

    /// The DC's character set and signature; DEFAULT_CHARSET with ERROR_INVALID_HANDLE for a DC
    /// that is none; GetFontLanguageInfo's flags from the code pages (the stand-in's font has
    /// Hebrew's and Arabic's) and GCP_ERROR without an error for a DC that is none.
    ///
    /// Pins: gdi32.GetTextCharset gdi32.GetTextCharsetInfo gdi32.GetFontLanguageInfo
    #[test]
    fn the_font_s_character_set() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
        let mut signature = FontSignature::default();
        assert_eq!(get_text_charset_info(DC, &mut signature, 0), 0);
        assert_eq!(signature.csb, [0x60, 0]);
        assert_eq!(get_text_charset(DC), 0);
        assert_eq!(get_font_language_info(DC), GCP_REORDER | GCP_GLYPHSHAPE);
        assert_eq!(get_font_language_info(BAD), GCP_ERROR);
        assert_eq!(LAST_ERROR.with(|error| error.get()), 0xF2F2);
        assert_eq!(get_text_charset(BAD), DEFAULT_CHARSET);
        assert_eq!(LAST_ERROR.with(|error| error.get()), ERROR_INVALID_HANDLE);
    }

    /// The flags each code page makes: none for Latin 1 or no signature (a raster font's);
    /// GCP_DBCS for Japanese; GCP_REORDER under TA_RTLREADING too.
    #[test]
    fn language_flags_follow_the_code_pages() {
        let of = |pages| FontSignature {
            usb: [0; 4],
            csb: [pages, 0],
        };
        assert_eq!(language_flags(&of(0), 0), 0);
        assert_eq!(language_flags(&of(1), 0), 0);
        assert_eq!(language_flags(&of(0x0002_0000), 0), GCP_DBCS);
        assert_eq!(language_flags(&of(0x20), 0), GCP_REORDER);
        assert_eq!(language_flags(&of(1), TA_RTLREADING), GCP_REORDER);
    }
}
