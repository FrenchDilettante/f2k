//! The fixed-layout tables: the font header (`head`), the horizontal header (`hhea`), the maximum
//! profile (`maxp`), the OS/2 and Windows metrics (`OS/2`) and the PostScript table's header
//! (`post`). Each is read whole into a structure of its fields, as the OpenType specification
//! names them.

use super::{read, Error};

/// The `head` table's magic number.
const HEAD_MAGIC: u32 = 0x5F0F_3CF5;

/// The font header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The font's revision, a 16.16 fixed-point number.
    pub font_revision: i32,
    pub checksum_adjustment: u32,
    pub flags: u16,
    /// The em square's size in font units: 16 to 16384.
    pub units_per_em: u16,
    /// The bounding box of every glyph, in font units.
    pub x_min: i16,
    pub y_min: i16,
    pub x_max: i16,
    pub y_max: i16,
    pub mac_style: u16,
    /// The smallest readable size, in pixels per em.
    pub lowest_rec_ppem: u16,
    pub font_direction_hint: i16,
    /// The `loca` table's entries: 0 for 16-bit offsets (halved), 1 for 32-bit ones.
    pub index_to_loc_format: i16,
}

impl Head {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        read::bytes(data, 0, 54)?;
        if read::u16(data, 0)? != 1 || read::u32(data, 12)? != HEAD_MAGIC {
            return Err(Error::Malformed);
        }
        let head = Self {
            font_revision: read::i32(data, 4)?,
            checksum_adjustment: read::u32(data, 8)?,
            flags: read::u16(data, 16)?,
            units_per_em: read::u16(data, 18)?,
            x_min: read::i16(data, 36)?,
            y_min: read::i16(data, 38)?,
            x_max: read::i16(data, 40)?,
            y_max: read::i16(data, 42)?,
            mac_style: read::u16(data, 44)?,
            lowest_rec_ppem: read::u16(data, 46)?,
            font_direction_hint: read::i16(data, 48)?,
            index_to_loc_format: read::i16(data, 50)?,
        };
        if !(16..=16384).contains(&head.units_per_em)
            || !(0..=1).contains(&head.index_to_loc_format)
        {
            return Err(Error::Malformed);
        }
        Ok(head)
    }
}

/// The horizontal header: the font's ascent, descent and line gap as the Macintosh uses them, and
/// the number of full entries in `hmtx`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hhea {
    pub ascender: i16,
    pub descender: i16,
    pub line_gap: i16,
    pub advance_width_max: u16,
    pub min_left_side_bearing: i16,
    pub min_right_side_bearing: i16,
    pub x_max_extent: i16,
    pub caret_slope_rise: i16,
    pub caret_slope_run: i16,
    pub caret_offset: i16,
    pub number_of_h_metrics: u16,
}

impl Hhea {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        read::bytes(data, 0, 36)?;
        if read::u16(data, 0)? != 1 {
            return Err(Error::Malformed);
        }
        let hhea = Self {
            ascender: read::i16(data, 4)?,
            descender: read::i16(data, 6)?,
            line_gap: read::i16(data, 8)?,
            advance_width_max: read::u16(data, 10)?,
            min_left_side_bearing: read::i16(data, 12)?,
            min_right_side_bearing: read::i16(data, 14)?,
            x_max_extent: read::i16(data, 16)?,
            caret_slope_rise: read::i16(data, 18)?,
            caret_slope_run: read::i16(data, 20)?,
            caret_offset: read::i16(data, 22)?,
            number_of_h_metrics: read::u16(data, 34)?,
        };
        if hhea.number_of_h_metrics == 0 {
            return Err(Error::Malformed);
        }
        Ok(hhea)
    }
}

/// The maximum profile: the glyph count, and (in a TrueType font's version 1.0) the most points,
/// contours and components a glyph holds. The maxima are the font's own claims; the outline reader
/// bounds its work by its caller's buffers, not by them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Maxp {
    /// 0x00005000 (version 0.5: the glyph count alone) or 0x00010000.
    pub version: u32,
    pub num_glyphs: u16,
    /// Version 1.0's fields, zero in version 0.5.
    pub max_points: u16,
    pub max_contours: u16,
    pub max_composite_points: u16,
    pub max_composite_contours: u16,
    pub max_zones: u16,
    pub max_twilight_points: u16,
    pub max_storage: u16,
    pub max_function_defs: u16,
    pub max_instruction_defs: u16,
    pub max_stack_elements: u16,
    pub max_size_of_instructions: u16,
    pub max_component_elements: u16,
    pub max_component_depth: u16,
}

impl Maxp {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let version = read::u32(data, 0)?;
        let num_glyphs = read::u16(data, 4)?;
        let field = |offset| {
            if version >= 0x0001_0000 {
                read::u16(data, offset)
            } else {
                Ok(0)
            }
        };
        if version != 0x0000_5000 && version != 0x0001_0000 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            version,
            num_glyphs,
            max_points: field(6)?,
            max_contours: field(8)?,
            max_composite_points: field(10)?,
            max_composite_contours: field(12)?,
            max_zones: field(14)?,
            max_twilight_points: field(16)?,
            max_storage: field(18)?,
            max_function_defs: field(20)?,
            max_instruction_defs: field(22)?,
            max_stack_elements: field(24)?,
            max_size_of_instructions: field(26)?,
            max_component_elements: field(28)?,
            max_component_depth: field(30)?,
        })
    }
}

/// The OS/2 and Windows metrics: the font's weight and width classes, its sub- and superscript
/// and strikeout geometry, its PANOSE classification, the character ranges and code pages it
/// covers, and the ascent and descent Windows uses (the `win` pair) and typographers use (the
/// `typo` triple). A field the table's version does not carry reads as zero; `version` says which
/// are present (0: through `us_win_descent`, though Apple's shorter version 0 stops before the
/// `typo` fields; 1: the code page ranges too; 2 and later: the x-height through
/// `us_max_context` too).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Os2 {
    pub version: u16,
    pub x_avg_char_width: i16,
    pub us_weight_class: u16,
    pub us_width_class: u16,
    pub fs_type: u16,
    pub y_subscript_x_size: i16,
    pub y_subscript_y_size: i16,
    pub y_subscript_x_offset: i16,
    pub y_subscript_y_offset: i16,
    pub y_superscript_x_size: i16,
    pub y_superscript_y_size: i16,
    pub y_superscript_x_offset: i16,
    pub y_superscript_y_offset: i16,
    pub y_strikeout_size: i16,
    pub y_strikeout_position: i16,
    pub s_family_class: i16,
    pub panose: [u8; 10],
    pub ul_unicode_range: [u32; 4],
    pub ach_vend_id: [u8; 4],
    pub fs_selection: u16,
    pub us_first_char_index: u16,
    pub us_last_char_index: u16,
    pub s_typo_ascender: i16,
    pub s_typo_descender: i16,
    pub s_typo_line_gap: i16,
    pub us_win_ascent: u16,
    pub us_win_descent: u16,
    pub ul_code_page_range: [u32; 2],
    pub sx_height: i16,
    pub s_cap_height: i16,
    pub us_default_char: u16,
    pub us_break_char: u16,
    pub us_max_context: u16,
}

impl Os2 {
    /// The table, at least Apple's 68-byte version 0.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        read::bytes(data, 0, 68)?;
        // A field past the table's end reads as zero: the table's version decides which exist,
        // and its length bounds them.
        let u16_or_zero = |offset| read::u16(data, offset).unwrap_or(0);
        let i16_or_zero = |offset| read::i16(data, offset).unwrap_or(0);
        let u32_or_zero = |offset| read::u32(data, offset).unwrap_or(0);
        let mut panose = [0; 10];
        panose.copy_from_slice(read::bytes(data, 32, 10)?);
        let mut ach_vend_id = [0; 4];
        ach_vend_id.copy_from_slice(read::bytes(data, 58, 4)?);
        let version = read::u16(data, 0)?;
        let (v1, v2) = (version >= 1, version >= 2);
        Ok(Self {
            version,
            x_avg_char_width: read::i16(data, 2)?,
            us_weight_class: read::u16(data, 4)?,
            us_width_class: read::u16(data, 6)?,
            fs_type: read::u16(data, 8)?,
            y_subscript_x_size: read::i16(data, 10)?,
            y_subscript_y_size: read::i16(data, 12)?,
            y_subscript_x_offset: read::i16(data, 14)?,
            y_subscript_y_offset: read::i16(data, 16)?,
            y_superscript_x_size: read::i16(data, 18)?,
            y_superscript_y_size: read::i16(data, 20)?,
            y_superscript_x_offset: read::i16(data, 22)?,
            y_superscript_y_offset: read::i16(data, 24)?,
            y_strikeout_size: read::i16(data, 26)?,
            y_strikeout_position: read::i16(data, 28)?,
            s_family_class: read::i16(data, 30)?,
            panose,
            ul_unicode_range: [
                read::u32(data, 42)?,
                read::u32(data, 46)?,
                read::u32(data, 50)?,
                read::u32(data, 54)?,
            ],
            ach_vend_id,
            fs_selection: read::u16(data, 62)?,
            us_first_char_index: read::u16(data, 64)?,
            us_last_char_index: read::u16(data, 66)?,
            s_typo_ascender: i16_or_zero(68),
            s_typo_descender: i16_or_zero(70),
            s_typo_line_gap: i16_or_zero(72),
            us_win_ascent: u16_or_zero(74),
            us_win_descent: u16_or_zero(76),
            ul_code_page_range: if v1 {
                [u32_or_zero(78), u32_or_zero(82)]
            } else {
                [0; 2]
            },
            sx_height: if v2 { i16_or_zero(86) } else { 0 },
            s_cap_height: if v2 { i16_or_zero(88) } else { 0 },
            us_default_char: if v2 { u16_or_zero(90) } else { 0 },
            us_break_char: if v2 { u16_or_zero(92) } else { 0 },
            us_max_context: if v2 { u16_or_zero(94) } else { 0 },
        })
    }
}

/// The PostScript table's header: the italic angle, the underline's geometry and the pitch. The
/// glyph names its later versions carry are not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Post {
    /// 0x00010000, 0x00020000, 0x00025000 or 0x00030000.
    pub version: u32,
    /// The italic angle, counter-clockwise from vertical, in degrees as 16.16 fixed point.
    pub italic_angle: i32,
    /// The underline's top, and its thickness, in font units.
    pub underline_position: i16,
    pub underline_thickness: i16,
    /// Nonzero for a monospaced font.
    pub is_fixed_pitch: u32,
}

impl Post {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        read::bytes(data, 0, 32)?;
        Ok(Self {
            version: read::u32(data, 0)?,
            italic_angle: read::i32(data, 4)?,
            underline_position: read::i16(data, 8)?,
            underline_thickness: read::i16(data, 10)?,
            is_fixed_pitch: read::u32(data, 12)?,
        })
    }
}
