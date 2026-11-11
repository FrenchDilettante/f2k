//! The font mapper's rules: which face a LOGFONT's face name asks for, through the face
//! substitutes Windows 2000 keeps for the dialog faces; the size its height asks for; whether its
//! weight asks for a bold face; and the stock fonts' LOGFONTs. The table ([`super::table`]) applies
//! them to the faces loaded.
//!
//! - A face name is compared without regard to case (ASCII letters).
//! - "MS Shell Dlg 2" is Tahoma and "MS Shell Dlg" Microsoft Sans Serif, as Windows 2000's
//!   `...\Windows NT\CurrentVersion\FontSubstitutes` key says (F2K has no registry on disk: a
//!   built-in list stands in for the key). GetTextFace answers the name asked for, as Windows 2000
//!   does for a substitute (the capture's "MS Shell Dlg 2" and "MS Shell Dlg"), whether its face is
//!   loaded or another stands in for it.
//! - A face F2K has no file of may have a stand-in among the faces it has ([`STAND_INS`]):
//!   Microsoft Sans Serif's is MS Sans Serif, as fonts/README.md says (a flagged deviation). A name
//!   reached through its stand-in is answered as asked, as Windows answers the face it has.
//! - Among the faces of a family, a weight of FW_SEMIBOLD or more asks for a bold one (Tahoma Bold
//!   for Tahoma), the face's own bold rather than one synthesised from the regular face; the
//!   regular face is emboldened only when the family has no bold face.
//! - A name no loaded face has, or none, is the System face, the font mapper's default (a LOGFONT
//!   left zeroed realises as the System font on Windows 2000), unless the request asks for a fixed
//!   pitch, which the System face is not. With no System face, or for a fixed pitch, it is the
//!   built-in font, F2K's stand-in for the System font: GetTextFace answers "System".
//! - A height of 0 asks for the default size: a cell of 16 pixels, the System font's at 96 DPI (an
//!   assumption: Windows 2000 documents a default without its value).
//! - The stock fonts are LOGFONTs the mapper realises as any other ([`stock_log_font`]); one whose
//!   face is not loaded realises as the built-in font, as every stock font did before F2K had faces
//!   of its own.

use rtl::gdi::{
    LogFontW,
    ANSI_CHARSET,
    ANSI_FIXED_FONT,
    ANSI_VAR_FONT,
    DEFAULT_GUI_FONT,
    DEVICE_DEFAULT_FONT,
    FF_SWISS,
    FIXED_PITCH,
    FW_BOLD,
    FW_NORMAL,
    LF_FACESIZE,
    OEM_FIXED_FONT,
    SYSTEM_FIXED_FONT,
    SYSTEM_FONT,
    VARIABLE_PITCH,
};

/// The face substitutes: the name asked for, the face it stands for.
pub const SUBSTITUTES: [(&str, &str); 2] = [
    ("MS Shell Dlg 2", "Tahoma"),
    ("MS Shell Dlg", "Microsoft Sans Serif"),
];

/// The faces F2K stands another in for: the face asked for, the face that answers for it.
pub const STAND_INS: [(&str, &str); 1] = [("Microsoft Sans Serif", "MS Sans Serif")];

/// The built-in font's face name, as GetTextFace answers it.
pub const BUILT_IN_FACE: &str = "System";

/// The face a name no loaded face has realises as: the System face.
pub const DEFAULT_FACE: &str = "System";

/// The LOGFONT height a height of 0 stands for: a cell of 16 pixels.
pub const DEFAULT_HEIGHT: i32 = 16;

/// Whether the two names are the same, without regard to the case of ASCII letters.
pub fn same_name(a: &[u16], b: &[u16]) -> bool {
    let fold = |unit: u16| {
        if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
            unit - 0x20
        } else {
            unit
        }
    };
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| fold(x) == fold(y))
}

/// Whether `units` spell the ASCII `text`, without regard to case.
pub fn names(units: &[u16], text: &str) -> bool {
    units.len() == text.len()
        && units
            .iter()
            .zip(text.bytes())
            .all(|(&unit, byte)| unit < 0x80 && (unit as u8).eq_ignore_ascii_case(&byte))
}

/// The face `face` stands for when it is a substitute's name.
pub fn substitute(face: &[u16]) -> Option<&'static str> {
    SUBSTITUTES
        .iter()
        .find(|(name, _)| names(face, name))
        .map(|&(_, target)| target)
}

/// The face that stands in for `face` when F2K has no file of it.
pub fn stand_in(face: &[u16]) -> Option<&'static str> {
    STAND_INS
        .iter()
        .find(|(name, _)| names(face, name))
        .map(|&(_, target)| target)
}

/// Whether `log_font` asks for a fixed pitch (the default face, the System face, is not one).
pub fn asks_fixed_pitch(log_font: &LogFontW) -> bool {
    log_font.pitch_and_family & 0x03 == FIXED_PITCH
}

/// Whether a weight of `weight` asks for a bold face (FW_SEMIBOLD and up, the weight from which a
/// lighter face is emboldened).
pub fn asks_bold(weight: i32) -> bool {
    weight >= rtl::truetype::metrics::EMBOLDEN_FROM
}

/// The LOGFONT height the mapper realises for `height`: the default for 0.
pub fn height(height: i32) -> i32 {
    if height == 0 {
        DEFAULT_HEIGHT
    } else {
        height
    }
}

/// The LOGFONT the stock font `index` is (GetStockObject's fonts, as Windows 2000 defines them),
/// realised through the mapper as a font object's is; none for an index that is no stock font's,
/// and for the stock fonts F2K has no face for, which stay the built-in font.
///
/// - SYSTEM_FONT is the System font: a cell of 16 pixels, bold (the guidc capture's tmHeight of 16
///   and tmAveCharWidth of 7 through it).
/// - DEVICE_DEFAULT_FONT is the display's own font, which is the System font on a display.
/// - DEFAULT_GUI_FONT is "MS Shell Dlg" at 8 points, an em of 11 pixels at 96 DPI (the platform's
///   documentation of the time calls it MS Sans Serif, the face "MS Shell Dlg" resolves to).
/// - ANSI_VAR_FONT, the variable-pitch system font of the ANSI character set, is MS Sans Serif at
///   its 8-point size, a cell of 13 pixels.
/// - ANSI_FIXED_FONT (Courier), OEM_FIXED_FONT (Terminal, the OEM code page's) and
///   SYSTEM_FIXED_FONT (Fixedsys) are fixed-pitch raster fonts F2K has no face for: the built-in
///   font, a fixed-pitch cell of 8 by 16 in code page 437 (the OEM code page), is the closest.
pub fn stock_log_font(index: u32) -> Option<LogFontW> {
    let (face, height, weight) = match index {
        SYSTEM_FONT | DEVICE_DEFAULT_FONT => (DEFAULT_FACE, 16, FW_BOLD),
        DEFAULT_GUI_FONT => ("MS Shell Dlg", -11, FW_NORMAL),
        ANSI_VAR_FONT => ("MS Sans Serif", 13, FW_NORMAL),
        ANSI_FIXED_FONT | OEM_FIXED_FONT | SYSTEM_FIXED_FONT => return None,
        _ => return None,
    };
    let mut log_font = <LogFontW as rtl::pod::Pod>::zeroed();
    log_font.height = height;
    log_font.weight = weight;
    log_font.char_set = ANSI_CHARSET;
    log_font.pitch_and_family = FF_SWISS | VARIABLE_PITCH;
    log_font.face_name = FaceName::ascii(face).padded();
    Some(log_font)
}

/// A face name, as a face holds it: up to LF_FACESIZE - 1 units (or a full name's 63).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Name<const N: usize> {
    units: [u16; N],
    length: usize,
}

impl<const N: usize> Name<N> {
    pub const fn empty() -> Self {
        Name {
            units: [0; N],
            length: 0,
        }
    }

    /// The name of `units`, cut at N - 1 units (a terminator's room kept).
    pub fn of(units: impl IntoIterator<Item = u16>) -> Self {
        let mut name = Self::empty();
        for unit in units.into_iter().take(N - 1) {
            name.units[name.length] = unit;
            name.length += 1;
        }
        name
    }

    /// The name of the ASCII `text`.
    pub fn ascii(text: &str) -> Self {
        Self::of(text.bytes().map(u16::from))
    }

    pub fn units(&self) -> &[u16] {
        &self.units[..self.length]
    }

    /// The name's units with their terminator, and zeros to N: a LOGFONT's or an ENUMLOGFONT's
    /// array.
    pub fn padded(&self) -> [u16; N] {
        self.units
    }
}

/// A face name in a LOGFONT.
pub type FaceName = Name<LF_FACESIZE>;

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> std::vec::Vec<u16> {
        text.encode_utf16().collect()
    }

    /// Names match without regard to ASCII case, and only whole.
    #[test]
    fn names_match_without_case() {
        assert!(same_name(&wide("F2K Tahoma"), &wide("f2k tAHOMA")));
        assert!(!same_name(&wide("F2K Tahoma"), &wide("F2K Tahom")));
        assert!(
            !same_name(&wide("É"), &wide("é")),
            "ASCII letters alone fold"
        );
        assert!(names(&wide("ms shell dlg"), "MS Shell Dlg"));
    }

    /// The dialog faces stand for Tahoma and Microsoft Sans Serif; another name stands for none.
    #[test]
    fn the_dialog_faces_are_substitutes() {
        assert_eq!(substitute(&wide("MS Shell Dlg 2")), Some("Tahoma"));
        assert_eq!(
            substitute(&wide("ms shell dlg")),
            Some("Microsoft Sans Serif")
        );
        assert_eq!(substitute(&wide("Tahoma")), None);
        assert_eq!(substitute(&wide("")), None);
    }

    /// Microsoft Sans Serif has MS Sans Serif standing in; a bold request is FW_SEMIBOLD and up.
    #[test]
    fn stand_ins_and_bold_requests() {
        assert_eq!(
            stand_in(&wide("microsoft sans serif")),
            Some("MS Sans Serif")
        );
        assert_eq!(stand_in(&wide("MS Sans Serif")), None);
        assert!(!asks_bold(0) && !asks_bold(500) && asks_bold(600) && asks_bold(700));
    }

    /// The stock fonts: System's cell and weight, the dialog face's 8 points, MS Sans Serif for
    /// the variable-pitch font, and none for the fixed-pitch ones or another object.
    #[test]
    fn the_stock_fonts_are_logfonts() {
        let system = stock_log_font(SYSTEM_FONT).unwrap();
        assert_eq!((system.height, system.weight), (16, 700));
        assert_eq!(system.face(), wide("System"));
        assert_eq!(stock_log_font(DEVICE_DEFAULT_FONT), Some(system));
        let gui = stock_log_font(DEFAULT_GUI_FONT).unwrap();
        assert_eq!((gui.height, gui.weight), (-11, 400));
        assert_eq!(gui.face(), wide("MS Shell Dlg"));
        let var = stock_log_font(ANSI_VAR_FONT).unwrap();
        assert_eq!((var.height, var.face()), (13, &wide("MS Sans Serif")[..]));
        for index in [ANSI_FIXED_FONT, OEM_FIXED_FONT, SYSTEM_FIXED_FONT, 0, 15] {
            assert_eq!(stock_log_font(index), None, "{index}");
        }
    }

    /// A height of 0 is the default cell; any other is as asked.
    #[test]
    fn a_height_of_zero_is_the_default() {
        assert_eq!(height(0), 16);
        assert_eq!(height(-11), -11);
        assert_eq!(height(16), 16);
    }

    /// A name keeps its terminator's room; padded, it is a LOGFONT's array.
    #[test]
    fn names_keep_their_terminator() {
        let long = FaceName::of(core::iter::repeat_n(u16::from(b'x'), 40));
        assert_eq!(long.units().len(), 31);
        assert_eq!(long.padded()[31], 0);
        let tahoma = FaceName::ascii("Tahoma");
        assert_eq!(tahoma.units(), wide("Tahoma"));
        assert_eq!(tahoma.padded()[6], 0);
    }
}
