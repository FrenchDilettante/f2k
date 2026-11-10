//! The font mapper's rules: which face a LOGFONT's face name asks for, through the face
//! substitutes Windows 2000 keeps for the dialog faces; the size its height asks for; whether its
//! weight emboldens the face. The table ([`super::table`]) applies them to the faces loaded.
//!
//! - A face name is compared without regard to case (ASCII letters).
//! - "MS Shell Dlg 2" is Tahoma and "MS Shell Dlg" Microsoft Sans Serif, as Windows 2000's
//!   `...\Windows NT\CurrentVersion\FontSubstitutes` key says (F2K has no registry on disk: a
//!   built-in list stands in for the key). GetTextFace answers the name asked for, as Windows 2000
//!   does for a substitute (the capture's "MS Shell Dlg 2" and "MS Shell Dlg"), whether its face is
//!   loaded or the built-in font stands in for it.
//! - A name no loaded face has, or none, is the built-in font, F2K's stand-in for the System font
//!   (the stock fonts stay on it as well): GetTextFace answers "System".
//! - A height of 0 asks for the default size: a cell of 16 pixels, the System font's at 96 DPI (an
//!   assumption: Windows 2000 documents a default without its value).

use rtl::gdi::LF_FACESIZE;

/// The face substitutes: the name asked for, the face it stands for.
pub const SUBSTITUTES: [(&str, &str); 2] = [
    ("MS Shell Dlg 2", "Tahoma"),
    ("MS Shell Dlg", "Microsoft Sans Serif"),
];

/// The built-in font's face name, as GetTextFace answers it.
pub const BUILT_IN_FACE: &str = "System";

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

/// The LOGFONT height the mapper realises for `height`: the default for 0.
pub fn height(height: i32) -> i32 {
    if height == 0 {
        DEFAULT_HEIGHT
    } else {
        height
    }
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
