//! The units an outline is read in: the font's own units, or pixels at a size in 26.6 fixed point
//! (a 64th of a pixel), as the TrueType scaler holds its points.

/// One pixel in 26.6 fixed point.
pub const ONE_PIXEL: i32 = 64;

/// The units an outline's coordinates are given in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scale {
    /// The font's units, as the glyphs hold them.
    FontUnits,
    /// Pixels in 26.6 fixed point at `ppem` pixels per em, for a font of `units_per_em`.
    Pixels { ppem: u16, units_per_em: u16 },
}

impl Scale {
    /// Pixels at `ppem` pixels per em, for a font of `units_per_em` (head's, never zero).
    pub fn pixels(ppem: u16, units_per_em: u16) -> Self {
        Self::Pixels {
            ppem,
            units_per_em: units_per_em.max(1),
        }
    }

    /// `value` font units in this scale's units, rounded to the nearest (a half up), and held to
    /// the range of an `i32`.
    pub fn apply(&self, value: i32) -> i32 {
        match *self {
            Self::FontUnits => value,
            Self::Pixels { ppem, units_per_em } => {
                let units_per_em = units_per_em as i64;
                let scaled = 2 * value as i64 * ppem as i64 * ONE_PIXEL as i64 + units_per_em;
                scaled
                    .div_euclid(2 * units_per_em)
                    .clamp(i32::MIN as i64, i32::MAX as i64) as i32
            }
        }
    }

    /// `value`, in this scale's units, at the nearest whole pixel (a half up) in pixel units; as
    /// it is in font units, which have no grid.
    pub fn round_to_grid(&self, value: i32) -> i32 {
        match self {
            Self::FontUnits => value,
            Self::Pixels { .. } => round_pixel(value) * ONE_PIXEL,
        }
    }
}

/// The whole pixel nearest a 26.6 value, a half rounding up.
pub fn round_pixel(value: i32) -> i32 {
    value.saturating_add(ONE_PIXEL / 2).div_euclid(ONE_PIXEL)
}
