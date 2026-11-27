//! Mapping modes: a DC's page transform, from its logical coordinates to its device coordinates
//! (from the DC's origin), as Windows 2000's DC keeps it: the mapping mode, the window's origin
//! and extents, the viewport's origin and extents ([`Mapping`]). Every drawing service takes its
//! coordinates through it ([`super::dc::Dc`]'s `surface_point` and kin), and LPtoDP and DPtoLP
//! answer it ([`Mapping::to_device`], [`Mapping::to_logical`]).
//!
//! A logical point (x, y) lands on the device point
//!
//! ```text
//! (x - window_org.x) * viewport_ext.x / window_ext.x + viewport_org.x
//! ```
//!
//! (y alike), rounded to the nearest pixel, a half up (towards plus infinity), as the mapmode
//! capture's LPtoDP and DPtoLP of points that fall on halves show: 2.5 rounds to 3 and -0.5 to 0,
//! whichever extent is negative. The inverse takes the device point back the same way.
//!
//! The modes:
//!
//! - MM_TEXT: both extents 1 by 1, a logical unit a pixel, y down;
//! - the metric and English modes and MM_TWIPS: a logical unit a fixed length (0.1 mm, 0.01 mm,
//!   0.01 in, 0.001 in, 1/1440 in), y up: the window's extents the display's size in those units,
//!   the viewport's its size in pixels, negated in y (the size in millimeters is
//!   [`rtl::gdi::DISPLAY_SIZE_MM`], Windows 2000's display drivers' 320 by 240);
//! - MM_ISOTROPIC: MM_LOMETRIC's extents when set (the capture's), then the program's; a logical
//!   unit kept as long in x as in y on the device: each extent set shrinks the viewport's extent in
//!   the direction that would stretch the more ([`Mapping::fix_isotropic`], Windows' adjustment);
//! - MM_ANISOTROPIC: the extents kept from the mode before, then the program's.
//!
//! The fixed modes (all but the last two) take no extents: SetWindowExtEx and SetViewportExtEx and
//! the Scale calls leave them, and succeed. The origins are any mode's.

use rtl::gdi::{
    DISPLAY_SIZE_MM,
    MM_ANISOTROPIC,
    MM_HIENGLISH,
    MM_HIMETRIC,
    MM_ISOTROPIC,
    MM_LOENGLISH,
    MM_LOMETRIC,
    MM_TEXT,
};

/// The device a mapping maps onto: its size in pixels and in millimeters (GetDeviceCaps' HORZRES
/// and VERTRES, HORZSIZE and VERTSIZE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Device {
    pub pixels: (i32, i32),
    pub millimeters: (i32, i32),
}

impl Device {
    /// The display, the device every DC of F2K's is (a memory DC is the display's): the current
    /// mode's resolution, Windows 2000's 320 by 240 millimeters.
    pub fn display() -> Device {
        let (width, height) = super::display::current_mode();
        Device {
            pixels: (width as i32, height as i32),
            millimeters: DISPLAY_SIZE_MM,
        }
    }
}

/// A DC's page transform (see the module notes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// The mapping mode, one of the MM_ modes.
    pub mode: u32,
    pub window_org: (i32, i32),
    pub window_ext: (i32, i32),
    pub viewport_org: (i32, i32),
    pub viewport_ext: (i32, i32),
}

/// `value * num / den`, rounded to the nearest integer, a half up; `den` is not 0.
fn mul_div_round(value: i64, num: i64, den: i64) -> i64 {
    let (mut num, mut den) = (i128::from(value) * i128::from(num), i128::from(den));
    if den < 0 {
        num = -num;
        den = -den;
    }
    (2 * num + den).div_euclid(2 * den) as i64
}

/// An i64 brought into i32's range.
fn saturate(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// Whether `mode` is a mapping mode.
pub fn is_mode(mode: u32) -> bool {
    (MM_TEXT..=MM_ANISOTROPIC).contains(&mode)
}

impl Mapping {
    /// MM_TEXT, its origins zero: a DC's mapping as it starts.
    pub const TEXT: Mapping = Mapping {
        mode: MM_TEXT,
        window_org: (0, 0),
        window_ext: (1, 1),
        viewport_org: (0, 0),
        viewport_ext: (1, 1),
    };

    /// Whether the mode takes extents (MM_ISOTROPIC, MM_ANISOTROPIC).
    pub fn scalable(&self) -> bool {
        matches!(self.mode, MM_ISOTROPIC | MM_ANISOTROPIC)
    }

    /// Whether a logical unit is a device unit, in the same direction (only the origins move a
    /// point): the drawing calls' fast path, and MM_TEXT's.
    pub fn is_unscaled(&self) -> bool {
        self.window_ext == self.viewport_ext
    }

    /// The metric or English mode `mode`'s extents on `device`: the window's (its size in the
    /// mode's units) and the viewport's (its size in pixels, y negated).
    fn fixed_extents(mode: u32, device: Device) -> ((i32, i32), (i32, i32)) {
        let (mm_x, mm_y) = device.millimeters;
        let in_units = |per_254_mm: i64| {
            (
                saturate(mul_div_round(i64::from(mm_x), per_254_mm, 254)),
                saturate(mul_div_round(i64::from(mm_y), per_254_mm, 254)),
            )
        };
        let window = match mode {
            MM_LOMETRIC => (mm_x.saturating_mul(10), mm_y.saturating_mul(10)),
            MM_HIMETRIC => (mm_x.saturating_mul(100), mm_y.saturating_mul(100)),
            MM_LOENGLISH => in_units(1_000),
            MM_HIENGLISH => in_units(10_000),
            _ => in_units(14_400),
        };
        (window, (device.pixels.0, device.pixels.1.saturating_neg()))
    }

    /// SetMapMode: the mode set, the one it had answered; none, the mapping untouched, for a value
    /// that is no mode. A mode set again changes nothing; MM_TEXT and the fixed modes set their
    /// extents, MM_ISOTROPIC MM_LOMETRIC's, MM_ANISOTROPIC keeps the ones there are (the mapmode
    /// capture's `modes`). The origins stay.
    pub fn set_mode(&mut self, mode: u32, device: Device) -> Option<u32> {
        if !is_mode(mode) {
            return None;
        }
        let previous = self.mode;
        if mode == previous {
            return Some(previous);
        }
        match mode {
            MM_TEXT => {
                self.window_ext = (1, 1);
                self.viewport_ext = (1, 1);
            }
            MM_ANISOTROPIC => {}
            MM_ISOTROPIC => {
                (self.window_ext, self.viewport_ext) = Mapping::fixed_extents(MM_LOMETRIC, device);
            }
            fixed => (self.window_ext, self.viewport_ext) = Mapping::fixed_extents(fixed, device),
        }
        self.mode = mode;
        Some(previous)
    }

    /// The window's extents set to (`x`, `y`) (MM_ISOTROPIC's and MM_ANISOTROPIC's, neither 0),
    /// the viewport's adjusted in MM_ISOTROPIC; false, the mapping untouched, otherwise. (The
    /// services set a coordinate at a time, [`Mapping::set_ext_coordinate`], as gdi32 asks; this is
    /// the pair's rule, which the tests drive.)
    #[cfg(test)]
    pub fn set_window_ext(&mut self, x: i32, y: i32, device: Device) -> bool {
        if !self.scalable() || x == 0 || y == 0 {
            return false;
        }
        self.window_ext = (x, y);
        self.fix_isotropic(device);
        true
    }

    /// The viewport's extents set to (`x`, `y`), as [`Mapping::set_window_ext`].
    #[cfg(test)]
    pub fn set_viewport_ext(&mut self, x: i32, y: i32, device: Device) -> bool {
        if !self.scalable() || x == 0 || y == 0 {
            return false;
        }
        self.viewport_ext = (x, y);
        self.fix_isotropic(device);
        true
    }

    /// One extent's coordinate set alone (NtGdiGetAndSetDCDword's: gdi32 sets x, then y, then
    /// asks for the isotropic adjustment): the previous value; none, untouched, in a fixed mode or
    /// for 0.
    pub fn set_ext_coordinate(&mut self, window: bool, y: bool, value: i32) -> Option<i32> {
        if !self.scalable() || value == 0 {
            return None;
        }
        let ext = if window {
            &mut self.window_ext
        } else {
            &mut self.viewport_ext
        };
        let slot = if y { &mut ext.1 } else { &mut ext.0 };
        Some(core::mem::replace(slot, value))
    }

    /// The extents `ext` scaled by `x_num / x_den` and `y_num / y_den`, truncated (the mapmode
    /// capture's 75 by 1/100 is 0, a failure); none for a denominator or a result of 0.
    fn scaled(
        ext: (i32, i32),
        x_num: i32,
        x_den: i32,
        y_num: i32,
        y_den: i32,
    ) -> Option<(i32, i32)> {
        if x_den == 0 || y_den == 0 {
            return None;
        }
        let x = saturate(i64::from(ext.0) * i64::from(x_num) / i64::from(x_den));
        let y = saturate(i64::from(ext.1) * i64::from(y_num) / i64::from(y_den));
        (x != 0 && y != 0).then_some((x, y))
    }

    /// ScaleViewportExtEx: in MM_ISOTROPIC and MM_ANISOTROPIC the viewport's extents scaled (and
    /// adjusted in MM_ISOTROPIC); false, untouched, for a denominator or a result of 0. A fixed
    /// mode's are left (true).
    pub fn scale_viewport_ext(
        &mut self,
        x_num: i32,
        x_den: i32,
        y_num: i32,
        y_den: i32,
        device: Device,
    ) -> bool {
        if !self.scalable() {
            return true;
        }
        let Some(ext) = Mapping::scaled(self.viewport_ext, x_num, x_den, y_num, y_den) else {
            return false;
        };
        self.viewport_ext = ext;
        self.fix_isotropic(device);
        true
    }

    /// ScaleWindowExtEx: the window's extents, as [`Mapping::scale_viewport_ext`].
    pub fn scale_window_ext(
        &mut self,
        x_num: i32,
        x_den: i32,
        y_num: i32,
        y_den: i32,
        device: Device,
    ) -> bool {
        if !self.scalable() {
            return true;
        }
        let Some(ext) = Mapping::scaled(self.window_ext, x_num, x_den, y_num, y_den) else {
            return false;
        };
        self.window_ext = ext;
        self.fix_isotropic(device);
        true
    }

    /// MM_ISOTROPIC's adjustment (none in another mode): a logical unit made as long in x as in y
    /// on `device`, by shrinking the viewport's extent in the direction a unit is the longer in,
    /// rounded and never to 0 (its sign kept). As Windows works it out: each direction's length of
    /// a unit is `|viewport_ext| * millimeters / (pixels * |window_ext|)`.
    pub fn fix_isotropic(&mut self, device: Device) {
        if self.mode != MM_ISOTROPIC {
            return;
        }
        let abs = |value: i32| i128::from(value).abs();
        let (wx, wy) = (abs(self.window_ext.0), abs(self.window_ext.1));
        let (vx, vy) = (abs(self.viewport_ext.0), abs(self.viewport_ext.1));
        let (mm_x, mm_y) = (
            i128::from(device.millimeters.0),
            i128::from(device.millimeters.1),
        );
        let (px_x, px_y) = (i128::from(device.pixels.0), i128::from(device.pixels.1));
        // The two lengths over a common denominator (px_x * px_y * wx * wy).
        let x_len = vx * mm_x * px_y * wy;
        let y_len = vy * mm_y * px_x * wx;
        if x_len <= 0 || y_len <= 0 {
            return;
        }
        let shrink = |ext: i32, num: i128, den: i128| {
            let value = i128::from(ext) * num;
            let rounded = (2 * value + den).div_euclid(2 * den);
            let rounded = rounded.clamp(i128::from(i32::MIN), i128::from(i32::MAX)) as i32;
            if rounded == 0 {
                ext.signum()
            } else {
                rounded
            }
        };
        if x_len > y_len {
            self.viewport_ext.0 = shrink(self.viewport_ext.0, y_len, x_len);
        } else if y_len > x_len {
            self.viewport_ext.1 = shrink(self.viewport_ext.1, x_len, y_len);
        }
    }

    /// Whether the mapping flips x, and y (its window's and viewport's extents of opposite signs).
    pub fn flips(&self) -> (bool, bool) {
        (
            (self.window_ext.0 < 0) != (self.viewport_ext.0 < 0),
            (self.window_ext.1 < 0) != (self.viewport_ext.1 < 0),
        )
    }

    /// The device point of the logical point (`x`, `y`) (from the DC's origin).
    pub fn to_device(self, x: i32, y: i32) -> (i32, i32) {
        if self.is_unscaled() {
            return (
                saturate(
                    i64::from(x) - i64::from(self.window_org.0) + i64::from(self.viewport_org.0),
                ),
                saturate(
                    i64::from(y) - i64::from(self.window_org.1) + i64::from(self.viewport_org.1),
                ),
            );
        }
        let one =
            |at: i32, window_org: i32, window_ext: i32, viewport_ext: i32, viewport_org: i32| {
                saturate(
                    mul_div_round(
                        i64::from(at) - i64::from(window_org),
                        i64::from(viewport_ext),
                        i64::from(window_ext),
                    ) + i64::from(viewport_org),
                )
            };
        (
            one(
                x,
                self.window_org.0,
                self.window_ext.0,
                self.viewport_ext.0,
                self.viewport_org.0,
            ),
            one(
                y,
                self.window_org.1,
                self.window_ext.1,
                self.viewport_ext.1,
                self.viewport_org.1,
            ),
        )
    }

    /// The logical point of the device point (`x`, `y`): [`Mapping::to_device`]'s inverse, rounded
    /// alike.
    pub fn to_logical(self, x: i32, y: i32) -> (i32, i32) {
        let swapped = Mapping {
            mode: self.mode,
            window_org: self.viewport_org,
            window_ext: self.viewport_ext,
            viewport_org: self.window_org,
            viewport_ext: self.window_ext,
        };
        swapped.to_device(x, y)
    }

    /// A logical distance (`dx`, `dy`) in device units (no origin: OffsetClipRgn's offset, a round
    /// rectangle's corner), rounded as a point is.
    pub fn distance_to_device(self, dx: i32, dy: i32) -> (i32, i32) {
        let origins = Mapping {
            window_org: (0, 0),
            viewport_org: (0, 0),
            ..self
        };
        origins.to_device(dx, dy)
    }
}

#[cfg(test)]
mod tests {
    use rtl::gdi::MM_TWIPS;

    use super::*;

    /// The capture machine's display: 320 by 240 millimeters; the resolution the test boots run.
    const DEVICE: Device = Device {
        pixels: (640, 480),
        millimeters: (320, 240),
    };

    fn aniso(window_ext: (i32, i32), viewport_ext: (i32, i32)) -> Mapping {
        let mut mapping = Mapping::TEXT;
        assert_eq!(mapping.set_mode(MM_ANISOTROPIC, DEVICE), Some(MM_TEXT));
        assert!(mapping.set_window_ext(window_ext.0, window_ext.1, DEVICE));
        assert!(mapping.set_viewport_ext(viewport_ext.0, viewport_ext.1, DEVICE));
        mapping
    }

    fn to_device(mapping: &Mapping, points: &[(i32, i32)]) -> std::vec::Vec<(i32, i32)> {
        points
            .iter()
            .map(|&(x, y)| mapping.to_device(x, y))
            .collect()
    }

    fn to_logical(mapping: &Mapping, points: &[(i32, i32)]) -> std::vec::Vec<(i32, i32)> {
        points
            .iter()
            .map(|&(x, y)| mapping.to_logical(x, y))
            .collect()
    }

    /// The capture's `extorg` in MM_TEXT: the origins move the points, the extents stay 1 by 1.
    #[test]
    fn mm_text_moves_by_the_origins() {
        let mut mapping = Mapping::TEXT;
        assert!(
            !mapping.set_window_ext(2, 3, DEVICE),
            "MM_TEXT takes no extents"
        );
        assert_eq!(mapping.window_ext, (1, 1));
        mapping.window_org = (5, 7);
        mapping.viewport_org = (-3, 4);
        assert_eq!(
            to_device(&mapping, &[(0, 0), (5, 7), (10, 20)]),
            [(-8, -3), (-3, 4), (2, 17)]
        );
        assert_eq!(to_logical(&mapping, &[(0, 0), (-3, 4)]), [(8, 3), (5, 7)]);
    }

    /// The capture's `extorg` in MM_ANISOTROPIC: points falling on halves round up (towards plus
    /// infinity), forwards and back, whichever extent is negative; an extent of 0 is refused.
    #[test]
    fn halves_round_up() {
        let mut mapping = aniso((100, 200), (50, -400));
        assert!(!mapping.set_window_ext(0, 10, DEVICE));
        assert!(!mapping.set_window_ext(10, 0, DEVICE));
        assert!(!mapping.set_viewport_ext(0, 0, DEVICE));
        assert_eq!(
            (mapping.window_ext, mapping.viewport_ext),
            ((100, 200), (50, -400))
        );
        mapping.window_org = (10, 20);
        mapping.viewport_org = (3, 4);
        assert_eq!(
            to_device(
                &mapping,
                &[
                    (10, 20),
                    (11, 20),
                    (13, 21),
                    (9, 19),
                    (7, 20),
                    (-10, 0),
                    (110, 220)
                ]
            ),
            [(3, 4), (4, 4), (5, 2), (3, 6), (2, 4), (-7, 44), (53, -396)]
        );
        assert_eq!(
            to_logical(&mapping, &[(3, 4), (4, 4), (3, 5), (4, 3), (0, 0)]),
            [(10, 20), (12, 20), (10, 20), (12, 21), (4, 22)]
        );
        assert!(mapping.set_window_ext(-100, 200, DEVICE));
        assert_eq!(
            to_device(&mapping, &[(10, 20), (11, 20), (13, 21)]),
            [(3, 4), (3, 4), (2, 2)]
        );
    }

    /// The capture's `offset`: the scales truncate, and a denominator or a result of 0 fails with
    /// the extents kept; MM_TEXT takes no scale.
    #[test]
    fn scales_truncate() {
        let mut mapping = aniso((100, 200), (50, -400));
        mapping.viewport_org = (7, -3);
        mapping.window_org = (-9, 13);
        assert!(mapping.scale_viewport_ext(3, 2, 1, 4, DEVICE));
        assert!(mapping.scale_window_ext(1, 2, 5, 1, DEVICE));
        assert_eq!(
            (mapping.window_ext, mapping.viewport_ext),
            ((50, 1000), (75, -100))
        );
        assert_eq!(
            to_device(&mapping, &[(0, 0), (20, 40)]),
            [(21, -2), (51, -6)]
        );
        assert!(!mapping.scale_viewport_ext(1, 0, 1, 1, DEVICE));
        assert!(!mapping.scale_window_ext(0, 1, 1, 1, DEVICE));
        assert!(!mapping.scale_viewport_ext(1, 100, 1, 1000, DEVICE));
        assert_eq!(
            (mapping.window_ext, mapping.viewport_ext),
            ((50, 1000), (75, -100))
        );
        assert!(mapping.scale_viewport_ext(2, 1, 2, 1, DEVICE));
        assert!(mapping.scale_window_ext(2, 1, 2, 1, DEVICE));
        assert_eq!(
            (mapping.window_ext, mapping.viewport_ext),
            ((100, 2000), (150, -200))
        );

        let mut text = Mapping::TEXT;
        assert!(text.scale_viewport_ext(2, 1, 3, 1, DEVICE));
        assert!(text.scale_window_ext(2, 1, 3, 1, DEVICE));
        assert_eq!(text, Mapping::TEXT);
    }

    /// The capture's `modes`: the fixed modes' units per pixel, y up; MM_ISOTROPIC takes
    /// MM_LOMETRIC's extents, MM_ANISOTROPIC keeps the ones there are; a value that is no mode is
    /// refused.
    #[test]
    fn the_modes_set_their_extents() {
        let mut mapping = Mapping::TEXT;
        assert_eq!(mapping.set_mode(MM_LOMETRIC, DEVICE), Some(MM_TEXT));
        let lometric = (mapping.window_ext, mapping.viewport_ext);
        assert_eq!(lometric, ((3200, 2400), (640, -480)));
        assert_eq!(mapping.to_device(1000, 1000), (200, -200));
        for (mode, per_mm) in [
            (MM_HIMETRIC, 100.0),
            (MM_LOENGLISH, 100.0 / 25.4),
            (MM_HIENGLISH, 1000.0 / 25.4),
            (MM_TWIPS, 1440.0 / 25.4),
        ] {
            mapping.set_mode(mode, DEVICE).unwrap();
            let unit = f64::from(mapping.window_ext.0) / f64::from(mapping.viewport_ext.0);
            let expected = per_mm * 320.0 / 640.0;
            assert!((unit - expected).abs() <= expected / 100.0, "mode {mode}");
            assert!(mapping.viewport_ext.1 < 0, "y up");
        }
        assert_eq!(mapping.set_mode(MM_ISOTROPIC, DEVICE), Some(MM_TWIPS));
        assert_eq!((mapping.window_ext, mapping.viewport_ext), lometric);
        assert_eq!(mapping.set_mode(MM_ANISOTROPIC, DEVICE), Some(MM_ISOTROPIC));
        assert_eq!((mapping.window_ext, mapping.viewport_ext), lometric);
        assert_eq!(mapping.set_mode(MM_TEXT, DEVICE), Some(MM_ANISOTROPIC));
        assert_eq!(mapping, Mapping::TEXT);
        assert_eq!(mapping.set_mode(MM_ANISOTROPIC, DEVICE), Some(MM_TEXT));
        assert_eq!(mapping.window_ext, (1, 1), "kept from MM_TEXT");
        assert_eq!(mapping.set_mode(0, DEVICE), None);
        assert_eq!(mapping.set_mode(9, DEVICE), None);
        assert_eq!(mapping.mode, MM_ANISOTROPIC);
    }

    /// The capture's `isotropic`: the viewport shrinks in the direction a unit would be the longer
    /// in, whichever extent was set last.
    #[test]
    fn isotropic_keeps_units_square() {
        for device in [
            DEVICE,
            Device {
                pixels: (1024, 768),
                millimeters: (320, 240),
            },
        ] {
            let mut mapping = Mapping::TEXT;
            mapping.set_mode(MM_ISOTROPIC, device).unwrap();
            assert!(mapping.set_window_ext(1000, 1000, device));
            assert!(mapping.set_viewport_ext(400, -300, device));
            assert_eq!(mapping.viewport_ext, (300, -300));
            assert_eq!(mapping.to_device(1000, 1000), (300, -300));
            assert!(mapping.set_window_ext(1000, 500, device));
            assert_eq!(mapping.viewport_ext, (300, -150));
            assert!(mapping.set_viewport_ext(400, -300, device));
            assert_eq!(mapping.viewport_ext, (400, -200));
            assert_eq!(mapping.set_mode(MM_ANISOTROPIC, device), Some(MM_ISOTROPIC));
            assert!(mapping.set_viewport_ext(400, -300, device));
            assert_eq!(mapping.viewport_ext, (400, -300), "no adjustment");
        }
        // A viewport shrunk below a pixel keeps its sign.
        let mut mapping = Mapping::TEXT;
        mapping.set_mode(MM_ISOTROPIC, DEVICE).unwrap();
        assert!(mapping.set_window_ext(100_000, 1, DEVICE));
        assert!(mapping.set_viewport_ext(-1, -5, DEVICE));
        assert_eq!(mapping.viewport_ext, (-1, -1));
    }

    /// The capture's `drawing`: an 8 by 6 window on a 16 by 12 viewport doubles; flipped, the
    /// viewport's origin at the bottom.
    #[test]
    fn scaled_and_flipped_points() {
        let mut mapping = aniso((8, 6), (16, 12));
        assert_eq!(to_device(&mapping, &[(1, 1), (4, 3)]), [(2, 2), (8, 6)]);
        assert_eq!(mapping.distance_to_device(3, -2), (6, -4));
        assert!(mapping.set_viewport_ext(16, -12, DEVICE));
        mapping.viewport_org = (0, 12);
        assert_eq!(to_device(&mapping, &[(1, 1), (4, 3)]), [(2, 10), (8, 6)]);
        assert_eq!(mapping.to_logical(8, 6), (4, 3));
    }

    /// Far points saturate rather than wrap.
    #[test]
    fn far_points_saturate() {
        let mapping = aniso((1, 1), (1000, 1000));
        assert_eq!(mapping.to_device(i32::MAX, i32::MIN), (i32::MAX, i32::MIN));
        let mut text = Mapping::TEXT;
        text.window_org = (-10, 10);
        assert_eq!(text.to_device(i32::MAX, i32::MIN), (i32::MAX, i32::MIN));
    }
}
