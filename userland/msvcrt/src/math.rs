//! The floating-point functions: ceil, floor, fabs and modf, worked on a double's bits, and _ftol,
//! the compiler's conversion of a double to an integer (src/math.s: it takes its value in ST0).
//!
//! As the C runtime reference documents them, and as Windows 2000's capture pins what it leaves
//! open: ceil and floor round toward plus and minus infinity, a result of zero keeping the value's
//! sign (ceil of -0.5 is -0); fabs clears the sign of a number; modf splits a value into its
//! integer part, toward zero, and the fraction `value - part`, which has the value's sign unless
//! it is an exact zero (modf of -2.0 is +0 and -2; of -0.0, -0 and -0). An infinity is its own
//! integer part (its fraction a zero of its sign) and its own ceil and floor. A NaN comes back as
//! itself from each, fabs included (the capture's fabs of -1.#IND is -1.#IND); ceil, floor and modf
//! then set errno to EDOM, the capture's 33, where MSDN documents no error return.

use crate::thread::{set_errno, EDOM};

/// A double's sign bit.
const SIGN: u64 = 1 << 63;
/// The fraction's bits, below the exponent.
const FRACTION_BITS: i32 = 52;
/// The exponent's bias.
const BIAS: i32 = 1023;

/// `value`'s integer part, toward zero, with its sign: an infinity, a NaN and a value of 2^52 or
/// more in magnitude are their own.
fn truncate(value: f64) -> f64 {
    let bits = value.to_bits();
    let exponent = ((bits >> FRACTION_BITS) & 0x7FF) as i32 - BIAS;
    if exponent >= FRACTION_BITS {
        return value;
    }
    if exponent < 0 {
        return f64::from_bits(bits & SIGN);
    }
    let fraction = (1u64 << (FRACTION_BITS - exponent)) - 1;
    f64::from_bits(bits & !fraction)
}

/// `magnitude` with the sign of `sign`.
fn with_sign_of(magnitude: f64, sign: f64) -> f64 {
    f64::from_bits(magnitude.to_bits() & !SIGN | sign.to_bits() & SIGN)
}

/// The smallest integer not below `value`.
pub fn ceiling(value: f64) -> f64 {
    let whole = truncate(value);
    if whole < value {
        whole + 1.0
    } else {
        whole
    }
}

/// The largest integer not above `value`.
pub fn floored(value: f64) -> f64 {
    let whole = truncate(value);
    if whole > value {
        whole - 1.0
    } else {
        whole
    }
}

/// `value`'s fraction and integer part: the part with its sign, the fraction the difference (so
/// +0 for a nonzero integer), a zero's own zero, and an infinity's a zero of its sign.
pub fn split(value: f64) -> (f64, f64) {
    let whole = truncate(value);
    let fraction = if value.is_infinite() {
        with_sign_of(0.0, value)
    } else if value == 0.0 {
        value
    } else {
        value - whole
    };
    (fraction, whole)
}

/// `value` itself, errno set to EDOM, for a NaN; None for a number.
fn domain_error(value: f64) -> Option<f64> {
    if value.is_nan() {
        set_errno(EDOM);
        Some(value)
    } else {
        None
    }
}

/// ceil.
#[unsafe(export_name = "f2k_export_ceil")]
pub extern "C" fn ceil(value: f64) -> f64 {
    domain_error(value).unwrap_or_else(|| ceiling(value))
}

/// floor.
#[unsafe(export_name = "f2k_export_floor")]
pub extern "C" fn floor(value: f64) -> f64 {
    domain_error(value).unwrap_or_else(|| floored(value))
}

/// fabs: a NaN unchanged, its sign kept.
#[unsafe(export_name = "f2k_export_fabs")]
pub extern "C" fn fabs(value: f64) -> f64 {
    if value.is_nan() {
        return value;
    }
    f64::from_bits(value.to_bits() & !SIGN)
}

/// modf: `value`'s fraction, its integer part stored at `integer`.
///
/// # Safety
///
/// `integer` is a double's storage.
#[unsafe(export_name = "f2k_export_modf")]
pub unsafe extern "C" fn modf(value: f64, integer: *mut f64) -> f64 {
    let (fraction, whole) = match domain_error(value) {
        Some(nan) => (nan, nan),
        None => split(value),
    };
    // SAFETY: the caller's double.
    unsafe { integer.write_unaligned(whole) };
    fraction
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thread::errno;

    /// A double's bits, for comparisons that see the sign of a zero and a NaN's payload.
    fn bits(value: f64) -> u64 {
        value.to_bits()
    }

    /// ceil and floor over halves, signed zeros, values past 2^52 and the infinities; a NaN comes
    /// back as itself, errno EDOM.
    #[test]
    fn ceil_and_floor_round_outward_and_inward() {
        let huge = 4_503_599_627_370_495.5;
        for (value, up, down) in [
            (2.5, 3.0, 2.0),
            (-2.5, -2.0, -3.0),
            (2.0, 2.0, 2.0),
            (-2.0, -2.0, -2.0),
            (0.5, 1.0, 0.0),
            (-0.5, -0.0, -1.0),
            (0.2, 1.0, 0.0),
            (-0.2, -0.0, -1.0),
            (0.0, 0.0, 0.0),
            (-0.0, -0.0, -0.0),
            (huge, huge + 0.5, huge - 0.5),
            (-huge, -huge + 0.5, -huge - 0.5),
            (1e300, 1e300, 1e300),
            (-1e-300, -0.0, -1.0),
            (f64::INFINITY, f64::INFINITY, f64::INFINITY),
            (f64::NEG_INFINITY, f64::NEG_INFINITY, f64::NEG_INFINITY),
        ] {
            assert_eq!(bits(ceil(value)), bits(up), "ceil({value})");
            assert_eq!(bits(floor(value)), bits(down), "floor({value})");
        }
        for nan in [
            f64::from_bits(0x7FF8_0000_0000_0000),
            f64::from_bits(0xFFF8 << 48),
        ] {
            set_errno(0);
            assert_eq!(bits(ceil(nan)), bits(nan));
            assert_eq!(errno(), EDOM);
            set_errno(0);
            assert_eq!(bits(floor(nan)), bits(nan));
            assert_eq!(errno(), EDOM);
            assert_eq!(bits(fabs(nan)), bits(nan));
        }
        assert_eq!(bits(fabs(-0.0)), 0);
        assert_eq!(fabs(-2.5), 2.5);
        assert_eq!(fabs(f64::NEG_INFINITY), f64::INFINITY);
    }

    /// modf's integer part keeps the value's sign, its fraction too unless it is an exact zero; an
    /// infinity is its own integer part.
    #[test]
    fn modf_splits_with_the_sign() {
        for (value, fraction, whole) in [
            (3.75, 0.75, 3.0),
            (-3.75, -0.75, -3.0),
            (0.5, 0.5, 0.0),
            (-0.5, -0.5, -0.0),
            (7.0, 0.0, 7.0),
            (-2.0, 0.0, -2.0),
            (-0.0, -0.0, -0.0),
            (1e300, 0.0, 1e300),
            (f64::INFINITY, 0.0, f64::INFINITY),
            (f64::NEG_INFINITY, -0.0, f64::NEG_INFINITY),
        ] {
            let mut integer = 42.0;
            // SAFETY: a double's storage.
            let got = unsafe { modf(value, &mut integer) };
            assert_eq!(
                (bits(got), bits(integer)),
                (bits(fraction), bits(whole)),
                "{value}"
            );
        }
        let nan = f64::from_bits(0x7FF8_0000_0000_0000);
        let mut integer = 0.0;
        set_errno(0);
        // SAFETY: as above.
        let got = unsafe { modf(nan, &mut integer) };
        assert_eq!(errno(), EDOM);
        assert_eq!((bits(got), bits(integer)), (bits(nan), bits(nan)));
    }
}
