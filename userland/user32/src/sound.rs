//! The sounds: MessageBeep.
//!
//! There is no sound device: a beep succeeds and nothing sounds (Windows 2000's falls back to the
//! speaker, or to nothing, as its sound settings and hardware allow; its answer is TRUE either
//! way for the types the capture shows).

/// MessageBeep: TRUE, whatever the sound type (MB_OK, MB_ICONHAND..., 0xFFFFFFFF for the simple
/// beep); the last error untouched.
#[unsafe(export_name = "f2k_export_MessageBeep")]
pub unsafe extern "system" fn message_beep(_kind: u32) -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    #[test]
    fn a_beep_succeeds_silently() {
        LAST_ERROR.with(|error| error.set(0xF2F2_F2F2));
        for kind in [0, 0xFFFF_FFFF, 0x10] {
            // SAFETY: the export.
            assert_eq!(unsafe { message_beep(kind) }, 1);
        }
        assert_eq!(LAST_ERROR.with(|error| error.get()), 0xF2F2_F2F2);
    }
}
