//! The audit-alarm entry points: ObjectOpenAuditAlarmA/W, ObjectCloseAuditAlarmA/W,
//! ObjectDeleteAuditAlarmA/W, ObjectPrivilegeAuditAlarmA/W and PrivilegedServiceAuditAlarmA/W.
//! F2K keeps no event log, so an alarm succeeds without generating anything: each form is a
//! no-op that returns TRUE, reads none of the caller's pointers (NULL names included) and
//! leaves the last error — GenerateOnClose included — untouched.

/// ObjectOpenAuditAlarmW: the alarm skipped, TRUE.
///
/// # Safety
/// The pointers are the caller's; the form reads none of them.
#[unsafe(export_name = "f2k_export_ObjectOpenAuditAlarmW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn object_open_audit_alarm_w(
    _subsystem_name: *const u16, _handle_id: *const u8, _object_type_name: *const u16, _object_name: *const u16,
    _security_descriptor: *const u8, _client_token: u32, _desired_access: u32, _granted_access: u32,
    _privileges: *const u8, _object_creation: u32, _access_granted: u32, _generate_on_close: *mut u32,
) -> u32 {
    1
}

/// ObjectOpenAuditAlarmA: the W form's no-op, the narrow names dropped.
///
/// # Safety
/// As the W form's.
#[unsafe(export_name = "f2k_export_ObjectOpenAuditAlarmA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn object_open_audit_alarm_a(
    _subsystem_name: *const u8, _handle_id: *const u8, _object_type_name: *const u8, _object_name: *const u8,
    _security_descriptor: *const u8, _client_token: u32, _desired_access: u32, _granted_access: u32,
    _privileges: *const u8, _object_creation: u32, _access_granted: u32, _generate_on_close: *mut u32,
) -> u32 {
    1
}

/// ObjectCloseAuditAlarmW: the alarm skipped, TRUE.
///
/// # Safety
/// The pointers are the caller's; the form reads none of them.
#[unsafe(export_name = "f2k_export_ObjectCloseAuditAlarmW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn object_close_audit_alarm_w(
    _subsystem_name: *const u16, _handle_id: *const u8, _object_type_name: *const u16, _object_name: *const u16,
    _security_descriptor: *const u8, _client_token: u32, _desired_access: u32, _granted_access: u32,
    _privileges: *const u8, _generate_on_close: *mut u32,
) -> u32 {
    1
}

/// ObjectCloseAuditAlarmA: the W form's no-op, the narrow names dropped.
///
/// # Safety
/// As the W form's.
#[unsafe(export_name = "f2k_export_ObjectCloseAuditAlarmA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn object_close_audit_alarm_a(
    _subsystem_name: *const u8, _handle_id: *const u8, _object_type_name: *const u8, _object_name: *const u8,
    _security_descriptor: *const u8, _client_token: u32, _desired_access: u32, _granted_access: u32,
    _privileges: *const u8, _generate_on_close: *mut u32,
) -> u32 {
    1
}

/// ObjectDeleteAuditAlarmW: the alarm skipped, TRUE.
///
/// # Safety
/// The pointers are the caller's; the form reads none of them.
#[unsafe(export_name = "f2k_export_ObjectDeleteAuditAlarmW")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn object_delete_audit_alarm_w(
    _subsystem_name: *const u16, _handle_id: *const u8, _object_type_name: *const u16, _object_name: *const u16,
    _security_descriptor: *const u8, _client_token: u32, _desired_access: u32, _granted_access: u32,
    _privileges: *const u8, _generate_on_close: *mut u32,
) -> u32 {
    1
}

/// ObjectDeleteAuditAlarmA: the W form's no-op, the narrow names dropped.
///
/// # Safety
/// As the W form's.
#[unsafe(export_name = "f2k_export_ObjectDeleteAuditAlarmA")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn object_delete_audit_alarm_a(
    _subsystem_name: *const u8, _handle_id: *const u8, _object_type_name: *const u8, _object_name: *const u8,
    _security_descriptor: *const u8, _client_token: u32, _desired_access: u32, _granted_access: u32,
    _privileges: *const u8, _generate_on_close: *mut u32,
) -> u32 {
    1
}

/// ObjectPrivilegeAuditAlarmW: the alarm skipped, TRUE.
///
/// # Safety
/// The pointers are the caller's; the form reads none of them.
#[unsafe(export_name = "f2k_export_ObjectPrivilegeAuditAlarmW")]
pub unsafe extern "system" fn object_privilege_audit_alarm_w(
    _subsystem_name: *const u16, _handle_id: *const u8, _client_token: u32, _privileges: *const u8, _access_granted: u32,
) -> u32 {
    1
}

/// ObjectPrivilegeAuditAlarmA: the W form's no-op, the narrow name dropped.
///
/// # Safety
/// As the W form's.
#[unsafe(export_name = "f2k_export_ObjectPrivilegeAuditAlarmA")]
pub unsafe extern "system" fn object_privilege_audit_alarm_a(
    _subsystem_name: *const u8, _handle_id: *const u8, _client_token: u32, _privileges: *const u8, _access_granted: u32,
) -> u32 {
    1
}

/// PrivilegedServiceAuditAlarmW: the alarm skipped, TRUE.
///
/// # Safety
/// The pointers are the caller's; the form reads none of them.
#[unsafe(export_name = "f2k_export_PrivilegedServiceAuditAlarmW")]
pub unsafe extern "system" fn privileged_service_audit_alarm_w(
    _subsystem_name: *const u16, _service_name: *const u16, _client_token: u32, _privileges: *const u8, _access_granted: u32,
) -> u32 {
    1
}

/// PrivilegedServiceAuditAlarmA: the W form's no-op, the narrow names dropped.
///
/// # Safety
/// As the W form's.
#[unsafe(export_name = "f2k_export_PrivilegedServiceAuditAlarmA")]
pub unsafe extern "system" fn privileged_service_audit_alarm_a(
    _subsystem_name: *const u8, _service_name: *const u8, _client_token: u32, _privileges: *const u8, _access_granted: u32,
) -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// Every alarm form returns TRUE with the last error untouched and NULL string pointers
    /// accepted; GenerateOnClose is left alone (nothing is ever generated).
    #[test]
    fn every_alarm_form_is_a_no_op_success() {
        let mut generate_on_close = 0xF2F2;
        arm();
        assert_eq!(
            unsafe {
                object_open_audit_alarm_w(core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0x58, 1, 2, core::ptr::null(), 0, 1, &mut generate_on_close)
            },
            1
        );
        assert_eq!(
            unsafe {
                object_open_audit_alarm_a(core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0x58, 1, 2, core::ptr::null(), 0, 1, &mut generate_on_close)
            },
            1
        );
        assert_eq!(
            unsafe {
                object_close_audit_alarm_w(core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0x58, 1, 2, core::ptr::null(), &mut generate_on_close)
            },
            1
        );
        assert_eq!(
            unsafe {
                object_close_audit_alarm_a(core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0x58, 1, 2, core::ptr::null(), &mut generate_on_close)
            },
            1
        );
        assert_eq!(
            unsafe {
                object_delete_audit_alarm_w(core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0x58, 1, 2, core::ptr::null(), &mut generate_on_close)
            },
            1
        );
        assert_eq!(
            unsafe {
                object_delete_audit_alarm_a(core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0x58, 1, 2, core::ptr::null(), &mut generate_on_close)
            },
            1
        );
        assert_eq!(
            unsafe { object_privilege_audit_alarm_w(core::ptr::null(), core::ptr::null(), 0x58, core::ptr::null(), 1) },
            1
        );
        assert_eq!(
            unsafe { object_privilege_audit_alarm_a(core::ptr::null(), core::ptr::null(), 0x58, core::ptr::null(), 1) },
            1
        );
        assert_eq!(
            unsafe { privileged_service_audit_alarm_w(core::ptr::null(), core::ptr::null(), 0x58, core::ptr::null(), 1) },
            1
        );
        assert_eq!(
            unsafe { privileged_service_audit_alarm_a(core::ptr::null(), core::ptr::null(), 0x58, core::ptr::null(), 1) },
            1
        );
        assert_eq!((last_error(), generate_on_close), (0xF2F2, 0xF2F2));
    }

    /// The ANSI forms take narrow names as they are: still TRUE, still no last error.
    #[test]
    fn the_ansi_forms_take_narrow_names() {
        let subsystem = b"File\0";
        let object = b"\\??\\C:\\TMP\0";
        let service = b"LanmanServer\0";
        let mut generate_on_close = 0xF2F2;
        arm();
        assert_eq!(
            unsafe {
                object_open_audit_alarm_a(subsystem.as_ptr(), core::ptr::null(), object.as_ptr(), object.as_ptr(), core::ptr::null(), 0x58, 1, 2, core::ptr::null(), 0, 1, &mut generate_on_close)
            },
            1
        );
        assert_eq!(
            unsafe {
                object_close_audit_alarm_a(subsystem.as_ptr(), core::ptr::null(), object.as_ptr(), object.as_ptr(), core::ptr::null(), 0x58, 1, 2, core::ptr::null(), &mut generate_on_close)
            },
            1
        );
        assert_eq!(
            unsafe {
                object_delete_audit_alarm_a(subsystem.as_ptr(), core::ptr::null(), object.as_ptr(), object.as_ptr(), core::ptr::null(), 0x58, 1, 2, core::ptr::null(), &mut generate_on_close)
            },
            1
        );
        assert_eq!(
            unsafe { object_privilege_audit_alarm_a(subsystem.as_ptr(), core::ptr::null(), 0x58, core::ptr::null(), 1) },
            1
        );
        assert_eq!(
            unsafe { privileged_service_audit_alarm_a(subsystem.as_ptr(), service.as_ptr(), 0x58, core::ptr::null(), 1) },
            1
        );
        assert_eq!((last_error(), generate_on_close), (0xF2F2, 0xF2F2));
    }
}
