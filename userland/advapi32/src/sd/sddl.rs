//! The string security descriptor conversions: ConvertSecurityDescriptorToStringSecurityDescriptorA/W
//! and ConvertStringSecurityDescriptorToSecurityDescriptorA/W, revision 1's format.
//!
//! The string is the sections `O:<sid>G:<sid>D:<flags><aces>S:<flags><aces>`, each present when
//! the information bits ask for it and the descriptor carries it. An ACE is
//! `(type;flags;rights;object guid;inherited guid;sid)`; a SID prints as its two-letter moniker
//! when it is a well-known one, else as `S-1-...`. The conversions allocate from the process
//! heap, which the caller frees.

use rtl::edge::{InStr, InWStr};
use rtl::heap::ProcessHeap as _;
use rtl::winerror::{ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY};

use crate::acl::{
    ace_count, dword, object_ace_sid_offset, sid_at, word, ACE_FLAGS_OFF, ACE_MASK_OFF,
    ACE_SIZE_OFF, ACE_TYPE_OFF, ACL_COUNT_OFF, ACL_HEADER, ACL_REV_OFF, ACL_REVISION,
    ACL_REVISION_DS, ACL_SIZE_OFF, KNOWN_ACE_FIXED, OBJECT_ACE_FIXED, SYSTEM_ALARM_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    ACCESS_DENIED_OBJECT_ACE_TYPE, GUID_SIZE, ACE_OBJECT_TYPE_PRESENT,
    ACE_INHERITED_OBJECT_TYPE_PRESENT, FAILED_ACCESS_ACE_FLAG, SUCCESSFUL_ACCESS_ACE_FLAG,
};
use crate::imports::{self as nt, ProcessHeap};
use crate::sid::{
    sid_len, sid_parts_bytes, sid_to_units, well_known_sid, ERROR_UNKNOWN_REVISION, SID_HEADER,
};
use crate::Out;

use super::{
    caller_sd, control, long_align, set_control, set_sd_field_value, FIELD_DACL, FIELD_GROUP,
    FIELD_OWNER, FIELD_SACL, SD_HEADER, SD_REVISION, SE_DACL_AUTO_INHERITED,
    SE_DACL_AUTO_INHERIT_REQ, SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_SACL_AUTO_INHERITED,
    SE_SACL_AUTO_INHERIT_REQ, SE_SACL_PRESENT, SE_SACL_PROTECTED, SE_SELF_RELATIVE,
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
};

// --- The lookup tables ---------------------------------------------------------------------------

/// The named access rights: their two-letter tags and masks.
const RIGHTS: &[(&str, u32)] = &[
    ("RP", 0x0000_0010),
    ("WP", 0x0000_0020),
    ("CC", 0x0000_0001),
    ("DC", 0x0000_0040),
    ("LC", 0x0000_0004),
    ("SW", 0x0000_0008),
    ("LO", 0x0000_0080),
    ("DT", 0x0000_0040),
    ("CR", 0x0000_0100),
    ("RC", 0x0002_0000),
    ("WD", 0x0004_0000),
    ("WO", 0x0008_0000),
    ("SD", 0x0001_0000),
    ("GA", 0x1000_0000),
    ("GR", 0x8000_0000),
    ("GW", 0x4000_0000),
    ("GX", 0x2000_0000),
    ("FA", 0x001F_01FF),
    ("FR", 0x0012_0089),
    ("FW", 0x0012_0116),
    ("FX", 0x0012_00A0),
    ("KA", 0x000F_003F),
    ("KR", 0x0002_0019),
    ("KW", 0x0002_0006),
    ("KX", 0x0002_0019),
];

/// The ACE types' letters.
const ACE_TYPES: &[(u8, &str)] = &[
    (ACCESS_ALLOWED_ACE_TYPE, "A"),
    (ACCESS_DENIED_ACE_TYPE, "D"),
    (SYSTEM_AUDIT_ACE_TYPE, "AU"),
    (SYSTEM_ALARM_ACE_TYPE, "AL"),
    (ACCESS_ALLOWED_OBJECT_ACE_TYPE, "OA"),
    (ACCESS_DENIED_OBJECT_ACE_TYPE, "OD"),
    (SYSTEM_AUDIT_OBJECT_ACE_TYPE, "AU"),
    (SYSTEM_ALARM_OBJECT_ACE_TYPE, "AL"),
];

/// The ACE flags' letters.
const ACE_FLAG_LETTERS: &[(u32, &str)] = &[
    (0x01, "OI"),
    (0x02, "CI"),
    (0x04, "NP"),
    (0x08, "IO"),
    (0x10, "ID"),
    (SUCCESSFUL_ACCESS_ACE_FLAG, "SA"),
    (FAILED_ACCESS_ACE_FLAG, "FA"),
];

/// The well-known SID monikers and their kinds (a WELL_KNOWN_SID_TYPE each).
const MONIKERS: &[(&str, u32)] = &[
    ("WD", 1),
    ("CO", 3),
    ("CG", 4),
    ("SY", 22),
    ("IU", 11),
    ("NU", 9),
    ("SU", 12),
    ("ED", 15),
    ("RC", 18),
    ("PS", 16),
    ("AU", 17),
    ("BA", 26),
    ("BG", 27),
    ("BU", 35),
    ("PU", 29),
    ("BO", 33),
    ("PO", 32),
    ("SO", 31),
    ("AO", 30),
    ("RE", 34),
    ("RU", 36),
];

// --- Small UTF-16 helpers ------------------------------------------------------------------------

fn push_str(units: &mut Vec<u16>, text: &str) {
    units.extend(text.encode_utf16());
}

fn push_unit(units: &mut Vec<u16>, unit: u16) {
    units.push(unit);
}

fn push_number(units: &mut Vec<u16>, mut value: u64, base: u64) {
    let mut digits = [0u16; 20];
    let mut count = 0;
    loop {
        let digit = (value % base) as u16;
        digits[count] = if digit > 9 {
            digit - 10 + u16::from(b'A')
        } else {
            u16::from(b'0') + digit
        };
        count += 1;
        value /= base;
        if value == 0 {
            break;
        }
    }
    while count > 0 {
        count -= 1;
        push_unit(units, digits[count]);
    }
}

/// The SID's text (its `S-1-...` form) into `units`.
fn push_sid_text(units: &mut Vec<u16>, sid: &[u8]) {
    let mut buffer = [0u16; 256];
    if let Some(len) = sid_to_units(sid, &mut buffer) {
        units.extend_from_slice(&buffer[..len]);
    }
}

/// The SID as a moniker when it is a well-known one, else its `S-1-...` text.
fn push_sid(units: &mut Vec<u16>, sid: &[u8]) {
    for (tag, kind) in MONIKERS {
        if let Some(parts) = well_known_sid(*kind, None) {
            let mut bytes = vec![0u8; sid_len(parts.count)];
            sid_parts_bytes(&parts, &mut bytes);
            if bytes == sid {
                push_str(units, tag);
                return;
            }
        }
    }
    push_sid_text(units, sid);
}

/// A GUID's `{...}` text into `units`.
fn push_guid(units: &mut Vec<u16>, guid: &[u8]) {
    push_unit(units, u16::from(b'{'));
    let d1 = u32::from_le_bytes(guid[0..4].try_into().unwrap_or([0; 4]));
    let d2 = u16::from_le_bytes(guid[4..6].try_into().unwrap_or([0; 2]));
    let d3 = u16::from_le_bytes(guid[6..8].try_into().unwrap_or([0; 2]));
    push_number(units, u64::from(d1), 16);
    push_unit(units, u16::from(b'-'));
    push_number(units, u64::from(d2), 16);
    push_unit(units, u16::from(b'-'));
    push_number(units, u64::from(d3), 16);
    push_unit(units, u16::from(b'-'));
    for byte in &guid[8..10] {
        push_number(units, u64::from(*byte), 16);
    }
    push_unit(units, u16::from(b'-'));
    for byte in &guid[10..16] {
        push_number(units, u64::from(*byte), 16);
    }
    push_unit(units, u16::from(b'}'));
}

/// The access mask's text into `units`: the exact named right, else the named bits, else hex.
fn push_rights(units: &mut Vec<u16>, mask: u32) {
    if let Some((tag, _)) = RIGHTS.iter().find(|(_, value)| *value == mask) {
        push_str(units, tag);
        return;
    }
    let mut remaining = mask;
    // The named bits, widest first.
    let mut entries: Vec<&(&str, u32)> = RIGHTS.iter().collect();
    entries.sort_by_key(|(_, value)| !value.count_ones());
    for (tag, value) in entries {
        if *value != 0 && remaining & value == *value {
            push_str(units, tag);
            remaining &= !value;
        }
    }
    if remaining != 0 {
        push_str(units, "0x");
        push_number(units, u64::from(remaining), 16);
    }
}

// --- The descriptor to string --------------------------------------------------------------------

/// One ACE's `(type;flags;rights;object guid;inherited guid;sid)` text.
fn push_ace(units: &mut Vec<u16>, acl: &[u8], at: usize, sacl: bool) {
    let kind = acl[at + ACE_TYPE_OFF];
    let flags = u32::from(acl[at + ACE_FLAGS_OFF]);
    let mask = dword(acl, at + ACE_MASK_OFF).unwrap_or(0);
    push_unit(units, u16::from(b'('));
    push_str(
        units,
        ACE_TYPES
            .iter()
            .find(|(value, _)| *value == kind)
            .map(|(_, tag)| *tag)
            .unwrap_or("?"),
    );
    push_unit(units, u16::from(b';'));
    for (bit, tag) in ACE_FLAG_LETTERS {
        if flags & bit != 0 && (sacl || *bit & (SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG) == 0)
        {
            push_str(units, tag);
        }
    }
    push_unit(units, u16::from(b';'));
    push_rights(units, mask);
    push_unit(units, u16::from(b';'));
    let object = matches!(
        kind,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE..=SYSTEM_ALARM_OBJECT_ACE_TYPE
    );
    if object {
        let object_flags = dword(acl, at + 8).unwrap_or(0);
        let mut guid_at = at + OBJECT_ACE_FIXED;
        if object_flags & ACE_OBJECT_TYPE_PRESENT != 0 {
            push_guid(units, &acl[guid_at..guid_at + GUID_SIZE]);
            guid_at += GUID_SIZE;
        }
        push_unit(units, u16::from(b';'));
        if object_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
            push_guid(units, &acl[guid_at..guid_at + GUID_SIZE]);
        }
        push_unit(units, u16::from(b';'));
        if let Some(sid) = sid_at(acl, at + object_ace_sid_offset(object_flags)) {
            push_sid(units, sid);
        }
    } else {
        push_unit(units, u16::from(b';'));
        push_unit(units, u16::from(b';'));
        if let Some(sid) = sid_at(acl, at + KNOWN_ACE_FIXED) {
            push_sid(units, sid);
        }
    }
    push_unit(units, u16::from(b')'));
}

/// One ACL's section text: the control letters then the ACEs.
fn push_acl(units: &mut Vec<u16>, acl: &[u8], sacl: bool, control_bits: u16) {
    if sacl {
        if control_bits & SE_SACL_PROTECTED != 0 {
            push_str(units, "P");
        }
        if control_bits & SE_SACL_AUTO_INHERIT_REQ != 0 {
            push_str(units, "AR");
        }
        if control_bits & SE_SACL_AUTO_INHERITED != 0 {
            push_str(units, "AI");
        }
    } else {
        if control_bits & SE_DACL_PROTECTED != 0 {
            push_str(units, "P");
        }
        if control_bits & SE_DACL_AUTO_INHERIT_REQ != 0 {
            push_str(units, "AR");
        }
        if control_bits & SE_DACL_AUTO_INHERITED != 0 {
            push_str(units, "AI");
        }
    }
    let mut at = ACL_HEADER;
    for _ in 0..ace_count(acl) {
        push_ace(units, acl, at, sacl);
        at += word(acl, at + ACE_SIZE_OFF).unwrap_or(0) as usize;
    }
}

/// The descriptor at `base` as its revision-1 string for the information bits `info`.
///
/// # Safety
///
/// The descriptor's components are read as it names them.
unsafe fn sd_to_string(base: usize, sd: &[u8], info: u32) -> Option<Vec<u16>> {
    let mut units = Vec::new();
    let current = control(sd);
    // SAFETY: the components are read as the descriptor names them.
    unsafe {
        if info & OWNER_SECURITY_INFORMATION != 0 {
            if let Some(owner) = component_sid(base, sd, FIELD_OWNER) {
                push_str(&mut units, "O:");
                push_sid(&mut units, owner);
            }
        }
        if info & GROUP_SECURITY_INFORMATION != 0 {
            if let Some(group) = component_sid(base, sd, FIELD_GROUP) {
                push_str(&mut units, "G:");
                push_sid(&mut units, group);
            }
        }
        if info & DACL_SECURITY_INFORMATION != 0 && current & SE_DACL_PRESENT != 0 {
            if let Some(dacl) = component_acl(base, sd, FIELD_DACL) {
                push_str(&mut units, "D:");
                push_acl(&mut units, dacl, false, current);
            }
        }
        if info & SACL_SECURITY_INFORMATION != 0 && current & SE_SACL_PRESENT != 0 {
            if let Some(sacl) = component_acl(base, sd, FIELD_SACL) {
                push_str(&mut units, "S:");
                push_acl(&mut units, sacl, true, current);
            }
        }
    }
    Some(units)
}

// The component readers, shared with the module root through `super`.
use super::{component_acl, component_sid};

// --- The string to descriptor --------------------------------------------------------------------

/// A cursor over the string's units.
struct Cursor<'a> {
    units: &'a [u16],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(units: &'a [u16]) -> Self {
        Cursor { units, at: 0 }
    }

    fn peek(&self) -> Option<u16> {
        self.units.get(self.at).copied()
    }

    fn bump(&mut self) -> Option<u16> {
        let unit = self.peek()?;
        self.at += 1;
        Some(unit)
    }

    fn expect(&mut self, unit: u16) -> Option<()> {
        if self.peek() == Some(unit) {
            self.at += 1;
            Some(())
        } else {
            None
        }
    }

    /// The units until `stop` (not consumed) or the end.
    fn until(&mut self, stop: u16) -> &'a [u16] {
        let start = self.at;
        while self.peek().is_some_and(|unit| unit != stop) {
            self.at += 1;
        }
        &self.units[start..self.at]
    }
}

/// Parse a number: `0x` hex, else decimal.
fn parse_number(units: &[u16]) -> Option<u64> {
    let text: String = units
        .iter()
        .map(|&unit| char::from_u32(u32::from(unit)).unwrap_or('?'))
        .collect();
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

/// Parse a SID: a moniker, or the `S-1-...` form.
fn parse_sid(units: &[u16]) -> Option<Vec<u8>> {
    let text: String = units
        .iter()
        .map(|&unit| char::from_u32(u32::from(unit)).unwrap_or('?'))
        .collect();
    let upper = text.to_ascii_uppercase();
    if let Some((_, kind)) = MONIKERS.iter().find(|(tag, _)| *tag == upper) {
        let parts = well_known_sid(*kind, None)?;
        let mut bytes = vec![0u8; sid_len(parts.count)];
        sid_parts_bytes(&parts, &mut bytes);
        return Some(bytes);
    }
    if !upper.starts_with("S-") {
        return None;
    }
    let mut cursor = Cursor::new(units);
    cursor.bump()?; // 'S'
    cursor.expect(u16::from(b'-'))?;
    let revision = parse_number(cursor.until(u16::from(b'-')))?;
    if revision != 1 {
        return None;
    }
    cursor.expect(u16::from(b'-'))?;
    let authority_units = cursor.until(u16::from(b'-'));
    let authority = parse_number(authority_units)?;
    let mut subs = Vec::new();
    while cursor.peek() == Some(u16::from(b'-')) {
        cursor.bump();
        let sub = parse_number(cursor.until(u16::from(b'-')))?;
        if sub > u32::MAX as u64 {
            return None;
        }
        subs.push(sub as u32);
    }
    if subs.is_empty() || subs.len() > 15 {
        return None;
    }
    let mut sid = vec![0u8; SID_HEADER + 4 * subs.len()];
    sid[0] = 1;
    sid[1] = subs.len() as u8;
    if authority_units.len() >= 2
        && authority_units[0] == u16::from(b'0')
        && (authority_units[1] == u16::from(b'x') || authority_units[1] == u16::from(b'X'))
    {
        // A 48-bit authority in hex, stored big-endian in the six bytes.
        if authority > 0xFFFF_FFFF_FFFF {
            return None;
        }
        sid[2..8].copy_from_slice(&authority.to_be_bytes()[2..]);
    } else {
        if authority > u32::MAX as u64 {
            return None;
        }
        // The low 32 bits, big-endian in the authority's low four bytes.
        sid[4..8].copy_from_slice(&(authority as u32).to_be_bytes());
    }
    for (index, sub) in subs.iter().enumerate() {
        sid[SID_HEADER + 4 * index..SID_HEADER + 4 * index + 4].copy_from_slice(&sub.to_le_bytes());
    }
    Some(sid)
}

/// Parse a GUID's `{...}` text (empty: none).
fn parse_guid(units: &[u16]) -> Option<Option<[u8; GUID_SIZE]>> {
    if units.is_empty() {
        return Some(None);
    }
    let text: String = units
        .iter()
        .map(|&unit| char::from_u32(u32::from(unit)).unwrap_or('?'))
        .collect();
    let inner = text.strip_prefix('{')?.strip_suffix('}')?;
    let hex: String = inner.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut guid = [0u8; GUID_SIZE];
    for (index, byte) in guid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).ok()?;
    }
    // The first three fields are little-endian in the structure.
    guid[0..4].reverse();
    guid[4..6].reverse();
    guid[6..8].reverse();
    Some(Some(guid))
}

/// Parse the access rights field: named tags, `0x` hex, or decimal.
fn parse_rights(units: &[u16]) -> Option<u32> {
    let text: String = units
        .iter()
        .map(|&unit| char::from_u32(u32::from(unit)).unwrap_or('?'))
        .collect();
    let text = text.trim();
    if text.is_empty() {
        return Some(0);
    }
    if text.starts_with("0x") || text.starts_with("0X") {
        return u32::try_from(parse_number(units)?).ok();
    }
    if text.chars().all(|c| c.is_ascii_digit()) {
        return u32::try_from(parse_number(units)?).ok();
    }
    // The named tags, two letters at a time.
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let named = !bytes.is_empty()
        && bytes.len() % 2 == 0
        && (0..bytes.len())
            .step_by(2)
            .all(|at| RIGHTS.iter().any(|(known, _)| known.as_bytes() == &bytes[at..at + 2]));
    if named {
        let mut mask = 0u32;
        for at in (0..bytes.len()).step_by(2) {
            mask |= RIGHTS
                .iter()
                .find(|(known, _)| known.as_bytes() == &bytes[at..at + 2])
                .map(|(_, value)| *value)?;
        }
        return Some(mask);
    }
    // A bare hex mask.
    if !text.is_empty() && text.chars().all(|c| c.is_ascii_hexdigit()) {
        return u32::try_from(u64::from_str_radix(text, 16).ok()?).ok();
    }
    None
}

/// Parse one ACE's `(...)` into its bytes.
fn parse_ace(cursor: &mut Cursor) -> Option<Vec<u8>> {
    cursor.expect(u16::from(b'('))?;
    let type_units = cursor.until(u16::from(b';'));
    cursor.expect(u16::from(b';'))?;
    let type_text: String = type_units
        .iter()
        .map(|&u| char::from_u32(u32::from(u)).unwrap_or('?'))
        .collect::<String>()
        .to_ascii_uppercase();
    let plain = match type_text.as_str() {
        "A" => ACCESS_ALLOWED_ACE_TYPE,
        "D" => ACCESS_DENIED_ACE_TYPE,
        "AU" => SYSTEM_AUDIT_ACE_TYPE,
        "AL" => SYSTEM_ALARM_ACE_TYPE,
        "OA" => ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        "OD" => ACCESS_DENIED_OBJECT_ACE_TYPE,
        _ => return None,
    };
    let flag_units = cursor.until(u16::from(b';'));
    cursor.expect(u16::from(b';'))?;
    let mut flags = 0u32;
    {
        let text: String = flag_units
            .iter()
            .map(|&u| char::from_u32(u32::from(u)).unwrap_or('?'))
            .collect::<String>()
            .to_ascii_uppercase();
        let bytes = text.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            let tag = &text[at..(at + 2).min(bytes.len())];
            let (bit, _) = ACE_FLAG_LETTERS.iter().find(|(_, known)| *known == tag)?;
            flags |= bit;
            at += 2;
        }
    }
    let rights = parse_rights(cursor.until(u16::from(b';')))?;
    cursor.expect(u16::from(b';'))?;
    let object_guid = parse_guid(cursor.until(u16::from(b';')))?;
    cursor.expect(u16::from(b';'))?;
    let inherited_guid = parse_guid(cursor.until(u16::from(b';')))?;
    cursor.expect(u16::from(b';'))?;
    let sid = parse_sid(cursor.until(u16::from(b')')))?;
    cursor.expect(u16::from(b')'))?;
    let object = matches!(
        plain,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE
    ) || ((plain == SYSTEM_AUDIT_ACE_TYPE || plain == SYSTEM_ALARM_ACE_TYPE)
        && (object_guid.is_some() || inherited_guid.is_some()));
    let kind = if object {
        match plain {
            ACCESS_ALLOWED_ACE_TYPE => ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ACCESS_DENIED_ACE_TYPE => ACCESS_DENIED_OBJECT_ACE_TYPE,
            SYSTEM_AUDIT_ACE_TYPE => SYSTEM_AUDIT_OBJECT_ACE_TYPE,
            _ => SYSTEM_ALARM_OBJECT_ACE_TYPE,
        }
    } else {
        plain
    };
    let mut object_flags = 0u32;
    if object_guid.is_some() {
        object_flags |= ACE_OBJECT_TYPE_PRESENT;
    }
    if inherited_guid.is_some() {
        object_flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
    }
    let ace_size = if object {
        OBJECT_ACE_FIXED + (object_flags.count_ones() as usize) * GUID_SIZE + sid.len()
    } else {
        KNOWN_ACE_FIXED + sid.len()
    };
    let mut ace = vec![0u8; ace_size];
    ace[ACE_TYPE_OFF] = kind;
    ace[ACE_FLAGS_OFF] = flags as u8;
    ace[ACE_SIZE_OFF..ACE_SIZE_OFF + 2].copy_from_slice(&(ace_size as u16).to_le_bytes());
    ace[ACE_MASK_OFF..ACE_MASK_OFF + 4].copy_from_slice(&rights.to_le_bytes());
    if object {
        ace[8..12].copy_from_slice(&object_flags.to_le_bytes());
        let mut at = OBJECT_ACE_FIXED;
        if let Some(guid) = object_guid {
            ace[at..at + GUID_SIZE].copy_from_slice(&guid);
            at += GUID_SIZE;
        }
        if let Some(guid) = inherited_guid {
            ace[at..at + GUID_SIZE].copy_from_slice(&guid);
            at += GUID_SIZE;
        }
        ace[at..].copy_from_slice(&sid);
    } else {
        ace[KNOWN_ACE_FIXED..].copy_from_slice(&sid);
    }
    Some(ace)
}

/// The section control letters into control bits (P, AR, AI), for the DACL or SACL prefix bits.
fn parse_control_letters(cursor: &mut Cursor, sacl: bool) -> u16 {
    let mut bits = 0u16;
    loop {
        match cursor.peek().map(|u| u as u8 as char) {
            Some('P') | Some('p') => {
                cursor.bump();
                bits |= if sacl { SE_SACL_PROTECTED } else { SE_DACL_PROTECTED };
            }
            Some('A') | Some('a') => {
                cursor.bump();
                match cursor.bump().map(|u| u as u8 as char) {
                    Some('R') | Some('r') => {
                        bits |= if sacl {
                            SE_SACL_AUTO_INHERIT_REQ
                        } else {
                            SE_DACL_AUTO_INHERIT_REQ
                        }
                    }
                    Some('I') | Some('i') => {
                        bits |= if sacl {
                            SE_SACL_AUTO_INHERITED
                        } else {
                            SE_DACL_AUTO_INHERITED
                        }
                    }
                    _ => return bits,
                }
            }
            _ => return bits,
        }
    }
}

/// Parse the whole string into a self-relative descriptor image: the header, the components
/// packed SACL, DACL, owner, group, the fields their offsets.
fn parse_sd(units: &[u16]) -> Option<Vec<u8>> {
    let mut cursor = Cursor::new(units);
    let mut control_bits = 0u16;
    let mut owner = Vec::new();
    let mut group = Vec::new();
    let mut dacl = Vec::new();
    let mut sacl = Vec::new();
    while let Some(unit) = cursor.peek() {
        let section = (unit as u8 as char).to_ascii_uppercase();
        cursor.bump();
        cursor.expect(u16::from(b':'))?;
        match section {
            'O' => {
                owner = parse_sid(cursor.until_section())?;
            }
            'G' => {
                group = parse_sid(cursor.until_section())?;
            }
            'D' => {
                control_bits |= parse_control_letters(&mut cursor, false);
                dacl = parse_aces(&mut cursor)?;
                control_bits |= SE_DACL_PRESENT;
            }
            'S' => {
                control_bits |= parse_control_letters(&mut cursor, true);
                sacl = parse_aces(&mut cursor)?;
                control_bits |= SE_SACL_PRESENT;
            }
            _ => return None,
        }
    }
    let components: [Option<Vec<u8>>; 4] = [
        if owner.is_empty() { None } else { Some(owner) },
        if group.is_empty() { None } else { Some(group) },
        if sacl.is_empty() { None } else { Some(sacl) },
        if dacl.is_empty() { None } else { Some(dacl) },
    ];
    let sum: usize = components.iter().flatten().map(|c| long_align(c.len())).sum();
    let mut image = vec![0u8; SD_HEADER + sum];
    image[0] = SD_REVISION;
    set_control(&mut image, control_bits | SE_SELF_RELATIVE);
    let mut running = SD_HEADER;
    for index in [FIELD_SACL, FIELD_DACL, FIELD_OWNER, FIELD_GROUP] {
        if let Some(component) = &components[index] {
            running = long_align(running);
            image[running..running + component.len()].copy_from_slice(component);
            set_sd_field_value(&mut image, index, running);
            running += long_align(component.len());
        }
    }
    Some(image)
}

impl<'a> Cursor<'a> {
    /// The units until a section letter followed by ':', a NUL, or the end (not consumed).
    fn until_section(&mut self) -> &'a [u16] {
        let start = self.at;
        while self.at + 1 < self.units.len() {
            let unit = self.units[self.at];
            let next = self.units[self.at + 1];
            if next == u16::from(b':') && (unit as u8 as char).is_ascii_alphabetic() {
                break;
            }
            self.at += 1;
        }
        &self.units[start..self.at]
    }
}

/// Parse the ACEs of a D:/S: section into an ACL image.
fn parse_aces(cursor: &mut Cursor) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    let mut count = 0u16;
    let mut object = false;
    while cursor.peek() == Some(u16::from(b'(')) {
        let ace = parse_ace(cursor)?;
        if ace[ACE_TYPE_OFF] >= ACCESS_ALLOWED_OBJECT_ACE_TYPE {
            object = true;
        }
        body.extend(ace);
        count += 1;
    }
    if count == 0 {
        return Some(Vec::new());
    }
    let mut acl = vec![0u8; ACL_HEADER];
    acl[ACL_REV_OFF] = if object { ACL_REVISION_DS as u8 } else { ACL_REVISION as u8 };
    acl[ACL_SIZE_OFF..ACL_SIZE_OFF + 2].copy_from_slice(&((ACL_HEADER + body.len()) as u16).to_le_bytes());
    acl[ACL_COUNT_OFF..ACL_COUNT_OFF + 2].copy_from_slice(&count.to_le_bytes());
    acl.extend(body);
    Some(acl)
}

// --- The exports ---------------------------------------------------------------------------------

/// ConvertSecurityDescriptorToStringSecurityDescriptorW: the descriptor at `sd` as its
/// revision-`revision` string in a process-heap block of UTF-16 units (the terminator
/// included), its address into `string` and its length into `length`.
///
/// # Safety
///
/// `sd` is null or a security descriptor the call may read; the rest the caller's places.
#[unsafe(export_name = "f2k_export_ConvertSecurityDescriptorToStringSecurityDescriptorW")]
pub unsafe extern "system" fn convert_sd_to_string_sd_w(
    sd: *const u8,
    revision: u32,
    info: u32,
    string: *mut *mut u16,
    length: *mut u32,
) -> u32 {
    // SAFETY: the caller's descriptor and places.
    let (buffer, mut string, mut length) = unsafe {
        (
            caller_sd(sd),
            Out::optional(string),
            Out::optional(length),
        )
    };
    let (Some(string), Some(length), Some(buffer)) = (string.as_mut(), length.as_mut(), buffer) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if info == 0 || revision != 1 || buffer[0] != SD_REVISION {
        nt::set_last_error(if revision != 1 || buffer[0] != SD_REVISION {
            ERROR_UNKNOWN_REVISION
        } else {
            ERROR_INVALID_PARAMETER
        });
        return 0;
    }
    // SAFETY: the components are read as the descriptor names them.
    let Some(units) = (unsafe { sd_to_string(sd as usize, buffer, info) }) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let block = ProcessHeap::allocate(2 * (units.len() + 1));
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: the heap's new block, ours until the caller frees it.
    let out = unsafe { core::slice::from_raw_parts_mut(block.cast::<u16>(), units.len() + 1) };
    out[..units.len()].copy_from_slice(&units);
    out[units.len()] = 0;
    string.set(block.cast());
    length.set((units.len() + 1) as u32);
    nt::set_last_error(0);
    1
}

/// ConvertSecurityDescriptorToStringSecurityDescriptorA: as the W form, the string in the ANSI
/// code page.
///
/// # Safety
///
/// As the W form's.
#[unsafe(export_name = "f2k_export_ConvertSecurityDescriptorToStringSecurityDescriptorA")]
pub unsafe extern "system" fn convert_sd_to_string_sd_a(
    sd: *const u8,
    revision: u32,
    info: u32,
    string: *mut *mut u8,
    length: *mut u32,
) -> u32 {
    // SAFETY: the caller's descriptor and places.
    let (buffer, mut string, mut length) = unsafe {
        (
            caller_sd(sd),
            Out::optional(string),
            Out::optional(length),
        )
    };
    let (Some(string), Some(length), Some(buffer)) = (string.as_mut(), length.as_mut(), buffer) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if info == 0 || revision != 1 || buffer[0] != SD_REVISION {
        nt::set_last_error(if revision != 1 || buffer[0] != SD_REVISION {
            ERROR_UNKNOWN_REVISION
        } else {
            ERROR_INVALID_PARAMETER
        });
        return 0;
    }
    // SAFETY: the components are read as the descriptor names them.
    let Some(units) = (unsafe { sd_to_string(sd as usize, buffer, info) }) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let mut wide = units;
    wide.push(0);
    let bytes = nt::unicode_to_multi_byte_size(&wide) as usize;
    let block = ProcessHeap::allocate(bytes);
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: the heap's new block, ours until the caller frees it.
    let out = unsafe { core::slice::from_raw_parts_mut(block, bytes) };
    let written = nt::unicode_to_multi_byte(out, &wide);
    string.set(block);
    length.set(written as u32);
    nt::set_last_error(0);
    1
}

/// ConvertStringSecurityDescriptorToSecurityDescriptorW's body: the string parsed into a
/// self-relative descriptor in a process-heap block, its address into `sd` and its size into
/// `size`.
fn string_to_sd(units: &[u16], revision: u32, sd: *mut *mut u8, size: *mut u32) -> u32 {
    if revision != 1 {
        nt::set_last_error(ERROR_UNKNOWN_REVISION);
        return 0;
    }
    let Some(image) = parse_sd(units) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let block = ProcessHeap::allocate(image.len());
    if block.is_null() {
        nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: the heap's new block, ours until the caller frees it.
    let out = unsafe { core::slice::from_raw_parts_mut(block, image.len()) };
    out.copy_from_slice(&image);
    // SAFETY: the caller's places.
    unsafe {
        if let Some(mut sd) = Out::optional(sd) {
            sd.set(block);
        }
        if let Some(mut size) = Out::optional(size) {
            size.set(image.len() as u32);
        }
    }
    nt::set_last_error(0);
    1
}

/// ConvertStringSecurityDescriptorToSecurityDescriptorW: the string at `string` as a
/// self-relative security descriptor in a process-heap block.
///
/// # Safety
///
/// `string` is null or a NUL-terminated UTF-16 string; the rest the caller's places.
#[unsafe(export_name = "f2k_export_ConvertStringSecurityDescriptorToSecurityDescriptorW")]
pub unsafe extern "system" fn convert_string_sd_to_sd_w(
    string: *const u16,
    revision: u32,
    sd: *mut *mut u8,
    size: *mut u32,
) -> u32 {
    // SAFETY: the caller's string.
    let Some(string) = (unsafe { InWStr::optional(string) }) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let units = string.units();
    let units: Vec<u16> = (0..units.len()).map(|at| units.get(at)).collect();
    string_to_sd(&units, revision, sd, size)
}

/// ConvertStringSecurityDescriptorToSecurityDescriptorA: as the W form, an ANSI string.
///
/// # Safety
///
/// As the W form's, for a NUL-terminated ANSI string.
#[unsafe(export_name = "f2k_export_ConvertStringSecurityDescriptorToSecurityDescriptorA")]
pub unsafe extern "system" fn convert_string_sd_to_sd_a(
    string: *const u8,
    revision: u32,
    sd: *mut *mut u8,
    size: *mut u32,
) -> u32 {
    // SAFETY: the caller's string.
    let Some(string) = (unsafe { InStr::optional(string) }) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let Ok(wide) = nt::ansi_to_unicode(string.bytes()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let units = wide.counted().units();
    string_to_sd(units, revision, sd, size)
}

