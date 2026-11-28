//! The security descriptors objects carry, and the ones registry keys keep for their next opens.

use sdcache::SdRef;

use super::*;
use crate::slots::{per_page, KernelId, Record, Slots};
use crate::status::NtStatus;

/// One registry key's descriptor, as last set on one of its key objects: the key (its record and
/// the record's generation) and the shared cache handle. Every open of the key makes its object
/// carry the key's descriptor rather than the type's default, so a set through one handle governs
/// the next open's grant. A deleted key's entry stays: its generation never comes back, so the
/// entry can never name another key, and the registry itself lives as long as the kernel does.
pub(super) struct KeySd {
    key: Option<crate::cm::Key>,
    sd: SdRef,
}

impl KeySd {
    fn free() -> Self {
        KeySd {
            key: None,
            sd: SdRef::NONE,
        }
    }
}

// SAFETY: writes a whole entry.
unsafe impl Record for KeySd {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(KeySd::free()) };
    }
}

/// The registry keys' descriptors: a page of entries at a time.
pub(super) type KeySds = Slots<KeySd, KernelId<KeySd>, { per_page::<KeySd>() }>;

impl Directory {
    /// The security descriptor of the live object `id` names, as a shared cache handle (a new
    /// reference on the entry); none for an id that names nothing. The handle keeps the entry
    /// alive for as long as it lives, so its bytes can be read with the lock let go.
    pub fn sd(&mut self, id: ObjectId) -> Option<SdRef> {
        self.sd_cell(id).map(|cell| cell.clone())
    }

    /// Replace the security descriptor of the live object `id` names with `sd`, releasing the
    /// old one's reference; false when `id` names nothing.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_sd(&mut self, id: ObjectId, sd: SdRef) -> bool {
        match self.sd_cell(id) {
            Some(cell) => {
                *cell = sd;
                true
            }
            None => false,
        }
    }

    /// The seam NtQuerySecurityObject takes: the security descriptor of the live object `id`
    /// names, as a shared cache handle; none for an id that names nothing.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn security_descriptor(&mut self, id: ObjectId) -> Option<SdRef> {
        self.sd(id)
    }

    /// The seam NtSetSecurityObject takes: replace the security descriptor of the live object
    /// `id` names with `sd`, logged into the shared cache at whatever length it takes (an equal
    /// descriptor already cached is shared, not copied). STATUS_INVALID_PARAMETER for an empty
    /// descriptor, STATUS_INSUFFICIENT_RESOURCES when the cache has no room for a new entry,
    /// STATUS_INVALID_HANDLE for an id that names nothing. A key object's descriptor is its key's
    /// too: it is remembered as the key's, so the objects later opens of it make carry it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_security_descriptor(&mut self, id: ObjectId, sd: &[u8]) -> Result<(), NtStatus> {
        use crate::status::{
            STATUS_INSUFFICIENT_RESOURCES,
            STATUS_INVALID_HANDLE,
            STATUS_INVALID_PARAMETER,
        };
        if sd.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let logged = sdcache::log(sd).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if !self.set_sd(id, logged.clone()) {
            return Err(STATUS_INVALID_HANDLE);
        }
        if id.kind == ObjectType::Key {
            let key = self
                .body::<crate::cm::KeyBody>(id)
                .and_then(|body| body.key);
            if let Some(key) = key {
                self.set_key_sd(key, logged);
            }
        }
        Ok(())
    }

    /// The descriptor last set on the registry key `key`, as a shared cache handle (a new
    /// reference on the entry); none when none was set on it.
    pub(super) fn key_sd(&self, key: crate::cm::Key) -> Option<SdRef> {
        self.key_sds
            .iter()
            .find(|(_, entry)| entry.key == Some(key))
            .map(|(_, entry)| entry.sd.clone())
    }

    /// Remember `sd` as the registry key `key`'s descriptor, replacing the one remembered before;
    /// false when no page is left for the table to grow (the key's objects keep their own
    /// descriptors then, only later opens fall back to the type's default).
    fn set_key_sd(&mut self, key: crate::cm::Key, sd: SdRef) -> bool {
        if let Some((_, entry)) = self
            .key_sds
            .iter_mut()
            .find(|(_, entry)| entry.key == Some(key))
        {
            entry.sd = sd;
            return true;
        }
        match self.key_sds.allocate_or_grow(0, pages()) {
            Ok((_, entry)) => {
                entry.key = Some(key);
                entry.sd = sd;
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::testkit::*;
    use crate::sched::event::EventKind;

    /// A small security descriptor's bytes for the tests: a self-relative header, a present DACL
    /// of one allowed ACE, the owner after it.
    fn test_sd(owner: &[u8], aces: &[Vec<u8>]) -> Vec<u8> {
        use crate::sec::{SecurityDescriptor, ACL_REVISION2, SE_DACL_PRESENT, SE_SELF_RELATIVE};
        let mut dacl = vec![ACL_REVISION2, 0];
        let size = (8 + aces.iter().map(|a| a.len()).sum::<usize>()) as u16;
        dacl.extend_from_slice(&size.to_le_bytes());
        dacl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        dacl.extend_from_slice(&0u16.to_le_bytes());
        for ace in aces {
            dacl.extend_from_slice(ace);
        }
        let mut v = vec![0u8; 20];
        let dacl_off = v.len() as u32;
        v.extend_from_slice(&dacl);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        let owner_off = v.len() as u32;
        v.extend_from_slice(owner);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        let h = SecurityDescriptor {
            revision: 1,
            sbz1: 0,
            control: SE_SELF_RELATIVE | SE_DACL_PRESENT,
            owner: owner_off,
            group: 0,
            sacl: 0,
            dacl: dacl_off,
        };
        assert!(h.write(&mut v[..]));
        v
    }

    /// An allowed ACE of `mask` to the SID's bytes `sid`.
    fn allowed_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
        use crate::sec::ACCESS_ALLOWED_ACE_TYPE;
        let size = (4 + 4 + sid.len() + 3) & !3;
        let mut v = vec![ACCESS_ALLOWED_ACE_TYPE, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(sid);
        v.resize(size, 0);
        v
    }

    /// The test user's SID's bytes.
    fn user_sid() -> Vec<u8> {
        let mut v = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 111, 222, 333, 1000] {
            v.extend_from_slice(&sub.to_le_bytes());
        }
        v
    }

    /// A SID of 15 sub-authorities, 68 bytes: an ACE over it with a 272-byte descriptor.
    fn long_sid() -> Vec<u8> {
        let mut v = vec![1u8, 15, 0, 0, 0, 0, 0, 5];
        for sub in 1u32..=15 {
            v.extend_from_slice(&sub.to_le_bytes());
        }
        v
    }

    /// A handle's descriptor bytes, copied out of its cache entry.
    fn sd_bytes(handle: &sdcache::SdRef) -> Vec<u8> {
        handle.with_bytes(|bytes| bytes.to_vec()).unwrap()
    }

    /// An object carries its security descriptor on its record as a shared cache handle: the
    /// default NULL DACL until a create's captured one (or a set) replaces it, read back per
    /// object, two objects holding different ones (or the same one sharing an entry), a dead id
    /// naming none. A descriptor of any size is stored whole.
    #[test]
    fn an_object_carries_its_security_descriptor() {
        let directory = directory();
        let a = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let b = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        // The default: a NULL DACL, present with a zero field, one entry shared by both.
        let null_dacl = security::null_dacl().unwrap();
        let sd_a = directory.security_descriptor(a).unwrap();
        let sd_b = directory.security_descriptor(b).unwrap();
        assert!(sd_a.same(&null_dacl) && sd_b.same(&null_dacl));
        assert_eq!(sd_bytes(&sd_a).len(), 20);
        assert_eq!(sd_bytes(&directory.sd(a).unwrap()), sd_bytes(&sd_a));

        // A set replaces it, on that object alone.
        let sd = test_sd(&user_sid(), &[allowed_ace(0x7, &user_sid())]);
        directory.set_security_descriptor(a, &sd).unwrap();
        assert_eq!(
            sd_bytes(&directory.security_descriptor(a).unwrap()),
            &sd[..]
        );
        assert!(
            directory.security_descriptor(b).unwrap().same(&null_dacl),
            "the other object keeps its own"
        );
        // Set again: replaced.
        let other = test_sd(&user_sid(), &[]);
        directory.set_security_descriptor(a, &other).unwrap();
        assert_eq!(
            sd_bytes(&directory.security_descriptor(a).unwrap()),
            &other[..]
        );

        // A descriptor past any old fixed bound is accepted and stored whole.
        let big = test_sd(
            &user_sid(),
            &[
                allowed_ace(0xFFFF_FFFF, &long_sid()),
                allowed_ace(0xFFFF_FFFF, &long_sid()),
                allowed_ace(0xFFFF_FFFF, &long_sid()),
                allowed_ace(0xFFFF_FFFF, &long_sid()),
            ],
        );
        assert!(big.len() > 256);
        directory.set_security_descriptor(b, &big).unwrap();
        assert_eq!(
            sd_bytes(&directory.security_descriptor(b).unwrap()),
            &big[..]
        );

        // The refusals: an empty descriptor, a dead id.
        assert_eq!(
            directory.set_security_descriptor(b, &[]),
            Err(crate::status::STATUS_INVALID_PARAMETER)
        );
        assert!(directory.set_sd(b, security::null_dacl().unwrap()));
        assert_eq!(directory.dereference(a), None);
        assert_eq!(
            directory.security_descriptor(a),
            None,
            "a dead id names none"
        );
        assert_eq!(
            directory.set_security_descriptor(a, &sd),
            Err(crate::status::STATUS_INVALID_HANDLE)
        );
    }

    /// A create's captured (pending) descriptor lands on the object its allocation made, as a
    /// shared handle to the entry its bytes were logged into; with none captured, the kind's
    /// default goes on, one entry shared by every object of the kind.
    #[test]
    fn a_pending_sd_lands_on_the_next_allocated_object() {
        let directory = directory();
        let sd = test_sd(&user_sid(), &[allowed_ace(0x7, &user_sid())]);
        security::set_pending(sdcache::log(&sd));
        let id = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert_eq!(
            sd_bytes(&directory.security_descriptor(id).unwrap()),
            &sd[..]
        );
        assert_eq!(security::take_pending(), None, "the allocation took it");

        // A slot-pool kind too, and the kind's default when nothing is pending.
        security::set_pending(sdcache::log(&sd));
        let section = directory.create_section(SectionObject::none()).unwrap();
        assert_eq!(
            sd_bytes(&directory.security_descriptor(section).unwrap()),
            &sd[..]
        );
        let file = directory
            .create_file(crate::fs::file::Context::Null, 0, 0, 0)
            .unwrap();
        assert_eq!(
            sd_bytes(&directory.security_descriptor(file).unwrap()),
            sd_bytes(&security::default_sd(ObjectType::File).unwrap())
        );
        let process = directory.create_process().unwrap();
        assert_eq!(
            sd_bytes(&directory.security_descriptor(process).unwrap()),
            sd_bytes(&security::default_sd(ObjectType::Process).unwrap())
        );
        // The defaults collapse: every file shares one entry, every process another, and the
        // dispatcher kinds the NULL DACL's.
        let file2 = directory
            .create_file(crate::fs::file::Context::Null, 0, 0, 0)
            .unwrap();
        assert!(
            directory
                .security_descriptor(file2)
                .unwrap()
                .same(&directory.security_descriptor(file).unwrap()),
            "two files share the file default's entry"
        );
        let event = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        assert!(
            directory
                .security_descriptor(event)
                .unwrap()
                .same(&security::null_dacl().unwrap()),
            "the dispatcher kinds keep the NULL DACL"
        );
    }

    /// A key object carries its key's own descriptor when one was set on the key (through any of
    /// its objects), the type's default when none was — so a set through one handle governs the
    /// next open's grant, and a replaced set replaces the key's.
    #[test]
    fn a_key_object_carries_its_keys_descriptor() {
        let directory = directory();
        let key = crate::cm::Registry::empty().root();
        let default = security::default_sd(ObjectType::Key).unwrap();

        // Never set on: the type's default, one entry shared with the kind's other objects.
        let a = directory.create_key(crate::cm::KeyBody::of(key)).unwrap();
        assert!(directory.security_descriptor(a).unwrap().same(&default));

        // Set on one of its objects: the key's, and the objects later opens make carry it.
        let sd = test_sd(&user_sid(), &[allowed_ace(0x1, &user_sid())]);
        directory.set_security_descriptor(a, &sd).unwrap();
        let b = directory.create_key(crate::cm::KeyBody::of(key)).unwrap();
        assert_eq!(
            sd_bytes(&directory.security_descriptor(b).unwrap()),
            &sd[..]
        );
        assert!(
            directory
                .security_descriptor(b)
                .unwrap()
                .same(&directory.security_descriptor(a).unwrap()),
            "both objects share the one entry the set logged"
        );

        // Set again through the other object: the key's descriptor is replaced.
        let other = test_sd(&user_sid(), &[]);
        directory.set_security_descriptor(b, &other).unwrap();
        let c = directory.create_key(crate::cm::KeyBody::of(key)).unwrap();
        assert_eq!(
            sd_bytes(&directory.security_descriptor(c).unwrap()),
            &other[..]
        );

        // A key never set on keeps the default, and so does an object naming no key.
        let unkeyed = directory.create_key(crate::cm::KeyBody::none()).unwrap();
        assert!(directory
            .security_descriptor(unkeyed)
            .unwrap()
            .same(&default));
    }

    /// A handle's grant checks the object's own descriptor: two events, one with a deny-all DACL,
    /// one default, grant differently to the same subject.
    #[test]
    fn a_handle_grant_checks_the_objects_own_sd() {
        use crate::sec::CallerMode;
        let directory = directory();
        let open = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let locked = directory
            .create_event(EventKind::Notification, false)
            .unwrap();
        let deny_all = test_sd(
            &user_sid(),
            &[{
                use crate::sec::ACCESS_DENIED_ACE_TYPE;
                let mut v = vec![ACCESS_DENIED_ACE_TYPE, 0];
                let size = (4 + 4 + user_sid().len() + 3) & !3;
                v.extend_from_slice(&(size as u16).to_le_bytes());
                v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
                v.extend_from_slice(&user_sid());
                v.resize(size, 0);
                v
            }],
        );
        directory
            .set_security_descriptor(locked, &deny_all)
            .unwrap();

        let token = crate::se::TokenBody::of(ObjectId {
            kind: ObjectType::Process,
            index: 1,
            generation: 0,
        });
        let parts = grant::subject_parts(&token);
        let event = ObjectType::Event;
        use rtl::nt::access::GENERIC_ALL;
        assert_eq!(
            grant::check_with(
                &parts,
                event,
                GENERIC_ALL,
                &sd_bytes(&directory.security_descriptor(open).unwrap()),
                CallerMode::User
            ),
            Ok(event.granted(GENERIC_ALL)),
            "the default NULL DACL grants all"
        );
        assert_eq!(
            grant::check_with(
                &parts,
                event,
                GENERIC_ALL,
                &sd_bytes(&directory.security_descriptor(locked).unwrap()),
                CallerMode::User
            ),
            Err(crate::status::STATUS_ACCESS_DENIED)
        );
        // Kernel mode bypasses the descriptor.
        assert_eq!(
            grant::check_with(
                &parts,
                event,
                GENERIC_ALL,
                &sd_bytes(&directory.security_descriptor(locked).unwrap()),
                CallerMode::Kernel
            ),
            Ok(event.granted(GENERIC_ALL))
        );
    }
}
