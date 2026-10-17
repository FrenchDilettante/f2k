//! The process environment's variables: what SetEnvironmentVariableA writes and
//! GetEnvironmentVariableA reads.
//!
//! The store is the environment block's own shape — `NAME=value` entries, each NUL-terminated,
//! packed one after another — in a fixed buffer inside the process record. Names compare without
//! regard to ASCII case (the platform upcases names for the comparison and keeps the spelling it
//! was given). Setting a variable replaces its entry (at the end of the block); setting it to
//! nothing deletes it.
//!
//! The block the startup replay hands the CRT (GetEnvironmentStrings) is still the replayed empty
//! one: the variables set here are not yet reflected there.

/// The store's capacity in bytes, entries and their terminators included.
pub const ENVIRONMENT_BYTES: usize = 8192;

/// A set the store cannot take.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvironmentError {
    /// The name is empty or carries an `=` past its first character.
    InvalidName,
    /// The entry does not fit.
    Full,
}

/// The variables. All zeros is the empty store.
pub struct Environment {
    bytes: [u8; ENVIRONMENT_BYTES],
    used: usize,
}

impl Environment {
    /// The empty store (the tests build processes by value; the kernel writes zeros in place).
    #[cfg(test)]
    pub const fn empty() -> Self {
        Environment {
            bytes: [0; ENVIRONMENT_BYTES],
            used: 0,
        }
    }

    /// The entries, without their terminators.
    fn entries(&self) -> impl Iterator<Item = (usize, &[u8])> {
        let mut offset = 0;
        core::iter::from_fn(move || {
            if offset >= self.used {
                return None;
            }
            let start = offset;
            let length = self.bytes[start..self.used].iter().position(|&b| b == 0)?;
            offset = start + length + 1;
            Some((start, &self.bytes[start..start + length]))
        })
    }

    /// The entry naming `name`: its offset and its bytes.
    fn find(&self, name: &[u8]) -> Option<(usize, &[u8])> {
        self.entries().find(|(_, entry)| {
            // An entry's name ends at its first `=` past the first character (a leading `=` is
            // part of the name, as in the drive-directory entries).
            let split = entry.iter().skip(1).position(|&b| b == b'=').map(|i| i + 1);
            split.is_some_and(|split| entry[..split].eq_ignore_ascii_case(name))
        })
    }

    /// The value of `name`, if set.
    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.find(name).map(|(_, entry)| &entry[name.len() + 1..])
    }

    /// Set `name` to a value of `length` bytes, returned for the caller to fill in place (the
    /// value is copied from user memory straight into the store). The old entry goes only once the
    /// new one is known to fit.
    pub fn reserve(&mut self, name: &[u8], length: usize) -> Result<&mut [u8], EnvironmentError> {
        if name.is_empty() || name[1..].contains(&b'=') || name.contains(&0) {
            return Err(EnvironmentError::InvalidName);
        }
        let existing = self.find(name).map(|(offset, entry)| (offset, entry.len() + 1));
        let freed = existing.map_or(0, |(_, length)| length);
        let needed = name.len() + 1 + length + 1;
        if self.used - freed + needed > ENVIRONMENT_BYTES {
            return Err(EnvironmentError::Full);
        }
        if let Some((offset, length)) = existing {
            self.remove(offset, length);
        }
        let start = self.used;
        self.bytes[start..start + name.len()].copy_from_slice(name);
        self.bytes[start + name.len()] = b'=';
        let value_start = start + name.len() + 1;
        self.bytes[value_start + length] = 0;
        self.used += needed;
        Ok(&mut self.bytes[value_start..value_start + length])
    }

    /// Set `name` to `value`, or delete it for none (deleting an unset name succeeds).
    pub fn set(&mut self, name: &[u8], value: Option<&[u8]>) -> Result<(), EnvironmentError> {
        if name.is_empty() || name[1..].contains(&b'=') || name.contains(&0) {
            return Err(EnvironmentError::InvalidName);
        }
        let existing = self.find(name).map(|(offset, entry)| (offset, entry.len() + 1));
        let Some(value) = value else {
            if let Some((offset, length)) = existing {
                self.remove(offset, length);
            }
            return Ok(());
        };
        if value.contains(&0) {
            return Err(EnvironmentError::Full);
        }
        self.reserve(name, value.len())?.copy_from_slice(value);
        Ok(())
    }

    fn remove(&mut self, offset: usize, length: usize) {
        self.bytes.copy_within(offset + length..self.used, offset);
        self.used -= length;
        self.bytes[self.used..self.used + length].fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Box<Environment> {
        Box::new(Environment::empty())
    }

    /// The runtime capture's sequence: set, read back by either case, replace, delete.
    #[test]
    fn a_variable_sets_replaces_and_deletes() {
        let mut env = store();
        env.set(b"F2KTEST", Some(b"first")).unwrap();
        assert_eq!(env.get(b"F2KTEST"), Some(&b"first"[..]));
        env.set(b"OTHER", Some(b"x")).unwrap();
        env.set(b"F2KTEST", Some(b"second value")).unwrap();
        assert_eq!(env.get(b"f2ktest"), Some(&b"second value"[..]));
        assert_eq!(env.get(b"OTHER"), Some(&b"x"[..]));
        env.set(b"F2KTEST", None).unwrap();
        assert_eq!(env.get(b"F2KTEST"), None);
        assert_eq!(env.get(b"OTHER"), Some(&b"x"[..]), "the other entry survives the delete");
        env.set(b"NOSUCH", None).unwrap();
        // A prefix is not a match, nor is an empty value a deletion.
        env.set(b"AB", Some(b"")).unwrap();
        assert_eq!(env.get(b"A"), None);
        assert_eq!(env.get(b"AB"), Some(&b""[..]));
    }

    /// Names: empty or carrying an `=` past the first character are refused; a leading `=` is
    /// part of the name.
    #[test]
    fn names_are_validated() {
        let mut env = store();
        assert_eq!(env.set(b"", Some(b"v")), Err(EnvironmentError::InvalidName));
        assert_eq!(env.set(b"A=B", Some(b"v")), Err(EnvironmentError::InvalidName));
        env.set(b"=C:", Some(b"C:\\")).unwrap();
        assert_eq!(env.get(b"=c:"), Some(&b"C:\\"[..]));
    }

    /// The capacity: an entry that does not fit is refused and the store is unchanged.
    #[test]
    fn the_store_fills() {
        let mut env = store();
        let big = [b'v'; ENVIRONMENT_BYTES - 8];
        env.set(b"BIG", Some(&big)).unwrap();
        assert_eq!(env.set(b"MORE", Some(b"xyz")), Err(EnvironmentError::Full));
        assert_eq!(env.get(b"BIG").map(<[u8]>::len), Some(big.len()));
        env.set(b"BIG", Some(b"small")).unwrap();
        env.set(b"MORE", Some(b"xyz")).unwrap();
    }
}
