//! Critical sections: the RTL_CRITICAL_SECTION protocol kernel32's Enter/Leave/TryEnter run, over
//! the structure's words as user code lays them out.
//!
//! Windows 2000's layout, 24 bytes: DebugInfo, LockCount, RecursionCount, OwningThread (the owner's
//! thread id), LockSemaphore (an auto-reset event handle, created on the first contention), and
//! SpinCount. LockCount is -1 when free and goes up by one for every entry — the owner's recursive
//! ones and each waiter's — so it is nonnegative after a leave exactly when someone waits.
//! Programs read RecursionCount and OwningThread directly.
//!
//! The protocol runs in user mode, as Windows 2000's ntdll runs it: Enter, TryEnter and Leave are
//! native exports (locked read-modify-writes on LockCount), and the kernel is entered only under
//! contention — an enter that finds another owner waits on the semaphore, and a leave that finds a
//! waiter counted signals it. The release hands the section over: the leave clears the owner and
//! leaves the waiter's count standing, and the woken waiter takes the section directly (no other
//! entrant can slip in, since LockCount stays nonnegative and every entrant then waits). The
//! methods here model those native bodies step for step (see `NATIVES` in `kernel32`).

/// The structure's size.
pub const SIZE: u32 = 24;

/// The words of an RTL_CRITICAL_SECTION.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Section {
    pub debug_info: u32,
    pub lock_count: i32,
    pub recursion_count: i32,
    pub owning_thread: u32,
    pub lock_semaphore: u32,
    pub spin_count: u32,
}

/// What an enter did.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Enter {
    /// The caller owns the section.
    Acquired,
    /// Another thread owns it: the caller is counted as a waiter and must wait on the semaphore,
    /// then take the section the leave hands it ([`Section::take`]).
    Wait,
}

impl Section {
    /// InitializeCriticalSection's state: free, no semaphore yet.
    pub const fn initialized() -> Section {
        Section {
            debug_info: 0,
            lock_count: -1,
            recursion_count: 0,
            owning_thread: 0,
            lock_semaphore: 0,
            spin_count: 0,
        }
    }

    pub fn from_bytes(bytes: &[u8; SIZE as usize]) -> Section {
        let word =
            |index: usize| u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
        Section {
            debug_info: word(0),
            lock_count: word(1) as i32,
            recursion_count: word(2) as i32,
            owning_thread: word(3),
            lock_semaphore: word(4),
            spin_count: word(5),
        }
    }

    pub fn to_bytes(self) -> [u8; SIZE as usize] {
        let words = [
            self.debug_info,
            self.lock_count as u32,
            self.recursion_count as u32,
            self.owning_thread,
            self.lock_semaphore,
            self.spin_count,
        ];
        let mut bytes = [0; SIZE as usize];
        for (index, word) in words.iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// EnterCriticalSection's native body by thread `thread`: count the entry; the first acquires,
    /// the owner's re-enters, anyone else's is a waiter, which waits on the semaphore and then
    /// [`take`](Section::take)s the section the leave hands it.
    #[cfg(test)]
    pub fn enter(&mut self, thread: u32) -> Enter {
        self.lock_count = self.lock_count.wrapping_add(1);
        if self.lock_count == 0 {
            self.owning_thread = thread;
            self.recursion_count = 1;
            Enter::Acquired
        } else if self.owning_thread == thread {
            self.recursion_count = self.recursion_count.wrapping_add(1);
            Enter::Acquired
        } else {
            Enter::Wait
        }
    }

    /// A woken waiter's take: the leave handed it the section, its entry already counted.
    pub fn take(&mut self, thread: u32) {
        self.owning_thread = thread;
        self.recursion_count = 1;
    }

    /// TryEnterCriticalSection's native body: acquire a free section (LockCount -1 to 0 in one
    /// compare-exchange), re-enter an owned one, or fail with no trace.
    #[cfg(test)]
    pub fn try_enter(&mut self, thread: u32) -> bool {
        if self.lock_count == -1 {
            self.lock_count = 0;
            self.owning_thread = thread;
            self.recursion_count = 1;
            true
        } else if self.owning_thread == thread {
            self.lock_count = self.lock_count.wrapping_add(1);
            self.recursion_count = self.recursion_count.wrapping_add(1);
            true
        } else {
            false
        }
    }

    /// LeaveCriticalSection's native body: drop one entry; the last clears the owner. True when the
    /// release must signal the semaphore (a waiter is counted). As on Windows the caller's
    /// ownership is not checked.
    #[cfg(test)]
    pub fn leave(&mut self) -> bool {
        self.recursion_count = self.recursion_count.wrapping_sub(1);
        if self.recursion_count != 0 {
            self.lock_count = self.lock_count.wrapping_sub(1);
            return false;
        }
        self.owning_thread = 0;
        self.lock_count = self.lock_count.wrapping_sub(1);
        self.lock_count >= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_round_trips() {
        let section = Section {
            debug_info: 1,
            lock_count: -1,
            recursion_count: 2,
            owning_thread: 8,
            lock_semaphore: 0x44,
            spin_count: 4000,
        };
        let bytes = section.to_bytes();
        assert_eq!(&bytes[4..8], &[0xFF; 4]);
        assert_eq!(&bytes[12..16], &8u32.to_le_bytes());
        assert_eq!(Section::from_bytes(&bytes), section);
    }

    /// Recursive entries count up and leave in turn; the last leave frees it, with no waiter to
    /// signal.
    #[test]
    fn recursion() {
        let mut section = Section::initialized();
        assert_eq!(section.enter(8), Enter::Acquired);
        assert_eq!(section.enter(8), Enter::Acquired);
        assert!(section.try_enter(8));
        assert_eq!(
            (
                section.recursion_count,
                section.owning_thread,
                section.lock_count
            ),
            (3, 8, 2)
        );
        assert!(!section.leave());
        assert!(!section.leave());
        assert!(!section.leave());
        assert_eq!(section, Section::initialized());
    }

    /// Another thread's try fails and leaves no trace; its enter is counted as a waiter, the
    /// owner's leave signals and hands over, and the woken waiter takes the section.
    #[test]
    fn contention_hands_the_section_over() {
        let mut section = Section::initialized();
        assert_eq!(section.enter(8), Enter::Acquired);
        assert!(!section.try_enter(12));
        assert_eq!(section.lock_count, 0);
        assert_eq!(section.enter(12), Enter::Wait);
        assert_eq!(section.enter(16), Enter::Wait);
        assert_eq!(section.lock_count, 2);
        assert!(section.leave(), "two waiters");
        assert_eq!(section.owning_thread, 0);
        section.take(12);
        assert!(section.leave(), "one waiter left");
        section.take(16);
        assert!(!section.leave());
        assert_eq!(section, Section::initialized());
    }

    /// Between the leave and the woken waiter's take nobody slips in: the section reads unowned,
    /// but an entrant is counted as one more waiter and a try fails.
    #[test]
    fn no_entrant_slips_into_a_handover() {
        let mut section = Section::initialized();
        section.enter(8);
        assert_eq!(section.enter(12), Enter::Wait);
        assert!(section.leave());
        assert!(!section.try_enter(16), "the try fails");
        assert_eq!(section.enter(16), Enter::Wait, "the entrant waits");
        section.take(12);
        assert!(section.leave(), "the entrant is signaled next");
        section.take(16);
        assert!(!section.leave());
        assert_eq!(section, Section::initialized());
    }
}
