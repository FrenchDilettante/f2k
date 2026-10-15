//! The console's input queue, and the bounded ring it is built on.
//!
//! A [`Ring`] holds up to `N` values first-in first-out; a push into a full ring drops the value
//! and counts it (input that arrives faster than anything reads it is lost, not stalled on). The
//! keyboard's interrupt path uses one for raw scancodes; the console keeps one of key events.

use super::keyboard::KeyEvent;

/// How many key events the console queues before dropping.
pub const INPUT_CAPACITY: usize = 64;

/// A bounded first-in first-out ring (see the module doc).
pub struct Ring<T: Copy, const N: usize> {
    slots: [T; N],
    /// The oldest value's slot.
    head: usize,
    len: usize,
    /// Values dropped because the ring was full.
    dropped: u32,
}

impl<T: Copy, const N: usize> Ring<T, N> {
    /// An empty ring; `fill` only initializes the unused slots.
    pub const fn new(fill: T) -> Self {
        Self {
            slots: [fill; N],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    /// Append `value`; false (and counted) when the ring is full.
    pub fn push(&mut self, value: T) -> bool {
        if self.len == N {
            self.dropped = self.dropped.wrapping_add(1);
            return false;
        }
        self.slots[(self.head + self.len) % N] = value;
        self.len += 1;
        true
    }

    /// Take the oldest value.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let value = self.slots[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(value)
    }
}

/// The console's key-event queue.
pub type InputQueue = Ring<KeyEvent, INPUT_CAPACITY>;

/// An empty key-event queue.
pub const fn input_queue() -> InputQueue {
    Ring::new(KeyEvent {
        key_down: false,
        virtual_key: 0,
        scan_code: 0,
        character: 0,
        control_state: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_come_out_in_order() {
        let mut ring: Ring<u8, 4> = Ring::new(0);
        assert!(ring.push(1));
        assert!(ring.push(2));
        assert_eq!(ring.pop(), Some(1));
        assert!(ring.push(3));
        assert_eq!(ring.len, 2);
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), Some(3));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn a_full_ring_drops_and_counts() {
        let mut ring: Ring<u8, 2> = Ring::new(0);
        assert!(ring.push(1));
        assert!(ring.push(2));
        assert!(!ring.push(3));
        assert!(!ring.push(4));
        assert_eq!(ring.dropped, 2);
        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn the_ring_wraps_around() {
        let mut ring: Ring<u8, 3> = Ring::new(0);
        for round in 0..10u8 {
            assert!(ring.push(round));
            assert!(ring.push(round + 100));
            assert_eq!(ring.pop(), Some(round));
            assert_eq!(ring.pop(), Some(round + 100));
        }
        assert_eq!(ring.len, 0);
        assert_eq!(ring.dropped, 0);
    }

    #[test]
    fn the_input_queue_holds_its_capacity() {
        let mut queue = input_queue();
        let mut event = queue.slots[0];
        for i in 0..INPUT_CAPACITY {
            event.virtual_key = i as u16;
            assert!(queue.push(event));
        }
        assert!(!queue.push(event));
        assert_eq!(queue.pop().unwrap().virtual_key, 0);
    }
}
