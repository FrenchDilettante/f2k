//! The per-process commit charge: what committing memory costs against the process's commit
//! limit, as plain arithmetic.
//!
//! A commit is charged against a limit — the system's memory plus its backing store — and the
//! frames come later, on first touch. [`CommitQuota`] holds the charged bytes and the limit: a
//! charge that would carry the total past the limit is refused with STATUS_COMMITMENT_LIMIT and
//! changes nothing, a discharge returns charge, and the room left is the limit minus what is
//! charged. The per-process instance and the wiring into the allocate path are not here yet.

use crate::status::{NtStatus, STATUS_COMMITMENT_LIMIT};

/// A process's commit charge: the bytes charged so far, against a limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitQuota {
    charged: u64,
    limit: u64,
}

impl CommitQuota {
    /// A quota with nothing charged against `limit` bytes.
    pub const fn new(limit: u64) -> Self {
        CommitQuota { charged: 0, limit }
    }

    /// The bytes charged so far.
    pub const fn charged(&self) -> u64 {
        self.charged
    }

    /// The limit the charge is counted against.
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// The room left: the limit minus the charged bytes.
    pub const fn available(&self) -> u64 {
        self.limit.saturating_sub(self.charged)
    }

    /// Charge `bytes`: counted, and `Ok(())`, when it fits under the limit — a charge that
    /// overflows the counter is past any limit; refused with the commitment-limit status, and
    /// no change, when it would carry the total past the limit.
    pub fn charge(&mut self, bytes: u64) -> Result<(), NtStatus> {
        match self.charged.checked_add(bytes) {
            Some(total) if total <= self.limit => {
                self.charged = total;
                Ok(())
            }
            _ => Err(STATUS_COMMITMENT_LIMIT),
        }
    }

    /// Return `bytes` of charge; discharging more than is charged returns all of it.
    pub fn discharge(&mut self, bytes: u64) {
        self.charged = self.charged.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh quota has nothing charged and the whole limit available.
    #[test]
    fn a_fresh_quota_has_the_whole_limit_available() {
        let quota = CommitQuota::new(1024);
        assert_eq!(quota.charged(), 0);
        assert_eq!(quota.limit(), 1024);
        assert_eq!(quota.available(), 1024);
    }

    /// Charging up to the limit succeeds, exactly at the limit included, in one step or many.
    #[test]
    fn charging_up_to_the_limit_succeeds() {
        let mut quota = CommitQuota::new(4096);
        assert!(quota.charge(4096).is_ok());
        assert_eq!(quota.charged(), 4096);
        assert_eq!(quota.available(), 0);

        let mut quota = CommitQuota::new(4096);
        assert!(quota.charge(1000).is_ok());
        assert!(quota.charge(3000).is_ok());
        assert!(quota.charge(96).is_ok());
        assert_eq!(quota.charged(), 4096);
        assert_eq!(quota.available(), 0);
    }

    /// A charge past the limit is refused with STATUS_COMMITMENT_LIMIT and changes nothing.
    #[test]
    fn a_charge_past_the_limit_is_refused_with_the_commitment_limit_status() {
        assert_eq!(STATUS_COMMITMENT_LIMIT.0, 0xC000_012D);

        let mut quota = CommitQuota::new(4096);
        assert!(quota.charge(4096).is_ok());
        assert!(quota.charge(1) == Err(STATUS_COMMITMENT_LIMIT));
        assert_eq!(quota.charged(), 4096);
        assert_eq!(quota.available(), 0);

        let mut quota = CommitQuota::new(10);
        assert!(quota.charge(11) == Err(STATUS_COMMITMENT_LIMIT));
        assert_eq!(quota.charged(), 0);
        assert_eq!(quota.available(), 10);
    }

    /// A discharge returns charge and restores the room it freed.
    #[test]
    fn a_discharge_restores_availability() {
        let mut quota = CommitQuota::new(4096);
        assert!(quota.charge(4096).is_ok());
        quota.discharge(1024);
        assert_eq!(quota.charged(), 3072);
        assert_eq!(quota.available(), 1024);
    }

    /// Discharging more than is charged returns the whole charge.
    #[test]
    fn a_discharge_past_the_charge_returns_everything() {
        let mut quota = CommitQuota::new(4096);
        assert!(quota.charge(100).is_ok());
        quota.discharge(1000);
        assert_eq!(quota.charged(), 0);
        assert_eq!(quota.available(), 4096);
    }

    /// A zero-size charge always succeeds and changes nothing, at the limit too.
    #[test]
    fn a_zero_charge_always_succeeds() {
        let mut quota = CommitQuota::new(8);
        assert!(quota.charge(0).is_ok());
        assert_eq!(quota.charged(), 0);
        assert!(quota.charge(8).is_ok());
        assert!(quota.charge(0).is_ok());
        assert_eq!(quota.charged(), 8);
        assert_eq!(quota.available(), 0);
    }

    /// A charge that would overflow the counter is past any limit: refused, no wraparound.
    #[test]
    fn an_overflowing_charge_is_refused_without_wrapping() {
        let mut quota = CommitQuota::new(u64::MAX);
        assert!(quota.charge(u64::MAX).is_ok());
        assert!(quota.charge(1) == Err(STATUS_COMMITMENT_LIMIT));
        assert_eq!(quota.charged(), u64::MAX);

        let mut quota = CommitQuota::new(u64::MAX);
        assert!(quota.charge(u64::MAX - 1).is_ok());
        assert_eq!(quota.available(), 1);
        assert!(quota.charge(2) == Err(STATUS_COMMITMENT_LIMIT));
        assert_eq!(quota.charged(), u64::MAX - 1);
    }

    /// Charge after discharge spends the returned room, and no more.
    #[test]
    fn a_charge_after_a_discharge_spends_the_returned_room() {
        let mut quota = CommitQuota::new(4096);
        assert!(quota.charge(4096).is_ok());
        assert!(quota.charge(1) == Err(STATUS_COMMITMENT_LIMIT));
        quota.discharge(2048);
        assert!(quota.charge(2048).is_ok());
        assert!(quota.charge(1) == Err(STATUS_COMMITMENT_LIMIT));
        assert_eq!(quota.charged(), 4096);
        assert_eq!(quota.available(), 0);
    }

    /// A zero limit refuses every non-zero charge.
    #[test]
    fn a_zero_limit_refuses_every_charge() {
        let mut quota = CommitQuota::new(0);
        assert!(quota.charge(0).is_ok());
        assert!(quota.charge(1) == Err(STATUS_COMMITMENT_LIMIT));
        assert_eq!(quota.charged(), 0);
        assert_eq!(quota.available(), 0);
    }
}
