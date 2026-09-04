//! IPC audit extension point.

use core::cmp::max;

use crate::sync::UPSafeCell;
use lazy_static::lazy_static;

use super::{IpcRequest, IpcResult};

/// Maximum number of events retained by the in-kernel audit log.
pub(crate) const AUDIT_RING_CAPACITY: usize = 256;

/// Maximum number of events returned by one audit read.
pub(crate) const AUDIT_READ_MAX_RECORDS: usize = 32;

/// Semantic audit event stored only inside the kernel.
///
/// `sequence == 0` is used for empty array slots. Slot validity is determined
/// by [`AuditRing::head`] and [`AuditRing::len`], not by this sentinel value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuditEvent {
    pub(crate) sequence: u64,//第几条事件
    pub(crate) timestamp_ms: u64,//发生时间
    pub(crate) operation: u16,//操作类型
    pub(crate) errno: i32,//失败原因，成功为0
    pub(crate) subject_pid: u64,//发起请求的进程id
    pub(crate) subject_uid: u32,//发起请求的用户id
    pub(crate) object_id: u64,//请求的对象id
    pub(crate) object_owner_uid: u32,//请求对象的所有者id
    pub(crate) requested_amount: u64,//请求的资源量
    pub(crate) result_value: u64,//请求的结果值
}

impl AuditEvent {
    /// Empty value used to initialize the fixed-size ring and snapshot arrays.
    pub(crate) const EMPTY: Self = Self {
        sequence: 0,
        timestamp_ms: 0,
        operation: 0,
        errno: 0,
        subject_pid: 0,
        subject_uid: 0,
        object_id: 0,
        object_owner_uid: 0,
        requested_amount: 0,
        result_value: 0,
    };
}

/// A bounded, value-only snapshot of audit events.
///
/// The syscall layer will later convert these events into stable ABI records
/// and copy them to user memory after the audit ring borrow has been released.
#[derive(Clone, Copy)]
pub(crate) struct AuditBatch {
    pub(crate) events: [AuditEvent; AUDIT_READ_MAX_RECORDS],
    pub(crate) len: usize,
    pub(crate) gap_before: bool,
}

impl AuditBatch {
    const fn empty() -> Self {
        Self {
            events: [AuditEvent::EMPTY; AUDIT_READ_MAX_RECORDS],
            len: 0,
            gap_before: false,
        }
    }
}

/// A self-consistent value snapshot of the audit counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuditStatsSnapshot {
    pub(crate) capacity: u64,
    pub(crate) retained: u64,
    pub(crate) first_sequence: u64,
    pub(crate) next_sequence: u64,
    pub(crate) total_events: u64,
    pub(crate) successful_events: u64,
    pub(crate) failed_events: u64,
    pub(crate) overwritten_events: u64,
}

/// Fixed-capacity ring buffer containing the most recent audit events.
struct AuditRing {
    events: [AuditEvent; AUDIT_RING_CAPACITY],
    /// Array index of the oldest retained event.
    head: usize,
    /// Number of valid events currently retained.
    len: usize,
    /// Sequence number assigned to the next accepted event.
    next_sequence: u64,
    total_events: u64,
    successful_events: u64,
    failed_events: u64,
    overwritten_events: u64,
}

impl AuditRing {
    const fn new() -> Self {
        Self {
            events: [AuditEvent::EMPTY; AUDIT_RING_CAPACITY],
            head: 0,
            len: 0,
            next_sequence: 1,
            total_events: 0,
            successful_events: 0,
            failed_events: 0,
            overwritten_events: 0,
        }
    }

    /// Append one event, overwriting the oldest retained event when full.
    ///
    /// Sequence exhaustion is practically unreachable. If it does happen, the
    /// event is ignored rather than allowing sequence numbers to wrap or be
    /// reused. Audit failure must never change the result of the IPC operation.
    fn push(&mut self, mut event: AuditEvent) {
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            return;
        };
        event.sequence = self.next_sequence;
        self.next_sequence = next_sequence;

        if self.len < AUDIT_RING_CAPACITY {
            let index = (self.head + self.len) % AUDIT_RING_CAPACITY;
            self.events[index] = event;
            self.len += 1;
        } else {
            self.events[self.head] = event;
            self.head = (self.head + 1) % AUDIT_RING_CAPACITY;
            self.overwritten_events += 1;
        }

        self.total_events += 1;
        if event.errno == 0 {
            self.successful_events += 1;
        } else {
            self.failed_events += 1;
        }
    }

    /// Return the sequence of the oldest retained event.
    fn first_sequence(&self) -> u64 {
        if self.len == 0 {
            self.next_sequence
        } else {
            self.events[self.head].sequence
        }
    }

    /// Build a non-destructive snapshot of events newer than `after_sequence`.
    fn snapshot(&self, after_sequence: u64, requested_capacity: usize) -> AuditBatch {
        let limit = requested_capacity.min(AUDIT_READ_MAX_RECORDS);
        if limit == 0 || self.len == 0 || after_sequence == u64::MAX {
            return AuditBatch::empty();
        }

        // Safe because u64::MAX was handled above.
        let wanted_sequence = after_sequence + 1;
        let first_sequence = self.first_sequence();
        let start_sequence = max(wanted_sequence, first_sequence);

        if start_sequence >= self.next_sequence {
            return AuditBatch::empty();
        }

        let count = (self.next_sequence - start_sequence).min(limit as u64) as usize;
        let offset = (start_sequence - first_sequence) as usize;
        let mut batch = AuditBatch::empty();

        for batch_index in 0..count {
            let ring_index = (self.head + offset + batch_index) % AUDIT_RING_CAPACITY;
            batch.events[batch_index] = self.events[ring_index];
        }

        batch.len = count;
        batch.gap_before = wanted_sequence < first_sequence;
        batch
    }

    /// Return a self-consistent snapshot of all public audit counters.
    fn stats(&self) -> AuditStatsSnapshot {
        AuditStatsSnapshot {
            capacity: AUDIT_RING_CAPACITY as u64,
            retained: self.len as u64,
            first_sequence: self.first_sequence(),
            next_sequence: self.next_sequence,
            total_events: self.total_events,
            successful_events: self.successful_events,
            failed_events: self.failed_events,
            overwritten_events: self.overwritten_events,
        }
    }
}

lazy_static! {
    /// Global audit state for the current single-core kernel.
    static ref AUDIT_RING: UPSafeCell<AuditRing> =
        unsafe { UPSafeCell::new(AuditRing::new()) };
}

/// Return a bounded event snapshot without exposing the ring borrow.
pub(crate) fn snapshot(after_sequence: u64, requested_capacity: usize) -> AuditBatch {
    let ring = AUDIT_RING.exclusive_access();
    ring.snapshot(after_sequence, requested_capacity)
}

/// Return a value snapshot of the audit statistics.
pub(crate) fn stats() -> AuditStatsSnapshot {
    let ring = AUDIT_RING.exclusive_access();
    ring.stats()
}

/// Record the outcome of an IPC request.
///
/// This compatibility implementation is intentionally a no-op so the audit
/// feature can be developed without changing callers.
pub(crate) fn record(_request: &IpcRequest, _outcome: &IpcResult<usize>) {}
