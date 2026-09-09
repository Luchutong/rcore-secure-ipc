//! D+C integration coverage for real pipe creation and quota-denial events.

#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::audit::{self, AUDIT_OP_PIPE_CREATE, AuditRecordV1, ENOSPC, IpcStatsV1};
use user_lib::{close, getpid, pipe};

const PIPE_LIMIT: usize = 8;

fn stats() -> IpcStatsV1 {
    let mut value = IpcStatsV1::default();
    assert_eq!(audit::stat(&mut value), 0);
    value
}

fn read_since(cursor: u64, records: &mut [AuditRecordV1]) -> usize {
    let result = audit::read(records, cursor);
    assert!(result >= 0);
    result as usize
}

fn assert_pipe_event(record: &AuditRecordV1, succeeded: bool) {
    assert_eq!(record.operation, AUDIT_OP_PIPE_CREATE);
    assert_eq!(record.subject_pid, getpid() as u64);
    assert_eq!(record.object_id, 0);
    assert_eq!(record.requested_amount, 1);
    assert_eq!(record.result_value, if succeeded { 1 } else { 0 });
    assert_eq!(record.errno, if succeeded { 0 } else { ENOSPC });
}

fn test_successful_pipe_event() {
    let before = stats();
    let cursor = before.next_sequence - 1;
    let mut pair = [0usize; 2];
    assert_eq!(pipe(&mut pair), 0);

    let mut records = [AuditRecordV1::default(); 2];
    let count = read_since(cursor, &mut records);
    assert_eq!(count, 1);
    assert_pipe_event(&records[0], true);

    let after = stats();
    assert_eq!(after.total_events, before.total_events + 1);
    assert_eq!(after.successful_events, before.successful_events + 1);
    assert_eq!(after.failed_events, before.failed_events);

    assert_eq!(close(pair[0]), 0);
    assert_eq!(close(pair[1]), 0);
}

fn test_quota_denial_event_and_recovery() {
    let before = stats();
    let cursor = before.next_sequence - 1;
    let mut pipes = [[0usize; 2]; PIPE_LIMIT];

    for pair in &mut pipes {
        assert_eq!(pipe(pair), 0);
    }

    let mut rejected = [usize::MAX; 2];
    assert_eq!(pipe(&mut rejected), -(ENOSPC as isize));
    assert_eq!(rejected, [usize::MAX; 2]);

    let mut records = [AuditRecordV1::default(); PIPE_LIMIT + 2];
    let count = read_since(cursor, &mut records);
    assert_eq!(count, PIPE_LIMIT + 1);
    for record in &records[..PIPE_LIMIT] {
        assert_pipe_event(record, true);
    }
    assert_pipe_event(&records[PIPE_LIMIT], false);

    let denied = stats();
    assert_eq!(
        denied.total_events,
        before.total_events + PIPE_LIMIT as u64 + 1
    );
    assert_eq!(
        denied.successful_events,
        before.successful_events + PIPE_LIMIT as u64
    );
    assert_eq!(denied.failed_events, before.failed_events + 1);

    // Releasing one complete pipe must make a new creation possible. This
    // also proves that the failed reservation did not leave quota charged.
    assert_eq!(close(pipes[0][0]), 0);
    assert_eq!(close(pipes[0][1]), 0);
    let recovery_cursor = denied.next_sequence - 1;
    assert_eq!(pipe(&mut rejected), 0);

    let mut recovery = [AuditRecordV1::default(); 1];
    assert_eq!(read_since(recovery_cursor, &mut recovery), 1);
    assert_pipe_event(&recovery[0], true);

    assert_eq!(close(rejected[0]), 0);
    assert_eq!(close(rejected[1]), 0);
    for pair in pipes.iter().skip(1) {
        assert_eq!(close(pair[0]), 0);
        assert_eq!(close(pair[1]), 0);
    }
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    test_successful_pipe_event();
    test_quota_denial_event_and_recovery();
    println!("ipc_audit_integration_test passed!");
    0
}
