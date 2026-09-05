//! 复用真实 CLI 和用户 API，替换 ecall 与终端输出以验证分页和错误边界。

extern crate self as user_lib;

#[path = "../../user/src/audit.rs"]
pub mod audit;
#[path = "../../user/src/bin/auditctl.rs"]
mod auditctl;

use audit::{AuditRecordV1, IpcStatsV1};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::{Arguments, Write};

enum Reply {
    Stat(isize, IpcStatsV1),
    Read(u64, isize, Vec<AuditRecordV1>),
}

thread_local! {
    static REPLIES: RefCell<VecDeque<Reply>> = RefCell::default();
    static OUTPUT: RefCell<String> = RefCell::default();
}

pub fn output(args: Arguments<'_>) {
    OUTPUT.with(|output| output.borrow_mut().write_fmt(args).unwrap());
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::output(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => { $crate::output(format_args!("{}\n", format_args!($($arg)*))) };
}

mod syscall {
    use super::*;

    pub fn sys_ipc_stat(stats: *mut IpcStatsV1, size: usize, flags: usize) -> isize {
        assert_eq!(size, 80);
        assert_eq!(flags, 0);
        REPLIES.with(|replies| match replies.borrow_mut().pop_front().unwrap() {
            Reply::Stat(result, value) => {
                // 指针来自真实 audit::stat(&mut stats)，有效到调用返回。
                unsafe { stats.write(value) };
                result
            }
            _ => panic!("unexpected stat call"),
        })
    }

    pub fn sys_audit_read(records: *mut AuditRecordV1, capacity: usize, after: u64) -> isize {
        assert_eq!(capacity, 32);
        REPLIES.with(|replies| match replies.borrow_mut().pop_front().unwrap() {
            Reply::Read(expected_cursor, result, values) => {
                assert_eq!(after, expected_cursor);
                assert!(values.len() <= capacity);
                // 允许负返回前写入前缀，检查 CLI 是否错误地展示这批失败数据。
                for (index, value) in values.into_iter().enumerate() {
                    unsafe { records.add(index).write(value) };
                }
                result
            }
            _ => panic!("unexpected read call"),
        })
    }
}

fn stats(first: u64, next: u64) -> IpcStatsV1 {
    IpcStatsV1 {
        abi_version: 1,
        struct_size: 80,
        capacity: 256,
        retained: next - first,
        first_sequence: first,
        next_sequence: next,
        total_events: next - 1,
        successful_events: next - 1,
        overwritten_events: first - 1,
        ..Default::default()
    }
}

fn record(sequence: u64) -> AuditRecordV1 {
    AuditRecordV1 {
        abi_version: 1,
        record_size: 80,
        sequence,
        timestamp_ms: 1234,
        subject_pid: 7,
        subject_uid: 42,
        operation: audit::AUDIT_OP_PIPE_READ,
        object_id: 99,
        object_owner_uid: audit::AUDIT_UID_UNKNOWN,
        requested_amount: 100,
        result_value: 60,
        ..Default::default()
    }
}

fn run(args: &[&str], replies: Vec<Reply>, expected_exit: i32) -> String {
    REPLIES.with(|pending| *pending.borrow_mut() = replies.into());
    OUTPUT.with(|output| output.borrow_mut().clear());
    assert_eq!(auditctl::main(args.len(), args), expected_exit);
    REPLIES.with(|pending| assert!(pending.borrow().is_empty()));
    OUTPUT.with(|output| output.borrow().clone())
}

#[test]
fn help_and_invalid_arguments_never_call_the_kernel() {
    for option in ["help", "--help", "-h"] {
        assert!(run(&["auditctl", option], vec![], 0).contains("Usage:"));
    }
    for args in [
        vec![],
        vec!["auditctl"],
        vec!["auditctl", "unknown"],
        vec!["auditctl", "stat", "extra"],
        vec!["auditctl", "read", "0", "extra"],
    ] {
        assert!(run(&args, vec![], 2).contains("Usage:"));
    }
    for cursor in ["", "-1", "+1", "0x10", "1x", "18446744073709551616"] {
        assert!(run(&["auditctl", "read", cursor], vec![], 2).contains("invalid after_sequence"));
    }
}

#[test]
fn stat_prints_all_counters_and_sequence_bounds() {
    let mut value = stats(101, 110);
    value.successful_events = 100;
    value.failed_events = 9;
    let text = run(&["auditctl", "stat"], vec![Reply::Stat(0, value)], 0);
    for expected in [
        "capacity=256 retained=9",
        "total_events=109 successful_events=100 failed_events=9 overwritten_events=100",
        "first_sequence=101 next_sequence=110",
    ] {
        assert!(text.contains(expected), "{text}");
    }
}

#[test]
fn incompatible_stats_and_inconsistent_counters_are_rejected() {
    let valid = stats(1, 2);
    for value in [
        IpcStatsV1 {
            abi_version: 2,
            ..valid
        },
        IpcStatsV1 {
            struct_size: 72,
            ..valid
        },
        IpcStatsV1 {
            retained: 257,
            ..valid
        },
        IpcStatsV1 {
            failed_events: 1,
            ..valid
        },
        IpcStatsV1 {
            successful_events: u64::MAX,
            failed_events: 2,
            ..valid
        },
        IpcStatsV1 {
            first_sequence: 0,
            ..valid
        },
        IpcStatsV1 {
            next_sequence: 0,
            ..valid
        },
    ] {
        run(&["auditctl", "read"], vec![Reply::Stat(0, value)], 1);
    }
    run(&["auditctl", "stat"], vec![Reply::Stat(1, valid)], 1);
}

#[test]
fn stat_errors_report_errno_without_using_output() {
    for (result, name) in [
        (-1, "EPERM"),
        (-14, "EFAULT"),
        (-22, "EINVAL"),
        (-99, "UNKNOWN"),
        (isize::MIN, "UNKNOWN"),
    ] {
        let text = run(
            &["auditctl", "stat"],
            vec![Reply::Stat(result, stats(1, 2))],
            1,
        );
        assert!(text.contains(name));
        assert!(!text.contains("capacity="));
    }
}

#[test]
fn empty_tail_and_maximum_cursor_do_not_read() {
    for (args, snapshot) in [
        (vec!["auditctl", "read"], stats(1, 1)),
        (vec!["auditctl", "read", "5"], stats(1, 6)),
        (
            vec!["auditctl", "read", "18446744073709551615"],
            stats(1, 6),
        ),
    ] {
        assert!(run(&args, vec![Reply::Stat(0, snapshot)], 0).contains("records=0"));
    }
}

#[test]
fn paginates_more_than_32_records_and_keeps_reading_short_batches() {
    let text = run(
        &["auditctl", "read", "10"],
        vec![
            Reply::Stat(0, stats(1, 46)),
            Reply::Read(10, 32, (11..=42).map(record).collect()),
            Reply::Read(42, 1, vec![record(43)]),
            Reply::Read(43, 2, vec![record(44), record(45)]),
        ],
        0,
    );
    assert_eq!(
        text.lines().filter(|line| line.starts_with("seq=")).count(),
        35
    );
    assert!(text.contains("records=35 cursor=45 through=45"));
}

#[test]
fn events_after_initial_tail_do_not_extend_command() {
    let text = run(
        &["auditctl", "read"],
        vec![
            Reply::Stat(0, stats(1, 3)),
            Reply::Read(0, 3, vec![record(1), record(2), record(3)]),
        ],
        0,
    );
    assert!(text.contains("seq=2 "));
    assert!(!text.contains("seq=3 "));
    assert!(text.contains("records=2 cursor=2 through=2"));
}

#[test]
fn gap_unknown_operation_flags_and_errno_are_displayed_without_panicking() {
    let first = AuditRecordV1 {
        flags: 0x8001,
        operation: 77,
        ..record(8)
    };
    let second = AuditRecordV1 {
        errno: 99,
        result_value: 0,
        object_owner_uid: 0,
        ..record(9)
    };
    let text = run(
        &["auditctl", "read"],
        vec![
            Reply::Stat(0, stats(8, 10)),
            Reply::Read(0, 2, vec![first, second]),
        ],
        0,
    );
    for expected in [
        "GAP_BEFORE before sequence 8",
        "time_ms=1234 pid=7 uid=42",
        "op=unknown(77)",
        "object_id=99 owner_uid=unknown",
        "requested=100 result=60 status=OK",
        "owner_uid=0",
        "status=ERROR errno=99(UNKNOWN)",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    assert_eq!(text.matches("GAP_BEFORE").count(), 1);
}

#[test]
fn reports_gap_even_if_all_initial_events_have_been_overwritten() {
    let later = AuditRecordV1 {
        flags: 1,
        ..record(100)
    };
    let text = run(
        &["auditctl", "read"],
        vec![Reply::Stat(0, stats(1, 3)), Reply::Read(0, 1, vec![later])],
        0,
    );
    assert!(text.contains("GAP_BEFORE"));
    assert!(!text.contains("seq=100 "));
    assert!(text.contains("records=0 cursor=0 through=2"));
}

#[test]
fn failed_batch_discards_partial_copy_and_preserves_last_successful_cursor() {
    let text = run(
        &["auditctl", "read"],
        vec![
            Reply::Stat(0, stats(1, 4)),
            Reply::Read(0, 1, vec![record(1)]),
            Reply::Read(1, -14, vec![record(2)]),
        ],
        1,
    );
    assert!(text.contains("seq=1 "));
    assert!(!text.contains("seq=2 "));
    assert!(text.contains("EFAULT"));
    assert!(text.contains("retry with: auditctl read 1"));
}

#[test]
fn invalid_counts_and_records_cannot_panic_or_repeat_forever() {
    run(
        &["auditctl", "read"],
        vec![Reply::Stat(0, stats(1, 3)), Reply::Read(0, 33, vec![])],
        1,
    );
    for second in [
        record(1),
        record(0),
        AuditRecordV1 {
            abi_version: 2,
            ..record(2)
        },
        AuditRecordV1 {
            record_size: 72,
            ..record(2)
        },
        AuditRecordV1 {
            errno: -1,
            ..record(2)
        },
        AuditRecordV1 {
            flags: 1,
            ..record(2)
        },
    ] {
        let text = run(
            &["auditctl", "read"],
            vec![
                Reply::Stat(0, stats(1, 3)),
                Reply::Read(0, 2, vec![record(1), second]),
            ],
            1,
        );
        assert!(!text.contains("seq=1 ")); // 整批通过校验后才显示
    }
}

#[test]
fn zero_read_return_ends_iteration() {
    let text = run(
        &["auditctl", "read"],
        vec![Reply::Stat(0, stats(1, 3)), Reply::Read(0, 0, vec![])],
        0,
    );
    assert!(text.contains("records=0 cursor=0 through=2"));
}
