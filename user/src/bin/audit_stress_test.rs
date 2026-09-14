//! 多进程审计压力回归。
//!
//! 子进程并发制造确定的 `ipc_stat(flags != 0)` 失败事件；父进程核对全局
//! 统计增量、覆盖语义、连续序号和记录中的进程身份。测试不依赖 A/B/C 的
//! 内部实现，也不把调度顺序写进断言。

#![no_std]
#![no_main]

use core::mem::size_of;
use user_lib::audit::{self, AuditRecordV1, IpcStatsV1};
use user_lib::{fork, get_time, println, waitpid, yield_};

const CHILDREN: usize = 6;
const EVENTS_PER_CHILD: usize = 128;
const EXPECTED_EVENTS: u64 = (CHILDREN * EVENTS_PER_CHILD) as u64;
const READ_BATCH: usize = 32;

macro_rules! require {
    ($condition:expr, $($message:tt)+) => {
        if !$condition {
            println!("[audit_stress_test] FAIL {}", core::format_args!($($message)+));
            return 1;
        }
    };
}

fn load_stats() -> Result<IpcStatsV1, isize> {
    let mut stats = IpcStatsV1::default();
    let ret = audit::stat(&mut stats);
    if ret == 0 { Ok(stats) } else { Err(ret) }
}

fn child_work() -> i32 {
    let mut untouched = IpcStatsV1::default();
    for index in 0..EVENTS_PER_CHILD {
        let ret = unsafe { audit::raw::ipc_stat(&mut untouched, size_of::<IpcStatsV1>(), 1) };
        if ret != -(audit::EINVAL as isize) {
            return 1;
        }
        if index % 8 == 7 {
            yield_();
        }
    }
    0
}

fn is_child_pid(pid: u64, children: &[isize; CHILDREN]) -> bool {
    children.iter().any(|candidate| *candidate as u64 == pid)
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    let before = match load_stats() {
        Ok(stats) => stats,
        Err(ret) => {
            println!("[audit_stress_test] FAIL initial ipc_stat returned {}", ret);
            return 1;
        }
    };
    require!(
        EXPECTED_EVENTS > before.capacity,
        "event count {} must exceed ring capacity {}",
        EXPECTED_EVENTS,
        before.capacity
    );

    let started_ms = get_time();
    require!(started_ms >= 0, "get_time returned {}", started_ms);
    let mut children = [-1isize; CHILDREN];
    for slot in &mut children {
        let pid = fork();
        if pid == 0 {
            return child_work();
        }
        require!(pid > 0, "fork returned {}", pid);
        *slot = pid;
    }

    for pid in children {
        let mut exit_code = -1;
        let waited = waitpid(pid as usize, &mut exit_code);
        require!(waited == pid, "waitpid({}) returned {}", pid, waited);
        require!(exit_code == 0, "child {} exited with {}", pid, exit_code);
    }

    let after = match load_stats() {
        Ok(stats) => stats,
        Err(ret) => {
            println!("[audit_stress_test] FAIL final ipc_stat returned {}", ret);
            return 1;
        }
    };
    let occupied = before.retained + EXPECTED_EVENTS;
    let expected_retained = occupied.min(before.capacity);
    let expected_overwritten = before.overwritten_events + occupied.saturating_sub(before.capacity);

    require!(
        after.total_events == before.total_events + EXPECTED_EVENTS,
        "total delta: expected={} actual={}",
        EXPECTED_EVENTS,
        after.total_events - before.total_events
    );
    require!(
        after.failed_events == before.failed_events + EXPECTED_EVENTS,
        "failed delta: expected={} actual={}",
        EXPECTED_EVENTS,
        after.failed_events - before.failed_events
    );
    require!(
        after.successful_events == before.successful_events,
        "successful count changed: before={} after={}",
        before.successful_events,
        after.successful_events
    );
    require!(
        after.retained == expected_retained,
        "retained: expected={} actual={}",
        expected_retained,
        after.retained
    );
    require!(
        after.overwritten_events == expected_overwritten,
        "overwritten: expected={} actual={}",
        expected_overwritten,
        after.overwritten_events
    );
    require!(
        after.next_sequence == before.next_sequence + EXPECTED_EVENTS,
        "next sequence: expected={} actual={}",
        before.next_sequence + EXPECTED_EVENTS,
        after.next_sequence
    );
    require!(
        after.first_sequence == after.next_sequence - after.retained,
        "invalid sequence window [{}, {})",
        after.first_sequence,
        after.next_sequence
    );

    let mut records = [AuditRecordV1::default(); READ_BATCH];
    let mut cursor = before.next_sequence - 1;
    let mut expected_sequence = after.first_sequence;
    let mut seen = 0u64;
    let mut previous_timestamp = 0u64;
    while expected_sequence < after.next_sequence {
        let ret = audit::read(&mut records, cursor);
        require!(ret > 0, "audit_read returned {} before reaching tail", ret);
        let count = ret as usize;
        require!(count <= READ_BATCH, "batch exceeds limit: {}", count);
        for (index, record) in records[..count].iter().enumerate() {
            require!(
                record.sequence == expected_sequence,
                "sequence: expected={} actual={}",
                expected_sequence,
                record.sequence
            );
            require!(
                record.has_gap_before() == (seen == 0 && index == 0),
                "unexpected GAP_BEFORE at sequence {}",
                record.sequence
            );
            require!(
                record.timestamp_ms >= previous_timestamp,
                "timestamp decreased at sequence {}",
                record.sequence
            );
            require!(
                record.operation == audit::AUDIT_OP_IPC_STAT
                    && record.errno == audit::EINVAL
                    && record.requested_amount == 0
                    && record.result_value == 0,
                "unexpected event fields at sequence {}",
                record.sequence
            );
            require!(
                is_child_pid(record.subject_pid, &children),
                "unknown subject pid {} at sequence {}",
                record.subject_pid,
                record.sequence
            );
            previous_timestamp = record.timestamp_ms;
            expected_sequence += 1;
            seen += 1;
        }
        cursor = records[count - 1].sequence;
    }

    require!(
        seen == after.retained,
        "read {} retained {}",
        seen,
        after.retained
    );
    require!(
        audit::read(&mut records, cursor) == 0,
        "tail read was not empty"
    );
    let elapsed_ms = get_time() - started_ms;
    println!(
        "[audit_stress_test] PASS children={} events_per_child={} total={} retained={} overwritten_delta={} elapsed_ms={}",
        CHILDREN,
        EVENTS_PER_CHILD,
        EXPECTED_EVENTS,
        after.retained,
        after.overwritten_events - before.overwritten_events,
        elapsed_ms
    );
    0
}
