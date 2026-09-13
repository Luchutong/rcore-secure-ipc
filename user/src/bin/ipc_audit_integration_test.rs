//! D+C integration coverage for real pipe creation and quota-denial events.

#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use core::arch::asm;
use core::mem::size_of;
use core::ptr::addr_of_mut;
use user_lib::audit::{
    self, AUDIT_OP_AUDIT_READ, AUDIT_OP_IPC_STAT, AUDIT_OP_PIPE_CREATE, AUDIT_OP_PIPE_READ,
    AUDIT_OP_PIPE_WRITE, AuditRecordV1, EFAULT, ENOSPC, IpcStatsV1,
};
use user_lib::{close, getpid, pipe, read, write};

const PIPE_LIMIT: usize = 8;
const SYSCALL_PIPE: usize = 59;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;

#[repr(C, align(4096))]
struct TwoUserPages([u8; 8192]);

static mut CROSS_PAGE_OUTPUT: TwoUserPages = TwoUserPages([0; 8192]);

fn raw_syscall(id: usize, args: [usize; 3]) -> isize {
    let mut result: isize;
    unsafe {
        asm!(
            "ecall",
            inlateout("x10") args[0] => result,
            in("x11") args[1],
            in("x12") args[2],
            in("x17") id,
        );
    }
    result
}

fn raw_pipe(output: usize) -> isize {
    raw_syscall(SYSCALL_PIPE, [output, 0, 0])
}

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

fn test_user_copy_failures_are_audited_and_rolled_back() {
    let before_pipe = stats();
    let pipe_cursor = before_pipe.next_sequence - 1;
    assert_eq!(raw_pipe(0x8020_0000), -(EFAULT as isize));

    let mut records = [AuditRecordV1::default(); 2];
    assert_eq!(read_since(pipe_cursor, &mut records), 1);
    assert_eq!(records[0].operation, AUDIT_OP_PIPE_CREATE);
    assert_eq!(records[0].errno, EFAULT);
    assert_eq!(records[0].requested_amount, 1);
    assert_eq!(records[0].result_value, 0);

    // 用户复制失败发生在配额预留之后；紧接着创建成功证明预留已回滚。
    let mut pair = [usize::MAX; 2];
    assert_eq!(pipe(&mut pair), 0);
    assert_eq!(close(pair[0]), 0);
    assert_eq!(close(pair[1]), 0);

    let before_read = stats();
    let read_cursor = before_read.next_sequence - 1;
    assert_eq!(
        unsafe { audit::raw::audit_read(core::ptr::null_mut(), 1, 0) },
        -(EFAULT as isize)
    );
    assert_eq!(read_since(read_cursor, &mut records), 1);
    assert_eq!(records[0].operation, AUDIT_OP_AUDIT_READ);
    assert_eq!(records[0].errno, EFAULT);
    assert_eq!(records[0].requested_amount, 1);

    let before_stat = stats();
    let stat_cursor = before_stat.next_sequence - 1;
    assert_eq!(
        unsafe { audit::raw::ipc_stat(core::ptr::null_mut(), size_of::<IpcStatsV1>(), 0,) },
        -(EFAULT as isize)
    );
    assert_eq!(read_since(stat_cursor, &mut records), 1);
    assert_eq!(records[0].operation, AUDIT_OP_IPC_STAT);
    assert_eq!(records[0].errno, EFAULT);
}

fn test_pipe_read_write_events() {
    let before = stats();
    let cursor = before.next_sequence - 1;
    let mut pair = [0usize; 2];
    assert_eq!(pipe(&mut pair), 0);

    let payload = *b"ipc42";
    let mut output = [0u8; 5];
    assert_eq!(write(pair[1], &payload), payload.len() as isize);
    assert_eq!(read(pair[0], &mut output), output.len() as isize);
    assert_eq!(output, payload);
    assert_eq!(write(pair[1], &[]), 0);
    assert_eq!(read(pair[0], &mut []), 0);
    assert_eq!(
        raw_syscall(SYSCALL_WRITE, [pair[1], 0x8020_0000, 5]),
        -(EFAULT as isize)
    );
    assert_eq!(
        raw_syscall(SYSCALL_READ, [pair[0], 0x8020_0000, 5]),
        -(EFAULT as isize)
    );

    let mut records = [AuditRecordV1::default(); 8];
    assert_eq!(read_since(cursor, &mut records), 7);
    assert_pipe_event(&records[0], true);
    let object_id = records[1].object_id;
    assert_ne!(object_id, 0);
    for (index, operation, requested, result, errno) in [
        (1, AUDIT_OP_PIPE_WRITE, 5, 5, 0),
        (2, AUDIT_OP_PIPE_READ, 5, 5, 0),
        (3, AUDIT_OP_PIPE_WRITE, 0, 0, 0),
        (4, AUDIT_OP_PIPE_READ, 0, 0, 0),
        (5, AUDIT_OP_PIPE_WRITE, 5, 0, EFAULT),
        (6, AUDIT_OP_PIPE_READ, 5, 0, EFAULT),
    ] {
        let record = &records[index];
        assert_eq!(record.operation, operation);
        assert_eq!(record.object_id, object_id);
        assert_eq!(record.object_owner_uid, 0);
        assert_eq!(record.requested_amount, requested);
        assert_eq!(record.result_value, result);
        assert_eq!(record.errno, errno);
    }

    assert_eq!(close(pair[0]), 0);
    assert_eq!(close(pair[1]), 0);
}

fn test_cross_page_unaligned_audit_output() {
    // 输出从第一页末尾前39字节开始，80字节结构横跨两页且未自然对齐。
    let base = unsafe { addr_of_mut!(CROSS_PAGE_OUTPUT.0).cast::<u8>() };
    let output = unsafe { base.add(4096 - 39).cast::<IpcStatsV1>() };
    assert_ne!((output as usize) % core::mem::align_of::<IpcStatsV1>(), 0);
    assert_eq!(
        unsafe { audit::raw::ipc_stat(output, size_of::<IpcStatsV1>(), 0) },
        0
    );
    let copied = unsafe { output.read_unaligned() };
    assert_eq!(copied.abi_version, audit::AUDIT_ABI_VERSION);
    assert_eq!(copied.struct_size, audit::IPC_STATS_V1_SIZE);
    assert_eq!(copied.capacity, 256);
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    test_successful_pipe_event();
    test_quota_denial_event_and_recovery();
    test_user_copy_failures_are_audited_and_rolled_back();
    test_pipe_read_write_events();
    test_cross_page_unaligned_audit_output();
    println!("ipc_audit_integration_test passed!");
    0
}
