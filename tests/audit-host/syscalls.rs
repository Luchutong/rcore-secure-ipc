//! 直接测试内核 602/603 主体，任务与用户复制使用可控替身。
//! 替身验证接口调用顺序和故障传播，不证明真实 RISC-V 页表已经安全。

#![allow(dead_code)]

#[path = "../../os/src/security/api.rs"]
mod api;
#[path = "../../os/src/security/audit.rs"]
mod audit;
#[path = "../../os/src/security/credentials.rs"]
mod credentials;
#[path = "../../os/src/sync/up.rs"]
mod sync;
#[path = "../../os/src/syscall/security.rs"]
mod syscalls;

use api::*;
use audit::*;
use std::sync::{Mutex, MutexGuard};
use syscalls::{sys_audit_read, sys_ipc_stat};

mod security {
    pub(crate) use crate::api::*;
    pub(crate) use crate::audit;
}

mod timer {
    pub fn get_time_ms() -> usize {
        5678
    }
}

mod task {
    use crate::{CapabilitySet, credentials::Credentials};
    use std::cell::{RefCell, RefMut};
    use std::rc::Rc;

    pub const TOKEN: usize = 77;
    pub const PID: usize = 42;

    pub struct SecurityState {
        pub credentials: Credentials,
    }

    pub struct TaskInner {
        pub security: SecurityState,
    }

    impl TaskInner {
        pub fn get_user_token(&self) -> usize {
            TOKEN
        }
    }

    pub struct Task {
        inner: RefCell<TaskInner>,
    }

    impl Task {
        pub fn getpid(&self) -> usize {
            PID
        }

        pub fn inner_exclusive_access(&self) -> RefMut<'_, TaskInner> {
            self.inner.borrow_mut()
        }
    }

    thread_local! {
        static CURRENT: Rc<Task> = Rc::new(Task {
            inner: RefCell::new(TaskInner {
                security: SecurityState { credentials: Credentials::initial() },
            }),
        });
    }

    pub fn current_task() -> Option<Rc<Task>> {
        Some(CURRENT.with(Rc::clone))
    }

    pub fn set_credentials(uid: u32, capabilities: CapabilitySet) {
        CURRENT.with(|task| {
            task.inner.borrow_mut().security.credentials = Credentials { uid, capabilities };
        });
    }
}

mod mm {
    use crate::{IpcError, IpcResult, audit, task};
    use std::cell::RefCell;
    use std::mem::{size_of, size_of_val};
    use std::ops::Range;

    #[derive(Default)]
    struct Memory {
        writable: Vec<Range<usize>>,
        calls: usize,
        fail_on: Option<usize>,
        append_on_first_copy: bool,
    }

    thread_local! {
        static MEMORY: RefCell<Memory> = RefCell::new(Memory::default());
    }

    pub fn reset() {
        MEMORY.with(|memory| *memory.borrow_mut() = Memory::default());
    }

    // 测试保证已登记缓冲区在系统调用返回前存活，替身只允许写入这些范围。
    pub fn allow<T>(buffer: &mut [T]) {
        let start = buffer.as_mut_ptr() as usize;
        let end = start + size_of_val(buffer);
        MEMORY.with(|memory| memory.borrow_mut().writable.push(start..end));
    }

    pub fn calls() -> usize {
        MEMORY.with(|memory| memory.borrow().calls)
    }

    pub fn fail_on(call: Option<usize>) {
        MEMORY.with(|memory| memory.borrow_mut().fail_on = call);
    }

    pub fn append_on_first_copy() {
        MEMORY.with(|memory| memory.borrow_mut().append_on_first_copy = true);
    }

    pub fn copy_to_user<T: Copy + 'static>(
        token: usize,
        destination: *mut T,
        value: &T,
    ) -> IpcResult<()> {
        assert_eq!(token, task::TOKEN);
        // 在复制入口重新借用任务和审计状态；若主体忘了释放借用，测试会 panic。
        let current = task::current_task().unwrap();
        drop(current.inner_exclusive_access());
        let _ = audit::stats();

        MEMORY.with(|memory| {
            let mut memory = memory.borrow_mut();
            memory.calls += 1;
            if memory.append_on_first_copy && memory.calls == 1 {
                crate::emit_failure();
            }
            if memory.fail_on == Some(memory.calls) {
                return Err(IpcError::InvalidAddress);
            }
            let start = destination as usize;
            let end = start
                .checked_add(size_of::<T>())
                .ok_or(IpcError::InvalidAddress)?;
            if !memory
                .writable
                .iter()
                .any(|range| start >= range.start && end <= range.end)
            {
                return Err(IpcError::InvalidAddress);
            }
            // 上面已经确认输出属于测试持有的可写缓冲区。
            unsafe { destination.write_unaligned(*value) };
            Ok(())
        })
    }
}

// 审计源码使用全局 UPSafeCell，必须串行访问；即使测试线程数增加也保持互斥。
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn setup() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    task::set_credentials(0, CapabilitySet::empty());
    mm::reset();
    guard
}

fn emit_failure() {
    record_control_failure(
        AuditControlOperation::IpcStat,
        &IpcSubject {
            pid: task::PID,
            uid: 0,
            capabilities: CapabilitySet::empty(),
        },
        0,
        IpcError::InvalidArgument,
    );
}

fn check_one_failure(before: AuditStatsSnapshot, operation: u16, errno: i32, amount: u64) {
    let after = stats();
    assert_eq!(after.total_events, before.total_events + 1);
    assert_eq!(after.failed_events, before.failed_events + 1);
    assert_eq!(after.successful_events, before.successful_events);
    let event = snapshot(before.next_sequence - 1, 32).record_at(0).unwrap();
    assert_eq!(event.operation, operation);
    assert_eq!(event.errno, errno);
    assert_eq!(event.requested_amount, amount);
    assert_eq!(event.subject_pid, task::PID as u64);
    assert_eq!(event.object_id, AUDIT_OBJECT_NONE);
    assert_eq!(event.object_owner_uid, AUDIT_UID_UNKNOWN);
    assert_eq!(event.result_value, 0);
}

#[test]
fn permission_precedes_parameters_and_zero_capacity() {
    let _guard = setup();
    // IPC_ADMIN/KILL 均不能替代 AUDIT_READ。也不能用零容量绕过权限检查。
    for capability in [
        CapabilitySet::empty(),
        CapabilitySet::KILL,
        CapabilitySet::IPC_ADMIN,
    ] {
        task::set_credentials(1000, capability);
        let before = stats();
        assert_eq!(sys_audit_read(core::ptr::null_mut(), 0, 0), -1);
        check_one_failure(before, 5, 1, 0);
        let before = stats();
        assert_eq!(sys_ipc_stat(core::ptr::null_mut(), 0, 1), -1);
        check_one_failure(before, 6, 1, 0);
        assert_eq!(
            snapshot(before.next_sequence - 1, 1).events[0].subject_uid,
            1000
        );
    }
    assert_eq!(mm::calls(), 0);
}

#[test]
fn root_and_audit_capability_can_read_without_feedback() {
    let _guard = setup();
    for (uid, capability) in [
        (0, CapabilitySet::empty()),
        (1000, CapabilitySet::AUDIT_READ),
    ] {
        task::set_credentials(uid, capability);
        emit_failure();
        let before = stats();
        let mut output = [IpcStatsV1::default(); 1];
        mm::allow(&mut output);
        assert_eq!(sys_ipc_stat(output.as_mut_ptr(), 80, 0), 0);
        assert_eq!(output[0], before.to_record());

        let mut records = [AuditRecordV1::default(); 1];
        mm::allow(&mut records);
        assert_eq!(
            sys_audit_read(records.as_mut_ptr(), 1, before.next_sequence - 2),
            1
        );
        assert_eq!(records[0].sequence, before.next_sequence - 1);
        assert_eq!(stats(), before);
    }
}

#[test]
fn zero_capacity_and_empty_tail_do_not_access_output() {
    let _guard = setup();
    let before = stats();
    assert_eq!(sys_audit_read(core::ptr::null_mut(), 0, 0), 0);
    assert_eq!(
        sys_audit_read(core::ptr::null_mut(), 32, before.next_sequence - 1),
        0
    );
    assert_eq!(
        sys_audit_read(core::ptr::null_mut(), usize::MAX, u64::MAX),
        0
    );
    assert_eq!(mm::calls(), 0);
    assert_eq!(stats(), before);
}

#[test]
fn invalid_stat_parameters_record_once_without_copying() {
    let _guard = setup();
    for (size, flags) in [(0, 0), (79, 0), (80, 1), (usize::MAX, usize::MAX)] {
        let before = stats();
        assert_eq!(sys_ipc_stat(core::ptr::null_mut(), size, flags), -22);
        check_one_failure(before, 6, 22, 0);
    }
    assert_eq!(mm::calls(), 0);
}

#[test]
fn stat_copies_only_eighty_bytes_and_preserves_tail() {
    let _guard = setup();
    #[repr(C)]
    struct Output {
        stats: IpcStatsV1,
        tail: [u8; 16],
    }
    let mut output = [Output {
        stats: IpcStatsV1::default(),
        tail: [0xa5; 16],
    }];
    mm::allow(&mut output);
    let before = stats();
    // 很大的 out_size 只声明空间充足，实际复制范围仍然是前 80 字节。
    assert_eq!(sys_ipc_stat(&mut output[0].stats, usize::MAX, 0), 0);
    assert_eq!(output[0].stats, before.to_record());
    assert_eq!(output[0].tail, [0xa5; 16]);
    assert_eq!(mm::calls(), 1);
    assert_eq!(stats(), before);
}

#[test]
fn null_and_wrapping_output_ranges_fail_before_copying() {
    let _guard = setup();
    emit_failure();
    for address in [0, usize::MAX - 39] {
        let before = stats();
        assert_eq!(sys_ipc_stat(address as *mut IpcStatsV1, 80, 0), -14);
        check_one_failure(before, 6, 14, 0);
        let before = stats();
        assert_eq!(
            sys_audit_read(address as *mut AuditRecordV1, 1, before.next_sequence - 2),
            -14
        );
        check_one_failure(before, 5, 14, 1);
    }
    assert_eq!(mm::calls(), 0);
}

#[test]
fn copy_failure_records_efault_and_preserves_cursor_for_retry() {
    let _guard = setup();
    let cursor = stats().next_sequence - 1;
    for _ in 0..3 {
        emit_failure();
    }
    let mut records = [AuditRecordV1::default(); 3];
    mm::allow(&mut records);
    mm::fail_on(Some(2));
    let before = stats();
    assert_eq!(sys_audit_read(records.as_mut_ptr(), 3, cursor), -14);
    check_one_failure(before, 5, 14, 3);
    assert_eq!(records[0].sequence, cursor + 1);
    assert_eq!(records[1], AuditRecordV1::default());

    mm::fail_on(None);
    let before_retry = stats();
    assert_eq!(sys_audit_read(records.as_mut_ptr(), 3, cursor), 3);
    assert_eq!(
        records.map(|record| record.sequence),
        [cursor + 1, cursor + 2, cursor + 3]
    );
    assert_eq!(stats(), before_retry);

    // 未登记的指针由复制替身返回 EFAULT，主体应仅追加一次统计查询失败。
    let before = stats();
    assert_eq!(sys_ipc_stat(0x1000 as *mut IpcStatsV1, 80, 0), -14);
    check_one_failure(before, 6, 14, 0);
}

#[test]
fn snapshot_excludes_events_appended_during_copy() {
    let _guard = setup();
    let cursor = stats().next_sequence - 1;
    emit_failure();
    emit_failure();
    let before = stats();
    let mut records = [AuditRecordV1::default(); 32];
    mm::allow(&mut records);
    mm::append_on_first_copy();
    assert_eq!(sys_audit_read(records.as_mut_ptr(), 32, cursor), 2);
    assert_eq!(records[1].sequence, before.next_sequence - 1);
    assert_eq!(stats().total_events, before.total_events + 1);
    assert_eq!(
        sys_audit_read(records.as_mut_ptr(), 32, before.next_sequence - 1),
        1
    );
    assert_eq!(records[0].sequence, before.next_sequence);
}

#[test]
fn overflow_reads_are_bounded_and_cursor_does_not_repeat() {
    let _guard = setup();
    let cursor = stats().next_sequence - 1;
    for _ in 0..=AUDIT_RING_CAPACITY {
        emit_failure();
    }
    let before = stats();
    let mut records = [AuditRecordV1::default(); 32];
    mm::allow(&mut records);
    assert_eq!(sys_audit_read(records.as_mut_ptr(), usize::MAX, cursor), 32);
    assert_eq!(records[0].flags, AUDIT_RECORD_F_GAP_BEFORE);
    assert_eq!(records[0].sequence, before.first_sequence);
    for pair in records.windows(2) {
        assert_eq!(pair[0].sequence + 1, pair[1].sequence);
        assert_eq!(pair[1].flags, 0);
    }
    let last = records[31].sequence;
    assert_eq!(sys_audit_read(records.as_mut_ptr(), 32, last), 32);
    assert_eq!(records[0].sequence, last + 1);
    assert_eq!(records[0].flags, 0);
    assert_eq!(stats(), before);
}
