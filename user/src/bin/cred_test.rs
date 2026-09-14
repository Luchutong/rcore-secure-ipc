#![no_std]
#![no_main]

//! A+D 接入测试：凭据继承/降权、信号授权，以及成功和拒绝结果的审计。

#[macro_use]
extern crate user_lib;

use user_lib::audit::{
    self, AUDIT_OP_AUDIT_READ, AUDIT_OP_IPC_STAT, AUDIT_OP_SIGNAL_SEND, AuditRecordV1, IpcStatsV1,
};
use user_lib::{
    SIGKILL, close, exit, fork, getpid, getuid, kill, pipe, read, setuid, waitpid, write, yield_,
};

fn stats() -> IpcStatsV1 {
    let mut value = IpcStatsV1::default();
    assert_eq!(audit::stat(&mut value), 0);
    value
}

fn inspect_since(cursor: u64, mut inspect: impl FnMut(&AuditRecordV1)) {
    let mut cursor = cursor;
    let mut records = [AuditRecordV1::default(); 32];
    loop {
        let count = audit::read(&mut records, cursor);
        assert!(count >= 0);
        if count == 0 {
            break;
        }
        for record in &records[..count as usize] {
            inspect(record);
            cursor = record.sequence;
        }
    }
}

fn wait_for_ready(fd: usize) {
    let mut byte = [0u8; 1];
    assert_eq!(read(fd, &mut byte), 1);
    assert_eq!(byte[0], 1);
}

fn child_wait_forever() -> ! {
    loop {
        yield_();
    }
}

fn test_cross_uid_denial_and_root_override() {
    let mut ready = [0usize; 2];
    assert_eq!(pipe(&mut ready), 0);
    let cursor = stats().next_sequence - 1;

    let victim = fork();
    assert!(victim >= 0);
    if victim == 0 {
        assert_eq!(close(ready[0]), 0);
        assert_eq!(setuid(2), 0);
        assert_eq!(getuid(), 2);
        assert_eq!(write(ready[1], &[1]), 1);
        child_wait_forever();
    }

    assert_eq!(close(ready[1]), 0);
    wait_for_ready(ready[0]);
    assert_eq!(close(ready[0]), 0);

    let attacker = fork();
    assert!(attacker >= 0);
    if attacker == 0 {
        assert_eq!(setuid(1), 0);
        assert_eq!(getuid(), 1);
        // 无 KILL capability 的不同 UID 发送者必须被拒绝。
        assert_eq!(kill(victim as usize, SIGKILL), -1);
        // 降权后也不能读取审计；失败本身由 D 记录。
        let mut denied = IpcStatsV1::default();
        assert_eq!(audit::stat(&mut denied), -1);
        exit(0);
    }

    let mut attacker_exit = 0;
    assert_eq!(waitpid(attacker as usize, &mut attacker_exit), attacker);
    assert_eq!(attacker_exit, 0);

    // root 可以跨 UID 终止目标，并且必须真的观察到目标以 SIGKILL 退出。
    assert_eq!(kill(victim as usize, SIGKILL), 0);
    let mut victim_exit = 0;
    assert_eq!(waitpid(victim as usize, &mut victim_exit), victim);
    assert_eq!(victim_exit, -SIGKILL);

    let mut denied_signal = false;
    let mut root_signal = false;
    let mut denied_audit_read = false;
    inspect_since(cursor, |record| {
        if record.operation == AUDIT_OP_SIGNAL_SEND
            && record.subject_uid == 1
            && record.object_owner_uid == 2
            && record.object_id == victim as u64
            && record.errno == 1
        {
            denied_signal = true;
        }
        if record.operation == AUDIT_OP_SIGNAL_SEND
            && record.subject_uid == 0
            && record.object_owner_uid == 2
            && record.object_id == victim as u64
            && record.errno == 0
            && record.result_value == 1
        {
            root_signal = true;
        }
        if (record.operation == AUDIT_OP_IPC_STAT || record.operation == AUDIT_OP_AUDIT_READ)
            && record.subject_uid == 1
            && record.errno == 1
        {
            denied_audit_read = true;
        }
    });
    assert!(denied_signal);
    assert!(root_signal);
    assert!(denied_audit_read);
}

fn test_same_uid_signal_and_fork_inheritance() {
    let cursor = stats().next_sequence - 1;
    let worker = fork();
    assert!(worker >= 0);
    if worker == 0 {
        assert_eq!(setuid(3), 0);
        let mut ready = [0usize; 2];
        assert_eq!(pipe(&mut ready), 0);
        let target = fork();
        assert!(target >= 0);
        if target == 0 {
            assert_eq!(getuid(), 3);
            assert_eq!(close(ready[0]), 0);
            assert_eq!(write(ready[1], &[1]), 1);
            child_wait_forever();
        }
        assert_eq!(close(ready[1]), 0);
        wait_for_ready(ready[0]);
        assert_eq!(close(ready[0]), 0);
        assert_eq!(kill(target as usize, SIGKILL), 0);
        let mut target_exit = 0;
        assert_eq!(waitpid(target as usize, &mut target_exit), target);
        assert_eq!(target_exit, -SIGKILL);
        exit(0);
    }

    let mut worker_exit = 0;
    assert_eq!(waitpid(worker as usize, &mut worker_exit), worker);
    assert_eq!(worker_exit, 0);

    let mut same_uid_signal = false;
    inspect_since(cursor, |record| {
        if record.operation == AUDIT_OP_SIGNAL_SEND
            && record.subject_uid == 3
            && record.object_owner_uid == 3
            && record.errno == 0
            && record.result_value == 1
        {
            same_uid_signal = true;
        }
    });
    assert!(same_uid_signal);
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    assert_eq!(getuid(), 0);
    assert!(getpid() >= 0);
    test_cross_uid_denial_and_root_override();
    test_same_uid_signal_and_fork_inheritance();
    println!("cred_test passed!");
    0
}
