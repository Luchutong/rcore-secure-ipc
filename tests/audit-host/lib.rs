//! 主机侧审计测试：直接编译内核源文件，只替换 RISC-V 硬件时钟。
//! 从仓库根目录运行：
//! cargo test --manifest-path tests/audit-host/Cargo.toml -- --test-threads=1

#![cfg(test)]

#[allow(dead_code)]
#[path = "../../os/src/security/api.rs"]
mod api;
#[path = "../../os/src/security/audit.rs"]
mod audit;
#[path = "../../os/src/sync/up.rs"]
mod sync;

use api::*;
use audit::*;

mod timer {
    // 固定时间使测试结果可重复，主机无需执行 RISC-V 的 time 指令。
    pub fn get_time_ms() -> usize {
        1234
    }
}

fn request(operation: IpcOperation) -> IpcRequest {
    IpcRequest {
        subject: IpcSubject {
            pid: 12,
            uid: 1000,
            capabilities: CapabilitySet::empty(),
        },
        object: IpcObject {
            id: 7,
            owner_uid: 42,
        },
        operation,
        amount: 100,
    }
}

#[test]
fn abi_layout_matches_v1() {
    use core::mem::{align_of, offset_of, size_of};

    assert_eq!(size_of::<AuditRecordV1>(), 80);
    assert_eq!(size_of::<IpcStatsV1>(), 80);
    assert_eq!(align_of::<AuditRecordV1>(), 8);
    assert_eq!(align_of::<IpcStatsV1>(), 8);

    // 同样大小的结构仍可能重排字段，因此额外逐项检查 ABI 偏移。
    assert_eq!(
        [
            offset_of!(AuditRecordV1, abi_version),
            offset_of!(AuditRecordV1, record_size),
            offset_of!(AuditRecordV1, operation),
            offset_of!(AuditRecordV1, flags),
            offset_of!(AuditRecordV1, errno),
            offset_of!(AuditRecordV1, subject_uid),
            offset_of!(AuditRecordV1, object_owner_uid),
            offset_of!(AuditRecordV1, reserved0),
            offset_of!(AuditRecordV1, sequence),
            offset_of!(AuditRecordV1, timestamp_ms),
            offset_of!(AuditRecordV1, subject_pid),
            offset_of!(AuditRecordV1, object_id),
            offset_of!(AuditRecordV1, requested_amount),
            offset_of!(AuditRecordV1, result_value),
            offset_of!(AuditRecordV1, reserved1),
        ],
        [0, 2, 4, 6, 8, 12, 16, 20, 24, 32, 40, 48, 56, 64, 72]
    );
    assert_eq!(
        [
            offset_of!(IpcStatsV1, abi_version),
            offset_of!(IpcStatsV1, struct_size),
            offset_of!(IpcStatsV1, flags),
            offset_of!(IpcStatsV1, capacity),
            offset_of!(IpcStatsV1, retained),
            offset_of!(IpcStatsV1, first_sequence),
            offset_of!(IpcStatsV1, next_sequence),
            offset_of!(IpcStatsV1, total_events),
            offset_of!(IpcStatsV1, successful_events),
            offset_of!(IpcStatsV1, failed_events),
            offset_of!(IpcStatsV1, overwritten_events),
            offset_of!(IpcStatsV1, reserved0),
        ],
        [0, 2, 4, 8, 16, 24, 32, 40, 48, 56, 64, 72]
    );
}

#[test]
fn operations_use_stable_ids_and_correct_success_amounts() {
    for (operation, id, result) in [
        (IpcOperation::SignalSend, 1, 1),
        (IpcOperation::PipeCreate, 2, 1),
        (IpcOperation::PipeRead, 3, 60),
        (IpcOperation::PipeWrite, 4, 60),
        (IpcOperation::AuditRead, 5, 60),
    ] {
        let mut req = request(operation);
        if matches!(
            operation,
            IpcOperation::SignalSend | IpcOperation::PipeCreate
        ) {
            req.amount = 1;
        }
        let event = AuditEvent::from_request(&req, &Ok(60), 1234);
        assert_eq!(event.operation, id);
        assert_eq!(event.errno, 0);
        assert_eq!(event.result_value, result);
        assert_eq!(event.requested_amount, req.amount as u64);
    }

    for operation in [IpcOperation::PipeRead, IpcOperation::PipeWrite] {
        let event = AuditEvent::from_request(&request(operation), &Ok(0), 1234);
        assert_eq!(event.errno, 0);
        assert_eq!(event.result_value, 0);
    }
}

#[test]
fn errors_use_positive_errno_and_zero_result() {
    for (error, errno) in [
        (IpcError::PermissionDenied, 1),
        (IpcError::ProcessNotFound, 3),
        (IpcError::TryAgain, 11),
        (IpcError::InvalidAddress, 14),
        (IpcError::InvalidArgument, 22),
        (IpcError::TooManyFiles, 24),
        (IpcError::ResourceExhausted, 28),
    ] {
        assert_eq!(error_to_errno(error), errno);
        for operation in [
            IpcOperation::SignalSend,
            IpcOperation::PipeCreate,
            IpcOperation::PipeRead,
            IpcOperation::PipeWrite,
            IpcOperation::AuditRead,
        ] {
            let outcome = Err(error);
            let event = AuditEvent::from_request(&request(operation), &outcome, 1234);
            assert_eq!(event.errno, errno);
            assert_eq!(event.result_value, 0);
            assert_eq!(outcome, Err(error));
        }
    }
}

#[test]
fn conversion_preserves_metadata_and_initializes_abi_fields() {
    let event = AuditEvent::from_request(&request(IpcOperation::PipeWrite), &Ok(60), 9876);
    assert_eq!(event.sequence, 0); // 入环前不能自行分配序号。
    let stored = AuditEvent {
        sequence: 9,
        ..event
    };
    assert_eq!(
        stored.to_record(false),
        AuditRecordV1 {
            abi_version: 1,
            record_size: 80,
            operation: 4,
            flags: 0,
            errno: 0,
            subject_uid: 1000,
            object_owner_uid: 42,
            reserved0: 0,
            sequence: 9,
            timestamp_ms: 9876,
            subject_pid: 12,
            object_id: 7,
            requested_amount: 100,
            result_value: 60,
            reserved1: 0,
        }
    );
    assert_eq!(stored.to_record(true).flags, 1);
    assert_eq!(stored.to_record(false).flags, 0);
    assert_eq!(stored.sequence, 9);

    // UID 0 是有效所有者；未知 UID 和大资源编号都必须原样保留。
    for owner_uid in [0, AUDIT_UID_UNKNOWN] {
        let mut req = request(IpcOperation::PipeRead);
        req.object.owner_uid = owner_uid;
        req.object.id = u64::MAX;
        req.amount = usize::MAX;
        let record = AuditEvent::from_request(&req, &Ok(0), 1).to_record(false);
        assert_eq!(record.object_owner_uid, owner_uid);
        assert_eq!(record.object_id, u64::MAX);
        assert_eq!(record.requested_amount, usize::MAX as u64);
    }
}

#[test]
fn batch_conversion_marks_only_first_valid_record() {
    let mut events = [AuditEvent::EMPTY; AUDIT_READ_MAX_RECORDS];
    events[0] = AuditEvent {
        sequence: 10,
        operation: 60000,
        ..AuditEvent::EMPTY
    };
    events[1] = AuditEvent {
        sequence: 11,
        ..AuditEvent::EMPTY
    };
    let batch = AuditBatch {
        events,
        len: 2,
        gap_before: true,
    };
    assert_eq!(batch.record_at(0).unwrap().flags, 1);
    assert_eq!(batch.record_at(1).unwrap().flags, 0);
    assert_eq!(batch.record_at(0).unwrap().operation, 60000); // 未知编号不引起 panic。
    assert_eq!(batch.record_at(2), None); // 空槽不能作为有效记录返回。
    assert_eq!(batch.record_at(usize::MAX), None);
    assert_eq!(batch.events[0], events[0]);
    assert_eq!(AuditBatch { len: 0, ..batch }.record_at(0), None);
}

#[test]
fn stats_conversion_preserves_one_consistent_snapshot() {
    let snapshot = AuditStatsSnapshot {
        capacity: 256,
        retained: 256,
        first_sequence: 5,
        next_sequence: 261,
        total_events: 260,
        successful_events: 160,
        failed_events: 100,
        overwritten_events: 4,
    };
    assert_eq!(
        snapshot.to_record(),
        IpcStatsV1 {
            abi_version: 1,
            struct_size: 80,
            flags: 0,
            capacity: 256,
            retained: 256,
            first_sequence: 5,
            next_sequence: 261,
            total_events: 260,
            successful_events: 160,
            failed_events: 100,
            overwritten_events: 4,
            reserved0: 0,
        }
    );
}

#[test]
fn recording_filters_feedback_and_keeps_ring_counters_consistent() {
    // 只有此测试访问全局 UPSafeCell；保持单线程，遵循内核的单核约束。
    let before = stats().to_record();
    let req = request(IpcOperation::PipeWrite);
    let outcome = Ok(60);
    record(&req, &outcome);
    assert_eq!(outcome, Ok(60));
    let first = snapshot(before.next_sequence - 1, 32).record_at(0).unwrap();
    assert_eq!(first.sequence, before.next_sequence);
    assert_eq!(first.timestamp_ms, 1234);
    assert_eq!(first.result_value, 60);

    let after_success = stats().to_record();
    record(&request(IpcOperation::AuditRead), &Ok(1));
    record(&request(IpcOperation::AuditRead), &Ok(0));
    assert_eq!(snapshot(after_success.next_sequence - 1, 32).len, 0);
    assert_eq!(stats().to_record(), after_success);

    record(
        &request(IpcOperation::AuditRead),
        &Err(IpcError::PermissionDenied),
    );
    record_control_failure(
        AuditControlOperation::AuditRead,
        &req.subject,
        33,
        IpcError::InvalidAddress,
    );
    record_control_failure(
        AuditControlOperation::IpcStat,
        &req.subject,
        999,
        IpcError::InvalidArgument,
    );
    let failures = snapshot(after_success.next_sequence - 1, 32);
    assert_eq!(failures.len, 3);
    for (index, operation, errno, amount) in [(0, 5, 1, 100), (1, 5, 14, 33), (2, 6, 22, 0)] {
        let record = failures.record_at(index).unwrap();
        assert_eq!(record.operation, operation);
        assert_eq!(record.errno, errno);
        assert_eq!(record.result_value, 0);
        assert_eq!(record.requested_amount, amount);
        assert_eq!(record.subject_pid, 12);
        assert_eq!(record.subject_uid, 1000);
        assert_eq!(record.timestamp_ms, 1234);
        if index != 0 {
            assert_eq!(record.object_id, 0);
            assert_eq!(record.object_owner_uid, u32::MAX);
        }
    }
    let after_failures = stats().to_record();
    assert_eq!(after_failures.total_events - before.total_events, 4);
    assert_eq!(
        after_failures.successful_events - before.successful_events,
        1
    );
    assert_eq!(after_failures.failed_events - before.failed_events, 3);

    // 通过真实写入入口触发覆盖，再验证快照转换没有回写 GAP_BEFORE。
    for _ in 0..=AUDIT_RING_CAPACITY {
        record_control_failure(
            AuditControlOperation::IpcStat,
            &req.subject,
            0,
            IpcError::InvalidArgument,
        );
    }
    let after_overflow = stats().to_record();
    assert_eq!(after_overflow.retained, after_overflow.capacity);
    assert_eq!(
        after_overflow.total_events,
        after_overflow.successful_events + after_overflow.failed_events
    );
    assert!(after_overflow.overwritten_events > after_failures.overwritten_events);
    let batch = snapshot(before.next_sequence - 1, usize::MAX);
    assert_eq!(batch.len, 32);
    assert_eq!(batch.record_at(0).unwrap().flags, 1);
    for index in 1..batch.len {
        let record = batch.record_at(index).unwrap();
        assert_eq!(record.flags, 0);
        assert_eq!(record.sequence, batch.events[0].sequence + index as u64);
    }
    let caught_up = snapshot(after_overflow.first_sequence - 1, 32);
    assert_eq!(caught_up.record_at(0).unwrap().flags, 0);
    assert_eq!(snapshot(u64::MAX, 32).len, 0);
    assert_eq!(snapshot(0, 0).len, 0);
    assert_eq!(stats().to_record(), after_overflow);
}
