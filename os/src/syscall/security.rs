//! 审计系统调用主体：602 读取事件，603 查询统计。
//!
//! 调用顺序为“复制调用者身份 → 检查权限/参数 → 取得值快照 → 复制用户内存”。
//! 任务状态和审计缓冲区的借用都不能跨越用户内存复制；成功查询不记录自身。
//! 页映射、可写权限和跨页复制由 mm::copy_to_user 保证，需配合 B 的加固实现。

use core::mem::size_of;

use crate::mm::copy_to_user;
use crate::security::audit::{self, AuditControlOperation, AuditRecordV1, IpcStatsV1};
use crate::security::{CapabilitySet, IpcError, IpcResult, IpcSubject};
use crate::task::current_task;

/// 从当前任务复制身份和地址空间标识，不把 RefMut 带到审计或复制路径中。
fn caller_context() -> (IpcSubject, usize) {
    // 系统调用只能由正在运行的用户任务进入；缺少任务属于内核调度错误。
    let task = current_task().expect("审计系统调用必须存在当前任务");
    let inner = task.inner_exclusive_access();
    let credentials = inner.security.credentials;
    let subject = IpcSubject {
        pid: task.getpid(),
        uid: credentials.uid,
        capabilities: credentials.capabilities,
    };
    let token = inner.get_user_token();
    // 返回的都是普通值；函数返回前自动释放任务内部借用。
    (subject, token)
}

/// 两个调用使用同一权限规则；先检查身份，再处理参数或生成快照。
fn check_permission(subject: &IpcSubject) -> IpcResult<()> {
    if subject.uid == 0 || subject.capabilities.contains(CapabilitySet::AUDIT_READ) {
        Ok(())
    } else {
        Err(IpcError::PermissionDenied)
    }
}

/// 仅检查实际输出范围的空地址与整数溢出，不代替用户页表检查。
fn check_output_range(start: usize, count: usize, item_size: usize) -> IpcResult<()> {
    let bytes = count
        .checked_mul(item_size)
        .ok_or(IpcError::InvalidAddress)?;
    if bytes != 0 && start == 0 {
        return Err(IpcError::InvalidAddress);
    }
    start.checked_add(bytes).ok_or(IpcError::InvalidAddress)?;
    Ok(())
}

/// 统一控制调用的出口：失败只记一次，日志保存正 errno，用户收到负 errno。
fn finish_control_call(
    operation: AuditControlOperation,
    subject: &IpcSubject,
    requested_amount: usize,
    outcome: IpcResult<usize>,
) -> isize {
    match outcome {
        // 成功只可能是 0 或不超过 32 的记录数，不调用 complete，避免自反馈。
        Ok(value) => value as isize,
        Err(error) => {
            audit::record_control_failure(operation, subject, requested_amount, error);
            -(audit::error_to_errno(error) as isize)
        }
    }
}

/// 系统调用 602：返回 sequence > after_sequence 的保留记录，最多 32 条。
///
/// records 是用户地址，只能交给 copy_to_user；内核不能直接解引用它。
/// 返回负值时，用户缓冲区可能已有前缀数据，用户必须保留原游标重试。
pub(crate) fn sys_audit_read(
    records: *mut AuditRecordV1,
    capacity: usize,
    after_sequence: u64,
) -> isize {
    let (subject, token) = caller_context();
    let outcome = read_records(&subject, token, records, capacity, after_sequence);
    finish_control_call(
        AuditControlOperation::AuditRead,
        &subject,
        capacity,
        outcome,
    )
}

fn read_records(
    subject: &IpcSubject,
    token: usize,
    records: *mut AuditRecordV1,
    capacity: usize,
    after_sequence: u64,
) -> IpcResult<usize> {
    check_permission(subject)?;
    if capacity == 0 {
        // 授权调用者可以传空指针；零容量不生成快照，也不访问输出地址。
        return Ok(0);
    }

    // snapshot 内部将容量截断到 32。它返回独立值，返回时审计借用已经释放。
    // 后续复制期间追加的事件不会混入本批次。
    let batch = audit::snapshot(after_sequence, capacity);
    if batch.len == 0 {
        return Ok(0);
    }

    let start = records as usize;
    let record_size = size_of::<AuditRecordV1>();
    // 只检查实际返回的记录范围；capacity 很大并不要求分配或校验整个用户数组。
    check_output_range(start, batch.len, record_size)?;

    for index in 0..batch.len {
        // 逐条构造 80 字节的 ABI 副本，不再在 8 KiB 内核栈上创建第二个批次数组。
        let record = batch.record_at(index).ok_or(IpcError::InvalidArgument)?;
        // 整段范围已经通过 checked_mul/checked_add，以下偏移不会回绕。
        let destination = (start + index * record_size) as *mut AuditRecordV1;
        copy_to_user(token, destination, &record).map_err(|_| IpcError::InvalidAddress)?;
    }

    // 读取不删除日志，也不在内核保存游标。全部复制成功后才报告记录数。
    Ok(batch.len)
}

/// 系统调用 603：返回一个一致的 80 字节统计快照，成功返回 0。
///
/// v1 只接受 flags == 0 和 out_size >= 80；多出的尾部字节保持不变。
pub(crate) fn sys_ipc_stat(stats: *mut IpcStatsV1, out_size: usize, flags: usize) -> isize {
    let (subject, token) = caller_context();
    let outcome = read_stats(&subject, token, stats, out_size, flags);
    finish_control_call(AuditControlOperation::IpcStat, &subject, 0, outcome)
}

fn read_stats(
    subject: &IpcSubject,
    token: usize,
    stats: *mut IpcStatsV1,
    out_size: usize,
    flags: usize,
) -> IpcResult<usize> {
    check_permission(subject)?;
    let struct_size = size_of::<IpcStatsV1>();
    if flags != 0 || out_size < struct_size {
        // 参数错误优先于地址检查，非法 flags 不触碰用户指针。
        return Err(IpcError::InvalidArgument);
    }
    check_output_range(stats as usize, 1, struct_size)?;

    // 全部计数来自一次借用。转换和用户复制都在审计借用释放之后进行。
    let record = audit::stats().to_record();
    copy_to_user(token, stats, &record).map_err(|_| IpcError::InvalidAddress)?;
    Ok(0)
}
