//! 有界 IPC 审计：事件转换、固定 ABI 输出与环形缓冲区。

use core::cmp::max;

use crate::sync::UPSafeCell;
use lazy_static::lazy_static;

use super::{IpcError, IpcOperation, IpcRequest, IpcResult, IpcSubject};

/// 内核最多保留的事件数量。
pub(crate) const AUDIT_RING_CAPACITY: usize = 256;

/// 一次审计读取最多返回的事件数量。
pub(crate) const AUDIT_READ_MAX_RECORDS: usize = 32;

/// 以下常量及结构布局由 docs/AUDIT_ABI_V1.md 冻结。
pub(crate) const AUDIT_ABI_VERSION: u16 = 1;
pub(crate) const AUDIT_RECORD_V1_SIZE: u16 = 80;
pub(crate) const IPC_STATS_V1_SIZE: u16 = 80;
/// 当前批次第一条记录之前，有调用者尚未读取的事件被覆盖。
pub(crate) const AUDIT_RECORD_F_GAP_BEFORE: u16 = 1 << 0;
/// 没有具体资源对象时使用 0；未知所有者不能使用表示 root 的 UID 0。
pub(crate) const AUDIT_OBJECT_NONE: u64 = 0;
pub(crate) const AUDIT_UID_UNKNOWN: u32 = u32::MAX;

pub(crate) const AUDIT_OP_UNSPECIFIED: u16 = 0;
pub(crate) const AUDIT_OP_SIGNAL_SEND: u16 = 1;
pub(crate) const AUDIT_OP_PIPE_CREATE: u16 = 2;
pub(crate) const AUDIT_OP_PIPE_READ: u16 = 3;
pub(crate) const AUDIT_OP_PIPE_WRITE: u16 = 4;
pub(crate) const AUDIT_OP_AUDIT_READ: u16 = 5;
pub(crate) const AUDIT_OP_IPC_STAT: u16 = 6;

/// 复制给用户态的稳定记录，字段顺序和类型必须与 ABI v1 一致。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuditRecordV1 {
    pub(crate) abi_version: u16,      // ABI 版本，固定为 1
    pub(crate) record_size: u16,      // 记录字节数，固定为 80
    pub(crate) operation: u16,        // 稳定操作编号，不是 Rust 枚举判别值
    pub(crate) flags: u16,            // 本次读取相关的记录标志
    pub(crate) errno: i32,            // 成功为 0，失败为正 errno
    pub(crate) subject_uid: u32,      // 发起请求的 UID
    pub(crate) object_owner_uid: u32, // 资源所有者 UID，未知时为 u32::MAX
    pub(crate) reserved0: u32,        // 保留字段，输出时必须为 0
    pub(crate) sequence: u64,         // 本次启动内的事件序号
    pub(crate) timestamp_ms: u64,     // 内核时钟毫秒数，不是 Unix 时间
    pub(crate) subject_pid: u64,      // 发起请求的 PID
    pub(crate) object_id: u64,        // 稳定资源编号，禁止填写内核地址
    pub(crate) requested_amount: u64, // 请求的字节数或资源数量
    pub(crate) result_value: u64,     // 成功时的实际数量，失败时为 0
    pub(crate) reserved1: u64,        // 保留字段，输出时必须为 0
}

/// 复制给用户态的统计快照，各计数来自同一次审计缓冲区借用。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct IpcStatsV1 {
    pub(crate) abi_version: u16,
    pub(crate) struct_size: u16,
    pub(crate) flags: u32,              // v1 固定为 0
    pub(crate) capacity: u64,           // 缓冲区容量
    pub(crate) retained: u64,           // 当前仍保留的事件数量
    pub(crate) first_sequence: u64,     // 最旧序号；空缓冲区等于 next_sequence
    pub(crate) next_sequence: u64,      // 下一条事件将获得的序号
    pub(crate) total_events: u64,       // 累计写入数量
    pub(crate) successful_events: u64,  // 累计成功事件数量
    pub(crate) failed_events: u64,      // 累计失败事件数量
    pub(crate) overwritten_events: u64, // 累计被覆盖数量
    pub(crate) reserved0: u64,          // 保留字段，输出时必须为 0
}

// 在 RV64 内核编译时检查大小，防止误改类型后悄悄破坏用户态 ABI。
const _: [(); 80] = [(); core::mem::size_of::<AuditRecordV1>()];
const _: [(); 80] = [(); core::mem::size_of::<IpcStatsV1>()];

/// 将公共操作类型转换为稳定编号；枚举新增变体时必须补充此映射。
const fn operation_to_audit_id(operation: IpcOperation) -> u16 {
    match operation {
        IpcOperation::SignalSend => AUDIT_OP_SIGNAL_SEND,
        IpcOperation::PipeCreate => AUDIT_OP_PIPE_CREATE,
        IpcOperation::PipeRead => AUDIT_OP_PIPE_READ,
        IpcOperation::PipeWrite => AUDIT_OP_PIPE_WRITE,
        IpcOperation::AuditRead => AUDIT_OP_AUDIT_READ,
    }
}

/// 返回正 errno；系统调用层返回错误时再转换为负 isize。
pub(crate) const fn error_to_errno(error: IpcError) -> i32 {
    match error {
        IpcError::PermissionDenied => 1,   // EPERM：权限不足
        IpcError::ProcessNotFound => 3,    // ESRCH：进程不存在
        IpcError::TryAgain => 11,          // EAGAIN：稍后重试
        IpcError::InvalidAddress => 14,    // EFAULT：用户地址无效
        IpcError::InvalidArgument => 22,   // EINVAL：参数无效
        IpcError::TooManyFiles => 24,      // EMFILE：文件描述符数量超限
        IpcError::ResourceExhausted => 28, // ENOSPC：资源耗尽
    }
}

/// 审计模块内部的控制操作，不向冻结的 IpcOperation 添加 IpcStat 变体。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditControlOperation {
    AuditRead,
    IpcStat,
}

/// 只在内核中保存的事件，不直接复制给用户态。
///
/// 空槽和待写入事件的 sequence 为 0；有效槽由 head 和 len 判定，
/// 正式事件序号统一在 AuditRing::push 中分配。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuditEvent {
    pub(crate) sequence: u64,         // 第几条事件
    pub(crate) timestamp_ms: u64,     // 发生时间
    pub(crate) operation: u16,        // 操作类型
    pub(crate) errno: i32,            // 失败原因，成功为 0
    pub(crate) subject_pid: u64,      // 发起请求的进程 ID
    pub(crate) subject_uid: u32,      // 发起请求的用户 ID
    pub(crate) object_id: u64,        // 请求的对象 ID
    pub(crate) object_owner_uid: u32, // 请求对象的所有者 ID
    pub(crate) requested_amount: u64, // 请求的资源量
    pub(crate) result_value: u64,     // 请求的结果值
}

impl AuditEvent {
    /// 用于初始化环形数组和快照数组的空值，不代表一条已记录的事件。
    pub(crate) const EMPTY: Self = Self {
        sequence: 0,
        timestamp_ms: 0,
        operation: AUDIT_OP_UNSPECIFIED,
        errno: 0,
        subject_pid: 0,
        subject_uid: 0,
        object_id: 0,
        object_owner_uid: 0,
        requested_amount: 0,
        result_value: 0,
    };

    /// 纯数据转换：时间戳由调用者传入，便于独立测试和限制借用范围。
    ///
    /// 调用方负责提供稳定资源 ID、未知所有者哨兵，以及符合操作语义的
    /// 请求数量。当前 RV64 目标的 usize 转为 u64 不会丢失信息。
    pub(crate) const fn from_request(
        request: &IpcRequest,
        outcome: &IpcResult<usize>,
        timestamp_ms: u64,
    ) -> Self {
        let (errno, result_value) = match *outcome {
            Ok(value) => {
                // 信号发送和管道创建成功表示完成 1 次操作；读写保存实际字节数。
                let amount = match request.operation {
                    IpcOperation::SignalSend | IpcOperation::PipeCreate => 1,
                    _ => value as u64,
                };
                (0, amount)
            }
            // 错误码只进入 errno，不能混入成功数量或转换成巨大的无符号数。
            Err(error) => (error_to_errno(error), 0),
        };

        Self {
            sequence: 0,
            timestamp_ms,
            operation: operation_to_audit_id(request.operation),
            errno,
            subject_pid: request.subject.pid as u64,
            subject_uid: request.subject.uid,
            object_id: request.object.id,
            object_owner_uid: request.object.owner_uid,
            requested_amount: request.amount as u64,
            result_value,
        }
    }

    /// 构造审计控制调用的失败事件，统计查询的请求数量固定为 0。
    const fn from_control_failure(
        operation: AuditControlOperation,
        subject: &IpcSubject,
        requested_amount: usize,
        error: IpcError,
        timestamp_ms: u64,
    ) -> Self {
        let (operation, requested_amount) = match operation {
            AuditControlOperation::AuditRead => (AUDIT_OP_AUDIT_READ, requested_amount as u64),
            AuditControlOperation::IpcStat => (AUDIT_OP_IPC_STAT, 0),
        };

        Self {
            sequence: 0,
            timestamp_ms,
            operation,
            errno: error_to_errno(error),
            subject_pid: subject.pid as u64,
            subject_uid: subject.uid,
            object_id: AUDIT_OBJECT_NONE,
            object_owner_uid: AUDIT_UID_UNKNOWN,
            requested_amount,
            result_value: 0,
        }
    }

    /// 转换成用户态 ABI 副本；覆盖标志仅影响副本，不修改内部事件。
    pub(crate) const fn to_record(&self, gap_before: bool) -> AuditRecordV1 {
        AuditRecordV1 {
            abi_version: AUDIT_ABI_VERSION,
            record_size: AUDIT_RECORD_V1_SIZE,
            operation: self.operation,
            flags: if gap_before {
                AUDIT_RECORD_F_GAP_BEFORE
            } else {
                0
            },
            errno: self.errno,
            subject_uid: self.subject_uid,
            object_owner_uid: self.object_owner_uid,
            reserved0: 0,
            sequence: self.sequence,
            timestamp_ms: self.timestamp_ms,
            subject_pid: self.subject_pid,
            object_id: self.object_id,
            requested_amount: self.requested_amount,
            result_value: self.result_value,
            reserved1: 0,
        }
    }
}

/// 不包含借用的有界事件快照。
///
/// 系统调用层取得快照后，再逐条转换 ABI 记录并复制到用户内存。
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

    /// 只转换有效记录，覆盖标志最多设置在本批次的第一条记录上。
    /// 逐条转换可避免在 8 KiB 内核栈上再放置一整批 ABI 数组。
    pub(crate) fn record_at(&self, index: usize) -> Option<AuditRecordV1> {
        if index >= self.len {
            return None;
        }
        self.events
            .get(index)
            .map(|event| event.to_record(index == 0 && self.gap_before))
    }
}

/// 来自同一临界区、各字段相互一致的统计快照。
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

impl AuditStatsSnapshot {
    /// 只转换已有快照，不重新访问全局统计，避免混入不同时间的计数。
    pub(crate) const fn to_record(&self) -> IpcStatsV1 {
        IpcStatsV1 {
            abi_version: AUDIT_ABI_VERSION,
            struct_size: IPC_STATS_V1_SIZE,
            flags: 0,
            capacity: self.capacity,
            retained: self.retained,
            first_sequence: self.first_sequence,
            next_sequence: self.next_sequence,
            total_events: self.total_events,
            successful_events: self.successful_events,
            failed_events: self.failed_events,
            overwritten_events: self.overwritten_events,
            reserved0: 0,
        }
    }
}

/// 固定容量的环形缓冲区，只保留最近的事件。
struct AuditRing {
    events: [AuditEvent; AUDIT_RING_CAPACITY],
    /// 最旧事件所在的数组下标。
    head: usize,
    /// 当前有效事件数量。
    len: usize,
    /// 下一条接受写入的事件序号。
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

    /// 写入事件，缓冲区满时覆盖最旧事件。
    ///
    /// 序号耗尽时停止接受新事件，避免回绕和重复使用序号。
    /// 无论审计是否写入，调用方的 IPC 操作结果都不能改变。
    fn push(&mut self, mut event: AuditEvent) {
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            return;
        };
        event.sequence = self.next_sequence;
        self.next_sequence = next_sequence;
        // 未满使用空槽，满了就覆盖最老的事件。
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

    /// 返回最旧序号，空缓冲区返回下一条序号。
    fn first_sequence(&self) -> u64 {
        if self.len == 0 {
            self.next_sequence
        } else {
            self.events[self.head].sequence
        }
    }

    /// 按游标生成非破坏性快照，读取不会删除记录或修改统计。
    fn snapshot(&self, after_sequence: u64, requested_capacity: usize) -> AuditBatch {
        let limit = requested_capacity.min(AUDIT_READ_MAX_RECORDS);
        if limit == 0 || self.len == 0 || after_sequence == u64::MAX {
            return AuditBatch::empty();
        }

        // 上面已排除 u64::MAX，因此加 1 不会溢出。
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

    /// 在一次借用中复制全部统计，保持字段间的不变量。
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
    /// 当前单核内核的全局审计状态；借用期间禁止调度或访问用户内存。
    static ref AUDIT_RING: UPSafeCell<AuditRing> =
        unsafe { UPSafeCell::new(AuditRing::new()) };
}

/// 返回值快照；函数返回时审计缓冲区的借用已经释放。
pub(crate) fn snapshot(after_sequence: u64, requested_capacity: usize) -> AuditBatch {
    let ring = AUDIT_RING.exclusive_access();
    ring.snapshot(after_sequence, requested_capacity)
}

/// 返回统计值快照，不记录查询自身。
pub(crate) fn stats() -> AuditStatsSnapshot {
    let ring = AUDIT_RING.exclusive_access();
    ring.stats()
}

/// 记录 IPC 结果，不修改或替换调用方持有的原始结果。
///
/// 时钟读取和事件转换都在借用环形缓冲区之前完成。
pub(crate) fn record(request: &IpcRequest, outcome: &IpcResult<usize>) {
    // 成功读取不生成新记录，避免读取者永远追不上日志尾部。
    if matches!(request.operation, IpcOperation::AuditRead) && outcome.is_ok() {
        return;
    }

    let timestamp_ms = crate::timer::get_time_ms() as u64;
    let event = AuditEvent::from_request(request, outcome, timestamp_ms);
    let mut ring = AUDIT_RING.exclusive_access();
    ring.push(event);
}

/// 审计读取/统计的失败专用入口；成功的控制调用不应调用此函数。
/// 同一次失败只选择一个记录入口，避免与 record 重复记录。
pub(crate) fn record_control_failure(
    operation: AuditControlOperation,
    subject: &IpcSubject,
    requested_amount: usize,
    error: IpcError,
) {
    let timestamp_ms = crate::timer::get_time_ms() as u64;
    let event =
        AuditEvent::from_control_failure(operation, subject, requested_amount, error, timestamp_ms);
    let mut ring = AUDIT_RING.exclusive_access();
    ring.push(event);
}
