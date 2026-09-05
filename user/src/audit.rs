//! 用户态 IPC 安全审计接口。
//!
//! 普通程序应使用 [`read`] 和 [`stat`]。[`raw`] 只用于构造非法参数的
//! 安全边界测试，不应成为审计工具的常规调用入口。

use core::mem::size_of;

use crate::syscall::{sys_audit_read, sys_ipc_stat};

/// 当前审计 ABI 版本。
pub const AUDIT_ABI_VERSION: u16 = 1;
/// `AuditRecordV1` 的固定字节数。
pub const AUDIT_RECORD_V1_SIZE: u16 = 80;
/// `IpcStatsV1` 的固定字节数。
pub const IPC_STATS_V1_SIZE: u16 = 80;

/// 当前记录之前存在已被覆盖的序号区间。
pub const AUDIT_RECORD_F_GAP_BEFORE: u16 = 1 << 0;

/// 未分类或旧实现无法识别的操作。
pub const AUDIT_OP_UNSPECIFIED: u16 = 0;
/// 发送进程信号。
pub const AUDIT_OP_SIGNAL_SEND: u16 = 1;
/// 创建管道。
pub const AUDIT_OP_PIPE_CREATE: u16 = 2;
/// 从管道读取。
pub const AUDIT_OP_PIPE_READ: u16 = 3;
/// 向管道写入。
pub const AUDIT_OP_PIPE_WRITE: u16 = 4;
/// 审计读取失败或拒绝事件。
pub const AUDIT_OP_AUDIT_READ: u16 = 5;
/// IPC 统计查询失败或拒绝事件。
pub const AUDIT_OP_IPC_STAT: u16 = 6;

/// 没有具体审计对象。
pub const AUDIT_OBJECT_NONE: u64 = 0;
/// 资源所有者未知。
pub const AUDIT_UID_UNKNOWN: u32 = u32::MAX;

/// Permission denied。
pub const EPERM: i32 = 1;
/// No such process。
pub const ESRCH: i32 = 3;
/// Try again。
pub const EAGAIN: i32 = 11;
/// Bad address。
pub const EFAULT: i32 = 14;
/// Invalid argument。
pub const EINVAL: i32 = 22;
/// Too many open files。
pub const EMFILE: i32 = 24;
/// No space left for the requested IPC resource。
pub const ENOSPC: i32 = 28;

/// ABI v1 的单条审计记录。
///
/// `operation` 和 `flags` 保留为整数，确保旧程序可以接收未来追加的值。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AuditRecordV1 {
    pub abi_version: u16,
    pub record_size: u16,
    pub operation: u16,
    pub flags: u16,
    pub errno: i32,
    pub subject_uid: u32,
    pub object_owner_uid: u32,
    pub reserved0: u32,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub subject_pid: u64,
    pub object_id: u64,
    pub requested_amount: u64,
    pub result_value: u64,
    pub reserved1: u64,
}

impl AuditRecordV1 {
    /// 本次被审计操作是否成功。
    pub const fn succeeded(&self) -> bool {
        self.errno == 0
    }

    /// 此记录之前是否存在已被覆盖、无法读取的事件。
    pub const fn has_gap_before(&self) -> bool {
        self.flags & AUDIT_RECORD_F_GAP_BEFORE != 0
    }
}

/// ABI v1 的审计统计快照。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IpcStatsV1 {
    pub abi_version: u16,
    pub struct_size: u16,
    pub flags: u32,
    pub capacity: u64,
    pub retained: u64,
    pub first_sequence: u64,
    pub next_sequence: u64,
    pub total_events: u64,
    pub successful_events: u64,
    pub failed_events: u64,
    pub overwritten_events: u64,
    pub reserved0: u64,
}

const _: [(); AUDIT_RECORD_V1_SIZE as usize] = [(); size_of::<AuditRecordV1>()];
const _: [(); IPC_STATS_V1_SIZE as usize] = [(); size_of::<IpcStatsV1>()];

/// 返回已知审计操作的稳定名称；未知编号原样留给调用者显示。
pub const fn operation_name(operation: u16) -> Option<&'static str> {
    match operation {
        AUDIT_OP_UNSPECIFIED => Some("unspecified"),
        AUDIT_OP_SIGNAL_SEND => Some("signal_send"),
        AUDIT_OP_PIPE_CREATE => Some("pipe_create"),
        AUDIT_OP_PIPE_READ => Some("pipe_read"),
        AUDIT_OP_PIPE_WRITE => Some("pipe_write"),
        AUDIT_OP_AUDIT_READ => Some("audit_read"),
        AUDIT_OP_IPC_STAT => Some("ipc_stat"),
        _ => None,
    }
}

/// 读取序号严格大于 `after_sequence` 的审计记录。
///
/// 返回值为 `0..=records.len()` 时表示成功；负值为负 errno。调用者只能在
/// 返回值非负后把它转换为 `usize`，并使用最后一条已处理记录的序号推进游标。
pub fn read(records: &mut [AuditRecordV1], after_sequence: u64) -> isize {
    sys_audit_read(records.as_mut_ptr(), records.len(), after_sequence)
}

/// 读取 ABI v1 的审计统计快照。
///
/// 成功返回 0。失败返回负 errno，此时调用者不能把 `stats` 当作新快照使用。
pub fn stat(stats: &mut IpcStatsV1) -> isize {
    sys_ipc_stat(stats as *mut IpcStatsV1, size_of::<IpcStatsV1>(), 0)
}

/// 用于系统调用边界测试的低级接口。
///
/// 这里允许测试传入非法地址、长度和标志；普通程序应使用 [`read`] 和 [`stat`]。
pub mod raw {
    use super::{AuditRecordV1, IpcStatsV1};
    use crate::syscall::{sys_audit_read, sys_ipc_stat};

    /// 使用未经切片约束的参数调用系统调用 602。
    ///
    /// # Safety
    ///
    /// 正常调用时，`records` 必须指向至少 `capacity` 个可写的
    /// `AuditRecordV1`。故意违反该约束只能用于验证内核的用户地址防护。
    pub unsafe fn audit_read(
        records: *mut AuditRecordV1,
        capacity: usize,
        after_sequence: u64,
    ) -> isize {
        sys_audit_read(records, capacity, after_sequence)
    }

    /// 使用未经安全封装固定的参数调用系统调用 603。
    ///
    /// # Safety
    ///
    /// 正常调用且 `out_size >= 80`、`flags == 0` 时，`stats` 必须指向至少一个
    /// 可写的 `IpcStatsV1`。故意传入非法参数只能用于验证内核的系统调用边界。
    pub unsafe fn ipc_stat(stats: *mut IpcStatsV1, out_size: usize, flags: usize) -> isize {
        sys_ipc_stat(stats, out_size, flags)
    }
}
