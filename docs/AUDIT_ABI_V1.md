# IPC 安全审计 ABI v1

状态：**实现基线（v1）**

适用架构：rCore 当前的 RV64 用户态/内核态系统调用边界

负责人：开发者 D（审计、测试与持续集成）

本文冻结审计日志在内核与用户程序之间的二进制契约。实现可以调整内部环形缓冲区、锁和辅助类型，但不得改变本文规定的结构布局、操作编号、读取语义和返回规则。后续变更必须提交独立的 API change PR，并按项目规则获得至少两名非作者成员批准。

## 1. 设计目标

- 审计不得改变原 IPC 操作的结果；
- 用户地址错误不得造成内核 panic 或日志丢失；
- 日志有界，缓冲区满时覆盖最旧记录；
- 不向用户态暴露 Rust 内部枚举、指针或不稳定布局；
- 支持按序号增量读取，不在内核保存每个读取者的游标；
- 记录安全元数据，不记录管道内容、用户缓冲区或其他敏感载荷。

## 2. 常量和版本

用户库和内核使用以下常量：

```rust
pub const AUDIT_ABI_VERSION: u16 = 1;
pub const AUDIT_RECORD_V1_SIZE: u16 = 80;
pub const IPC_STATS_V1_SIZE: u16 = 80;

pub const AUDIT_RECORD_F_GAP_BEFORE: u16 = 1 << 0;

pub const AUDIT_OBJECT_NONE: u64 = 0;
pub const AUDIT_UID_UNKNOWN: u32 = u32::MAX;
```

参考实现使用 256 条记录的固定容量环形缓冲区，并且每次系统调用最多复制 32 条。用户程序不得硬编码缓冲区容量，应通过 `ipc_stat` 查询；当请求数量超过单次实现上限时，内核可以只返回前一批记录。

## 3. 稳定操作编号

审计 ABI 使用显式整数，不直接复制 `IpcOperation` 的 Rust 枚举判别值。

| 值 | 名称 | 含义 |
| ---: | --- | --- |
| 0 | `AUDIT_OP_UNSPECIFIED` | 未分类或旧实现无法识别 |
| 1 | `AUDIT_OP_SIGNAL_SEND` | 发送进程信号 |
| 2 | `AUDIT_OP_PIPE_CREATE` | 创建管道 |
| 3 | `AUDIT_OP_PIPE_READ` | 从管道读取 |
| 4 | `AUDIT_OP_PIPE_WRITE` | 向管道写入 |
| 5 | `AUDIT_OP_AUDIT_READ` | 审计读取失败或拒绝事件 |
| 6 | `AUDIT_OP_IPC_STAT` | IPC 统计查询失败或拒绝事件 |

新增操作只能追加新编号，禁止改变或复用已有编号。

## 4. `AuditRecordV1`

内核和用户库必须使用相同的 `#[repr(C)]` 结构：

```rust
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
```

字段布局固定为 80 字节：

| 偏移 | 字段 | 语义 |
| ---: | --- | --- |
| 0 | `abi_version` | 固定为 `1` |
| 2 | `record_size` | 固定为 `80` |
| 4 | `operation` | 第 3 节定义的稳定操作编号 |
| 6 | `flags` | 记录标志；未知位由读取者忽略 |
| 8 | `errno` | 成功为 0，失败为正的 errno 值 |
| 12 | `subject_uid` | 发起操作的 UID |
| 16 | `object_owner_uid` | 目标所有者 UID；未知时为 `u32::MAX` |
| 20 | `reserved0` | 必须写 0 |
| 24 | `sequence` | 本次启动期间单调递增的事件序号，从 1 开始 |
| 32 | `timestamp_ms` | 自内核启动后的毫秒数，不是 Unix 时间 |
| 40 | `subject_pid` | 发起操作的进程 PID |
| 48 | `object_id` | 稳定资源 ID；没有具体对象时为 0，不得填写内核地址 |
| 56 | `requested_amount` | 请求的字节数或资源数量 |
| 64 | `result_value` | 成功后的实际字节数/数量；失败时为 0 |
| 72 | `reserved1` | 必须写 0 |

`errno == 0` 表示成功；`errno != 0` 表示失败。`result_value` 不承载错误码。

### 4.1 资源字段约定

| 操作 | `object_id` | `requested_amount` | `result_value` |
| --- | --- | ---: | ---: |
| 信号发送 | 目标 PID | 1 | 成功时 1 |
| 管道创建 | 已有稳定 ID 时填管道 ID，否则 0 | 1 | 成功时 1 |
| 管道读写 | 管道的稳定 `ResourceId` | 请求字节数 | 实际读写字节数 |
| 审计读取 | 0（全局审计对象） | 用户请求的记录数 | 实际复制的记录数 |
| IPC 统计 | 0（全局审计对象） | 0 | 0 |

管道资源 ID 必须来自内核维护的稳定编号，禁止将 `Arc`、裸指针或物理地址暴露给用户态。

### 4.2 记录标志

`AUDIT_RECORD_F_GAP_BEFORE` 只可能出现在一次 `audit_read` 返回的第一条记录上，表示调用者的游标早于当前仍保留的最旧事件，中间记录已经被环形缓冲区覆盖。该标志可以在生成用户态副本时设置，不需要改变内核保存的原始事件。

## 5. `IpcStatsV1`

`ipc_stat` 返回以下固定布局：

```rust
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
```

结构大小固定为 80 字节，约束如下：

- `abi_version == 1`，`struct_size == 80`，`flags == 0`；
- `retained <= capacity`；
- `total_events == successful_events + failed_events`；
- `overwritten_events` 表示因容量不足而被覆盖的累计记录数；
- 缓冲区非空时，`first_sequence` 是仍保留的最旧序号；
- 缓冲区为空时，`first_sequence == next_sequence`；
- `next_sequence` 是下一条事件将获得的序号；
- `reserved0` 必须写 0。

## 6. 系统调用 602：`audit_read`

RV64 用户 ABI：

```rust
pub fn audit_read(
    records: *mut AuditRecordV1,
    capacity: usize,
    after_sequence: u64,
) -> isize;
```

寄存器约定：

| 寄存器 | 内容 |
| --- | --- |
| `a7` | 602 |
| `a0` | `records` 用户地址 |
| `a1` | 数组容量，单位是记录而不是字节 |
| `a2` | 调用者已经处理的最后一个序号 |

### 6.1 读取语义

1. 返回所有满足 `sequence > after_sequence` 的保留记录，按序号升序；
2. `after_sequence == 0` 表示从当前仍保留的最旧记录开始；
3. 读取是非破坏性的，不从环形缓冲区删除记录；
4. 返回值大于 0 时，调用者以最后一条记录的 `sequence` 作为下一次游标；
5. 没有新记录时返回 0；
6. `capacity == 0` 时返回 0，且不访问 `records`；
7. 请求超过单次复制上限时只返回当前批次，调用者继续使用游标读取；
8. 如果游标对应的下一条记录已经被覆盖，从当前最旧记录开始返回，并在第一条记录设置 `AUDIT_RECORD_F_GAP_BEFORE`；
9. 系统调用开始后新产生的事件不进入本次快照；
10. 成功读取不向同一个环形缓冲区追加事件，避免监控程序每次读取都制造一条新记录而永远无法追上日志尾部；权限拒绝、无效参数和地址错误仍记录为 `AUDIT_OP_AUDIT_READ` 失败事件。

内核必须在释放审计缓冲区借用后复制到用户地址。若用户地址在部分复制后失败，返回 `-EFAULT`；用户缓冲区可能已有前缀数据，但日志不会丢失，调用者不得在负返回值时推进游标。

### 6.2 返回值

| 返回值 | 含义 |
| ---: | --- |
| `0..N` | 成功复制的记录数 |
| `-EPERM` | 调用者既不是 UID 0，也没有 `AUDIT_READ` capability |
| `-EFAULT` | 用户输出范围无效、不可写或地址计算溢出 |
| `-EINVAL` | 参数组合或 ABI 值无效 |

## 7. 系统调用 603：`ipc_stat`

RV64 用户 ABI：

```rust
pub fn ipc_stat(
    stats: *mut IpcStatsV1,
    out_size: usize,
    flags: usize,
) -> isize;
```

寄存器约定：

| 寄存器 | 内容 |
| --- | --- |
| `a7` | 603 |
| `a0` | `stats` 用户地址 |
| `a1` | 用户缓冲区字节数 |
| `a2` | v1 必须为 0 |

v1 要求 `out_size >= 80`。内核只写前 80 字节，较大的尾部保持不变。成功返回 0；失败返回 `-EPERM`、`-EFAULT` 或 `-EINVAL`。该调用与 `audit_read` 使用相同的读取权限。成功查询不向同一个环形缓冲区追加事件；失败查询记录为 `AUDIT_OP_IPC_STAT`，避免统计工具自身持续污染统计结果。

## 8. 权限模型

以下任一条件成立即可调用 602/603：

- 调用者 UID 为 0；
- 调用者 capability 集合包含 `CapabilitySet::AUDIT_READ`。

权限拒绝本身也必须生成失败审计事件，但不得向无权限调用者返回其他进程的日志或统计内容。

## 9. errno 数值

审计 ABI 使用稳定的 Linux/RISC-V errno 数值。系统调用失败返回负值，`AuditRecordV1.errno` 保存对应的正值。

| 名称 | 数值 | 对应 `IpcError` |
| --- | ---: | --- |
| `EPERM` | 1 | `PermissionDenied` |
| `ESRCH` | 3 | `ProcessNotFound` |
| `EAGAIN` | 11 | `TryAgain` |
| `EFAULT` | 14 | `InvalidAddress` |
| `EINVAL` | 22 | `InvalidArgument` |
| `EMFILE` | 24 | `TooManyFiles` |
| `ENOSPC` | 28 | `ResourceExhausted` |

该数值约定首先约束新建的 602/603 接口，不要求为了统一数值而改变 rCore 已有系统调用的历史行为。

## 10. 必须记录与不记录的范围

必须记录：

- 进入安全门面的 IPC 成功操作；
- 授权拒绝、配额拒绝和实际 IPC 失败；
- `audit_read`、`ipc_stat` 的权限拒绝、无效参数和地址错误；
- 能安全构造 `IpcRequest` 的无效参数和用户地址错误。

不属于 v1 强制范围：

- 未知系统调用、普通页故障和非 IPC 异常；
- 内核启动日志和驱动日志；
- 还未形成安全请求就终止的严重 Trap；
- 管道载荷、文件内容、用户字符串和内核地址。

当前 `security::preflight` 在失败时无法返回 `IpcPermit`，实现阶段必须保证授权/配额失败在返回前直接写入一次失败事件，或者通过单独批准的门面调整达到相同语义，不能只记录成功通过 `preflight` 的操作。

## 11. 锁和故障约束

- 审计内部借用期间不得访问用户内存、调度、阻塞或再次进入安全门面；
- 先在短临界区内生成最多一批记录的快照，释放借用后再执行 `copy_to_user`；
- `audit::record` 不得动态无限增长、不得 `unwrap` 用户数据、不得改变原操作结果；
- 缓冲区满时覆盖最旧记录，同时更新 `overwritten_events`；
- 统计计数和记录序号在一次启动期间不得复用；
- 预留字段写 0，读取者必须忽略未知记录标志，便于未来扩展。

## 12. 版本演进规则

- v1 字段不得重排、删除或改变语义；
- 新操作编号只能追加；
- 兼容扩展优先使用预留字段或新结构版本；
- 不兼容变更必须提高 `abi_version`，同步更新内核、用户库、测试与本文档；
- 内核和用户库应加入 `size_of::<AuditRecordV1>() == 80` 与 `size_of::<IpcStatsV1>() == 80` 的编译期或测试断言。

## 13. 验收测试

实现至少通过以下场景：

1. 空日志读取返回 0；
2. 多条记录按递增序号返回，游标不会重复读取；
3. 缓冲区覆盖后首条设置 `GAP_BEFORE`，统计的覆盖数正确；
4. `capacity == 0` 不访问空指针；
5. 无权限读取返回 `-EPERM` 且不泄露数据；
6. 不可写、跨页和溢出地址返回 `-EFAULT`，内核继续运行；
7. 部分复制失败后使用原游标可以重新读取；
8. `ipc_stat` 的计数不变量成立；
9. 成功的 `audit_read`、`ipc_stat` 不产生反馈事件，失败访问能够被后续读取；
10. 原有 rCore 用户测试继续通过。
