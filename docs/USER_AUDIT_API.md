# 用户态审计 API 设计说明

状态：已按设计接入用户库；内核 602/603 总路由尚待独立提交

对应内核接口：[内核 602/603 系统调用主体](AUDIT_SYSCALLS.md)

二进制契约：[IPC 安全审计 ABI v1](AUDIT_ABI_V1.md)

## 1. 目标与边界

用户态审计 API 为普通用户程序、`auditctl` 和审计测试提供统一入口。它只负责：

- 在用户态声明 ABI v1 的常量和固定布局结构；
- 将 Rust 切片或结构引用转换为 602/603 系统调用参数；
- 原样保留内核返回的成功值或负 errno；
- 帮助调用者正确维护非破坏性读取游标；
- 在遇到未来新增的操作编号或标志位时保持向前兼容。

用户库不负责权限决策、页表校验、日志存储或容量截断。这些语义由内核实现。用户库也不在进程内保存全局游标；每个读取者自行决定从哪个序号开始读取。

首版 API 不依赖堆分配，调用者提供记录数组。这样可在当前 `no_std` 用户库中使用，也不会让日志量决定用户态内存增长。

## 2. 模块分层

计划新增和修改以下文件：

```text
user/src/audit.rs       ABI 类型、常量、安全封装和显示辅助函数
user/src/syscall.rs     602/603 的最低层 ecall 封装
user/src/lib.rs         公开 audit 模块
```

调用关系固定为：

```text
用户程序
  → user_lib::audit::{read, stat}
  → syscall::{sys_audit_read, sys_ipc_stat}
  → ecall
  → 内核 syscall 602/603
```

`user/src/syscall.rs` 继续保持用户库私有。普通程序不直接调用裸系统调用，而是使用 `user_lib::audit`。

为了支持后续恶意地址和非法参数测试，`audit` 模块可以提供明确标记的低级测试入口。低级入口不应被 `auditctl` 或正常业务代码使用。

## 3. 公开常量

用户态重复声明 ABI v1 的稳定常量，不从内核 crate 共享 Rust 类型，避免把内核实现细节引入用户程序。

```rust
pub const AUDIT_ABI_VERSION: u16 = 1;
pub const AUDIT_RECORD_V1_SIZE: u16 = 80;
pub const IPC_STATS_V1_SIZE: u16 = 80;

pub const AUDIT_RECORD_F_GAP_BEFORE: u16 = 1 << 0;

pub const AUDIT_OP_UNSPECIFIED: u16 = 0;
pub const AUDIT_OP_SIGNAL_SEND: u16 = 1;
pub const AUDIT_OP_PIPE_CREATE: u16 = 2;
pub const AUDIT_OP_PIPE_READ: u16 = 3;
pub const AUDIT_OP_PIPE_WRITE: u16 = 4;
pub const AUDIT_OP_AUDIT_READ: u16 = 5;
pub const AUDIT_OP_IPC_STAT: u16 = 6;

pub const AUDIT_OBJECT_NONE: u64 = 0;
pub const AUDIT_UID_UNKNOWN: u32 = u32::MAX;

pub const EPERM: i32 = 1;
pub const ESRCH: i32 = 3;
pub const EAGAIN: i32 = 11;
pub const EFAULT: i32 = 14;
pub const EINVAL: i32 = 22;
pub const EMFILE: i32 = 24;
pub const ENOSPC: i32 = 28;
```

操作编号必须保持为整数常量。不能使用没有数据载荷的封闭 Rust 枚举代替 `u16`，否则未来内核追加操作编号时，旧用户程序可能无法表达该值。

## 4. 用户态 ABI 类型

### 4.1 `AuditRecordV1`

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

### 4.2 `IpcStatsV1`

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

两种类型必须有编译期大小断言：

```rust
const _: [(); AUDIT_RECORD_V1_SIZE as usize] =
    [(); core::mem::size_of::<AuditRecordV1>()];
const _: [(); IPC_STATS_V1_SIZE as usize] =
    [(); core::mem::size_of::<IpcStatsV1>()];
```

所有字段保持公开，便于无堆用户程序读取和格式化。调用者不得写入这些结构后把它们当成内核事件；602/603 都是单向输出接口。

## 5. 底层系统调用封装

`user/src/syscall.rs` 新增编号和两个函数：

```rust
const SYSCALL_AUDIT_READ: usize = 602;
const SYSCALL_IPC_STAT: usize = 603;

pub(crate) fn sys_audit_read(
    records: *mut AuditRecordV1,
    capacity: usize,
    after_sequence: u64,
) -> isize;

pub(crate) fn sys_ipc_stat(
    stats: *mut IpcStatsV1,
    out_size: usize,
    flags: usize,
) -> isize;
```

RV64 上 `usize` 和 `u64` 都是 64 位，`after_sequence` 放入 `a2` 时不截断。`sys_audit_read` 按以下顺序传参：

```text
a0 = records 用户地址
a1 = capacity 记录数量
a2 = after_sequence
a7 = 602
```

`sys_ipc_stat` 按以下顺序传参：

```text
a0 = stats 用户地址
a1 = out_size 字节数
a2 = flags
a7 = 603
```

底层函数只负责寄存器传递，不解释负返回值，也不读取输出指针。

## 6. 面向普通程序的公开 API

首版接口与现有 `user_lib` 的 `read`、`write`、`open` 风格一致，返回内核的 `isize`：

```rust
pub fn read(records: &mut [AuditRecordV1], after_sequence: u64) -> isize;

pub fn stat(stats: &mut IpcStatsV1) -> isize;
```

建议实现：

```rust
pub fn read(records: &mut [AuditRecordV1], after_sequence: u64) -> isize {
    sys_audit_read(records.as_mut_ptr(), records.len(), after_sequence)
}

pub fn stat(stats: &mut IpcStatsV1) -> isize {
    sys_ipc_stat(
        stats as *mut IpcStatsV1,
        core::mem::size_of::<IpcStatsV1>(),
        0,
    )
}
```

切片封装保证地址和记录容量来自同一个 Rust 对象。空切片允许产生非空悬空指针，但内核看到 `capacity == 0` 后不得访问该地址，所以这是合法调用。

`stat` 固定传入精确的 80 字节和 `flags == 0`。普通调用者不能通过该接口意外触发版本不匹配或非法标志。

## 7. 返回值和错误处理

`read` 的返回规则：

- `0`：当前游标之后没有记录；
- `1..=32`：本批成功写入的记录数量；
- 负数：负 errno，缓冲区内容不能视为成功结果。

调用者必须先检查符号，再转换为 `usize`：

```rust
let ret = audit::read(&mut records, cursor);
if ret < 0 {
    println!("audit_read failed: errno={}", -ret);
    return ret as i32;
}
let count = ret as usize;
```

禁止以下写法：

```rust
let count = audit::read(&mut records, cursor) as usize;
```

负返回值表示本批整体失败。即使内核已经复制了前缀记录，调用者也不得展示该前缀、不得推进游标；修复错误后使用原游标重试。

`stat` 成功只返回 0。调用者只能在返回值为 0 时读取 `stats`；失败时原结构可能仍保留初始化值或旧快照。

## 8. 游标使用规则

用户库不隐藏游标。典型的分批读取循环如下：

```rust
let mut cursor = 0u64;
let mut records = [AuditRecordV1::default(); 32];

loop {
    let ret = audit::read(&mut records, cursor);
    if ret < 0 {
        // 不推进 cursor。
        break;
    }
    if ret == 0 {
        break;
    }

    let count = ret as usize;
    for record in &records[..count] {
        // 先处理当前记录，再更新到它的序号。
        cursor = record.sequence;
    }
}
```

调用者必须使用本批最后一条成功处理的 `sequence` 作为下一次 `after_sequence`。不能使用返回数量推算序号，因为覆盖后序号可能存在缺口。

如果第一条记录包含 `AUDIT_RECORD_F_GAP_BEFORE`，表示游标之后的一部分记录已经被覆盖。读取者应提示数据缺口，但仍可处理当前批次并继续推进游标。

## 9. 辅助查询函数

为避免 `auditctl` 和测试重复位运算，`audit.rs` 可以提供无分配辅助函数：

```rust
impl AuditRecordV1 {
    pub const fn succeeded(&self) -> bool {
        self.errno == 0
    }

    pub const fn has_gap_before(&self) -> bool {
        self.flags & AUDIT_RECORD_F_GAP_BEFORE != 0
    }
}

pub const fn operation_name(operation: u16) -> Option<&'static str>;
```

`operation_name` 对 1～6 返回稳定名称，对未知值返回 `None`。调用者在 `None` 分支显示原始数字，例如 `operation=17`，不能 panic，也不能把未知值归并成已有操作。

未知 `flags` 位必须忽略。检查缺口时只测试 `AUDIT_RECORD_F_GAP_BEFORE`，不能要求 `flags` 与该常量完全相等。

## 10. 低级测试入口

独立审计测试需要构造 `flags != 0` 的 603 调用；B 合入后还要构造空指针、跨页和不可写地址。普通 `stat`/`read` 不应暴露这些参数，因此测试入口单独放入子模块：

```rust
pub mod raw {
    pub unsafe fn audit_read(
        records: *mut AuditRecordV1,
        capacity: usize,
        after_sequence: u64,
    ) -> isize;

    pub unsafe fn ipc_stat(
        stats: *mut IpcStatsV1,
        out_size: usize,
        flags: usize,
    ) -> isize;
}
```

这里的 `unsafe` 表示调用者需要自行保证正常调用所需的指针和长度关系：602 的有效输出范围由 `capacity × 80` 决定；603 在 `out_size >= 80` 且 `flags == 0` 时只要求一个可写的 `IpcStatsV1`，因为内核固定只写 80 字节。内核仍必须把恶意地址作为不可信输入处理。`raw` 主要供 `audit_test` 和用户地址攻击测试使用，不能成为 `auditctl` 的常规依赖。

若团队不希望把攻击测试入口纳入公开用户库，也可以让测试程序直接定义局部 `ecall` 封装。首选公开的 `raw` 子模块，因为它能避免多个测试重复系统调用编号和寄存器约定。

## 11. 统计快照的用户态校验

成功取得 `IpcStatsV1` 后，测试和诊断工具至少检查：

```text
abi_version == 1
struct_size == 80
retained <= capacity
total_events == successful_events + failed_events
```

若版本或结构大小未知，工具应报告不兼容并停止解释后续字段。普通库函数不把该情况改写为系统调用错误，因为系统调用本身已经成功；兼容性判断属于数据消费者。

`first_sequence == next_sequence` 只在缓冲区为空时成立。非空时，`first_sequence` 是仍保留的最旧事件，而不是本次读取者的游标。

## 12. `auditctl` 使用约定

后续工具只依赖安全 API：

```text
auditctl stat
  → audit::stat
  → 校验 ABI 和统计不变量
  → 输出容量、保留数、总数、成功数、失败数和覆盖数

auditctl read
  → 使用 32 条栈数组
  → audit::read
  → 检查负返回值
  → 按 sequence 顺序输出
  → 使用最后一条 sequence 继续读取
  → 返回 0 后结束
```

工具只显示安全元数据，不尝试把 `object_id` 当作地址，也不输出用户载荷。未知 UID、未知操作和未知标志必须使用数值或明确占位文本表示。

## 13. 测试计划

### 13.1 用户库编译检查

- 两个结构的大小均为 80；
- 602/603 编号正确；
- `read` 使用切片长度作为记录容量；
- `stat` 固定传 80 字节和零标志；
- 用户库在 `riscv64gc-unknown-none-elf` 下编译。

### 13.2 不依赖 A/B/C 的真实用户态测试

- 成功 `stat` 返回 0；
- `raw::ipc_stat(..., flags = 1)` 返回 `-EINVAL` 并生成失败事件；
- `read` 的返回数量不超过切片长度和单批上限 32；
- 使用最后序号作为游标不会重复读取；
- 覆盖后首条记录具有 `GAP_BEFORE`；
- 成功 `read/stat` 不增加审计事件总数；
- 未知操作编号的显示路径不 panic。

### 13.3 等待集成的测试

- A：非 root、`AUDIT_READ` capability 和 `-EPERM`；
- B：空指针、不可写页、跨页、地址溢出和部分复制；
- C：管道资源 ID、请求/实际字节数及配额失败。

## 14. 实现和提交顺序

建议将用户 API 保持为一个独立提交：

1. 新增 `user/src/audit.rs`；
2. 在 `user/src/syscall.rs` 登记 602/603 和底层函数；
3. 在 `user/src/lib.rs` 添加 `pub mod audit;`；
4. 执行格式检查和 RV64 构建；
5. 检查 diff 中没有内核 ABI、工具或测试的混入。

建议提交信息：

```text
feat: add user audit API
```

验证命令：

```bash
cd user
cargo fmt --all -- --check
cargo build --release

cd ../os
make build
cargo doc --no-deps

cd ..
git diff --check
git status --short
```

## 15. 完成标准

用户态审计 API 设计和实现满足以下条件时完成：

1. 用户结构与 ABI v1 字段、顺序、大小完全一致；
2. 普通 API 不暴露裸指针或可变 `flags`；
3. 空切片调用不会要求可访问的输出地址；
4. 负返回值在转换为记录数量前被检查；
5. 游标只在成功处理记录后推进；
6. 未知操作编号和标志不会导致 panic；
7. 正常接口不进行堆分配，也不保存全局游标；
8. 低级攻击测试入口与正常接口明确隔离；
9. RV64 用户库、内核和文档构建无回退；
10. 没有修改冻结的内核审计 ABI。
