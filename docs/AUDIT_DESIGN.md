# IPC 安全审计内部设计

状态：实现设计（对应审计 ABI v1）

负责人：开发者 D（审计、测试与持续集成）

## 1. 文档目的

本文描述 rCore Secure IPC 的内核审计实现方案，包括内部事件模型、有界环形缓冲区、序号游标、覆盖检测、统计快照、锁范围、失败记录路径以及系统调用 602/603 的实现边界。

用户态可见的二进制布局、操作编号和错误码以 [IPC 安全审计 ABI v1](AUDIT_ABI_V1.md) 为唯一契约。本文只约束内部实现，不改变已经冻结的 ABI。

## 2. 设计目标与非目标

### 2.1 设计目标

- 审计存储占用固定且有上限，不能随事件数量无限增长；
- 每条已接受事件获得本次启动期间唯一且递增的序号；
- 缓冲区满后覆盖最旧记录，并让读取者能够检测数据缺口；
- 审计记录失败不能改变原 IPC 操作的返回值；
- 读取为非破坏性操作，内核不维护每个读取者的游标；
- 持有审计缓冲区借用时不访问用户内存、不调度、不阻塞；
- 用户态只能看到稳定编号和安全元数据，不能看到 Rust 枚举布局、用户载荷或内核地址；
- 成功的审计读取和统计查询不制造自反馈事件；
- 授权拒绝、配额拒绝以及审计系统调用自身失败均能形成失败记录。

### 2.2 非目标

- 不提供日志持久化，重启后序号和记录重新开始；
- 不提供按用户、PID 或操作类型的内核侧过滤；
- 不为每个读取者保存状态；
- 不审计普通文件内容、管道载荷、用户字符串、页故障或未知系统调用；
- 不实现多核并发审计。本项目当前使用单核 rCore 和 `UPSafeCell`；若以后支持 SMP，需要替换同步原语并重新审查锁顺序。

## 3. 固定参数

内核实现使用以下固定参数：

```rust
const AUDIT_RING_CAPACITY: usize = 256;
const AUDIT_READ_MAX_RECORDS: usize = 32;
```

- 环形缓冲区固定保存 256 条事件；
- 一次 `audit_read` 最多返回 32 条；
- 用户程序不得假定容量恒为 256，必须通过 `ipc_stat` 查询；
- 请求容量超过 32 时不是错误，内核只返回当前批次，用户程序使用新游标继续读取。

按照 80 字节的 ABI 记录估算，即使内部直接保存同等大小的数据，缓冲区上限也只有 20 KiB。实际内部事件不保存 ABI 头部和保留字段，占用通常更小。

## 4. 内部数据模型

### 4.1 `AuditEvent`

`AuditEvent` 是仅在内核中使用的语义事件，不直接复制给用户态。建议字段如下：

```rust
#[derive(Clone, Copy)]
struct AuditEvent {
    sequence: u64,
    timestamp_ms: u64,
    operation: u16,
    errno: i32,
    subject_pid: u64,
    subject_uid: u32,
    object_id: u64,
    object_owner_uid: u32,
    requested_amount: u64,
    result_value: u64,
}
```

实现提供一个全零的 `EMPTY` 常量，用于初始化固定数组。数组槽是否有效只由 `AuditRing.head` 和 `AuditRing.len` 决定，不能把 `sequence == 0` 作为唯一有效性判断。

`operation` 保存审计 ABI 的稳定整数，而不是 `IpcOperation` 的 Rust 判别值。这样未来调整内部枚举顺序不会破坏用户态兼容性。

### 4.2 ABI 输出结构

内核定义与 ABI 完全一致的 `#[repr(C)]` 类型：

- `AuditRecordV1`：80 字节；
- `IpcStatsV1`：80 字节。

内核和用户库都必须加入编译期大小断言：

```rust
const _: [(); 80] = [(); core::mem::size_of::<AuditRecordV1>()];
const _: [(); 80] = [(); core::mem::size_of::<IpcStatsV1>()];
```

所有保留字段写 0。生成 `AuditRecordV1` 时才填写 `abi_version`、`record_size` 和读取视图相关的 `flags`。

### 4.3 `AuditRing`

建议结构如下：

```rust
struct AuditRing {
    events: [AuditEvent; AUDIT_RING_CAPACITY],
    head: usize,
    len: usize,
    next_sequence: u64,
    total_events: u64,
    successful_events: u64,
    failed_events: u64,
    overwritten_events: u64,
}
```

字段语义：

- `head`：当前最旧有效事件所在的数组下标；
- `len`：当前保留的事件数，始终满足 `len <= AUDIT_RING_CAPACITY`；
- `next_sequence`：下一条被接受事件的序号，初值为 1；
- `total_events`：已成功写入环形缓冲区的事件总数；
- `successful_events`：其中 `errno == 0` 的数量；
- `failed_events`：其中 `errno != 0` 的数量；
- `overwritten_events`：由于容量已满而被覆盖的历史事件数量。

始终保持以下不变量：

```text
len <= AUDIT_RING_CAPACITY
total_events == successful_events + failed_events
len == 0  => first_sequence == next_sequence
len > 0   => first_sequence == events[head].sequence
```

## 5. 事件写入与覆盖算法

### 5.1 序号分配

事件序号在 `push` 的同一个临界区内分配：

1. 读取当前 `next_sequence` 作为新事件序号；
2. 将 `next_sequence` 增加 1；
3. 写入数组并更新统计。

序号从 1 开始，0 表示读取者尚未处理任何事件。序号在一次启动期间不得复用。

`u64` 在本项目运行周期内不可能实际耗尽。实现仍应使用 `checked_add` 防止回绕；若序号已达到 `u64::MAX`，停止接受新审计事件并直接返回，不得复用旧序号，也不得影响原 IPC 操作结果。

### 5.2 缓冲区未满

当 `len < AUDIT_RING_CAPACITY` 时：

```text
index = (head + len) % AUDIT_RING_CAPACITY
events[index] = new_event
len += 1
```

### 5.3 缓冲区已满

当 `len == AUDIT_RING_CAPACITY` 时：

```text
events[head] = new_event
head = (head + 1) % AUDIT_RING_CAPACITY
overwritten_events += 1
```

此时 `len` 保持不变。覆盖只删除当前最旧事件，不改变新事件的序号，也不减少累计成功、失败或总事件计数。

### 5.4 成功与失败统计

每次成功插入事件时：

- `total_events += 1`；
- `errno == 0` 时 `successful_events += 1`；
- `errno != 0` 时 `failed_events += 1`。

必须在一次 `push` 中完成上述更新，避免记录与统计不一致。

## 6. 事件转换

### 6.1 操作编号

`IpcOperation` 到稳定审计编号的映射必须使用显式 `match`：

| 内部操作 | 审计编号 |
| --- | ---: |
| `SignalSend` | 1 |
| `PipeCreate` | 2 |
| `PipeRead` | 3 |
| `PipeWrite` | 4 |
| `AuditRead` | 5 |
| `ipc_stat` 内部控制事件 | 6 |

当前公共 `IpcOperation` 没有 `IpcStat` 变体。为避免修改冻结 API，`ipc_stat` 失败由审计模块内部的控制事件辅助函数记录，并直接使用稳定编号 6。不能为了该事件私自修改 `security/api.rs`。

### 6.2 errno 映射

`IpcError` 显式映射到正 errno：

| `IpcError` | errno |
| --- | ---: |
| `PermissionDenied` | 1 (`EPERM`) |
| `ProcessNotFound` | 3 (`ESRCH`) |
| `TryAgain` | 11 (`EAGAIN`) |
| `InvalidAddress` | 14 (`EFAULT`) |
| `InvalidArgument` | 22 (`EINVAL`) |
| `TooManyFiles` | 24 (`EMFILE`) |
| `ResourceExhausted` | 28 (`ENOSPC`) |

成功事件保存 `errno = 0` 和实际 `result_value`。失败事件保存正 errno，并强制 `result_value = 0`。系统调用返回错误时再对 errno 取负数。

### 6.3 字段来源

- `timestamp_ms`：在进入审计锁前调用 `timer::get_time_ms()`；
- `subject_pid`、`subject_uid`：来自 `IpcRequest.subject`；
- `object_id`：来自稳定 `ResourceId`，没有对象时写 `AUDIT_OBJECT_NONE`；
- `object_owner_uid`：已知时来自 `IpcRequest.object.owner_uid`，未知时写 `AUDIT_UID_UNKNOWN`；
- `requested_amount`：来自 `IpcRequest.amount`；
- `result_value`：成功时来自 IPC 操作的实际返回数量，失败时为 0。

禁止把 `Arc` 地址、裸指针、物理地址或用户缓冲区内容写入事件。

## 7. 读取快照与游标语义

### 7.1 有界快照

`audit_read` 在内核栈上使用固定批次缓冲区：

```rust
struct AuditBatch {
    records: [AuditRecordV1; AUDIT_READ_MAX_RECORDS],
    len: usize,
}
```

最大占用约 2.5 KiB，低于当前 8 KiB 内核栈大小。不得在一次读取中按用户提供的 `capacity` 进行无界分配。

实际批次上限为：

```text
limit = min(user_capacity, AUDIT_READ_MAX_RECORDS)
```

### 7.2 定位第一条记录

读取目标是所有满足 `sequence > after_sequence` 的保留事件。

1. 缓冲区为空时直接返回空批次；
2. `after_sequence == u64::MAX` 时直接返回空批次；
3. 计算 `wanted = after_sequence + 1`；
4. 取得当前 `first_sequence`；
5. 以 `max(wanted, first_sequence)` 作为返回起点；
6. 从环形数组中按序号升序复制，直到达到 `limit` 或日志尾部。

如果 `wanted < first_sequence`，说明读取者需要的下一条记录已被覆盖。本次返回的第一条 `AuditRecordV1` 设置 `AUDIT_RECORD_F_GAP_BEFORE`。该标志只修改快照副本，不能写回内部 `AuditEvent`。

如果 `after_sequence >= next_sequence - 1`，说明没有新事件，返回 0。

### 7.3 非破坏性读取

读取不修改 `head`、`len`、事件内容或任何累计统计。多个读取者可以各自维护用户态游标，互不影响。

系统调用开始后新写入的事件不进入当前批次，因为当前批次以持锁期间生成的快照为准。

## 8. 统计快照

`ipc_stat` 在审计锁内复制以下状态，然后立即释放锁：

- 固定容量；
- 当前保留数量；
- 最旧序号；
- 下一序号；
- 总事件数；
- 成功事件数；
- 失败事件数；
- 覆盖事件数。

空缓冲区必须返回：

```text
retained == 0
first_sequence == next_sequence
```

统计快照生成后，在没有审计锁的情况下复制到用户地址。因此用户拿到的是某一时刻自洽的快照，不保证返回瞬间全局状态仍未发生变化。

## 9. 全局状态与锁规则

全局缓冲区使用：

```rust
lazy_static! {
    static ref AUDIT_RING: UPSafeCell<AuditRing> =
        unsafe { UPSafeCell::new(AuditRing::new()) };
}
```

`UPSafeCell` 基于 `RefCell`，重复可变借用会 panic，因此必须严格限制借用范围。

审计临界区内只允许：

- 分配事件序号；
- 写入或覆盖固定数组槽；
- 更新计数器；
- 生成最多 32 条记录或一个统计结构的值拷贝。

审计临界区内禁止：

- 访问或复制用户内存；
- 调用可能调度、阻塞或睡眠的函数；
- 进行控制台输出；
- 动态分配无界容器；
- 再次调用 `audit::record`；
- 持有任务、配额或 IPC 对象借用。

系统全局锁顺序仍为：

```text
任务内部状态 → 配额状态 → IPC 对象 → 审计缓冲区
```

更安全的做法是先把凭据、PID、资源 ID 和结果复制成普通值，释放前面的借用后再进入审计锁。

## 10. `audit::record` 行为

`security::complete` 调用：

```rust
audit::record(&permit.request, &outcome);
```

`record` 应执行：

1. 在锁外把 `IpcRequest` 和 `IpcResult` 转换为待记录事件；
2. 在锁外取得时间戳；
3. 短暂借用 `AUDIT_RING`；
4. 分配序号、写入事件并更新统计；
5. 释放借用后返回。

`record` 不返回 `IpcResult`，不得覆盖、包装或改变传入的 IPC 结果。内部审计失败只能导致本条审计信息丢失，不能让已经成功的管道或信号操作变成失败。

## 11. 预检查失败的审计路径

当前 `security::preflight` 使用 `?` 直接传播 `policy::authorize` 和 `quota::reserve` 的错误。失败时不会产生 `IpcPermit`，调用者也无法调用 `complete`，因此仅在 `complete` 中记录事件会漏掉授权和配额拒绝。

集成阶段采用以下路径：

```rust
pub fn preflight(request: IpcRequest) -> IpcResult<IpcPermit> {
    if let Err(error) = policy::authorize(&request) {
        let outcome = Err(error);
        audit::record(&request, &outcome);
        return Err(error);
    }

    let reservation = match quota::reserve(&request) {
        Ok(reservation) => reservation,
        Err(error) => {
            let outcome = Err(error);
            audit::record(&request, &outcome);
            return Err(error);
        }
    };

    Ok(IpcPermit { request, reservation })
}
```

该方案不改变 `preflight` 的公开签名，也不会产生双重记录：

- 预检查失败：由 `preflight` 记录一次，不产生 permit；
- 预检查成功：不立即记录，最终由 `complete` 根据实际操作结果记录一次。

`security/mod.rs` 属于冻结集成文件，因此上述改动不能混入环形缓冲区提交。应在 A/C 接入前由团队确认，并作为独立的集成提交处理。

## 12. 审计系统调用自身的事件路径

### 12.1 权限

`audit_read` 和 `ipc_stat` 允许以下调用者：

```text
uid == 0 || capabilities.contains(CapabilitySet::AUDIT_READ)
```

读取当前任务凭据时只复制普通值，随后立即释放任务内部借用。不得同时持有任务借用和审计缓冲区借用。

系统调用先检查权限，再处理其他参数。无权限时返回 `-EPERM` 并记录失败，但不生成或复制日志快照。

### 12.2 成功调用

- 成功的 `audit_read` 不写 `AUDIT_OP_AUDIT_READ`；
- 成功的 `ipc_stat` 不写 `AUDIT_OP_IPC_STAT`。

这样监控程序可以追上日志尾部，统计工具也不会因查询本身持续改变统计值。

### 12.3 失败调用

审计模块提供内部辅助入口，用于记录控制系统调用失败：

```text
record_control_failure(operation, subject, requested_amount, error)
```

它只接受 `AuditRead` 或 `IpcStat` 两种内部操作，不暴露给用户态，也不修改冻结的 `IpcOperation`。

以下情况必须记录：

- 权限不足：`EPERM`；
- 参数或标志无效：`EINVAL`；
- 用户输出地址无效或复制失败：`EFAULT`。

失败事件的 `object_id` 为 0、`object_owner_uid` 为 `AUDIT_UID_UNKNOWN`、`result_value` 为 0。

## 13. 用户内存复制

`sys_audit_read` 的顺序为：

1. 读取并释放调用者凭据；
2. 检查权限；
3. `capacity == 0` 时返回 0，且完全不访问 `records`；
4. 检查记录数组地址计算是否溢出；
5. 在审计锁内生成最多 32 条记录的快照；
6. 释放审计锁；
7. 使用 `mm::copy_to_user` 逐条复制快照；
8. 全部成功时返回复制数量。

用户地址计算必须使用 `checked_mul` 和 `checked_add`，不能依赖会回绕的裸指针偏移。

如果第 N 条复制失败：

- 返回 `-EFAULT`；
- 用户缓冲区前 N 条可能已被写入；
- 不删除或修改环形缓冲区中的原记录；
- 记录一次 `AUDIT_OP_AUDIT_READ` 失败事件；
- 用户程序在负返回值时不得推进游标，可以用原游标重试。

`sys_ipc_stat` 同样在释放审计锁后复制统计结构。v1 要求 `flags == 0` 且 `out_size >= 80`，否则返回并记录 `-EINVAL`。

用户地址安全性的最终保证由开发者 B 的 `copy_to_user` 实现提供。B 合入前只验证合法地址路径，不执行空指针、跨页、不可写页或溢出地址攻击测试。

## 14. 用户态接口约束

用户库在 `user/src/audit.rs` 中定义与内核一致的两个 `#[repr(C)]` 结构，并提供：

```rust
pub fn read(records: &mut [AuditRecordV1], after_sequence: u64) -> isize;
pub fn stat(stats: &mut IpcStatsV1) -> isize;
```

用户封装必须保留负返回值，检查成功后才能转换为 `usize`。不能把未知操作编号转换成封闭 Rust 枚举并 `unwrap`；`auditctl` 对未知编号直接显示数字。

`auditctl read` 使用返回批次最后一条记录的 `sequence` 更新游标，循环读取直至返回 0。看到 `GAP_BEFORE` 时提示已有记录被覆盖，但继续显示当前批次。

## 15. 测试策略

### 15.1 不依赖 A/B/C 的测试

当前初始进程 UID 为 0，可以利用无效 `ipc_stat(flags != 0)` 生成确定的失败事件，独立验证：

- 两个 ABI 结构大小为 80；
- 空尾部读取返回 0；
- 序号单调递增；
- 更新游标后不重复读取；
- 单批最多返回 32 条；
- 连续生成超过 256 条事件后覆盖最旧记录；
- 覆盖后第一条返回记录带 `GAP_BEFORE`；
- `overwritten_events` 增加；
- `retained <= capacity`；
- `total_events == successful_events + failed_events`；
- 成功读取和成功统计不产生自反馈事件。

测试必须比较操作前后的统计增量，不能假设全局日志初始为空。

### 15.2 集成后测试

等待其他模块合入后再验证：

- A：root、capability、普通用户读取权限以及信号授权事件；
- B：空指针、不可写页、跨页、地址溢出和部分复制失败；
- C：管道创建/读写、资源 ID、配额拒绝、回滚和退出释放；
- A/C 与门面：`preflight` 失败恰好记录一次；
- 全模块：压力测试、原版回归和性能对比。

## 16. 文件边界与提交拆分

建议按以下顺序提交：

```text
docs: document audit ring design
feat: implement bounded audit ring
feat: add audit ABI record conversion
feat: implement audit syscalls
feat: wire audit syscalls
feat: add user audit API
feat: add auditctl user tool
test: add audit cursor and overflow tests
ci: run audit integration tests
docs: document audit implementation results
```

其中：

- `security/api.rs` 不由 D 私自修改；
- `security/mod.rs` 的预检查失败接线作为独立集成提交；
- `syscall/mod.rs` 的 602/603 路由单独提交，便于处理与 A 的冲突；
- 用户测试入口只在 `audit_test` 已经独立运行通过后修改；
- 不提交 `target/`、文件系统镜像、调试日志或个人环境配置。

## 17. 验收标准

实现满足以下条件时，审计内部设计完成落地：

1. 环形缓冲区最多保留 256 条事件；
2. 序号从 1 开始且不复用；
3. 覆盖行为可由 `GAP_BEFORE` 和统计值检测；
4. 所有统计不变量始终成立；
5. 一次读取最多复制 32 条；
6. 审计锁内不访问用户内存、不调度、不阻塞；
7. 失败复制不删除日志，调用者可以用原游标重试；
8. 成功的读取与统计不产生自反馈；
9. 预检查失败和最终 IPC 结果都恰好记录一次；
10. 审计失败不改变原 IPC 结果；
11. ABI 结构大小、编号和保留字段符合 v1；
12. 原有 rCore 用户测试无回退。
