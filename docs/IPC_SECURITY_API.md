# IPC Security API v1

## 1. 目的

该接口是四个功能模块之间的唯一稳定契约。系统调用层按照统一顺序完成用户参数复制、授权、资源预留、实际操作和审计，功能模块不得互相访问内部状态。

接口冻结后，如需修改公开类型、错误码或调用顺序，必须通过独立的 API change PR，并由至少两名非作者成员批准。

## 2. 目录与所有权

```text
os/src/security/
├── mod.rs
├── api.rs
├── credentials.rs
├── policy.rs
├── quota.rs
└── audit.rs

os/src/mm/
└── user_access.rs
```

- `security::api`：公共类型，不保存运行时状态；
- `security::credentials`：进程身份和能力集合；
- `security::policy`：访问控制决策；
- `security::quota`：IPC 资源预留、提交和回滚；
- `security::audit`：有界事件记录；
- `mm::user_access`：用户地址验证和安全复制。

## 3. 公共数据结构草案

```rust
pub type Uid = u32;
pub type ResourceId = u64;

bitflags! {
    pub struct CapabilitySet: u32 {
        const KILL = 1 << 0;
        const IPC_ADMIN = 1 << 1;
        const AUDIT_READ = 1 << 2;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcOperation {
    SignalSend,
    PipeCreate,
    PipeRead,
    PipeWrite,
    AuditRead,
}

#[derive(Clone, Copy, Debug)]
pub struct IpcSubject {
    pub pid: usize,
    pub uid: Uid,
    pub capabilities: CapabilitySet,
}

#[derive(Clone, Copy, Debug)]
pub struct IpcObject {
    pub id: ResourceId,
    pub owner_uid: Uid,
}

#[derive(Clone, Copy, Debug)]
pub struct IpcRequest {
    pub subject: IpcSubject,
    pub object: IpcObject,
    pub operation: IpcOperation,
    pub amount: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    PermissionDenied,
    InvalidAddress,
    InvalidArgument,
    ProcessNotFound,
    TooManyFiles,
    ResourceExhausted,
    TryAgain,
}

pub type IpcResult<T> = Result<T, IpcError>;
```

类型名称可在 API 冻结会议中调整，但语义必须保持稳定。`IpcPermit` 应为不可由系统调用层自行构造的不透明类型，防止绕过预检查。

## 4. 门面接口草案

```rust
pub fn preflight(request: &IpcRequest) -> IpcResult<IpcPermit>;

pub fn complete(
    permit: IpcPermit,
    outcome: IpcResult<usize>,
) -> IpcResult<usize>;
```

`preflight` 必须：

1. 读取当前进程凭据；
2. 执行访问控制策略；
3. 预留所需资源；
4. 创建审计上下文；
5. 成功时返回 `IpcPermit`。

`complete` 必须：

1. 根据操作结果提交或回滚资源；
2. 记录成功或失败审计事件；
3. 返回统一的 IPC 结果。

## 5. 用户地址接口草案

```rust
pub fn copy_from_user<T: Copy>(token: usize, src: *const T) -> IpcResult<T>;

pub fn copy_to_user<T: Copy>(
    token: usize,
    dst: *mut T,
    value: &T,
) -> IpcResult<()>;

pub fn copy_bytes_from_user(
    token: usize,
    src: *const u8,
    len: usize,
) -> IpcResult<UserBuffer>;
```

所有接口必须检查地址加法溢出、页面映射、用户权限和跨页范围。用户输入错误只能返回错误，不得调用 `unwrap` 或触发内核 panic。

## 6. 错误码映射

| `IpcError` | 用户态错误 | 数值 | 场景 |
| --- | --- | ---: | --- |
| `PermissionDenied` | `EPERM` | 1 | 无权发送信号或管理 IPC |
| `InvalidAddress` | `EFAULT` | 14 | 用户地址未映射或权限错误 |
| `InvalidArgument` | `EINVAL` | 22 | 信号编号、标志或长度无效 |
| `ProcessNotFound` | `ESRCH` | 3 | 目标 PID 不存在 |
| `TooManyFiles` | `EMFILE` | 24 | 进程 FD 达到上限 |
| `ResourceExhausted` | `ENOSPC` | 28 | 系统或进程 IPC 配额耗尽 |
| `TryAgain` | `EAGAIN` | 11 | 非阻塞操作暂时无法完成 |

新安全系统调用失败时返回对应的负数值。rCore 已有系统调用不因本表被追溯修改。审计记录保存正的 errno；具体规则见 [IPC 安全审计 ABI v1](AUDIT_ABI_V1.md)。

## 7. 锁与生命周期约束

- 锁顺序固定为：进程内部状态 → 配额状态 → IPC 对象 → 审计缓冲区；
- 持有审计锁时不得阻塞、调度或访问用户内存；
- `preflight` 后任意失败路径都必须调用 `complete` 或显式回滚；
- 进程退出必须释放 FD、管道配额和临时许可；
- 审计缓冲区满时覆盖最旧事件或增加丢弃计数，不得无限分配。

## 8. 兼容性原则

- 现有合法管道和信号程序应保持行为兼容；
- 新安全检查只改变原本不安全或未定义的行为；
- 每次 API 变更都必须同时更新用户态封装、测试和本文档；
- `main` 上只发布完整通过 CI 的 API 版本。

## 9. 预留系统调用号

为避免四个分支分别选择编号，API v1 预留以下教学内核私有编号：

| 编号 | 接口 | 负责人 |
| ---: | --- | --- |
| 600 | `getuid` | A |
| 601 | 受限凭据设置接口 | A |
| 602 | `audit_read` | D |
| 603 | `ipc_stat` | D |
| 604 | `pipe2` | C |

功能分支实现对应内核函数，但不单独编辑系统调用总路由；D 在 `integration` 阶段按本表统一登记内核分发与用户态封装。未经过 API change PR 不得占用其他编号。

## 10. 审计 ABI v1

系统调用 602/603 的结构布局、操作编号、游标读取、权限、溢出处理和错误返回已经统一定义在 [IPC 安全审计 ABI v1](AUDIT_ABI_V1.md)。内核、用户库、测试和审计工具必须以该文档为共同契约，不得直接将 Rust 内部枚举或内核指针复制到用户态。
