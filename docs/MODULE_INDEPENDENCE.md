# 模块独立性审计

## 结论

原始 rCore 第七章代码并不是为四人并行安全扩展设计的：系统调用、任务控制块和用户地址转换存在明显交叉修改点。若直接按最初计划开工，四个分支可以分别开发，但合并时很容易在 `task/task.rs`、`syscall/fs.rs` 和 `syscall/process.rs` 发生冲突。

在 `integration` 上加入公共安全门面、进程安全状态和用户访问适配层后，四个功能已经达到以下独立性：

- **源码所有权独立**：四人日常修改的主要 Rust 文件不重叠；
- **编译起点一致**：四个分支从同一接口骨架提交创建；
- **接口依赖单向**：功能模块依赖 `security::api`，不依赖其他成员的内部实现；
- **行为可渐进替换**：未实现模块使用兼容占位实现，单个功能分支可以独立编译；
- **最终行为仍需集成验证**：授权、配额和审计作用于同一次 IPC 操作，运行时语义不能完全割裂。

因此结论不是“模块完全没有依赖”，而是“开发可以独立推进，依赖被限制在冻结接口和最终集成测试中”。

## 原始冲突面

| 冲突文件 | 原计划涉及成员 | 风险 |
| --- | --- | --- |
| `task/task.rs` | A 凭据、C 配额 | 同时增加进程字段并修改 `new/fork` |
| `syscall/process.rs` | A 授权、B 用户地址 | 同时改 `kill/sigaction/exec/waitpid` |
| `syscall/fs.rs` | B 用户地址、C 配额 | 同时改 `read/write/pipe/close/dup` |
| `syscall/mod.rs` | A/C/D 新系统调用 | 系统调用号和路由容易重复 |
| 用户测试入口 | 四人 | 测试名称、超时和执行顺序冲突 |

## 已建立的隔离点

### 1. 冻结公共 API

`os/src/security/api.rs` 只定义公共操作、请求、身份、资源和错误类型。功能模块不得在其中加入私有状态。

### 2. 稳定安全门面

`security::preflight` 固定执行策略与配额预留，`security::complete` 固定执行配额完成与审计。A、C、D 分别替换 `policy`、`quota`、`audit` 实现，无需修改调用顺序。

### 3. 预留进程安全状态

`TaskControlBlockInner` 只增加一次 `ProcessSecurityState`：

```text
ProcessSecurityState
├── Credentials  → A 维护
└── QuotaState   → C 维护
```

初始化与 `fork` 分别调用子模块钩子，A 和 C 不再同时编辑任务控制块。

### 4. 用户地址适配层

`mm::copy_from_user` 和 `mm::copy_to_user` 是固定调用入口。B 负责加固其内部实现；A、C 只在各自系统调用文件中使用它们。

### 5. 文件级独占所有权

| 模块 | 独占负责人 | 允许修改 |
| --- | --- | --- |
| 凭据与授权 | A | `security/credentials.rs`、`security/policy.rs`、`syscall/process.rs` |
| 用户地址安全 | B | `mm/user_access.rs`、`mm/page_table.rs`、对应攻击测试 |
| IPC 资源治理 | C | `security/quota.rs`、`fs/pipe.rs`、`syscall/fs.rs` |
| 审计与测试 | D | `security/audit.rs`、`syscall/security.rs`、`syscall/mod.rs`、CI 与集成测试 |

## 冻结文件

以下文件由接口骨架提交维护，普通功能 PR 不得直接修改：

- `os/src/security/api.rs`
- `os/src/security/mod.rs`
- `os/src/main.rs`
- `os/src/mm/mod.rs`
- `os/src/task/task.rs` 中的安全状态字段及构造逻辑
- 已统一分配的系统调用号

如确需修改，应单独提交 API change PR，不与功能代码混合，并由至少两名其他成员批准。API 变更合入 `integration` 后，四个功能分支都要先 rebase 再继续开发。

## 仍然存在的运行时耦合

### 锁顺序

任务状态、配额、管道和审计缓冲区在运行时可能同时出现。必须统一遵守：

```text
任务内部状态 → 配额状态 → IPC 对象 → 审计缓冲区
```

### 失败回滚

授权通过后，管道创建或用户地址复制仍可能失败。C 的配额模块与 D 的审计模块必须通过 `complete` 观察同一个最终结果，不能各自猜测成功状态。

### 进程生命周期

`fork`、`exec` 和 `exit` 同时影响凭据、文件描述符、配额和审计。这些场景由联合测试负责，不归任何单一模块自行宣布完成。

### ABI 一致性

内核错误码、用户态封装和测试程序必须同步。新增系统调用号统一由 D 登记，其他成员不得自行选择号码。

## 分支独立验收

每个功能分支合入 `integration` 前必须满足：

1. 只修改本模块文件，或附带已批准的 API change PR；
2. 能在其他三个模块仍为兼容占位实现时完成编译；
3. 提供本模块的正常与错误路径测试；
4. 不通过读取其他模块私有字段实现功能；
5. 不改变冻结接口的语义；
6. CI 文档构建和 rCore 用户测试通过。
