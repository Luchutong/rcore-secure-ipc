# 四人协作开发计划

## 1. 项目目标

在 rCore-Tutorial-v3 第七章教学内核基础上，构建一套结构清晰、可测试、可审计的 IPC 安全扩展，核心范围包括：

- 进程凭据与信号发送授权；
- 用户指针及系统调用边界安全；
- 管道和文件描述符资源治理；
- IPC 安全审计、测试与性能评估。

三周内不实现完整 POSIX 用户管理、SELinux、网络 IPC 或通用消息加密。

## 2. 协作模型

所有功能必须通过 [IPC Security API v1](IPC_SECURITY_API.md) 接入，不允许系统调用直接依赖其他成员的内部模块。

分支结构：

```text
main                         仅保存通过全部验收的稳定版本
└── integration             四个功能分支的日常集成目标
    ├── feature/credentials-authz
    ├── feature/user-access
    ├── feature/ipc-resource
    └── feature/audit-testing
```

协作规则：

1. 第一阶段共同评审并冻结 `api-v1`，之后四人从同一个 `integration` 提交创建功能分支。
2. 功能分支只修改各自负责模块；修改公共接口必须单独提交“API change” PR，并至少由另外两人同意。
3. 功能 PR 先合入 `integration`，不得直接合入 `main`。
4. `integration` 通过完整 CI、攻击测试和性能回归后，再提交最终 PR 合入 `main`。
5. 禁止在共享分支使用普通 `git push --force`；需要整理个人分支时使用 `--force-with-lease`。

## 3. 四人职责划分

### 开发者 A：进程凭据与授权策略

负责分支：`feature/credentials-authz`

主要文件：

- `os/src/security/credentials.rs`
- `os/src/security/policy.rs`
- `os/src/syscall/process.rs`

交付内容：

- `Uid`、`CapabilitySet` 和进程凭据结构；
- `fork` 继承与 `exec` 保留规则；
- `getuid` 和受限的凭据管理接口；
- `kill` 的同 UID、自发送和特权能力校验；
- 允许/拒绝权限矩阵测试。

验收重点：无权限发送信号返回 `EPERM`，现有信号行为不回退。

### 开发者 B：用户地址与系统调用边界安全

负责分支：`feature/user-access`

主要文件：

- `os/src/mm/user_access.rs`
- `os/src/mm/page_table.rs`
- `user/src/bin/` 下的用户地址攻击测试

交付内容：

- 返回 `Result` 的 `copy_from_user`、`copy_to_user` 和字符串复制接口；
- 地址溢出、未映射页、跨页和权限检查；
- 移除 IPC 路径中由无效用户输入触发的 `unwrap`；
- 错误统一映射为 `EFAULT` 或 `EINVAL`；
- 恶意指针和模糊输入测试。

验收重点：错误地址不得导致内核 panic，后续合法系统调用仍可运行。

### 开发者 C：IPC 资源与生命周期治理

负责分支：`feature/ipc-resource`

主要文件：

- `os/src/security/quota.rs`
- `os/src/fs/pipe.rs`
- `os/src/syscall/fs.rs`

交付内容：

- 每进程文件描述符和管道数量上限；
- 配额申请、提交与自动释放，失败路径不得泄漏计数；
- 明确的 `EMFILE`、`ENOSPC` 和 `EAGAIN` 行为；
- 可选 `pipe2(O_CLOEXEC)` 及 `exec` 生命周期处理；
- 资源耗尽与并发创建/关闭测试。

验收重点：资源耗尽只能影响调用进程，不得拖垮内核或永久泄漏资源。

### 开发者 D：审计、测试与持续集成

负责分支：`feature/audit-testing`

主要文件：

- `os/src/security/audit.rs`
- `os/src/syscall/security.rs`
- `user/src/bin/` 下的安全测试与工具
- `.github/workflows/`
- `docs/`

交付内容：

- 有界审计环形缓冲区；
- 统一记录 PID、UID、操作、资源、结果和时间；
- 审计读取/统计系统调用及用户态查看工具；
- 原版漏洞复现、集成测试、压力测试和性能基准；
- CI、测试日志、图表数据及演示脚本。

验收重点：审计不可造成无限内存增长，记录满时行为明确，测试可重复运行。

## 4. 统一接口与依赖边界

公共接口目录规划：

```text
os/src/security/
├── mod.rs          对内核其他模块暴露的唯一门面
├── api.rs          冻结的公共数据结构、操作类型和错误码
├── credentials.rs  A 负责
├── policy.rs       A 负责
├── quota.rs        C 负责
└── audit.rs        D 负责

os/src/mm/
└── user_access.rs  B 负责
```

统一调用顺序：

```text
用户参数
  → UserAccess 安全复制与校验
  → security::preflight 身份、授权和配额检查
  → 执行管道或信号操作
  → security::complete 释放/提交资源并写入审计
  → 统一 Errno 返回用户态
```

模块之间只能通过 `api.rs` 中的类型通信，禁止出现 `policy` 直接访问 `audit` 内部缓冲区等横向依赖。

公共骨架已经在创建功能分支前写入 `integration`。以下文件视为冻结的集成文件，功能分支不得直接修改：

- `os/src/security/api.rs`
- `os/src/security/mod.rs`
- `os/src/main.rs`
- `os/src/mm/mod.rs`
- `os/src/task/task.rs` 中的 `ProcessSecurityState` 接入点
- `os/src/syscall/mod.rs` 中按 API 文档预留的系统调用编号

开发者 B 只实现 `mm::user_access` 的安全语义；A、C 在各自拥有的系统调用文件中调用稳定复制接口，因此 B 不需要同时修改 `fs.rs` 或 `process.rs`。凭据和配额状态均已预留在 `ProcessSecurityState` 中，A、C 不再同时修改任务控制块。

## 5. 三周时间表

### 第 1～3 天：基线与接口冻结

- 四人共同跑通原版 QEMU、用户测试和 CI；
- 复现任意 PID 信号、恶意用户指针和资源耗尽场景；
- 冻结 API v1、错误码、锁顺序和审计事件格式；
- 创建 `integration` 与四个功能分支。

里程碑：`integration` 与 `main` 行为一致，全部基线测试通过。

### 第 4～9 天：并行功能开发

- A～D 在独立功能分支实现各自模块；
- 每个功能至少包含单元/用户态测试和设计说明；
- 每日同步公共接口问题，但不直接改他人内部模块。

里程碑：四个功能分支各自编译通过，并完成最小演示。

### 第 10～13 天：首次集成

- 按“用户访问 → 凭据授权 → 资源治理 → 审计测试”顺序合入 `integration`；
- 解决 `TaskControlBlock`、系统调用表和错误码等交叉修改；
- 完成权限、异常地址和资源耗尽联合测试。

里程碑：`integration` 全部 CI 通过，无已知内核 panic。

### 第 14～17 天：压力与性能优化

- 多进程信号与管道压力测试；
- 检查锁顺序、配额回滚、进程退出清理和审计覆盖；
- 测量安全检查前后的吞吐量、延迟和内存开销。

里程碑：形成可复现数据及性能分析初稿。

### 第 18～20 天：交付材料

- 整理测试脚本、日志、截图和图表；
- 完成设计报告、个人分工、AI 使用记录和演示脚本；
- 进行代码审查和答辩演练。

### 第 21 天：稳定版合并

- 冻结 `integration`；
- 运行完整 CI 和验收清单；
- 通过最终 PR 将 `integration` 合入 `main`；
- 创建版本标签并保存测试日志。

## 6. 合并验收清单

- 原版 rCore 用户测试全部通过；
- Rust 文档可以构建，CI 不使用过时的只读令牌发布文档；
- 未授权信号被拒绝，返回值符合 API v1；
- 无效用户地址不会导致内核 panic；
- 文件描述符和管道资源可回收，无退出泄漏；
- 每类 IPC 操作都有成功和失败审计记录；
- 至少包含正常、越权、边界和并发四类测试；
- 有原版与改造版的定量性能对比；
- 四名成员的提交、测试和文档责任可由 Git 历史核查。
