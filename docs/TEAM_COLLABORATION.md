# 团队分工与开发规范

本项目采用四人并行开发模式。公共安全接口由 `integration` 分支统一维护，成员在各自功能分支独立实现，完成后通过 Pull Request 合并到 `integration`，全部联调通过后再合并到 `main`。

## 分工与分支

| 成员 | 负责内容 | 主要文件 | 开发分支 |
| --- | --- | --- | --- |
| A | 进程 UID、Capability、凭据继承与 IPC 权限检查 | `security/credentials.rs`、`security/policy.rs`、`syscall/process.rs` | `feature/credentials-authz` |
| B | 用户指针校验、安全复制、跨页和非法地址测试 | `mm/user_access.rs`、`mm/page_table.rs`、用户指针测试 | `feature/user-access` |
| C | 文件描述符和管道配额、资源回收、失败回滚及 `pipe2` | `security/quota.rs`、`fs/pipe.rs`、`syscall/fs.rs` | `feature/ipc-resource` |
| D | 安全审计、系统调用统一接线、跨模块测试、CI 与文档 | `security/audit.rs`、安全系统调用、测试和 CI 配置 | `feature/audit-testing` |

成员姓名确定后，在上述表格中用实际姓名替换 A～D。

## 合并流程

```text
个人功能分支 -> Pull Request -> integration -> 集成测试 -> main
```

- 不直接向 `main` 提交功能代码。
- 个人分支的 Pull Request 以 `integration` 为目标分支。
- `integration` 必须通过文档构建和 rCore 用户测试，才可以合并到 `main`。
- 不在个人分支中合并其他成员尚未完成的实现。

开始工作前执行：

```bash
git fetch origin
git switch <个人分支>
git pull --ff-only
```

## 接口与文件边界

公共类型、错误语义和调用顺序以 [IPC Security API v1](IPC_SECURITY_API.md) 为准。模块依赖关系和残余运行时耦合见 [模块独立性审计](MODULE_INDEPENDENCE.md)。

- 不自行修改 `security/api.rs` 中的公共数据类型。
- 不绕过 `security::preflight` 和 `security::complete` 直接访问其他模块内部状态。
- 不自行修改其他成员负责文件；确需跨模块修改时，先在团队内确认并在 PR 中说明。
- `main.rs`、`task/task.rs`、`mm/mod.rs` 和全局系统调用路由属于集成边界，由负责集成的成员统一修改。
- 新增或调整系统调用编号、参数、返回值和错误码前必须先讨论，禁止私自占用编号。
- 保留 rCore 原有系统调用 ABI；新功能采用增量扩展，不改变已有系统调用语义。

## 提交规范

每个提交只处理一个明确问题，不混入无关格式化、构建产物或个人环境配置。建议使用以下提交前缀：

```text
feat: implement credential inheritance
fix: reject invalid user pointer
test: add pipe quota exhaustion test
docs: update security API description
refactor: simplify audit event handling
```

- 不对共享分支强制推送或重写历史。
- 提交前检查 `git diff` 和 `git status`。
- 每位成员使用自己的 Git 姓名和邮箱提交，确保工作量可以通过历史核查。
- 引用 rCore 或其他开源成果时，在 README 或相关文档中注明来源。
- 使用 AI 辅助时，按照课程要求记录在 [AI 使用说明](AI_USAGE.md) 中。

## 测试要求

每项功能至少覆盖：

- 正常操作路径；
- 权限不足或参数非法；
- 资源耗尽；
- 操作失败后的状态回滚；
- `fork`、退出和资源释放等生命周期场景。

提交 Pull Request 前至少运行：

```bash
make run TEST=1
```

如果本地环境无法运行 QEMU，应在 PR 中说明，并等待 GitHub Actions 完整通过后再合并。

## Pull Request 要求

PR 描述中需要写明：

1. 完成的功能和对应任务；
2. 修改的模块与文件；
3. 测试方法和测试结果；
4. 是否影响公共接口或系统调用 ABI；
5. 已知限制和需要其他成员配合的事项。

发生冲突时，先确认冲突是否涉及公共接口或他人负责模块，再由相关成员共同处理，避免为了消除文本冲突而破坏模块语义。
