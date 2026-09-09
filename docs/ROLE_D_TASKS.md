# 角色 D：安全审计、测试与持续集成任务清单

负责分支：`feature/audit-testing`

主要目标：实现有界 IPC 安全审计机制、审计系统调用、用户态工具、集成测试和 CI 接线。

## 一、准备工作

- [x] 在 WSL 中配置 Rust、RISC-V 目标和 QEMU 运行环境。
- [x] 确认本地仓库远程地址正确。
- [x] 将个人分支同步到最新 `integration`。
- [x] 确认包含审计 ABI 提交 `8364fb3`。
- [ ] 运行原始基线测试并保存结果。

```bash
git fetch origin integration
git switch feature/audit-testing
git merge --ff-only origin/integration
git push origin feature/audit-testing

cd os
cargo doc --no-deps
make run TEST=1
```

## 二、审计 ABI 与设计

- [x] 确定 `AuditRecordV1`，固定大小为 80 字节。
- [x] 确定 `IpcStatsV1`，固定大小为 80 字节。
- [x] 确定系统调用 602：`audit_read`。
- [x] 确定系统调用 603：`ipc_stat`。
- [x] 确定非破坏性序号游标读取语义。
- [x] 确定缓冲区覆盖和 `GAP_BEFORE` 标志。
- [x] 确定权限与 errno 映射。
- [x] 将 ABI 文档提交到 `integration`。
- [x] 编写审计内部设计文档 `docs/AUDIT_DESIGN.md`。
- [x] 明确环形缓冲区容量、单次读取上限及锁规则。
- [x] 明确授权或配额预检查失败时的审计路径。

参考文档：

- `docs/AUDIT_ABI_V1.md`
- `docs/IPC_SECURITY_API.md`
- `docs/MODULE_INDEPENDENCE.md`

## 三、审计环形缓冲区

主要文件：

```text
os/src/security/audit.rs
```

任务：

- [x] 定义内部 `AuditEvent`。
- [x] 定义固定容量 `AuditRing`。
- [x] 使用固定数组或有界数据结构保存事件。
- [x] 实现事件序号分配，序号从 1 开始。
- [x] 实现 `push` 写入操作。
- [x] 缓冲区已满时覆盖最旧记录。
- [x] 更新 `overwritten_events` 计数。
- [x] 统计成功事件数量。
- [x] 统计失败事件数量。
- [x] 统计总事件数量。
- [x] 实现按照 `after_sequence` 查询事件。
- [x] 检测调用者是否错过已覆盖记录。
- [x] 在第一条返回记录上设置 `GAP_BEFORE`。
- [x] 实现统计快照接口。
- [x] 使用 `UPSafeCell` 管理全局审计缓冲区。
- [x] 保证持有审计缓冲区借用时不访问用户内存。
- [x] 保证 `audit::record` 不改变原 IPC 操作结果。
- [x] 保证成功的 `audit_read` 和 `ipc_stat` 不产生自反馈事件。

建议提交：

```text
feat: implement bounded audit ring
```

## 四、事件转换与错误映射

主要文件：

```text
os/src/security/audit.rs
```

任务：

- [x] 将 `IpcRequest` 转换为内部 `AuditEvent`。
- [x] 将 `IpcOperation` 映射为稳定的审计操作编号。
- [x] 将 `IpcError` 映射为稳定 errno。
- [x] 使用 `timer::get_time_ms()` 生成时间戳。
- [x] 正确填写 PID、UID、资源 ID 和所有者 UID。
- [x] 正确填写请求数量和实际结果数量。
- [x] 失败事件的 `result_value` 固定为 0。
- [x] 未知资源所有者使用 `AUDIT_UID_UNKNOWN`。
- [x] 禁止将 Rust 内部枚举直接复制到用户态。
- [x] 禁止把内核指针作为 `object_id`。
- [x] 实现 `AuditEvent` 到 `AuditRecordV1` 的转换。
- [x] 添加 `AuditRecordV1` 大小断言。
- [x] 添加 `IpcStatsV1` 大小断言。

建议提交：

```text
feat: add audit ABI record conversion
```

## 五、内核审计系统调用

新增文件：

```text
os/src/syscall/security.rs
```

需要修改：

```text
os/src/syscall/mod.rs
```

任务：

- [x] 实现 `sys_audit_read`。
- [x] 实现 `sys_ipc_stat`。
- [x] 检查调用者 UID 或 `AUDIT_READ` Capability。
- [x] `capacity == 0` 时返回 0 且不访问用户指针。
- [x] 限制一次最多复制 32 条记录。
- [x] 在临界区内生成记录快照。
- [x] 释放审计缓冲区借用后再复制到用户地址。
- [x] 使用统一的 `copy_to_user` 接口。
- [ ] 用户地址无效时返回 `-EFAULT`。
- [x] 参数无效时返回 `-EINVAL`。
- [x] 无权限时返回 `-EPERM`。
- [x] 部分复制失败时不删除或丢失日志。
- [x] 在内核路由中注册系统调用 602。
- [x] 在内核路由中注册系统调用 603。
- [x] 将全局路由修改作为单独提交。

建议提交：

```text
feat: implement audit syscalls
feat: wire audit syscalls
```

## 六、用户态审计接口

建议新增：

```text
user/src/audit.rs
```

需要修改：

```text
user/src/syscall.rs
user/src/lib.rs
```

任务：

- [x] 在用户态定义相同布局的 `AuditRecordV1`。
- [x] 在用户态定义相同布局的 `IpcStatsV1`。
- [x] 添加 ABI 结构大小检查。
- [x] 在用户系统调用模块中注册编号 602。
- [x] 在用户系统调用模块中注册编号 603。
- [x] 实现底层 `sys_audit_read`。
- [x] 实现底层 `sys_ipc_stat`。
- [x] 实现安全的切片封装 `audit::read`。
- [x] 实现统计封装 `audit::stat`。
- [x] 保证负返回值不会被当作记录数量。
- [x] 遇到未知操作编号时保留数值，不触发 panic。

建议提交：

```text
feat: add user audit API
```

## 七、用户态审计工具

新增文件：

```text
user/src/bin/auditctl.rs
```

任务：

- [x] 实现 `auditctl stat`。
- [x] 实现 `auditctl read`。
- [x] 输出缓冲区容量和当前记录数量。
- [x] 输出总事件、成功、失败和覆盖数量。
- [x] 按序号输出审计记录。
- [x] 显示时间、PID、UID、操作和资源 ID。
- [x] 显示成功结果或 errno。
- [x] 检测并提示 `GAP_BEFORE`。
- [x] 支持分批读取超过 32 条的记录。
- [x] 不输出用户数据内容或内核地址。

设计与验证：[auditctl 工具设计与使用](AUDITCTL.md)。

建议提交：

```text
feat: add auditctl user tool
```

## 八、独立审计测试

测试设计已整理到 [游标、覆盖与统计测试设计](AUDIT_TEST_DESIGN.md)，包含独立事件源、
测试矩阵、精确计数公式、QEMU 缓冲区约束及分阶段验收方法。用户态实现及实际验证见该文档第11节。

新增文件：

```text
user/src/bin/audit_test.rs
```

任务：

- [x] 验证 `AuditRecordV1` 大小为 80。
- [x] 验证 `IpcStatsV1` 大小为 80。
- [x] 验证从日志尾部读取返回 0。
- [x] 验证事件序号单调递增。
- [x] 验证使用新游标不会重复读取。
- [x] 验证一次最多读取规定数量。
- [x] 验证缓冲区覆盖最旧记录。
- [x] 验证覆盖后设置 `GAP_BEFORE`。
- [x] 验证 `overwritten_events` 增加。
- [x] 验证 `retained <= capacity`。
- [x] 验证 `total_events == successful_events + failed_events`。
- [x] 验证 `flags != 0` 的 `ipc_stat` 返回 `-EINVAL`。
- [x] 利用无效 `ipc_stat` 参数生成独立失败事件。
- [x] 验证成功读取不会不断制造新的审计事件。
- [x] 测试采用统计增量，不依赖全局计数初始值。

建议提交：

```text
test: add audit cursor and overflow tests
```

## 九、跨模块集成测试

这些测试需要在 A、B、C 合并到 `integration` 后完成。

### 与角色 A 集成

- [ ] 验证 UID 0 可以读取审计日志。
- [ ] 验证拥有 `AUDIT_READ` Capability 的进程可以读取。
- [ ] 验证普通进程读取返回 `-EPERM`。
- [ ] 验证越权信号发送产生失败审计记录。
- [ ] 验证合法信号发送产生成功审计记录。

### 与角色 B 集成

- [ ] 验证不可写用户地址返回 `-EFAULT`。
- [ ] 验证空指针不会导致内核 panic。
- [ ] 验证跨页无效范围不会导致内核 panic。
- [ ] 验证地址加法溢出被拒绝。
- [ ] 验证部分复制失败后日志仍可重新读取。

### 与角色 C 集成

- [x] 验证管道创建产生审计记录（`audit-c-integration-preview@e8a06cc`）。
- [ ] 验证管道读写记录请求及实际字节数。
- [x] 验证资源耗尽产生 `ENOSPC` 审计事件（`audit-c-integration-preview@e8a06cc`）。
- [x] 验证配额失败回滚后统计正确（`audit-c-integration-preview@e8a06cc`）。
- [x] 验证管道关闭和进程退出不会产生资源泄漏（C 的 `quota_test` 与 D+C 联调用例）。

建议提交：

```text
test: add IPC security integration tests
```

## 十、CI 接线

需要修改：

```text
user/src/bin/usertests.rs
```

视需要修改：

```text
.github/workflows/doc-and-test.yml
```

任务：

- [x] 将 `audit_test` 加入 `SUCC_TESTS`。
- [x] 确认 `make run TEST=1` 会执行审计测试。
- [x] 确认审计测试失败会让 CI 失败（本地临时失败断言验证 make 非零退出；PR #1 远端 CI 已验证成功路径）。
- [x] 保留原有 rCore 用户测试。
- [x] 不扩大普通 CI 的 GitHub Token 权限。
- [x] 不允许功能分支发布 `gh-pages`。
- [x] 只有确实需要时才修改 CI 工作流。
- [ ] 如增加压力测试，为其设置合理超时。
- [x] 保存必要的测试日志（见 `docs/D_VERIFICATION.md`；性能数据仍待最终集成后补充）。

建议提交：

```text
ci: run audit integration tests
```

## 十一、文档与记录

需要新增或修改：

```text
docs/AUDIT_DESIGN.md
docs/IPC_SECURITY_API.md
docs/AI_USAGE.md
README.md
```

任务：

- [x] 说明环形缓冲区的数据结构。
- [x] 说明覆盖策略。
- [x] 说明序号游标语义。
- [x] 说明成功读取不产生自反馈事件。
- [x] 说明权限与错误码。
- [x] 说明锁范围和禁止事项。
- [x] 说明系统调用参数及返回值。
- [x] 说明测试方法和测试结果。
- [ ] 记录 AI 辅助内容及人工验证结果（自动验证已记录，仍待成员人工复核）。
- [x] 不随意修改已经冻结的 ABI v1。

建议提交：

```text
docs: document audit implementation
```

## 十二、提交前检查

每次提交前执行：

```bash
cd ~/work/rcore-secure-ipc/os

cargo fmt --all -- --check
cargo doc --no-deps
make run TEST=1

cd ..
git diff --check
git status
```

检查内容：

- [x] 没有调试用代码。
- [x] 没有无关格式化修改。
- [x] 没有构建产物。
- [x] 没有个人环境配置。
- [x] 没有密钥或令牌。
- [x] 没有修改其他成员的内部模块。
- [x] 共享文件修改已经拆成独立提交。
- [x] 原有用户测试全部通过。

## 十三、Pull Request

- [x] 将功能分支推送到 GitHub。
- [x] 创建面向 `integration` 的 PR（#1）。
- [x] 填写完成内容和所属模块。
- [x] 列出修改范围。
- [x] 说明 ABI 是否变化。
- [x] 列出实际测试命令和结果。
- [x] 说明当前尚未完成的联合测试。
- [x] 等待 CI 完整通过。
- [ ] 至少邀请一名成员进行代码审查。
- [ ] 公共 API 变更邀请至少两名非作者成员审查。
- [x] 不直接向 `main` 提交功能代码。

## 十四、完成标准

角色 D 的任务完成需要满足：

- [x] 审计缓冲区容量有界。
- [x] 事件序号稳定且单调递增。
- [x] 覆盖行为可检测、可统计。
- [x] `audit_read` 支持非破坏性游标读取。
- [x] `ipc_stat` 返回一致的统计结果。
- [ ] 用户地址错误不导致内核 panic。
- [ ] 无权限进程不能读取日志。
- [x] 审计失败不改变原 IPC 操作结果。
- [x] 不记录用户载荷和内核地址。
- [x] 用户态工具可以读取并展示日志。
- [x] 独立审计测试通过。
- [ ] A、B、C 联合测试通过。
- [x] 原有 rCore 用户测试无回退。
- [x] GitHub Actions 全部通过（D PR #1 当前提交）。
- [ ] 文档、测试记录和 AI 使用记录完整。
