# 角色 D 进度与验证记录

最后核对时间：2026-09-09（Asia/Shanghai）

本文记录角色 D 的实现证据、跨分支联调结果和仍待其他角色提供的接口。它是一次可复核的状态快照；远程分支继续更新后，应重新执行本文命令并更新提交号。

## 1. 四个角色的远程进度

以下计数以 `origin/integration` 的 `8364fb3` 为基准，格式为“落后 / 独有提交”。

| 角色 | 远程分支 | 最新提交 | 落后 / 独有 | 已验证状态 | 当前缺口 |
| --- | --- | --- | ---: | --- | --- |
| A | `feature/credentials-authz` | `ecfee9b` | 2 / 2 | 最近一次分支 CI 成功 | 分支尚未同步 ABI 基线；信号路径尚未统一经过 `preflight/complete`；测试未登记到 `usertests`；公共 syscall 编号与冻结文档不一致 |
| B | `feature/user-access` | `0760a25` | 2 / 0 | 提交已包含在 `integration` | `copy_from_user/copy_to_user` 仍是 `translated_ref/translated_refmut` 的兼容封装，尚未提供地址溢出、跨页、映射和写权限安全语义 |
| C | `feature/ipc-resource` | `20ab386` | 2 / 7 | 分支 CI 成功；已完成 C+D 预览联调 | 管道创建和配额生命周期已实现；管道读写审计仍未接线，分支对冻结门面文件有修改，需通过集成提交统一处理 |
| D | `feature/audit-testing` | 见本文所在分支最新提交 | 0 / 17 | 独立审计及压力实现提交 `ea82dd6` 的 push/PR CI 均成功 | 等待 A/B 接口后完成真实权限、信号和恶意用户地址联合测试；等待 C 的管道读写事件 |

D 功能 PR：<https://github.com/Luchutong/rcore-secure-ipc/pull/1>

C+D 联调分支：`audit-c-integration-preview`。该分支用于提前暴露接口问题，不代替各角色面向 `integration` 的正式 PR。

## 2. D 独立实现验证

在角色 D 当前功能分支上执行：

```bash
cd tests/audit-host
cargo test

cd ../../os
cargo check --target riscv64gc-unknown-none-elf
cargo doc --no-deps
make run TEST=1
```

结果：

- 原始 `main@a74354d` 基线：21 个正常用例与 4 个预期失败用例，25/25 通过；
- 宿主侧 ABI、环形缓冲区、系统调用与 `auditctl` 测试：28/28 通过；
- D 分支 QEMU 回归：24 个正常用例与 4 个预期失败用例，28/28 通过；
- `audit_stress_test` 使用 6 个子进程生成 768 条失败事件，保留 256 条，覆盖增量为 768；
- 两次成功运行中压力测试本体耗时 13～18 ms，含超时包装器为 35～42 ms，远低于 10 秒独立上限；耗时仅作诊断，不作通过条件；
- 临时令压力子进程返回 7 后，失败依次传播为压力测试 1、包装器 1、`usertests` 27/28 和 `make` 非零；恢复后不保留故障注入；
- 用户 shell 中运行 `until_timeout infloop 100`，100 ms 后以信号编号 9 触发 `SIGKILL`，完成回收并返回 shell；这同时修复了旧实现误传信号位掩码后永久等待的问题；
- 修复原有多进程信号测试的父子退出竞态后，`sig_tests` 在同一次 QEMU 启动中连续运行 10 次全部通过，随后完整 QEMU 27/27 通过；
- GitHub Actions `34359479710`（push）、`34359485457`（PR）：压力实现提交 `ea82dd6` 的文档构建和 28/28 QEMU 用户测试均成功；
- 功能分支上的文档发布任务按策略跳过，只有 `main` 可以发布 `gh-pages`；
- `preflight` 的授权和配额拒绝路径会写失败审计记录，且保留原错误返回值。

## 3. C+D 提前联调验证

`audit-c-integration-preview` 合并 C 的 `20ab386` 后，额外完成：

- 将审计 ABI 中一次 `PipeCreate` 的 `requested_amount` 固定为 1，配额内部仍原子预留两个端点；
- 调整 `auditctl_test`，正确识别测试捕获输出时产生的真实管道创建事件；
- 新增 `ipc_audit_integration_test`，验证成功创建、`ENOSPC` 拒绝、统计增量、失败回滚和关闭后的配额恢复；
- 保留 D 的授权/配额预检查失败审计路径。

验证命令：

```bash
cd tests/audit-host && cargo test
cd ../../os
cargo check --target riscv64gc-unknown-none-elf
make run TEST=1
```

结果：宿主侧 28/28 通过；加入多进程审计压力测试后，QEMU 26 个正常用例与 4 个预期失败
用例，共 30/30 通过。`quota_test`、`ipc_audit_integration_test`、`auditctl_test`、`audit_test`
和 `audit_stress_test` 均通过，其中压力测试精确记录 768 条失败事件。GitHub Actions
`34359479579` 对预览提交 `6e597d9` 的文档构建和 30/30 QEMU 用户测试均成功，功能分支的
发布任务按策略跳过。

## 4. 尚不能宣告完成的联合验收

- A：需要稳定的 UID/Capability 设置方式，并让 `kill` 经过统一门面，才能验证 root、`AUDIT_READ`、普通用户及信号成功/拒绝审计。
- B：需要真正返回 `Result` 的用户地址复制实现，才能在 QEMU 中证明空指针、只读页、跨页无效范围和地址溢出不会引发内核 panic。
- C：需要在管道读写路径构造 `PipeRead/PipeWrite` 请求并调用统一门面，才能验证请求字节数与实际字节数。
- 全项目：已完成原始 `main`、D 未接线组和 C+D 管道创建安全路径的[性能初测](PERFORMANCE.md)，尚缺最终安全版本复测、最终集成压力数据和演示材料。

因此，目前可以确认 D 的独立审计机制和 C 的管道创建/配额联调通过，但不能把 A、B、C 全部联合验收或项目最终性能验收标记为完成。

## 5. 复核命令

```bash
git fetch --all --prune
git rev-list --left-right --count origin/integration...origin/feature/audit-testing
gh pr checks 1
gh run list --branch audit-c-integration-preview --limit 3
```
