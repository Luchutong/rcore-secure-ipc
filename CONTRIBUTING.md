# 贡献与合并规范

## 分支流程

1. 从最新 `integration` 创建自己的 `feature/*` 分支。
2. 每个提交只处理一个可解释的变更，并使用 `feat:`、`fix:`、`test:`、`docs:` 或 `refactor:` 前缀。
3. 推送功能分支，向 `integration` 创建 Pull Request。
4. 至少一名其他成员审查普通 PR；公共 API 变更至少需要两名其他成员批准。
5. CI 全部通过且讨论解决后，使用 squash merge 合入 `integration`。
6. 只有最终稳定版本通过 `integration -> main` PR 合并。

## 开始开发

```bash
git fetch origin
git switch integration
git pull --ff-only origin integration
git switch -c feature/<module-name>
```

保持功能分支同步：

```bash
git fetch origin
git rebase origin/integration
```

不要在 `main` 或 `integration` 上直接开发，也不要对共享分支强制推送。

## 提交前检查

- 运行 `cargo fmt --check`；
- 构建内核和用户程序；
- 运行与修改相关的用户态测试；
- 确认错误路径不会 panic 或泄漏资源；
- 同步更新接口、测试、设计文档和 AI 使用记录；
- 在 PR 中填写测试命令和实际结果。

## 冲突归属

- 功能模块冲突由对应负责人解决；
- `security/api.rs`、系统调用号表和 `TaskControlBlock` 的冲突由 PR 作者与受影响负责人共同解决；
- 不允许通过删除他人测试或降低 CI 检查来解决冲突。

## AI 工具

使用 AI 协助设计、编码、调试或文档时，应更新 `docs/AI_USAGE.md`，并对采用内容进行人工验证。
