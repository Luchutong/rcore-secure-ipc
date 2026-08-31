# rCore Secure IPC

基于 Rust 与 RISC-V 的教学操作系统 IPC 安全扩展实践项目。

本项目在 rCore 已有的地址空间隔离、文件描述符、管道和信号机制上，研究并实现进程身份、信号授权、IPC 边界检查、资源限制与安全审计。

## 项目目标

- 为进程增加最小化凭据模型（UID 与能力位）。
- 为信号发送增加调用者身份与权限校验。
- 加固 IPC 系统调用的用户指针验证和错误处理。
- 增加每进程 IPC 资源限制与安全审计接口。
- 提供正常、越权、边界和并发压力测试，并与原版 rCore 对比。

## 当前状态

项目处于基线阶段。仓库包含可供后续改造的 rCore 第七章教学内核源码，以及项目路线图和 AI 使用记录。

- [四人协作开发计划](docs/ROADMAP.md)
- [IPC Security API v1](docs/IPC_SECURITY_API.md)
- [模块独立性审计](docs/MODULE_INDEPENDENCE.md)
- [贡献与合并规范](CONTRIBUTING.md)
- [AI 工具使用记录](docs/AI_USAGE.md)

## 上游成果与致谢

本项目的教学内核基线来源于 rCore 社区开发的 [rCore-Tutorial-v3](https://github.com/rcore-os/rCore-Tutorial-v3)，采用其 `ch7` 分支在提交 `af89aff` 时的源码。管道、信号、进程管理、虚拟内存、文件系统及相关用户态支持均来自该上游项目，本仓库的工作是在此基础上开展安全扩展与实验分析。

- 上游源码：[rcore-os/rCore-Tutorial-v3](https://github.com/rcore-os/rCore-Tutorial-v3)
- 中文教程：[rCore-Tutorial-Book-v3](https://rcore-os.cn/rCore-Tutorial-Book-v3/)
- 上游贡献者与历史：[Contributors](https://github.com/rcore-os/rCore-Tutorial-v3/graphs/contributors)

感谢 rCore 社区及所有上游贡献者提供的教学内核、文档和开发成果。

## 许可证

本仓库保留上游项目的 GNU General Public License v3.0，详见 [LICENSE](LICENSE)。基于上游源码的修改继续遵循该许可证。

## 上游同步

本地仓库保留名为 `upstream` 的远程地址，用于查看和同步官方代码：

```bash
git fetch upstream
```

上游历史不会合并进本项目的 `main` 提交历史；需要同步时应以明确的代码变更提交记录引入。
