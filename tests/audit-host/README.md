# 审计事件与系统调用主体的主机测试

从仓库根目录运行：

```bash
cargo test --manifest-path tests/audit-host/Cargo.toml -- --test-threads=1
```

原有 `lib.rs` 直接引用内核的 `audit.rs`、`security/api.rs` 和 `sync/up.rs`，
只用固定毫秒值替代 RISC-V 硬件时钟。新增的 `syscalls.rs` 还引用真实的
`os/src/syscall/security.rs` 和凭据类型，并为当前任务、用户复制提供测试替身。
不要在 `os/` 目录中执行该命令，
以免继承内核的 RISC-V 目标和链接脚本配置。

测试覆盖 ABI 大小与字段偏移、稳定操作编号、七种 errno、部分读写及零字节成功、
身份与资源元数据、统计快照、批次覆盖标志，以及实际记录入口的计数和自反馈过滤。
涉及全局审计缓冲区的操作集中在一个测试中；继续增加测试时也应保持单线程访问，
因为 `UPSafeCell` 只适用于单核、不可重入的借用场景。

系统调用的 9 项测试覆盖：权限优先级与 Capability、零容量/空尾部、非法参数、
统计只写 80 字节、空输出/地址整数溢出、部分复制失败后的游标重试、
复制时不持有任务/审计借用、快照隔离、覆盖标志和 32 条上限。
这个测试二进制通过互斥锁保护对全局审计状态的访问，测试之间使用统计增量。

只运行系统调用测试：

```bash
cargo test --manifest-path tests/audit-host/Cargo.toml --test syscalls
```

主机测试不验证真实时钟、真实用户页表的安全复制、602/603 分发或 A/B/C 的事件接线。
复制替身返回 `EFAULT` 只能证明主体正确传播错误，不能证明 B 的实现已经完成。
内核编译和已有用户程序的回归仍需运行：

```bash
make -C os run TEST=1
```
