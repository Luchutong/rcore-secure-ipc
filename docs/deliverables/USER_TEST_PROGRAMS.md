# 用户态测试程序交付说明

## 1. 交付范围

最终版本已经包含可直接编译进 easy-fs 镜像的用户态安全测试，不需要为答辩临时编造测试。
统一自动入口是 `user/src/bin/usertests.rs`；安全相关独立程序如下。

| 程序 | 对应模块 | 主要验证 | 成功标志 |
| --- | --- | --- | --- |
| `cred_test` | A+D | UID、fork 继承、同/跨 UID 信号、root 放行、审计权限 | `cred_test passed!` |
| `badptr` | B | 8 类恶意地址，open/pipe/read/write 的 EFAULT 传播 | `badptr summary: 8/8 passed` |
| `quota_test` | C | FD、pipe、dup、回滚、fork 隔离、并发创建关闭 | `quota_test passed!` |
| `ipc_audit_integration_test` | B+C+D | 管道创建/读写审计、坏指针、配额拒绝、稳定对象 ID、跨页输出 | `ipc_audit_integration_test passed!` |
| `auditctl_test` | D | 用户工具 stat/read、分页、游标、覆盖、无反馈 | `auditctl_test passed: ...` |
| `audit_test` | D | 80 字节 ABI、哨兵、统计一致性、游标和覆盖语义 | `audit_test passed!` |
| `audit_stress_test` | D | 6 进程并发产生 768 个事件、有界保留和连续序号 | `[audit_stress_test] PASS ...` |
| `ipc_bench` | C+D | 管道创建/关闭安全路径的端到端耗时和审计增量 | `BENCH ...` |
| `auditctl` | D 工具 | 人工读取统计和事件，不是判定型测试 | `capacity=...` / `seq=...` |

## 2. 自动完整测试

### 2.1 命令

```bash
git switch main
git pull --ff-only
git describe --tags --always
cd os
make run TEST=1
```

推荐记录环境：

```bash
rustc --version
cargo --version
qemu-system-riscv64 --version
git rev-parse HEAD
```

### 2.2 判定规则

`usertests` 先运行 28 个应正常退出的程序，再运行 4 个应由内核异常终止的程序。后四项
只有在退出码精确匹配预期时才算 PASS：

| 程序 | 预期退出码 | 含义 |
| --- | ---: | --- |
| `stack_overflow` | -11 | 用户栈访问异常，SIGSEGV |
| `priv_csr` | -4 | 用户态执行特权 CSR 指令，SIGILL |
| `priv_inst` | -4 | 用户态执行特权指令，SIGILL |
| `store_fault` | -11 | 非法存储访问，SIGSEGV |

最终必须同时出现：

```text
[usertests] expected-success suite result: 28/28 passed
[usertests] expected-failure suite result: 4/4 passed
[usertests] PASS all tests: 32/32
Usertests passed!
```

不要只截最后一行：至少保留两个分组统计，以证明 4 个异常退出是“符合预期”，而不是被遗漏。

## 3. 独立演示方法

启动交互式用户 shell：

```bash
cd os
make run
```

进入 `Rust user shell` 后，可按下列顺序演示：

```text
cred_test
badptr
quota_test
ipc_audit_integration_test
audit_stress_test
ipc_bench 20000
auditctl stat
```

退出 QEMU：按 `Ctrl+A`，松开后按 `X`。不要直接关闭终端，否则日志可能不完整。

## 4. 各程序的测试设计与答辩解释

### 4.1 `cred_test`：凭据与信号授权

测试过程：

1. root 父进程创建受害进程，受害进程降权到 UID 2。
2. 攻击进程降权到 UID 1，尝试向 UID 2 发送 SIGKILL，预期返回 `-EPERM`。
3. UID 1 同时尝试读取审计统计，预期因没有 `AUDIT_READ` 返回 `-EPERM`。
4. root 父进程向 UID 2 发送 SIGKILL，预期成功。
5. 另一个 UID 3 进程 fork 子进程，验证凭据继承和同 UID 信号放行。
6. root 读取审计记录，核对拒绝信号、成功信号和拒绝审计读取均恰好出现。

答辩时要说明：内核输出两次 `Killed, SIGKILL=9` 是测试主动终止目标进程，不是内核崩溃。

### 4.2 `badptr`：系统调用边界安全

程序直接发起原始系统调用，避免先在 Rust 用户态构造本身就违反语言规则的引用或切片。

| 编号 | 操作 | 非法输入 | 预期 |
| --- | --- | --- | --- |
| B01 | write | NULL | `-EFAULT` |
| B02 | write | 内核地址 `0x80200000` | `-EFAULT` |
| B03 | write | 高地址 `0xfffffffffffff000` | `-EFAULT` |
| B04 | write | `ptr+len` 整数回绕 | `-EFAULT` |
| B05 | write | 非零未映射页 | `-EFAULT` |
| B06 | write | 从有效栈页跨入未映射页 | `-EFAULT` |
| B07 | read | 输出地址位于只读代码页 | `-EFAULT` |
| B08 | read | 输出范围跨越只读页边界 | `-EFAULT` |

关键判据不是“程序没有 panic”，而是每项都精确返回 `-14`，测试继续运行并打印 8/8；随后再运行
`hello_world`，证明攻击测试结束后内核仍能调度新的用户程序。

### 4.3 `quota_test`：资源耗尽与恢复

七组场景：

1. 普通 open 达到 `MAX_OPEN_FILES=32`，下一次返回 `EMFILE`，关闭一个 FD 后恢复。
2. dup 达到 FD 上限，失败后关闭并恢复。
3. 8 条管道占满 16 个管道端点，下一次返回 `ENOSPC`，关闭一条后恢复。
4. 剩余 FD 只有一个时，pipe 的两个端点不能部分安装；失败必须完整回滚。
5. dup 管道端点计入 pipe 配额，关闭副本后恢复。
6. fork 继承初始用量，但父子后续计数隔离。
7. 父子各重复 32 轮创建/关闭，检查描述符复用和释放。

答辩重点：配额失败只影响当前进程；关闭资源后可恢复，证明没有永久计数泄漏。

### 4.4 `ipc_audit_integration_test`：跨模块联合验证

该程序最能说明项目不是四个孤立模块，建议报告中重点介绍：

- 成功 pipe：产生一条成功 `PipeCreate`，请求量与结果均为 1。
- 配额拒绝：产生 `ENOSPC` 失败事件，关闭资源后 pipe 再次成功。
- 用户复制失败：错误输出地址返回 `EFAULT`，预留的两个端点被回滚。
- pipe read/write：同一管道使用稳定非零 object ID，记录请求字节数、实际字节数和 errno。
- 零长度读写：成功且请求/结果均为 0。
- 无效读写地址：结果 0、errno=EFAULT，内核继续运行。
- 跨页非对齐统计输出：80 字节 `IpcStatsV1` 能安全复制并保持 ABI 字段正确。

### 4.5 `audit_test` 与 `auditctl_test`

`audit_test` 负责内核 ABI 边界，`auditctl_test` 负责真实用户工具端到端行为，两者不可互相替代：

- `audit_test` 使用 80 字节固定结构和尾部哨兵检查，防止越界写。
- 单次 `audit_read` 最多 32 条，游标只在整批复制成功后推进。
- 环形缓冲覆盖后首条记录带 `GAP_BEFORE`，消费者能发现丢失区间。
- `auditctl` 固定初始 tail，读取期间新事件不会让命令无限追赶。
- 成功读取和统计不记录自身，避免“读取日志又制造日志”的反馈循环。
- 非法参数、无权限和复制失败会记录一次失败控制事件。

### 4.6 `audit_stress_test`

固定配置为 6 个子进程、每个 128 次非法 `ipc_stat(flags=1)`，共 768 个可预测的 EINVAL
事件。父进程检查：

- 总事件和失败事件精确增加 768；
- 子进程全部正常退出；
- 当前保留记录不超过容量 256；
- 保留序号连续，时间戳不倒退，PID 属于六个子进程之一；
- 缓冲满后覆盖旧记录，但统计不会丢失写入量。

`overwritten_delta` 取决于测试开始时缓冲区已有多少记录。最终完整 CI 开始该测试时缓冲区已满，
因此增量为 768；独立运行可能得到 512～768 之间的其他合法值。不要把这个值硬编码进截图判定。

### 4.7 `ipc_bench`

程序先预热 64 次，再计时指定轮数的 `pipe → close(read_fd) → close(write_fd)`。计时前后读取
审计统计，确保每轮确实写入一次 PipeCreate 事件。建议连续运行 5 次：

```text
ipc_bench 20000
ipc_bench 20000
ipc_bench 20000
ipc_bench 20000
ipc_bench 20000
```

按 `elapsed_ms` 排序取中位数，不设置硬性性能 PASS 阈值。QEMU 和宿主调度有噪声，性能程序
因此不加入自动 `usertests`。

## 5. 宿主测试

宿主测试复用真实审计核心源码，并为任务状态和用户复制提供替身，适合快速检查 ABI 和算法：

```bash
cd tests/audit-host
cargo test
```

共 28 项：核心 7、工具 12、系统调用主体 9。它不能替代 QEMU 页表、调度、真实系统调用路由
和进程生命周期测试；报告必须把两类证据并列呈现。

## 6. 交付前代码检查

```bash
git status --short
git describe --tags --always
git diff v1.0.0 -- user/src/bin user/src/audit.rs user/src/syscall.rs
```

正式成果应以 `v1.0.0` 为基线。若组员为了展示修改测试输出，必须另建分支，不得改动测试语义，
且应重新运行完整 QEMU 测试。严禁仅删除断言、吞掉非零退出码或把失败文本改成 PASS。
