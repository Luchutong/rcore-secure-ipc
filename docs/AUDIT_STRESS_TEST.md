# 多进程审计压力测试

## 1. 测试目标

`audit_stress_test` 验证多个进程连续写入审计日志时，固定容量环形缓冲区仍保持一致。它使用
`ipc_stat(flags != 0)` 作为确定的失败事件源，不依赖角色 A、B、C 的内部实现。

测试由 6 个子进程各生成 128 条 `EINVAL` 事件，共 768 条，必然超过当前 256 条容量。父进程
不假设子进程调度顺序，只验证可由 ABI 观察到的不变量：

- `total_events` 和 `failed_events` 精确增加 768，成功计数不变；
- `retained` 不超过容量，`overwritten_events` 按数学模型增加；
- `[first_sequence, next_sequence)` 与保留数量一致；
- 使用写入前游标读取时，第一条记录设置 `GAP_BEFORE`；
- 保留记录的序号连续、时间戳不递减，操作和 errno 正确；
- 每条保留记录的 PID 都属于本轮创建的子进程；
- 读到日志尾部后再次读取返回 0。

## 2. 超时和失败传播

CI 通过以下等价命令运行压力用例：

```text
until_timeout audit_stress_test 10000
```

10 秒是用户程序启动后的独立截止时间，不包含内核和文件系统镜像编译。`until_timeout` 在子进程
正常退出时立即返回其退出码；超时后以信号编号 `SIGKILL` 终止并回收子进程，返回 124。因此断言失败、执行失败和超时
都会使 `usertests` 及 CI 失败，而不会被包装程序掩盖。工作流仍保留整个 QEMU 测试任务的
10 分钟上限。

## 3. 复现方法

完整回归：

```bash
cd os
make run TEST=1
```

手工运行时启动普通用户 shell，然后执行：

```text
until_timeout audit_stress_test 10000
```

成功输出包含子进程数、每个子进程事件数、总事件数、保留数、覆盖增量和运行时间。时间只用于
诊断，不设置性能通过阈值，避免把宿主负载波动变成功能测试失败。

超时分支可在用户 shell 中用 `until_timeout infloop 100` 复核：包装器应在约 100 ms 后打印超时
信息，内核打印 `Killed, SIGKILL=9`，随后返回 shell。`kill` 的参数是信号编号，不可传入
`SignalFlags::SIGKILL.bits()` 位掩码。

## 4. 当前边界

本测试覆盖多进程审计写入及覆盖压力，不替代最终联合压力测试。A、B、C 正式集成后仍需增加
多 UID 信号、恶意用户地址，以及管道创建、读写、关闭和退出回收并行压力场景。
