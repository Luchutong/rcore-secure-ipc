use crate::fs::{OpenFlags, open_file};
use crate::mm::{MAX_ARGV, MAX_STR_LEN, copy_from_user, copy_to_user, try_translated_str};
use crate::security::{
    self, CapabilitySet, IpcError, IpcObject, IpcOperation, IpcRequest, IpcSubject, Uid,
};
use crate::task::{
    MAX_SIG, SignalAction, SignalFlags, add_task, current_task, current_user_token,
    exit_current_and_run_next, pid2task, suspend_current_and_run_next,
};
use crate::timer::get_time_ms;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

fn ipc_error_to_ret(error: IpcError) -> isize {
    match error {
        IpcError::PermissionDenied => -1,
        IpcError::InvalidAddress => -14,
        IpcError::InvalidArgument => -22,
        IpcError::ProcessNotFound => -3,
        IpcError::TooManyFiles => -24,
        IpcError::ResourceExhausted => -28,
        IpcError::TryAgain => -11,
    }
}

pub fn sys_exit(exit_code: i32) -> ! {
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

pub fn sys_get_time() -> isize {
    get_time_ms() as isize
}

pub fn sys_getpid() -> isize {
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8, mut args: *const usize) -> isize {
    let token = current_user_token();
    // 校验路径字符串：非法指针或超长返回 -1
    let Some(path) = try_translated_str(token, path, MAX_STR_LEN) else {
        return -14;
    };
    let mut args_vec: Vec<String> = Vec::new();
    loop {
        // 逐项校验参数指针：非法地址返回 -1，不 panic
        let Ok(arg_str_ptr) = copy_from_user(token, args) else {
            return -14;
        };
        if arg_str_ptr == 0 {
            break;
        }
        // 限制参数个数，防止未以 0 结尾的 argv 数组导致无限遍历
        if args_vec.len() >= MAX_ARGV {
            return -1;
        }
        let Some(arg) = try_translated_str(token, arg_str_ptr as *const u8, MAX_STR_LEN) else {
            return -14;
        };
        args_vec.push(arg);
        args = args.wrapping_add(1);
    }
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        let argc = args_vec.len();
        task.exec(all_data.as_slice(), args_vec);
        // return argc because cx.x[10] will be covered with it later
        argc as isize
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = &inner.children[idx];
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        // 先复制退出码：非法地址返回 EFAULT，且不移动 children 列表，调用方可重试。
        if copy_to_user(inner.memory_set.token(), exit_code_ptr, &exit_code).is_err() {
            return -14;
        }
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

pub fn sys_kill(pid: usize, signum: i32) -> isize {
    if signum < 0 || signum as usize > MAX_SIG {
        return ipc_error_to_ret(IpcError::InvalidArgument);
    }
    let flag = match SignalFlags::from_bits(1u32 << signum as u32) {
        Some(f) => f,
        None => return ipc_error_to_ret(IpcError::InvalidArgument),
    };

    let target = match pid2task(pid) {
        Some(t) => t,
        None => return ipc_error_to_ret(IpcError::ProcessNotFound),
    };

    let caller = current_task().unwrap();
    let caller_pid = caller.getpid();
    let target_uid = {
        let inner = target.inner_exclusive_access();
        inner.security.credentials.uid
    };

    // A+D integration point: policy, quota bookkeeping and audit all pass
    // through the stable facade. Authorization failures are recorded by preflight.
    let permit = {
        let mut inner = caller.inner_exclusive_access();
        let credentials = inner.security.credentials;
        let request = IpcRequest {
            subject: IpcSubject {
                pid: caller_pid,
                uid: credentials.uid,
                capabilities: credentials.capabilities,
            },
            object: IpcObject {
                id: pid as u64,
                owner_uid: target_uid,
            },
            operation: IpcOperation::SignalSend,
            amount: 1,
        };
        match security::preflight(&mut inner.security, request) {
            Ok(permit) => permit,
            Err(error) => return ipc_error_to_ret(error),
        }
    };

    let outcome = {
        let mut target_inner = target.inner_exclusive_access();
        if target_inner.signals.contains(flag) {
            Err(IpcError::TryAgain)
        } else {
            target_inner.signals.insert(flag);
            Ok(1)
        }
    };

    let mut inner = caller.inner_exclusive_access();
    match security::complete(&mut inner.security, permit, outcome) {
        Ok(_) => 0,
        Err(error) => ipc_error_to_ret(error),
    }
}

pub fn sys_sigprocmask(mask: u32) -> isize {
    if let Some(task) = current_task() {
        let mut inner = task.inner_exclusive_access();
        let old_mask = inner.signal_mask;
        if let Some(flag) = SignalFlags::from_bits(mask) {
            inner.signal_mask = flag;
            old_mask.bits() as isize
        } else {
            -1
        }
    } else {
        -1
    }
}

pub fn sys_sigreturn() -> isize {
    if let Some(task) = current_task() {
        let mut inner = task.inner_exclusive_access();
        inner.handling_sig = -1;
        // restore the trap context
        let trap_ctx = inner.get_trap_cx();
        *trap_ctx = inner.trap_ctx_backup.unwrap();
        // Here we return the value of a0 in the trap_ctx,
        // otherwise it will be overwritten after we trap
        // back to the original execution of the application.
        trap_ctx.x[10] as isize
    } else {
        -1
    }
}

fn check_sigaction_error(signal: SignalFlags, action: usize, old_action: usize) -> bool {
    if action == 0
        || old_action == 0
        || signal == SignalFlags::SIGKILL
        || signal == SignalFlags::SIGSTOP
    {
        true
    } else {
        false
    }
}

pub fn sys_sigaction(
    signum: i32,
    action: *const SignalAction,
    old_action: *mut SignalAction,
) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if signum as usize > MAX_SIG {
        return -1;
    }
    if let Some(flag) = SignalFlags::from_bits(1 << signum) {
        if check_sigaction_error(flag, action as usize, old_action as usize) {
            return -1;
        }
        let prev_action = inner.signal_actions.table[signum as usize];
        // 复制输入后再写回旧动作；任一地址非法都返回 EFAULT，不修改内核动作表。
        let Ok(new_action) = copy_from_user(token, action) else {
            return -14;
        };
        if copy_to_user(token, old_action, &prev_action).is_err() {
            return -14;
        }
        inner.signal_actions.table[signum as usize] = new_action;
        0
    } else {
        -1
    }
}

// ---------------------------------------------------------------------------
//  Credential syscalls
// ---------------------------------------------------------------------------

/// Return the UID of the calling process.
pub fn sys_getuid() -> isize {
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    inner.security.credentials.uid as isize
}

/// Change the UID of the calling process.
///
/// Only root (UID 0) may call this.  After the call the process loses root
/// privileges (its capabilities are cleared) unless `uid == 0`.
/// Returns 0 on success, -1 on failure.
pub fn sys_setuid(uid: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    let cred = &mut inner.security.credentials;

    // Only root can change UID.
    if !cred.is_root() {
        return ipc_error_to_ret(IpcError::PermissionDenied);
    }

    let Ok(new_uid) = Uid::try_from(uid) else {
        return ipc_error_to_ret(IpcError::InvalidArgument);
    };
    cred.uid = new_uid;
    // Dropping root: lose all capabilities.
    // Staying root: keep all capabilities.
    if new_uid != 0 {
        cred.capabilities = CapabilitySet::empty();
    }
    0
}
