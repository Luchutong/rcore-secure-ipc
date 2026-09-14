#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::{SIGKILL, exec, fork, get_time, kill, waitpid, waitpid_nb, yield_};

#[unsafe(no_mangle)]
pub fn main(argc: usize, argv: &[&str]) -> i32 {
    if argc != 3 {
        println!("usage: until_timeout <program> <timeout_ms>");
        return 2;
    }
    let timeout_ms = match argv[2].parse::<isize>() {
        Ok(value) if value > 0 => value,
        _ => {
            println!("invalid timeout: {}", argv[2]);
            return 2;
        }
    };
    let fork_ret = fork();
    if fork_ret < 0 {
        println!("fork failed: {}", fork_ret);
        return 1;
    }
    let pid = fork_ret as usize;
    if pid == 0 {
        if exec(argv[1], &[core::ptr::null::<u8>()]) != 0 {
            println!("Error when executing '{}'", argv[1]);
            return 127;
        }
    } else {
        let start_time = get_time();
        let mut exit_code: i32 = 0;
        loop {
            let wait_ret = waitpid_nb(pid, &mut exit_code);
            if wait_ret == pid as isize {
                println!(
                    "child exited in {}ms, exit_code = {}",
                    get_time() - start_time,
                    exit_code,
                );
                return exit_code;
            }
            if wait_ret == -1 {
                println!("waitpid failed for child {}", pid);
                return 1;
            }
            if get_time() - start_time >= timeout_ms {
                println!("child has run for {}ms, kill it!", timeout_ms);
                // `kill` 的第二个参数是信号编号，而不是 SignalFlags 位掩码。
                let kill_ret = kill(pid, SIGKILL);
                if kill_ret < 0 {
                    println!("kill({}) returned {}", pid, kill_ret);
                }
                let wait_ret = waitpid(pid, &mut exit_code);
                if wait_ret != pid as isize {
                    println!("waitpid({}) returned {}", pid, wait_ret);
                }
                return 124;
            }
            yield_();
        }
    }
    0
}
