//! Manual IPC security overhead benchmark.
//!
//! This program is intentionally not part of `usertests`: elapsed time under
//! emulation is environment-dependent. It prints raw counters so repeated
//! runs can be summarized without turning timing noise into a CI failure.

#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::audit::{self, IpcStatsV1};
use user_lib::{close, get_time, pipe};

const DEFAULT_ITERATIONS: usize = 4_000;
const WARMUP_ITERATIONS: usize = 64;

fn parse_iterations(argc: usize, argv: &[&str]) -> usize {
    if argc < 2 {
        return DEFAULT_ITERATIONS;
    }
    match argv[1].parse::<usize>() {
        Ok(value) if value > 0 => value,
        _ => {
            println!("usage: ipc_bench [positive-iterations]");
            0
        }
    }
}

fn snapshot() -> IpcStatsV1 {
    let mut stats = IpcStatsV1::default();
    assert_eq!(audit::stat(&mut stats), 0);
    stats
}

fn create_and_close_pipe() {
    let mut pair = [0usize; 2];
    assert_eq!(pipe(&mut pair), 0);
    assert_eq!(close(pair[0]), 0);
    assert_eq!(close(pair[1]), 0);
}

#[unsafe(no_mangle)]
pub fn main(argc: usize, argv: &[&str]) -> i32 {
    let iterations = parse_iterations(argc, argv);
    if iterations == 0 {
        return 2;
    }

    for _ in 0..WARMUP_ITERATIONS {
        create_and_close_pipe();
    }

    let before = snapshot();
    let start_ms = get_time();
    for _ in 0..iterations {
        create_and_close_pipe();
    }
    let elapsed_ms = (get_time() - start_ms) as usize;
    let after = snapshot();

    let event_delta = after.total_events - before.total_events;
    let success_delta = after.successful_events - before.successful_events;
    let ns_per_iteration = elapsed_ms.saturating_mul(1_000_000) / iterations;

    println!(
        "BENCH pipe_create_close iterations={} elapsed_ms={} ns_per_iteration={} audit_events={} audit_successes={}",
        iterations, elapsed_ms, ns_per_iteration, event_delta, success_delta,
    );
    0
}
