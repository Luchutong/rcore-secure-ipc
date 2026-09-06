#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

// not in SUCC_TESTS & FAIL_TESTS
// count_lines, infloop, user_shell, usertests

// item of TESTS : app_name(argv_0), argv_1, argv_2, argv_3, exit_code
type TestCase = (&'static str, &'static str, &'static str, &'static str, i32);

static SUCC_TESTS: &[TestCase] = &[
    ("filetest_simple\0", "\0", "\0", "\0", 0),
    ("cat\0", "filea\0", "\0", "\0", 0),
    ("cmdline_args\0", "1\0", "2\0", "3\0", 0),
    ("exit\0", "\0", "\0", "\0", 0),
    ("fantastic_text\0", "\0", "\0", "\0", 0),
    ("forktest_simple\0", "\0", "\0", "\0", 0),
    ("forktest\0", "\0", "\0", "\0", 0),
    ("forktest2\0", "\0", "\0", "\0", 0),
    ("forktree\0", "\0", "\0", "\0", 0),
    ("hello_world\0", "\0", "\0", "\0", 0),
    ("huge_write\0", "\0", "\0", "\0", 0),
    ("matrix\0", "\0", "\0", "\0", 0),
    ("pipe_large_test\0", "\0", "\0", "\0", 0),
    ("pipetest\0", "\0", "\0", "\0", 0),
    ("run_pipe_test\0", "\0", "\0", "\0", 0),
    ("sleep_simple\0", "\0", "\0", "\0", 0),
    ("sleep\0", "\0", "\0", "\0", 0),
    ("sig_simple\0", "\0", "\0", "\0", 0),
    ("sig_simple2\0", "\0", "\0", "\0", 0),
    ("sig_tests\0", "\0", "\0", "\0", 0),
    ("yield\0", "\0", "\0", "\0", 0),
    // Security audit regressions are part of the same suite run by CI through
    // `make run TEST=1`; a non-zero exit from either test must fail the suite.
    ("auditctl_test\0", "\0", "\0", "\0", 0),
    ("audit_test\0", "\0", "\0", "\0", 0),
];

static FAIL_TESTS: &[TestCase] = &[
    ("stack_overflow\0", "\0", "\0", "\0", -11),
    ("priv_csr\0", "\0", "\0", "\0", -4),
    ("priv_inst\0", "\0", "\0", "\0", -4),
    ("store_fault\0", "\0", "\0", "\0", -11),
];

use user_lib::{exec, exit, fork, waitpid};

fn test_name(program: &str) -> &str {
    program.strip_suffix('\0').unwrap_or(program)
}

fn argv_for(test: &TestCase) -> [*const u8; 4] {
    let arguments = [test.1, test.2, test.3];
    let mut argv = [core::ptr::null::<u8>(); 4];
    argv[0] = test.0.as_ptr();
    for (index, argument) in arguments.iter().enumerate() {
        if *argument != "\0" {
            argv[index + 1] = argument.as_ptr();
        }
    }
    argv
}

fn run_tests(suite: &str, tests: &[TestCase]) -> usize {
    let mut passed = 0;
    println!(
        "[usertests] Running {} suite ({} tests)",
        suite,
        tests.len()
    );

    for test in tests {
        let name = test_name(test.0);
        let argv = argv_for(test);
        println!("[usertests] RUN  {}", name);

        let pid = fork();
        if pid < 0 {
            println!(
                "\x1b[31m[usertests] FAIL {}: fork returned {}\x1b[0m",
                name, pid
            );
            continue;
        }
        if pid == 0 {
            let result = exec(test.0, &argv);
            println!(
                "\x1b[31m[usertests] FAIL {}: exec unexpectedly returned {}\x1b[0m",
                name, result
            );
            exit(127);
        }

        let mut exit_code = 0;
        let wait_pid = waitpid(pid as usize, &mut exit_code);
        if wait_pid != pid {
            println!(
                "\x1b[31m[usertests] FAIL {}: waitpid expected {} but returned {}\x1b[0m",
                name, pid, wait_pid
            );
            continue;
        }

        if exit_code == test.4 {
            passed += 1;
            println!(
                "\x1b[32m[usertests] PASS {}: exit={}\x1b[0m",
                name, exit_code
            );
        } else {
            println!(
                "\x1b[31m[usertests] FAIL {}: expected exit={} actual exit={}\x1b[0m",
                name, test.4, exit_code
            );
        }
    }

    println!(
        "[usertests] {} suite result: {}/{} passed",
        suite,
        passed,
        tests.len()
    );
    passed
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    let succ_num = run_tests("expected-success", SUCC_TESTS);
    let err_num = run_tests("expected-failure", FAIL_TESTS);
    let passed = succ_num + err_num;
    let total = SUCC_TESTS.len() + FAIL_TESTS.len();

    if passed == total {
        println!(
            "\x1b[32m[usertests] PASS all tests: {}/{}\nUsertests passed!\x1b[0m",
            passed, total
        );
        0
    } else {
        println!(
            "\x1b[31m[usertests] FAIL summary: {}/{} passed\nUsertests failed!\x1b[0m",
            passed, total
        );
        1
    }
}
