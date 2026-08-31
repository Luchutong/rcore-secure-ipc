use crate::device_tree::clock_freq;
use crate::sbi::set_timer;
use riscv::register::time;

const TICKS_PER_SEC: usize = 100;
const MSEC_PER_SEC: usize = 1000;

pub fn get_time() -> usize {
    time::read()
}

pub fn get_time_ms() -> usize {
    time::read() / (clock_freq() / MSEC_PER_SEC)
}

pub fn set_next_trigger() {
    set_timer(get_time() + clock_freq() / TICKS_PER_SEC);
}
