mod address;
mod frame_allocator;
mod heap_allocator;
mod memory_set;
mod page_table;
mod user_access;

use address::VPNRange;
pub use address::{PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum};
pub use frame_allocator::{FrameTracker, frame_alloc, frame_dealloc};
pub use memory_set::remap_test;
pub use memory_set::{KERNEL_SPACE, MapPermission, MemorySet, kernel_token};
use page_table::PTEFlags;
pub use page_table::{
    MAX_ARGV, MAX_STR_LEN, PageTable, PageTableEntry, UserBuffer, check_user_range,
    try_translated_byte_buffer, try_translated_ref, try_translated_refmut, try_translated_str,
};
pub use user_access::{copy_from_user, copy_to_user};

pub fn init() {
    heap_allocator::init_heap();
    frame_allocator::init_frame_allocator();
    KERNEL_SPACE.exclusive_access().activate();
}
