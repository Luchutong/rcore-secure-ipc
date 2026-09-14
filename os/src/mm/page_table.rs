use super::{FrameTracker, PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum, frame_alloc};
use crate::config::{PAGE_SIZE, PAGE_SIZE_BITS};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::*;

/// 用户字符串（路径/命令行参数）的最大长度。
///
/// 防止恶意应用传入无 `\0` 终止的字符串，导致内核逐字节翻译时无限循环。
pub const MAX_STR_LEN: usize = 0x10000;

/// `exec` 参数指针数组的最大项数。
///
/// 防止参数数组未以 0 结尾时内核无限遍历用户内存。
pub const MAX_ARGV: usize = 64;

/// SV39 用户虚拟地址空间正区上限（2^38）。
///
/// 用户指针及其覆盖区间必须严格位于 `[0, USER_VA_LIMIT)` 内，
/// 超出该范围的地址（内核区、trampoline、trap context 等）一律拒绝。
const USER_VA_LIMIT: usize = 1 << 38;

bitflags! {
    pub struct PTEFlags: u8 {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct PageTableEntry {
    pub bits: usize,
}

impl PageTableEntry {
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        PageTableEntry {
            bits: ppn.0 << 10 | flags.bits as usize,
        }
    }
    pub fn empty() -> Self {
        PageTableEntry { bits: 0 }
    }
    pub fn ppn(&self) -> PhysPageNum {
        (self.bits >> 10 & ((1usize << 44) - 1)).into()
    }
    pub fn flags(&self) -> PTEFlags {
        PTEFlags::from_bits(self.bits as u8).unwrap()
    }
    pub fn is_valid(&self) -> bool {
        (self.flags() & PTEFlags::V) != PTEFlags::empty()
    }
    pub fn readable(&self) -> bool {
        (self.flags() & PTEFlags::R) != PTEFlags::empty()
    }
    pub fn writable(&self) -> bool {
        (self.flags() & PTEFlags::W) != PTEFlags::empty()
    }
    pub fn executable(&self) -> bool {
        (self.flags() & PTEFlags::X) != PTEFlags::empty()
    }
}

pub struct PageTable {
    root_ppn: PhysPageNum,
    frames: Vec<FrameTracker>,
}

/// Assume that it won't oom when creating/mapping.
impl PageTable {
    pub fn new() -> Self {
        let frame = frame_alloc().unwrap();
        PageTable {
            root_ppn: frame.ppn,
            frames: vec![frame],
        }
    }
    /// Temporarily used to get arguments from user space.
    pub fn from_token(satp: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(satp & ((1usize << 44) - 1)),
            frames: Vec::new(),
        }
    }
    fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                let frame = frame_alloc().unwrap();
                *pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                self.frames.push(frame);
            }
            ppn = pte.ppn();
        }
        result
    }
    fn find_pte(&self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                return None;
            }
            ppn = pte.ppn();
        }
        result
    }
    #[allow(unused)]
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) {
        let pte = self.find_pte_create(vpn).unwrap();
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
    }
    #[allow(unused)]
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        let pte = self.find_pte(vpn).unwrap();
        assert!(pte.is_valid(), "vpn {:?} is invalid before unmapping", vpn);
        *pte = PageTableEntry::empty();
    }
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.find_pte(vpn).map(|pte| *pte)
    }
    pub fn translate_va(&self, va: VirtAddr) -> Option<PhysAddr> {
        self.find_pte(va.clone().floor()).map(|pte| {
            let aligned_pa: PhysAddr = pte.ppn().into();
            let offset = va.page_offset();
            let aligned_pa_usize: usize = aligned_pa.into();
            (aligned_pa_usize + offset).into()
        })
    }
    pub fn token(&self) -> usize {
        8usize << 60 | self.root_ppn.0
    }
}

/// 校验用户提供的地址区间 `[ptr, ptr + len)` 是否安全可访问。
///
/// 通过要求：
/// 1. `ptr + len` 不产生 usize 溢出，且整个区间落在用户正区 `[0, USER_VA_LIMIT)` 内；
/// 2. 区间覆盖的每一页在当前用户页表中均已映射；
/// 3. 每一页的 PTE 均带 `U` 标志（拒绝内核页 / trap context / trampoline）；
/// 4. 每一页的权限满足访问意图（`write == true` 要求 `W`，否则要求 `R`）。
///
/// 返回 `false` 表示该区间不可访问，调用方应拒绝本次访问（如返回 -1），
/// 绝不能继续解引用。
pub fn check_user_range(token: usize, ptr: usize, len: usize, write: bool) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };
    if ptr >= USER_VA_LIMIT || end > USER_VA_LIMIT {
        return false;
    }
    let page_table = PageTable::from_token(token);
    let mut cur = ptr;
    while cur < end {
        let pte = match page_table.translate(VirtAddr::from(cur).floor()) {
            Some(pte) => pte,
            None => return false,
        };
        let flags = pte.flags();
        if !flags.contains(PTEFlags::U) {
            return false;
        }
        if write {
            if !flags.contains(PTEFlags::W) {
                return false;
            }
        } else if !flags.contains(PTEFlags::R) {
            return false;
        }
        // 跳到下一页边界（或区间终点）
        let page_end = (cur & !(PAGE_SIZE - 1)) + PAGE_SIZE;
        cur = page_end.min(end);
    }
    true
}

/// 安全版 `translated_byte_buffer`。
///
/// `write` 表示内核的访问意图：内核将向该缓冲区写入（如 `read` 系统调用）
/// 时传 `true`，要求用户页可写；内核将从该缓冲区读取（如 `write` 系统调用）
/// 时传 `false`，要求用户页可读。区间非法时返回 `None`，调用方应优雅失败。
pub fn try_translated_byte_buffer(
    token: usize,
    ptr: *const u8,
    len: usize,
    write: bool,
) -> Option<Vec<&'static mut [u8]>> {
    if !check_user_range(token, ptr as usize, len, write) {
        return None;
    }
    // 校验通过后，以下逐页翻译不会触发未映射 panic
    let page_table = PageTable::from_token(token);
    let mut start = ptr as usize;
    let end = start + len;
    let mut v = Vec::new();
    while start < end {
        let start_va = VirtAddr::from(start);
        let mut vpn = start_va.floor();
        let ppn = page_table.translate(vpn).unwrap().ppn();
        vpn.step();
        let mut end_va: VirtAddr = vpn.into();
        end_va = end_va.min(VirtAddr::from(end));
        if end_va.page_offset() == 0 {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..]);
        } else {
            v.push(&mut ppn.get_bytes_array()[start_va.page_offset()..end_va.page_offset()]);
        }
        start = end_va.into();
    }
    Some(v)
}

/// 安全版 `translated_str`：从用户空间加载以 `\0` 结尾的字符串。
///
/// 逐页扫描：只要求“实际扫描过的页”已映射、带 `U` 标志、可读，
/// 一旦遇到 `\0` 立即成功返回；因此字符串很短时不会要求其后的内存也映射。
/// 若扫描超过 `max_len` 仍无终止符（或中途遇到非法页），返回 `None`。
pub fn try_translated_str(token: usize, ptr: *const u8, max_len: usize) -> Option<String> {
    let start = ptr as usize;
    if start == 0 || max_len == 0 {
        return None;
    }
    // 仅做数值边界检查：扫描上限不得溢出、不得越过用户正区
    let limit = start.checked_add(max_len)?;
    if limit > USER_VA_LIMIT {
        return None;
    }
    let page_table = PageTable::from_token(token);
    let mut string = String::new();
    let mut cur = start;
    while cur < limit {
        // 只校验当前扫描到的这一页：必须映射、带 U 标志、可读
        let pte = page_table.translate(VirtAddr::from(cur).floor())?;
        let flags = pte.flags();
        if !flags.contains(PTEFlags::U) || !flags.contains(PTEFlags::R) {
            return None;
        }
        let ppn = pte.ppn();
        let offset = cur & (PAGE_SIZE - 1);
        let chunk = (PAGE_SIZE - offset).min(limit - cur);
        let bytes = ppn.get_bytes_array();
        let slice = &bytes[offset..offset + chunk];
        match slice.iter().position(|&b| b == 0) {
            Some(z) => {
                string.extend(slice[..z].iter().map(|&b| b as char));
                return Some(string);
            }
            None => {
                string.extend(slice.iter().map(|&b| b as char));
                cur += chunk;
            }
        }
    }
    None
}

/// 安全版 `translated_ref`：校验后返回对用户内存中 `T` 的共享引用。
///
/// 要求 `T` 完整落在同一用户页内（避免跨页时物理内存不连续导致读错数据），
/// 且该页已映射、带 `U` 标志、可读。非法时返回 `None`。
pub fn try_translated_ref<T>(token: usize, ptr: *const T) -> Option<&'static T> {
    let addr = ptr as usize;
    let size = core::mem::size_of::<T>();
    if size == 0 || addr == 0 || addr % core::mem::align_of::<T>() != 0 {
        return None;
    }
    let end = addr.checked_add(size)?;
    if end > USER_VA_LIMIT {
        return None;
    }
    // 跨页检查：整个 T 必须位于同一页内
    if (addr >> PAGE_SIZE_BITS) != ((end - 1) >> PAGE_SIZE_BITS) {
        return None;
    }
    if !check_user_range(token, addr, size, false) {
        return None;
    }
    let page_table = PageTable::from_token(token);
    page_table
        .translate_va(VirtAddr::from(addr))
        .map(|pa| pa.get_ref())
}

/// 安全版 `translated_refmut`：校验后返回对用户内存中 `T` 的可变引用。
///
/// 要求与 `try_translated_ref` 相同，且该页可写。非法时返回 `None`。
pub fn try_translated_refmut<T>(token: usize, ptr: *mut T) -> Option<&'static mut T> {
    let addr = ptr as usize;
    let size = core::mem::size_of::<T>();
    if size == 0 || addr == 0 || addr % core::mem::align_of::<T>() != 0 {
        return None;
    }
    let end = addr.checked_add(size)?;
    if end > USER_VA_LIMIT {
        return None;
    }
    // 跨页检查：整个 T 必须位于同一页内
    if (addr >> PAGE_SIZE_BITS) != ((end - 1) >> PAGE_SIZE_BITS) {
        return None;
    }
    if !check_user_range(token, addr, size, true) {
        return None;
    }
    let page_table = PageTable::from_token(token);
    page_table
        .translate_va(VirtAddr::from(addr))
        .map(|pa| pa.get_mut())
}

pub struct UserBuffer {
    pub buffers: Vec<&'static mut [u8]>,
}

impl UserBuffer {
    pub fn new(buffers: Vec<&'static mut [u8]>) -> Self {
        Self { buffers }
    }
    pub fn len(&self) -> usize {
        let mut total: usize = 0;
        for b in self.buffers.iter() {
            total += b.len();
        }
        total
    }
}

impl IntoIterator for UserBuffer {
    type Item = *mut u8;
    type IntoIter = UserBufferIterator;
    fn into_iter(self) -> Self::IntoIter {
        UserBufferIterator {
            buffers: self.buffers,
            current_buffer: 0,
            current_idx: 0,
        }
    }
}

pub struct UserBufferIterator {
    buffers: Vec<&'static mut [u8]>,
    current_buffer: usize,
    current_idx: usize,
}

impl Iterator for UserBufferIterator {
    type Item = *mut u8;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_buffer >= self.buffers.len() {
            None
        } else {
            let r = &mut self.buffers[self.current_buffer][self.current_idx] as *mut _;
            if self.current_idx + 1 == self.buffers[self.current_buffer].len() {
                self.current_idx = 0;
                self.current_buffer += 1;
            } else {
                self.current_idx += 1;
            }
            Some(r)
        }
    }
}
