use super::File;
use crate::mm::UserBuffer;
use crate::security::{IpcError, IpcObject, IpcResult, ResourceId, Uid};
use crate::sync::UPSafeCell;
use alloc::sync::{Arc, Weak};
use lazy_static::lazy_static;

use crate::task::suspend_current_and_run_next;

pub struct Pipe {
    readable: bool,
    writable: bool,
    buffer: Arc<UPSafeCell<PipeRingBuffer>>,
    object: IpcObject,
}

impl Pipe {
    pub fn read_end_with_buffer(
        buffer: Arc<UPSafeCell<PipeRingBuffer>>,
        object: IpcObject,
    ) -> Self {
        Self {
            readable: true,
            writable: false,
            buffer,
            object,
        }
    }
    pub fn write_end_with_buffer(
        buffer: Arc<UPSafeCell<PipeRingBuffer>>,
        object: IpcObject,
    ) -> Self {
        Self {
            readable: false,
            writable: true,
            buffer,
            object,
        }
    }
}

const RING_BUFFER_SIZE: usize = 32;

#[derive(Copy, Clone, PartialEq)]
enum RingBufferStatus {
    Full,
    Empty,
    Normal,
}

pub struct PipeRingBuffer {
    arr: [u8; RING_BUFFER_SIZE],
    head: usize,
    tail: usize,
    status: RingBufferStatus,
    write_end: Option<Weak<Pipe>>,
}

impl PipeRingBuffer {
    pub fn new() -> Self {
        Self {
            arr: [0; RING_BUFFER_SIZE],
            head: 0,
            tail: 0,
            status: RingBufferStatus::Empty,
            write_end: None,
        }
    }
    pub fn set_write_end(&mut self, write_end: &Arc<Pipe>) {
        self.write_end = Some(Arc::downgrade(write_end));
    }
    pub fn write_byte(&mut self, byte: u8) {
        self.status = RingBufferStatus::Normal;
        self.arr[self.tail] = byte;
        self.tail = (self.tail + 1) % RING_BUFFER_SIZE;
        if self.tail == self.head {
            self.status = RingBufferStatus::Full;
        }
    }
    pub fn read_byte(&mut self) -> u8 {
        self.status = RingBufferStatus::Normal;
        let c = self.arr[self.head];
        self.head = (self.head + 1) % RING_BUFFER_SIZE;
        if self.head == self.tail {
            self.status = RingBufferStatus::Empty;
        }
        c
    }
    pub fn available_read(&self) -> usize {
        if self.status == RingBufferStatus::Empty {
            0
        } else if self.tail > self.head {
            self.tail - self.head
        } else {
            self.tail + RING_BUFFER_SIZE - self.head
        }
    }
    pub fn available_write(&self) -> usize {
        if self.status == RingBufferStatus::Full {
            0
        } else {
            RING_BUFFER_SIZE - self.available_read()
        }
    }
    pub fn all_write_ends_closed(&self) -> bool {
        self.write_end.as_ref().unwrap().upgrade().is_none()
    }
}

lazy_static! {
    /// Stable, monotonically increasing pipe IDs; kernel addresses never enter audit records.
    static ref NEXT_PIPE_ID: UPSafeCell<ResourceId> = unsafe { UPSafeCell::new(1) };
}

fn allocate_pipe_id() -> IpcResult<ResourceId> {
    let mut next = NEXT_PIPE_ID.exclusive_access();
    let id = *next;
    *next = id.checked_add(1).ok_or(IpcError::ResourceExhausted)?;
    Ok(id)
}

/// Return (read_end, write_end) with shared stable audit metadata.
pub fn make_pipe(owner_uid: Uid) -> IpcResult<(Arc<Pipe>, Arc<Pipe>)> {
    let object = IpcObject {
        id: allocate_pipe_id()?,
        owner_uid,
    };
    let buffer = Arc::new(unsafe { UPSafeCell::new(PipeRingBuffer::new()) });
    let read_end = Arc::new(Pipe::read_end_with_buffer(buffer.clone(), object));
    let write_end = Arc::new(Pipe::write_end_with_buffer(buffer.clone(), object));
    buffer.exclusive_access().set_write_end(&write_end);
    Ok((read_end, write_end))
}

impl File for Pipe {
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn ipc_object(&self) -> Option<IpcObject> {
        Some(self.object)
    }
    fn read(&self, buf: UserBuffer) -> usize {
        assert!(self.readable());
        let want_to_read = buf.len();
        let mut buf_iter = buf.into_iter();
        let mut already_read = 0usize;
        loop {
            let mut ring_buffer = self.buffer.exclusive_access();
            let loop_read = ring_buffer.available_read();
            if loop_read == 0 {
                if ring_buffer.all_write_ends_closed() {
                    return already_read;
                }
                drop(ring_buffer);
                suspend_current_and_run_next();
                continue;
            }
            for _ in 0..loop_read {
                if let Some(byte_ref) = buf_iter.next() {
                    unsafe {
                        *byte_ref = ring_buffer.read_byte();
                    }
                    already_read += 1;
                    if already_read == want_to_read {
                        return want_to_read;
                    }
                } else {
                    return already_read;
                }
            }
        }
    }
    fn write(&self, buf: UserBuffer) -> usize {
        assert!(self.writable());
        let want_to_write = buf.len();
        let mut buf_iter = buf.into_iter();
        let mut already_write = 0usize;
        loop {
            let mut ring_buffer = self.buffer.exclusive_access();
            let loop_write = ring_buffer.available_write();
            if loop_write == 0 {
                drop(ring_buffer);
                suspend_current_and_run_next();
                continue;
            }
            // write at most loop_write bytes
            for _ in 0..loop_write {
                if let Some(byte_ref) = buf_iter.next() {
                    ring_buffer.write_byte(unsafe { *byte_ref });
                    already_write += 1;
                    if already_write == want_to_write {
                        return want_to_write;
                    }
                } else {
                    return already_write;
                }
            }
        }
    }
}
