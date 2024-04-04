#![allow(unused_unsafe)]
//In this file we are explicit about unsafe, even in unsafe functions
//Hopefully one day we won't need this

use crate::wireguard_nt_raw;
use std::{alloc::Layout, sync::Arc};

/// A wrapper struct that allows a type to be Send and Sync
pub(crate) struct UnsafeHandle<T>(pub T);

/// We never read from the pointer. It only serves as a handle we pass to the kernel or C code
/// (where locks are used internally)
unsafe impl<T> Send for UnsafeHandle<T> {}
unsafe impl<T> Sync for UnsafeHandle<T> {}

/// Returns the major and minor version of the wireguard driver
pub fn get_running_driver_version(wireguard: &Arc<wireguard_nt_raw::wireguard>) -> u32 {
    unsafe { wireguard.WireGuardGetRunningDriverVersion() }
}

pub(crate) struct StructWriter {
    start: *mut u8,
    offset: usize,
    layout: Layout,
}

impl StructWriter {
    /// Creates a struct writer that has the given initial capacity `capacity`,
    /// and whose allocation is aligned to `align`
    pub fn new(capacity: usize, align: usize) -> Self {
        let layout = Layout::from_size_align(capacity, align).unwrap();
        let start = unsafe { std::alloc::alloc(layout) };
        // Safety:
        // start is writeable for `capacity` bytes because that is the size of the allocation
        unsafe { start.write_bytes(0, capacity) };
        Self {
            start,
            offset: 0,
            layout,
        }
    }

    /// Returns a reference of the desired type, which can be used to write a T into the
    /// buffer at the internal pointer. The internal pointer will be advanced by `size_of::<T>()` so that
    /// the next call to [`write`] will return a reference to an adjacent memory location.
    /// The returned refrence will be the zero bit pattern initially.
    ///
    /// # Safety:
    /// 1. The caller must ensure the internal pointer is aligned suitably for writing to a T.
    /// In most C APIs (like Wireguard NT) the structs are setup in such a way that calling write
    /// repeatedly to pack data into the buffer always yields a struct that is aligned because the
    /// previous struct was aligned.
    /// 2. The caller must ensure that the zero bit pattern is valid for type T
    ///
    /// # Panics
    /// 1. If writing a struct of size T would overflow the buffer.
    /// 2. If the internal pointer does not meet the alignment requirements of T.
    pub unsafe fn write<T>(&mut self) -> &mut T {
        let size = std::mem::size_of::<T>();
        if size + self.offset > self.layout.size() {
            panic!(
                "Overflow attempting to write struct of size {}. To allocation size: {}, offset: {}",
                size,
                self.layout.size(),
                self.offset
            );
        }
        // Safety:
        // ptr is within this allocation by the bounds check above
        let ptr = unsafe { self.start.add(self.offset) };
        self.offset += size;
        assert_eq!(ptr as usize % std::mem::align_of::<T>(), 0);

        // Safety:
        // 1. This pointer is valid and within the bounds of this memory allocation
        // 2. The caller ensures that they the struct is aligned
        unsafe { &mut *ptr.cast::<T>() }
    }

    pub fn ptr(&self) -> *const u8 {
        self.start
    }

    /// Returns true if this writer's capacity is full, false otherwise
    pub fn is_full(&self) -> bool {
        self.layout.size() == self.offset
    }
}

impl Drop for StructWriter {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.start, self.layout) };
    }
}

pub(crate) struct StructReader {
    start: *mut u8,
    offset: usize,
    layout: Layout,
}

impl StructReader {
    /// Creates a struct reader that has the given initial capacity `capacity`,
    /// and whose allocation is aligned to `align`
    pub fn new(capacity: usize, align: usize) -> Self {
        let layout = Layout::from_size_align(capacity, align).unwrap();
        let start = unsafe { std::alloc::alloc(layout) };
        Self {
            start,
            offset: 0,
            layout,
        }
    }

    /// Reads a given type from the internal buffer.
    /// This advances the internal pointer by the size of the read type, such that a given instance of
    /// the given type can only be read once.
    ///
    /// # Safety
    /// The caller must ensure the internal pointer is aligned suitably for reading a T.
    /// In most C APIs (like Wireguard NT) the structs are setup in such a way that calling read
    /// repeatedly to read packed data always yields a struct that is aligned because the
    /// previous struct was aligned.
    ///
    /// # Panics
    /// 1. If reading a struct of size T would overflow the buffer.
    /// 2. If the internal pointer does not meet the alignment requirements of T.
    pub unsafe fn read<T>(&mut self) -> &T {
        let size = std::mem::size_of::<T>();
        if size + self.offset > self.layout.size() {
            panic!(
                "Overflow attempting to read struct of size {}. To allocation size: {}, offset: {}",
                size,
                self.layout.size(),
                self.offset
            );
        }
        // Safety:
        // ptr is within this allocation by the bounds check above
        let ptr = unsafe { self.start.add(self.offset) };
        self.offset += size;
        assert_eq!(ptr as usize % std::mem::align_of::<T>(), 0);

        unsafe { &*ptr.cast::<T>() }
    }

    pub fn ptr_mut(&self) -> *mut u8 {
        self.start
    }

    /// Returns true if this reader's capacity is full, false otherwise
    #[allow(dead_code)]
    pub fn is_full(&self) -> bool {
        self.layout.size() == self.offset
    }
}

impl Drop for StructReader {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.start, self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of_val, size_of_val};

    #[test]
    fn reader_basic() {
        #[derive(Debug)]
        #[repr(C)]
        struct Data {
            field_a: u8,
            field_b: u32,
        }
        let expected_data = Data {
            field_a: 0b10000001,
            field_b: 0x00FFFF00,
        };
        let mut reader =
            StructReader::new(size_of_val(&expected_data), align_of_val(&expected_data));
        let byte_buffer: &mut [u8; 8] = unsafe { &mut *(reader.ptr_mut() as *mut [u8; 8]) };
        byte_buffer[0] = 0b10000001;
        byte_buffer[4] = 0x0;
        byte_buffer[5] = 0xFF;
        byte_buffer[6] = 0xFF;
        byte_buffer[7] = 0x0;
        let actual_data: &Data = unsafe { reader.read() };
        assert_eq!(actual_data.field_a, expected_data.field_a);
        assert_eq!(actual_data.field_b, expected_data.field_b);
    }

    #[test]
    #[should_panic]
    fn reader_overflow() {
        unsafe { StructReader::new(1, align_of_val(&1)).read::<u64>() };
    }

    #[test]
    fn writer_basic() {
        let mut buf = StructWriter::new(20, 4);
        *unsafe { buf.write::<u16>() } = 0;
        //Keep bit patterns symmetrical so that this doesn't fail on big-endian systems
        *unsafe { buf.write::<u16>() } = 0xCCCC;
        *unsafe { buf.write::<u32>() } = 0x00FFFF00;
        *unsafe { buf.write::<u32>() } = 0x80808080;
        *unsafe { buf.write::<u32>() } = 0xFFFFFFFF;

        let slice: &[u8] = unsafe { std::slice::from_raw_parts(buf.ptr(), 16) };
        assert_eq!(
            slice,
            &[0, 0, 204, 204, 0, 255, 255, 0, 128, 128, 128, 128, 255, 255, 255, 255]
        );
    }

    #[test]
    #[should_panic]
    fn writer_unaligned() {
        let mut buf = StructWriter::new(8, 4);
        *unsafe { buf.write::<u8>() } = 0;
        *unsafe { buf.write::<u32>() } = 0xFFFFFFFF;
    }

    #[test]
    #[should_panic]
    fn writer_overflow() {
        let mut buf = StructWriter::new(16, 4);
        *unsafe { buf.write::<u32>() } = 0xFFFFFFFF;
        *unsafe { buf.write::<u32>() } = 0xFFFFFF00;
        *unsafe { buf.write::<u32>() } = 0xFFFF00FF;
        *unsafe { buf.write::<u32>() } = 0xFF00FFFF;

        //Panic here
        *unsafe { buf.write::<u8>() } = 5;
    }
}
