#![allow(unused_unsafe)]
//In this file we are explicit about unsafe, even in unsafe functions
//Hopefully one day we won't need this

use crate::wireguard_nt_raw;
use std::{alloc::Layout, sync::Arc};

/// A wrapper struct that allows a type to be Send and Sync
pub(crate) struct UnsafeHandle<T>(pub T);

/// We never read from the pointer. It only serves as a handle we pass to the kernel or C code that
/// doesn't have the same mutable aliasing restrictions we have in Rust
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
    ///
    /// # Safety:
    /// The caller must ensure the internal pointer is aligned suitably for writing to a T.
    /// In most C APIs (like Wireguard NT) the structs are setup in such a way that calling write
    /// repeatedly to pack data into the buffer always yields a struct that is aligned because the
    /// previous struct was aligned.
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
        assert!(ptr as usize % std::mem::align_of::<T>() == 0);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
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
    fn unaligned() {
        let mut buf = StructWriter::new(8, 4);
        *unsafe { buf.write::<u8>() } = 0;
        *unsafe { buf.write::<u32>() } = 0xFFFFFFFF;
    }

    #[test]
    #[should_panic]
    fn overflow() {
        let mut buf = StructWriter::new(16, 4);
        *unsafe { buf.write::<u32>() } = 0xFFFFFFFF;
        *unsafe { buf.write::<u32>() } = 0xFFFFFF00;
        *unsafe { buf.write::<u32>() } = 0xFFFF00FF;
        *unsafe { buf.write::<u32>() } = 0xFF00FFFF;

        //Panic here
        *unsafe { buf.write::<u8>() } = 5;
    }
}
