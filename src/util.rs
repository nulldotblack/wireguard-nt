use crate::wireguard_nt_raw;
use std::sync::Arc;

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
