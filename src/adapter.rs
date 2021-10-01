/// Representation of a wireguard adapter with safe idiomatic bindings to the functionality provided by
/// the WireGuard* C functions.
///
/// The [`Adapter::create`] and [`Adapter::open`] functions serve as the entry point to using
/// wireguard functionality
use crate::util::UnsafeHandle;
use crate::wireguard_nt_raw;

use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Arc;

use widestring::U16CStr;
use widestring::U16CString;
use rand::Rng;

/// Wrapper around a `WIREGUARD_ADAPTER_HANDLE`
pub struct Adapter {
    adapter: UnsafeHandle<wireguard_nt_raw::WIREGUARD_ADAPTER_HANDLE>,
    wireguard: Arc<wireguard_nt_raw::wireguard>,
}

/// Holds the newly created adapter and reboot suggestion from the system when a new adapter is
/// created
pub struct CreateData {
    pub adapter: Adapter,
    pub reboot_required: bool,
}

fn encode_utf16(string: &str, max_characters: usize) -> Result<U16CString, crate::WireGuardError> {
    let utf16 = U16CString::from_str(string)?;
    if utf16.len() >= max_characters {
        //max_characters is the maximum number of characters including the null terminator. And .len() measures the
        //number of characters (excluding the null terminator). Therefore we can hold a string with
        //max_characters - 1 because the null terminator sits in the last element. However a string
        //of length max_characters needs max_characters + 1 to store the null terminator the >=
        //check holds
        Err(format!(
            //TODO: Better error handling
            "Length too large. Size: {}, Max: {}",
            utf16.len(),
            max_characters
        )
        .into())
    } else {
        Ok(utf16)
    }
}

fn encode_pool_name(name: &str) -> Result<U16CString, crate::WireGuardError> {
    encode_utf16(name, crate::MAX_POOL)
}

fn encode_adapter_name(name: &str) -> Result<U16CString, crate::WireGuardError> {
    encode_utf16(name, crate::MAX_POOL)
}

fn get_adapter_name(
    wireguard: &Arc<wireguard_nt_raw::wireguard>,
    adapter: wireguard_nt_raw::WIREGUARD_ADAPTER_HANDLE,
) -> String {
    let mut name = MaybeUninit::<[u16; crate::MAX_POOL as usize]>::uninit();

    //SAFETY: name is a allocated on the stack above therefore it must be valid, non-null and
    //aligned for u16
    let first = unsafe { *name.as_mut_ptr() }.as_mut_ptr();
    //Write default null terminator in case WireGuardGetAdapterName leaves name unchanged
    unsafe { first.write(0u16) };
    unsafe { wireguard.WireGuardGetAdapterName(adapter, first) };

    //SAFETY: first is a valid, non-null, aligned, null terminated pointer
    unsafe { U16CStr::from_ptr_str(first) }.to_string_lossy()
}

/// Contains information about a single existing adapter
pub struct EnumeratedAdapter {
    pub name: String,
}

impl Adapter {
    //TODO: Call get last error for error information on failure and improve error types

    /// Creates a new wireguard adapter inside the pool `pool` with name `name`
    ///
    /// Optionally a GUID can be specified that will become the GUID of this adapter once created.
    /// Adapters obtained via this function will be able to return their adapter index via
    /// [`Adapter::get_adapter_index`]
    pub fn create(
        wireguard: &Arc<wireguard_nt_raw::wireguard>,
        pool: &str,
        name: &str,
        guid: Option<u128>,
    ) -> Result<CreateData, crate::WireGuardError> {
        let pool_utf16 = encode_pool_name(pool)?;
        let name_utf16 = encode_adapter_name(name)?;

        let guid = match guid {
            Some(guid) => guid,
            None => {
                // Use random bytes so that we can identify this adapter in get_adapter_index
                let mut guid_bytes: [u8; 16] = [0u8; 16];
                rand::thread_rng().fill(&mut guid_bytes);
                u128::from_ne_bytes(guid_bytes)
            }
        };
        //SAFETY: guid is a unique integer so transmuting either all zeroes or the user's preferred
        //guid to the winapi guid type is safe and will allow the windows kernel to see our GUID
        let guid_struct: wireguard_nt_raw::GUID = unsafe { std::mem::transmute(guid) };
        //TODO: The guid of the adapter once created might differ from the one provided because of
        //the byte order of the segments of the GUID struct that are larger than a byte. Verify
        //that this works as expected

        let guid_ptr = &guid_struct as *const wireguard_nt_raw::GUID;

        let mut reboot_required = 0;

        crate::log::set_default_logger_if_unset(&wireguard);

        //SAFETY: the function is loaded from the wireguard dll properly, we are providing valid
        //pointers, and all the strings are correct null terminated UTF-16. This safety rationale
        //applies for all WireGuard* functions below
        let result = unsafe {
            wireguard.WireGuardCreateAdapter(
                pool_utf16.as_ptr(),
                name_utf16.as_ptr(),
                guid_ptr,
                &mut reboot_required as *mut i32,
            )
        };

        if result == ptr::null_mut() {
            Err("Failed to crate adapter".into())
        } else {
            Ok(CreateData {
                adapter: Adapter {
                    adapter: UnsafeHandle(result),
                    wireguard: wireguard.clone(),
                },
                reboot_required: reboot_required != 0,
            })
        }
    }

    /// Attempts to open an existing wireguard interface inside `pool` with name `name`.
    /// Adapters opened via this call will have an unknown GUID meaning [`Adapter::get_adapter_index`]
    /// will always fail because knowing the adapter's GUID is required to determine its index.
    /// Currently a workaround is to delete and re-create a new adapter every time one is needed so
    /// that it gets created with a known GUID, allowing [`Adapter::get_adapter_index`] to works as
    /// expected. There is likely a way to get the GUID of our adapter using the Windows Registry
    /// or via the Win32 API, so PR's that solve this issue are always welcome!
    pub fn open(
        wireguard: &Arc<wireguard_nt_raw::wireguard>,
        pool: &str,
        name: &str,
    ) -> Result<Adapter, crate::WireGuardError> {
        let _ = encode_pool_name(pool)?;

        let pool_utf16 = encode_pool_name(pool)?;
        let name_utf16 = encode_adapter_name(name)?;

        crate::log::set_default_logger_if_unset(&wireguard);

        let result = unsafe { wireguard.WireGuardOpenAdapter(pool_utf16.as_ptr(), name_utf16.as_ptr()) };

        if result == ptr::null_mut() {
            Err("WireGuardOpenAdapter failed".into())
        } else {
            Ok(Adapter {
                adapter: UnsafeHandle(result),
                wireguard: wireguard.clone(),
            })
        }
    }

    /// Returns a vector of the wintun adapters that exist in a particular pool
    pub fn list_all(
        wireguard: &Arc<wireguard_nt_raw::wireguard>,
        pool: &str,
    ) -> Result<Vec<EnumeratedAdapter>, crate::WireGuardError> {
        let pool_utf16 = encode_pool_name(pool)?;
        let mut result = Vec::new();

        //Maybe oneday this will be part of the language, or a proc macro
        struct CallbackData<'a> {
            vec: &'a mut Vec<EnumeratedAdapter>,
            wireguard: &'a Arc<wireguard_nt_raw::wireguard>,
        }

        extern "C" fn enumerate_one(
            adapter: wireguard_nt_raw::WIREGUARD_ADAPTER_HANDLE,
            param: wireguard_nt_raw::LPARAM,
        ) -> wireguard_nt_raw::BOOL {
            let data = unsafe { (param as *mut CallbackData).as_mut() }.unwrap();
            //Push adapter information when the callback is called
            data.vec.push(EnumeratedAdapter {
                name: get_adapter_name(data.wireguard, adapter),
            });
            1
        }
        let mut data = CallbackData {
            vec: &mut result,
            wireguard,
        };

        unsafe {
            wireguard.WireGuardEnumAdapters(
                pool_utf16.as_ptr(),
                Some(enumerate_one),
                (&mut data as *mut CallbackData) as wireguard_nt_raw::LPARAM,
            )
        };

        Ok(result)
    }

    /// Delete an adapter, consuming it in the process
    /// Returns `Ok(reboot_suggested: bool)` on success
    pub fn delete(self) -> Result<bool, ()> {
        let mut reboot_required = 0;

        let result = unsafe {
            self.wireguard.WireGuardDeleteAdapter(
                self.adapter.0,
                &mut reboot_required as *mut i32,
            )
        };

        if result != 0 {
            Ok(reboot_required != 0)
        } else {
            Err(())
        }
    } 

    /// Returns the name of this adapter. Set by calls to [`Adapter::create`]
    pub fn get_adapter_name(&self) -> String {
        // TODO: also expose WintunSetAdapterName
        get_adapter_name(&self.wireguard, self.adapter.0)
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        //Free adapter on drop
        //This is why we need an Arc of wireguard 
        unsafe { self.wireguard.WireGuardFreeAdapter(self.adapter.0) };
        self.adapter = UnsafeHandle(ptr::null_mut());
    }
}
