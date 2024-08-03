//! Safe rust idiomatic bindings for the WireGuard NT C library: <https://git.zx2c4.com/wireguard-nt/about>
//!
//! Features of the WireGuard NT library are wrapped using pure rust types and functions to make
//! usage ergonomic.
//!
//! # Usage
//!
//! Add a dependency on this library to your `Cargo.toml`
//!
//! ```toml
//! [dependencies]
//! wireguard-nt = "0.4"
//! ```
//!
//! Inside your code load the wireguard.dll signed driver file, downloaded from <https://git.zx2c4.com/wireguard-nt/about>
//!
//! Then either call [`Adapter::create`] or [`Adapter::open`] to obtain a wireguard
//! adapter. Start by setting its config with [`Adapter::set_config`].
//!
//! # Example
//! ```no_run
//! // Must be run as Administrator because we create network adapters
//! 
//! // Load the wireguard dll file so that we can call the underlying C functions
//! // Unsafe because we are loading an arbitrary dll file
//! let wireguard =
//!     unsafe { wireguard_nt::load_from_path("examples/wireguard_nt/bin/amd64/wireguard.dll") }
//!         .expect("Failed to load wireguard dll");
//!
//! // Try to open an adapter from the given pool with the name "Demo"
//! let adapter =
//!     wireguard_nt::Adapter::open(&wireguard, "Demo").unwrap_or_else(|_| {
//!         wireguard_nt::Adapter::create(&wireguard, "WireGuard", "Demo", None)
//!             .expect("Failed to create wireguard adapter!")
//!     });
//!
//! let interface = wireguard_nt::SetInterface {
//!     //Let the OS pick a port for us
//!     listen_port: None,
//!     //Generated from the private key if not specified
//!     public_key: None,
//!     //Fill in private keys in real code
//!     private_key: None,
//!     //Add a peer
//!     peers: vec![wireguard_nt::SetPeer {
//!         //Provide a public key so that we can communicate with them
//!         public_key: None,
//!         //Disable additional AES encryption
//!         preshared_key: None,
//!         //Send a keepalive packet every 21 seconds
//!         keep_alive: Some(21),
//!         //Route all traffic through the WireGuard interface
//!         allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
//!         //The peer's ip address
//!         endpoint: "1.2.3.4".parse().unwrap(),
//!     }],
//! };
//!
//! //Set the config our adapter will use
//! //This lets it know about the peers and keys
//! adapter.set_config(&interface).unwrap();
//!
//! let internal_ip = "10.4.0.2".parse().unwrap();
//! let internal_prefix_length = 24;
//! let internal_ipnet = ipnet::Ipv4Net::new(internal_ip, internal_prefix_length).unwrap();
//! //Set up the routing table with the allowed ips for our peers,
//! //and assign an ip to the interface
//! adapter.set_default_route(&[internal_ipnet.into()], &interface).unwrap();
//!
//! //drop(adapter)
//! //The adapter closes its resources when dropped
//! ```
//!    
//! See `examples/demo_server.rs` that connects to the wireguard demo server
//!
//! # Version compatibility
//! Wireguard NT versions 0.10 and above are supported. Versions < 0.10 have breaking changes that
//! make interoperability hard. Please file an issue if this effects your use case.
//!

mod adapter;
mod log;
mod util;

//Generated by bingen, so ignore lints
#[allow(
    non_snake_case,
    dead_code,
    unused_variables,
    non_camel_case_types,
    deref_nullptr,
    clippy::all
)]
mod wireguard_nt_raw;

pub(crate) const MAX_NAME: usize = 256;

pub use crate::adapter::*;
pub use crate::log::*;
pub use crate::util::get_running_driver_version;

pub use wireguard_nt_raw::wireguard as Sys;
use std::sync::Arc;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// An error caused by calling into the wireguard-nt driver
    #[error("{0}")]
    Driver(#[from] std::io::Error),
    /// Unable to encode UTF-16 string due to early null
    #[error("invalid string: {0}")]
    Null(#[from] widestring::NulError::<u16>),
    #[error("name too large (max {})", crate::MAX_NAME)]
    NameTooLarge,
    /// The windows function (self.0), failed with the given error (self.1)
    #[error("{0}: {1}")]
    Windows(String, std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Wireguard(Arc<Sys>);

impl Wireguard {
    pub fn into_inner(self) -> Arc<Sys> {
        self.0
    }
}

impl std::ops::Deref for Wireguard {
    type Target = Sys;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Attempts to load the Wireguand NT library from the current directory using the default name "wireguard.dll".
///
/// Use [`load_from_path`] with an absolute path when more control is needed as to where wireguard.dll is
///
///
/// # Safety
/// This function loads a dll file with the name wireguard.dll using the default system search paths.
/// This is inherently unsafe as a user could simply rename undefined_behavior.dll to wireguard.dll
/// and do nefarious things inside of its DllMain function. In most cases, a regular wireguard.dll
/// file which exports all of the required functions for these bindings to work is loaded. Because
/// WireGuard NT is a well-written and well-tested library, loading a _normal_ wireguard.dll file should be safe.
/// Hoverer one can never be too cautious when loading a dll file.
///
/// For more information see [`libloading`]'s dynamic library safety guarantees: [`libloading`][`libloading::Library::new`]
pub unsafe fn load() -> std::result::Result<Wireguard, libloading::Error> {
    load_from_path("wireguard")
}

/// Attempts to load the wireguard library as a dynamic library from the given path.
///
///
/// # Safety
/// This function loads a dll file with the path provided.
/// This is inherently unsafe as a user could simply rename undefined_behavior.dll to wireguard.dll
/// and do nefarious things inside of its DllMain function. In most cases, a regular wireguard.dll
/// file which exports all of the required functions for these bindings to work is loaded. Because
/// WireGuard NT is a well-written and well-tested library, loading a _normal_ wireguard.dll file should be safe.
/// Hoverer one can never be too cautious when loading a dll file.
///
/// For more information see [`libloading`]'s dynamic library safety guarantees: [`libloading`][`libloading::Library::new`]
pub unsafe fn load_from_path<P>(path: P) -> std::result::Result<Wireguard, libloading::Error>
where
    P: AsRef<::std::ffi::OsStr>,
{
    Ok(Wireguard(Arc::new(wireguard_nt_raw::wireguard::new(path)?)))
}

/// Attempts to load the WireGuard NT library from an existing [`libloading::Library`].
///
///
/// # Safety
/// This function loads the required WireGuard NT functions using the provided library. Reading a symbol table
/// of a dynamic library and transmuting the function pointers inside to have the parameters and return
/// values expected by the functions documented at: <https://git.zx2c4.com/wireguard-nt/about/>
/// is inherently unsafe.
///
/// For more information see [`libloading`]'s dynamic library safety guarantees: [`libloading::Library::new`]
pub unsafe fn load_from_library<L>(library: L) -> std::result::Result<Wireguard, libloading::Error>
where
    L: Into<libloading::Library>,
{
    Ok(Wireguard(Arc::new(wireguard_nt_raw::wireguard::from_library(
        library,
    )?)))
}

// The error type
// pub type WireGuardError = Box<dyn std::error::Error>;
