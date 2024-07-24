use std::mem::{align_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rand::Rng;
use widestring::U16CString;
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_MORE_DATA, ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS},
    NetworkManagement::{
        IpHelper::{
            CreateIpForwardEntry2, CreateUnicastIpAddressEntry, GetIpInterfaceEntry,
            InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
            SetIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
        },
        Ndis,
    },
    Networking::{
        WinSock::{IpDadStatePreferred, RouterDiscoveryDisabled, AF_INET, AF_INET6},
        WinSock::{IN6_ADDR, IN_ADDR},
    },
};

use crate::log::AdapterLoggingLevel;
use crate::util;
use crate::util::{StructReader, UnsafeHandle};
use crate::wireguard_nt_raw::{
    in6_addr, in_addr, wireguard, GUID, WIREGUARD_ADAPTER_HANDLE, WIREGUARD_ALLOWED_IP,
    WIREGUARD_INTERFACE, WIREGUARD_INTERFACE_FLAG, WIREGUARD_PEER, WIREGUARD_PEER_FLAG,
    _NET_LUID_LH,
};
use crate::WireGuardError;

/// Representation of a wireGuard adapter with safe idiomatic bindings to the functionality provided by
/// the WireGuard* C functions.
///
/// The [`Adapter::create`] and [`Adapter::open`] functions serve as the entry point to using
/// wireguard functionality
///
/// Wrapper around a `WIREGUARD_ADAPTER_HANDLE`
///
/// Related functions from WireGuardXXX are functions with an adapter self parameter
pub struct Adapter {
    adapter: UnsafeHandle<WIREGUARD_ADAPTER_HANDLE>,
    wireguard: Arc<wireguard>,
}

/// Representation of a WireGuard peer when setting the config
#[derive(Clone)]
pub struct SetPeer {
    /// The peer's public key
    pub public_key: Option<[u8; 32]>,

    /// A preshared key used to symmetrically encrypt data with this peer
    pub preshared_key: Option<[u8; 32]>,

    /// How often to send a keep alive packet to prevent NATs from blocking UDP packets
    ///
    /// Set to None if no keep alive behavior is wanted
    pub keep_alive: Option<u16>,

    /// The address this peer is reachable from using UDP across the internet
    pub endpoint: SocketAddr,

    /// The set of [`IpNet`]'s that dictate what packets are allowed to be sent of received from
    /// this peer
    pub allowed_ips: Vec<IpNet>,
}

pub type RebootRequired = bool;

/// The data required when setting the config for an interface
pub struct SetInterface {
    /// The port this interface should listen on.
    /// The default 51820 is used if this is set to `None`
    pub listen_port: Option<u16>,

    /// The public key of this interface.
    /// If this is `None`, the public key is generated from the private key
    pub public_key: Option<[u8; 32]>,

    /// The private key of this interface
    pub private_key: Option<[u8; 32]>,

    /// The peers that this interface is allowed to communicate with
    pub peers: Vec<SetPeer>,
}

fn encode_name(
    name: &str,
    wireguard: Arc<wireguard>,
) -> Result<(U16CString, Arc<wireguard>), (WireGuardError, Arc<wireguard>)> {
    let utf16 = match U16CString::from_str(name) {
        Ok(u) => u,
        Err(e) => return Err((e.into(), wireguard)),
    };
    let max = crate::MAX_NAME;
    if utf16.len() >= max {
        //max_characters is the maximum number of characters including the null terminator. And .len() measures the
        //number of characters (excluding the null terminator). Therefore, we can hold a string with
        //max_characters - 1 because the null terminator sits in the last element. A string
        //of length max_characters needs max_characters + 1 to store the null terminator so the >=
        //check holds
        Err((
            format!(
                //TODO: Better error handling
                "Length too large. Size: {}, Max: {}",
                utf16.len(),
                max,
            )
            .into(),
            wireguard,
        ))
    } else {
        Ok((utf16, wireguard))
    }
}

/// Contains information about a single existing adapter
pub struct EnumeratedAdapter {
    /// The name of the adapter
    pub name: String,
}

fn win_error(context: &str, error_code: u32) -> Result<(), Box<dyn std::error::Error>> {
    let e = std::io::Error::from_raw_os_error(error_code as i32);
    Err(format!("{} - {}", context, e).into())
}

const WIREGUARD_STATE_DOWN: i32 = 0;
const WIREGUARD_STATE_UP: i32 = 1;

impl Adapter {
    //TODO: Call get last error for error information on failure and improve error types

    /// Creates a new wireguard adapter inside the pool `pool` with name `name`
    ///
    /// Optionally a GUID can be specified that will become the GUID of this adapter once created.
    pub fn create(
        wireguard: Arc<wireguard>,
        pool: &str,
        name: &str,
        guid: Option<u128>,
    ) -> Result<Adapter, (WireGuardError, Arc<wireguard>)> {
        let (pool_utf16, wireguard) = encode_name(pool, wireguard)?;
        let (name_utf16, wireguard) = encode_name(name, wireguard)?;

        let guid = guid.unwrap_or_else(|| {
            let mut guid_bytes = [0u8; 16];
            rand::thread_rng().fill(&mut guid_bytes);
            u128::from_ne_bytes(guid_bytes)
        });
        //SAFETY: guid is a unique integer so transmuting either all zeroes or the user's preferred
        //guid to the WinAPI guid type is safe and will allow the Windows kernel to see our GUID
        let guid_struct = unsafe { std::mem::transmute::<u128, GUID>(guid) };
        //TODO: The guid of the adapter once created might differ from the one provided because of
        //the byte order of the segments of the GUID struct that are larger than a byte. Verify
        //that this works as expected

        crate::log::set_default_logger_if_unset(&wireguard);

        //SAFETY: the function is loaded from the wireguard dll properly, we are providing valid
        //pointers, and all the strings are correct null terminated UTF-16. This safety rationale
        //applies for all WireGuard* functions below
        let result = unsafe {
            wireguard.WireGuardCreateAdapter(
                pool_utf16.as_ptr(),
                name_utf16.as_ptr(),
                &guid_struct as *const GUID,
            )
        };

        if result.is_null() {
            Err(("Failed to create adapter".into(), wireguard))
        } else {
            Ok(Self {
                adapter: UnsafeHandle(result),
                wireguard,
            })
        }
    }

    /// Attempts to open an existing wireguard with name `name`.
    pub fn open(
        wireguard: Arc<wireguard>,
        name: &str,
    ) -> Result<Adapter, (WireGuardError, Arc<wireguard>)> {
        let (name_utf16, wireguard) = encode_name(name, wireguard)?;

        crate::log::set_default_logger_if_unset(&wireguard);

        let result = unsafe { wireguard.WireGuardOpenAdapter(name_utf16.as_ptr()) };

        if result.is_null() {
            Err(("WireGuardOpenAdapter failed".into(), wireguard))
        } else {
            Ok(Adapter {
                adapter: UnsafeHandle(result),
                wireguard,
            })
        }
    }

    /// Sets the wireguard configuration of this adapter
    pub fn set_config(&self, config: &SetInterface) -> Result<(), WireGuardError> {
        bitflags::bitflags! {
            struct InterfaceFlags: i32 {
                const HAS_PUBLIC_KEY =  1 << 0;
                const HAS_PRIVATE_KEY = 1 << 1;
                const HAS_LISTEN_PORT = 1 << 2;
                const REPLACE_PEERS =  1 << 3;
            }
        }

        bitflags::bitflags! {
            struct PeerFlags: i32 {
                const HAS_PUBLIC_KEY =  1 << 0;
                const HAS_PRESHARED_KEY = 1 << 1;
                const HAS_PERSISTENT_KEEPALIVE = 1 << 2;
                const HAS_ENDPOINT = 1 << 3;
                const REPLACE_ALLOWED_IPS = 1 << 5;
                const REMOVE = 1 << 6;
                const UPDATE = 1 << 7;
            }
        }

        let peer_size = config
            .peers
            .iter()
            .map(|p| {
                size_of::<WIREGUARD_PEER>()
                    + p.allowed_ips.len() * size_of::<WIREGUARD_ALLOWED_IP>()
            })
            .sum::<usize>();

        let size = size_of::<WIREGUARD_INTERFACE>() + peer_size;
        let align = align_of::<WIREGUARD_INTERFACE>();

        let mut writer = util::StructWriter::new(size, align);
        //Most of this function is writing data into `writer`, in a format that wireguard expects
        //so that it can decode the data when we call WireGuardSetConfiguration

        // Safety:
        // 1. `writer` has the correct alignment for a `WIREGUARD_INTERFACE`
        // 2. Nothing has been written to writer so the internal pointer must be aligned
        let interface = unsafe { writer.write::<WIREGUARD_INTERFACE>() };
        interface.Flags = {
            let mut flags = InterfaceFlags::REPLACE_PEERS;
            if let Some(private_key) = &config.private_key {
                flags |= InterfaceFlags::HAS_PRIVATE_KEY;
                interface.PrivateKey.copy_from_slice(private_key);
            }
            if let Some(pub_key) = &config.public_key {
                flags |= InterfaceFlags::HAS_PUBLIC_KEY;
                interface.PublicKey.copy_from_slice(pub_key);
            }

            if let Some(listen_port) = config.listen_port {
                flags |= InterfaceFlags::HAS_LISTEN_PORT;
                interface.ListenPort = listen_port;
            }

            flags.bits()
        };
        interface.PeersCount = config.peers.len() as u32;

        for peer in &config.peers {
            // Safety:
            // `align_of::<WIREGUARD_INTERFACE` is 8, WIREGUARD_PEER has no special alignment
            // requirements, and writer is already aligned to hold `WIREGUARD_INTERFACE` structs,
            // therefore we uphold the alignment requirements of `write`
            let wg_peer = unsafe { writer.write::<WIREGUARD_PEER>() };

            wg_peer.Flags = {
                let mut flags = PeerFlags::HAS_ENDPOINT;
                if let Some(pub_key) = &peer.public_key {
                    flags |= PeerFlags::HAS_PUBLIC_KEY;
                    wg_peer.PublicKey.copy_from_slice(pub_key);
                }
                if let Some(preshared_key) = &peer.preshared_key {
                    flags |= PeerFlags::HAS_PRESHARED_KEY;
                    wg_peer.PresharedKey.copy_from_slice(preshared_key);
                }
                if let Some(keep_alive) = peer.keep_alive {
                    flags |= PeerFlags::HAS_PERSISTENT_KEEPALIVE;
                    wg_peer.PersistentKeepalive = keep_alive;
                }
                flags.bits()
            };

            log::info!("endpoint: {}", &peer.endpoint);
            match peer.endpoint {
                SocketAddr::V4(v4) => unsafe {
                    let addr = std::mem::transmute::<[u8; 4], in_addr>(v4.ip().octets());
                    wg_peer.Endpoint.Ipv4.sin_family = AF_INET;
                    //Make sure to put the port in network byte order
                    wg_peer.Endpoint.Ipv4.sin_port = u16::from_ne_bytes(v4.port().to_be_bytes());
                    wg_peer.Endpoint.Ipv4.sin_addr = addr;
                },
                SocketAddr::V6(v6) => unsafe {
                    let addr = std::mem::transmute::<[u8; 16], in6_addr>(v6.ip().octets());
                    wg_peer.Endpoint.Ipv6.sin6_family = AF_INET6;
                    wg_peer.Endpoint.Ipv4.sin_port = u16::from_ne_bytes(v6.port().to_be_bytes());
                    wg_peer.Endpoint.Ipv6.sin6_addr = addr;
                },
            }

            wg_peer.AllowedIPsCount = peer.allowed_ips.len() as u32;

            for allowed_ip in &peer.allowed_ips {
                // Safety:
                // Same as above, `writer` is aligned because it was aligned before
                let wg_allowed_ip = unsafe { writer.write::<WIREGUARD_ALLOWED_IP>() };
                match allowed_ip {
                    IpNet::V4(v4) => {
                        let addr =
                            unsafe { std::mem::transmute::<[u8; 4], in_addr>(v4.addr().octets()) };
                        wg_allowed_ip.Address.V4 = addr;
                        wg_allowed_ip.AddressFamily = AF_INET;
                        wg_allowed_ip.Cidr = v4.prefix_len();
                    }
                    IpNet::V6(v6) => {
                        let addr = unsafe {
                            std::mem::transmute::<[u8; 16], in6_addr>(v6.addr().octets())
                        };
                        wg_allowed_ip.Address.V6 = addr;
                        wg_allowed_ip.AddressFamily = AF_INET6;
                        wg_allowed_ip.Cidr = v6.prefix_len();
                    }
                }
            }
        }

        //Make sure that our allocation math was correct and that we filled all of writer
        debug_assert!(writer.is_full());

        let result = unsafe {
            self.wireguard.WireGuardSetConfiguration(
                self.adapter.0,
                writer.ptr().cast(),
                size as u32,
            )
        };

        match result {
            0 => Err("WireGuardSetConfiguration failed".into()),
            _ => Ok(()),
        }
    }

    /// Assigns this adapter an ip address and adds route(s) so that packets sent
    /// within the `interface_addr` IpNet will be sent across the WireGuard VPN
    pub fn set_default_route(
        &self,
        interface_addrs: &[IpNet],
        config: &SetInterface,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let luid = self.get_luid();
        unsafe {
            for allowed_ip in config.peers.iter().flat_map(|p| p.allowed_ips.iter()) {
                let mut default_route = std::mem::zeroed::<MIB_IPFORWARD_ROW2>();
                InitializeIpForwardEntry(&mut default_route);
                default_route.InterfaceLuid = std::mem::transmute::<u64, Ndis::NET_LUID_LH>(luid);
                default_route.Metric = 0;

                match allowed_ip {
                    IpNet::V4(v4) => {
                        default_route.DestinationPrefix.Prefix.si_family = AF_INET;
                        default_route.DestinationPrefix.Prefix.Ipv4.sin_addr =
                            std::mem::transmute::<[u8; 4], IN_ADDR>(v4.addr().octets());

                        default_route.DestinationPrefix.PrefixLength = v4.prefix_len();

                        //Next hop is 0.0.0.0/0, because it is the address of a local interface
                        //(the wireguard interface). So because the struct is zeroed we don't need
                        //to set anything except the address family
                        default_route.NextHop.si_family = AF_INET;
                    }
                    IpNet::V6(v6) => {
                        default_route.DestinationPrefix.Prefix.si_family = AF_INET6;
                        default_route.DestinationPrefix.Prefix.Ipv6.sin6_addr =
                            std::mem::transmute::<[u8; 16], IN6_ADDR>(v6.addr().octets());

                        default_route.DestinationPrefix.PrefixLength = v6.prefix_len();
                        default_route.NextHop.si_family = AF_INET6;
                    }
                }

                let err = CreateIpForwardEntry2(&default_route);
                if err != ERROR_SUCCESS && err != ERROR_OBJECT_ALREADY_EXISTS {
                    return win_error("Failed to set default route", err);
                }
            }

            let mut ip_interface = std::mem::zeroed::<MIB_IPINTERFACE_ROW>();
            InitializeIpInterfaceEntry(&mut ip_interface);
            ip_interface.InterfaceLuid = std::mem::transmute::<u64, Ndis::NET_LUID_LH>(luid);

            for interface_addr in interface_addrs {
                let mut address_row = std::mem::zeroed::<MIB_UNICASTIPADDRESS_ROW>();
                InitializeUnicastIpAddressEntry(&mut address_row);
                address_row.InterfaceLuid = std::mem::transmute::<u64, Ndis::NET_LUID_LH>(luid);
                address_row.OnLinkPrefixLength = interface_addr.prefix_len();
                address_row.DadState = IpDadStatePreferred;

                match interface_addr {
                    IpNet::V4(interface_addr_v4) => {
                        ip_interface.Family = AF_INET;

                        address_row.Address.Ipv4.sin_family = AF_INET;
                        address_row.Address.Ipv4.sin_addr = std::mem::transmute::<[u8; 4], IN_ADDR>(
                            interface_addr_v4.addr().octets(),
                        );
                    }
                    IpNet::V6(interface_addr_v6) => {
                        ip_interface.Family = AF_INET6;

                        address_row.Address.Ipv6.sin6_family = AF_INET6;
                        address_row.Address.Ipv6.sin6_addr =
                            std::mem::transmute::<[u8; 16], IN6_ADDR>(
                                interface_addr_v6.addr().octets(),
                            );
                    }
                }

                let err = CreateUnicastIpAddressEntry(&address_row);
                if err != ERROR_SUCCESS && err != ERROR_OBJECT_ALREADY_EXISTS {
                    return win_error("Failed to set IP interface", err);
                }
            }

            let err = GetIpInterfaceEntry(&mut ip_interface);
            if err != ERROR_SUCCESS {
                return win_error("Failed to get IP interface", err);
            }

            ip_interface.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
            ip_interface.DadTransmits = 0;
            ip_interface.ManagedAddressConfigurationSupported = 0;
            ip_interface.OtherStatefulConfigurationSupported = 0;
            ip_interface.UseAutomaticMetric = 0;
            ip_interface.Metric = 0;
            ip_interface.NlMtu = 1420;
            ip_interface.SitePrefixLength = 0;
            let err = SetIpInterfaceEntry(&mut ip_interface);
            if err != ERROR_SUCCESS {
                return win_error("Failed to set metric and MTU", err);
            }

            Ok(())
        }
    }

    /// Puts this adapter into the up state
    pub fn up(&self) -> bool {
        unsafe {
            self.wireguard
                .WireGuardSetAdapterState(self.adapter.0, WIREGUARD_STATE_UP)
                != 0
        }
    }

    /// Puts this adapter into the down state
    pub fn down(&self) -> bool {
        unsafe {
            self.wireguard
                .WireGuardSetAdapterState(self.adapter.0, WIREGUARD_STATE_DOWN)
                != 0
        }
    }

    /// Returns the adapter's LUID.
    /// This is a 64bit unique identifier that windows uses when referencing this adapter
    pub fn get_luid(&self) -> u64 {
        let mut luid = 0u64;
        let ptr = &mut luid as *mut u64 as *mut _NET_LUID_LH;
        unsafe { self.wireguard.WireGuardGetAdapterLUID(self.adapter.0, ptr) };
        luid
    }

    /// Sets the logging level of this adapter
    ///
    /// Log messages will be sent to the current logger (set using [`crate::set_logger`]
    pub fn set_logging(&self, level: AdapterLoggingLevel) -> bool {
        let level = match level {
            AdapterLoggingLevel::Off => 0,
            AdapterLoggingLevel::On => 1,
            AdapterLoggingLevel::OnWithPrefix => 2,
        };
        unsafe {
            self.wireguard
                .WireGuardSetAdapterLogging(self.adapter.0, level)
                != 0
        }
    }

    /// Gets the current configuration of this adapter
    pub fn get_config(&self) -> WireguardInterface {
        // calling wireguard.WireGuardGetConfiguration with Bytes = 0 returns ERROR_MORE_DATA
        // and updates Bytes to the correct value
        let mut size = 0u32;
        let res = unsafe {
            self.wireguard
                .WireGuardGetConfiguration(self.adapter.0, ptr::null_mut(), &mut size)
        };
        // Should never fail since we
        assert_eq!(res, 0, "Failed to query size of wireguard configuration");
        assert_eq!(
            unsafe { GetLastError() },
            ERROR_MORE_DATA,
            "WireGuardGetConfiguration returned invalid error for size request"
        );
        assert_ne!(size, 0, "Wireguard config is zero bytes"); // size has been updated
        let align = align_of::<WIREGUARD_INTERFACE>();
        let mut reader = StructReader::new(size as usize, align);
        let res = unsafe {
            self.wireguard.WireGuardGetConfiguration(
                self.adapter.0,
                reader.ptr_mut().cast(),
                &mut size,
            )
        };
        assert_ne!(res, 0);

        // # Safety:
        // 1. `WireGuardGetConfiguration` writes a `WIREGUARD_INTERFACE` at offset 0 to the buffer we give it.
        // 2. The buffer's alignment is set to be the proper alignment for a `WIREGUARD_INTERFACE` by the line above
        // 3. We calculate the size of `reader` with the first call to `WireGuardGetConfiguration`. Wireguard writes at
        //    least one `WIREGUARD_INTERFACE`, and size is updated accordingly, therefore `reader`'s allocation is at least
        //    the size of a `WIREGUARD_INTERFACE`
        let wireguard_interface = unsafe { reader.read::<WIREGUARD_INTERFACE>() };
        let mut wg_interface = WireguardInterface {
            flags: wireguard_interface.Flags,
            listen_port: wireguard_interface.ListenPort,
            private_key: wireguard_interface.PrivateKey,
            public_key: wireguard_interface.PublicKey,
            peers: Vec::with_capacity(wireguard_interface.PeersCount as usize),
        };

        for _ in 0..wireguard_interface.PeersCount {
            // # Safety:
            // 1. `WireGuardGetConfiguration` writes a `WIREGUARD_PEER` immediately after the WIREGUARD_INTERFACE we read above.
            // 2. We rely on Wireguard-NT to specify the number of peers written, and therefore we never read too many times unless Wireguard-NT (wrongly) tells us to
            let peer = unsafe { reader.read::<WIREGUARD_PEER>() };
            let endpoint = peer.Endpoint;
            let address_family = unsafe { endpoint.si_family };
            let endpoint = match address_family {
                AF_INET => {
                    // #Safety
                    // This enum is valid to access because the address is a [u8; 4] which is set properly by the call above,
                    // and it can have any value.
                    let octets = unsafe { endpoint.Ipv4.sin_addr.S_un.S_un_b };
                    let address = Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4);
                    let port = u16::from_be(unsafe { endpoint.Ipv4.sin_port });
                    SocketAddr::V4(SocketAddrV4::new(address, port))
                }
                AF_INET6 => {
                    let octets = unsafe { endpoint.Ipv6.sin6_addr.u.Byte };
                    let address = Ipv6Addr::from(octets);
                    let port = u16::from_be(unsafe { endpoint.Ipv6.sin6_port });
                    let flow_info = unsafe { endpoint.Ipv6.sin6_flowinfo };
                    let scope_id = unsafe { endpoint.Ipv6.__bindgen_anon_1.sin6_scope_id };
                    SocketAddr::V6(SocketAddrV6::new(address, port, flow_info, scope_id))
                }
                _ => {
                    panic!("Illegal address family {}", address_family);
                }
            };
            let last_handshake = if peer.LastHandshake == 0 {
                None
            } else {
                // The number of 100ns intervals between 1-1-1600 and 1-1-1970
                const UNIX_EPOCH_FROM_1_1_1600: u64 = 116444736000000000;
                let ns_from_unix_epoch =
                    peer.LastHandshake.saturating_sub(UNIX_EPOCH_FROM_1_1_1600) * 100;
                Some(SystemTime::UNIX_EPOCH + Duration::from_nanos(ns_from_unix_epoch))
            };

            let mut wg_peer = WireguardPeer {
                flags: peer.Flags,
                public_key: peer.PublicKey,
                preshared_key: peer.PresharedKey,
                persistent_keepalive: peer.PersistentKeepalive,
                endpoint,
                tx_bytes: peer.TxBytes,
                rx_bytes: peer.RxBytes,
                last_handshake,
                allowed_ips: Vec::with_capacity(peer.AllowedIPsCount as usize),
            };
            for _ in 0..peer.AllowedIPsCount {
                // # Safety:
                // 1. `WireGuardGetConfiguration` writes zero or more `WIREGUARD_ALLOWED_IP`s immediately after the WIREGUARD_PEER we read above.
                // 2. We rely on Wireguard-NT to specify the number of allowed ips written, and therefore we never read too many times unless Wireguard-NT (wrongly) tells us to
                let allowed_ip = unsafe { reader.read::<WIREGUARD_ALLOWED_IP>() };
                let prefix_length = allowed_ip.Cidr;
                let allowed_ip = match allowed_ip.AddressFamily {
                    AF_INET => {
                        let octets = unsafe { allowed_ip.Address.V4.S_un.S_un_b };
                        let address =
                            Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4);
                        IpNet::V4(Ipv4Net::new(address, prefix_length).expect("prefix is valid"))
                    }
                    AF_INET6 => {
                        let octets = unsafe { allowed_ip.Address.V6.u.Byte };
                        let address = Ipv6Addr::from(octets);
                        IpNet::V6(Ipv6Net::new(address, prefix_length).expect("prefix is valid"))
                    }
                    _ => {
                        panic!("Illegal address family {}", allowed_ip.AddressFamily);
                    }
                };
                wg_peer.allowed_ips.push(allowed_ip);
            }
            wg_interface.peers.push(wg_peer);
        }
        wg_interface
    }
}

#[derive(Debug)]
pub struct WireguardPeer {
    /// Bitwise combination of flags
    pub flags: WIREGUARD_PEER_FLAG,
    /// Public key, the peer's primary identifier
    pub public_key: [u8; 32usize],
    /// Preshared key for additional layer of post-quantum resistance
    pub preshared_key: [u8; 32usize],
    /// Seconds interval, or 0 to disable
    pub persistent_keepalive: u16,
    /// Endpoint, with IP address and UDP port number
    pub endpoint: SocketAddr,
    /// Number of bytes transmitted
    pub tx_bytes: u64,
    /// Number of bytes received
    pub rx_bytes: u64,
    /// Time of the last handshake, `None` if no handshake has occurred
    pub last_handshake: Option<SystemTime>,
    /// Number of allowed IP structs following this struct
    pub allowed_ips: Vec<IpNet>,
}

#[derive(Debug)]
pub struct WireguardInterface {
    /// Bitwise combination of flags
    pub flags: WIREGUARD_INTERFACE_FLAG,
    /// Port for UDP listen socket, or 0 to choose randomly
    pub listen_port: u16,
    /// Private key of interface
    pub private_key: [u8; 32usize],
    /// Corresponding public key of private key
    pub public_key: [u8; 32usize],
    /// Number of peer structs following this struct
    pub peers: Vec<WireguardPeer>,
}

impl Drop for Adapter {
    fn drop(&mut self) {
        //Free adapter on drop
        //This is why we need an Arc of wireguard, so we have access to it here
        unsafe { self.wireguard.WireGuardCloseAdapter(self.adapter.0) };
        self.adapter = UnsafeHandle(ptr::null_mut());
    }
}
