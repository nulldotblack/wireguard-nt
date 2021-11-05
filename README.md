# wireguard-nt

Safe rust idiomatic bindings for the WireGuard NT C library: <https://git.zx2c4.com/wireguard-nt/about>

Features of the WireGuard NT library are wrapped using pure rust types and functions to make
usage feel ergonomic.

## Usage

Add a dependency on this library to your `Cargo.toml`

```toml
[dependencies]
wireguard-nt = "0.2"
```

Inside your code load the wireguard.dll signed driver file, downloaded from <https://git.zx2c4.com/wireguard-nt/about>

Then either call [`Adapter::create`] or [`Adapter::open`] to obtain a wireguard
adapter. Start by setting its config with [`Adapter::set_config`].

## Example
```rust
//Must be run as Administrator because we create network adapters
//Load the wireguard dll file so that we can call the underlying C functions
//Unsafe because we are loading an arbitrary dll file
let wireguard = unsafe { wireguard_nt::load_from_path("path/to/wireguard.dll") }.expect("Failed to load wireguard dll");
//Try to open an adapter with the name "Demo"
let adapter = match wireguard_nt::Adapter::open(wireguard, "Demo") {
    Ok(a) => a,
    Err((_, wireguard)) => {
        //If loading failed (most likely it didn't exist), create a new one
        match wireguard_nt::Adapter::create(wireguard, "WireGuard", "Demo", None) {
            Ok(a) => a,
            Err((e, _)) => panic!("Failed to create adapter: {:?}", e),
        }
    }
};

let interface = wireguard_nt::SetInterface {
    //Let the OS pick a port for us
    listen_port: None,
    //Generated from the private key if not specified
    public_key: None,
    //Fill in private keys in real code
    private_key: None,
    //Add a peer
    peers: vec![wireguard_nt::SetPeer {
        //Provide a public key so that we can communicate with them
        public_key: None,
        //Disable additional AES encryption
        preshared_key: None,
        //Send a keepalive packet every 21 seconds
        keep_alive: Some(21),
        //Route all traffic through the WireGuard interface
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
        //The peer's ip address
        endpoint: "1.2.3.4".parse().unwrap(),
    }],
};

//Set the config our adapter will use
//This lets it know about the peers and keys
adapter.set_config(&interface).unwrap();

let internal_ip = "10.4.0.2".parse().unwrap();
let internal_prefix_length = 24;
let internal_ipnet = ipnet::Ipv4Net::new(internal_ip, internal_prefix_length).unwrap();
//Set up the routing table with the allowed ips for our peers,
//and assign an ip to the interface
adapter.set_default_route(internal_ipnet, &interface).unwrap();

//drop(adapter)
//The adapter closes its resources when dropped
```

See `examples/demo_server.rs` that connects to the wireguard demo server

## Version compatibility
Wireguard NT versions 0.10 and above are supported. Versions < 0.10 have breaking changes that
make interoperability hard. Please file an issue if this effects your use case.


License: MIT
