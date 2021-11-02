# wireguard-nt

Safe rust idiomatic bindings for the WireGuard NT C library: <https://git.zx2c4.com/wireguard-nt/about>

All features of the WireGuard NT library are wrapped using pure rust types and functions to make
usage feel ergonomic.

## Usage

Add a dependency on this library to your `Cargo.toml`

```toml
[dependencies]
wireguard-nt = "0.1"
```

Inside your code load the wireguard.dll signed driver file, downloaded from <https://git.zx2c4.com/wireguard-nt/about>

Then either call [`Adapter::create`] or [`Adapter::open`] to obtain a wireguard
adapter. Start set its config with [`Adapter::set_config`].

## Example
```rust

//Must be run as Administrator because we create network adapters
//Load the wireguard dll file so that we can call the underlying C functions
//Unsafe because we are loading an arbitrary dll file
let wireguard = unsafe { wireguard_nt::load_from_path("path/to/wireguard.dll") }.expect("Failed to load wireguard dll");
//Try to open an adapter from the given pool with the name "Demo"
let adapter = match wireguard_nt::Adapter::open(&wireguard, "WireGuard", "Demo") {
    Ok(a) => a,
    Err(_) =>
        //If loading failed (most likely it didn't exist), create a new one
        wireguard_nt::Adapter::create(&wireguard, "WireGuard", "Demo", None).expect("Failed to create wireguard adapter!").adapter,
};

todo!("Set config");
//Delete the adapter when finished.
adapter.delete().unwrap();
//drop(adapter)
//And the adapter closes its resources when dropped

```

See `examples/demo_server.rs` that connects to the wireguard demo server


License: MIT
