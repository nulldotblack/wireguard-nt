use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ipnet::{Ipv4Net, Ipv6Net};
use log::*;

fn main() {
    env_logger::init();

    let private = x25519_dalek::StaticSecret::random();
    let public = x25519_dalek::PublicKey::from(&private);

    let (demo_pub, internal_ip, endpoint) =
        get_demo_server_config(public.as_bytes()).expect("Failed to get demo server credentials");
    println!("Connecting to {} - internal ip: {}", endpoint, internal_ip);

    //Must be run as Administrator because we create network adapters
    //Load the wireguard dll file so that we can call the underlying C functions
    //Unsafe because we are loading an arbitrary dll file
    let wireguard = unsafe { wireguard_nt::load_from_path("wireguard_nt/bin/amd64/wireguard.dll") }
        .expect("Failed to load wireguard dll");

    //Try to open an adapter from the given pool with the name "Demo"
    let adapter =
        wireguard_nt::Adapter::open(wireguard, "Demo").unwrap_or_else(|(_, wireguard)| {
            wireguard_nt::Adapter::create(wireguard, "WireGuard", "Demo", None)
                .map_err(|e| e.0)
                .expect("Failed to create wireguard adapter!")
        });
    let mut interface_private = [0; 32];
    let mut peer_pub = [0; 32];

    interface_private.copy_from_slice(private.as_bytes());
    peer_pub.copy_from_slice(demo_pub.as_slice());

    //Only allow traffic going to the demo server to pass through the wireguard interface
    let allowed_ip = match endpoint.ip() {
        IpAddr::V4(v4) => Ipv4Net::new(v4, 32).unwrap().into(),
        IpAddr::V6(v6) => Ipv6Net::new(v6, 128).unwrap().into(),
    };

    let interface = wireguard_nt::SetInterface {
        listen_port: None,
        public_key: None,
        private_key: Some(interface_private),
        peers: vec![wireguard_nt::SetPeer {
            public_key: Some(peer_pub),
            preshared_key: None,
            keep_alive: Some(21),
            //Uncomment to tunnel all traffic
            //allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            allowed_ips: vec![allowed_ip], //Only tunnel traffic bound for the demo server the wireguard interface
            endpoint,
        }],
    };
    assert!(adapter.set_logging(wireguard_nt::AdapterLoggingLevel::OnWithPrefix));

    adapter.set_config(&interface).unwrap();
    match adapter.set_default_route(&[Ipv4Net::new(internal_ip, 24).unwrap().into()], &interface) {
        Ok(()) => {}
        Err(err) => panic!("Failed to set default route: {}", err),
    }
    assert!(adapter.up());

    // Go to http://demo.wireguard.com/ and see the bandwidth numbers change!
    println!("Printing peer bandwidth statistics");
    println!("Press enter to exit");
    let done = Arc::new(AtomicBool::new(false));
    let done2 = Arc::clone(&done);
    let thread = std::thread::spawn(move || 'outer: loop {
        let stats = adapter.get_config();
        for peer in stats.peers {
            let handshake_age = peer
                .last_handshake
                .map(|h| SystemTime::now().duration_since(h).unwrap_or_default());
            let handshake_msg = match handshake_age {
                Some(age) => format!("handshake performed {:.2}s ago", age.as_secs_f32()),
                None => "no active handshake".to_string(),
            };

            println!(
                "  {:?}, {} bytes up, {} bytes down, {handshake_msg}",
                peer.allowed_ips, peer.tx_bytes, peer.rx_bytes
            );
        }
        for _ in 0..10 {
            if done2.load(Ordering::Relaxed) {
                break 'outer;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });

    let mut _buf = [0u8; 32];
    let _ = std::io::stdin().read(&mut _buf);

    done.store(true, Ordering::Relaxed);
    thread.join().unwrap();
    println!("Exiting!");
}

/// Gets info from the demo server that can be used to connect.
/// pub_key is a 32 byte public key that corresponds to the private key that the caller has
fn get_demo_server_config(pub_key: &[u8]) -> Result<(Vec<u8>, Ipv4Addr, SocketAddr), String> {
    use std::net::{TcpStream, ToSocketAddrs};
    let addrs: Vec<SocketAddr> = "demo.wireguard.com:42912"
        .to_socket_addrs()
        .unwrap()
        .collect();

    let mut s: TcpStream = TcpStream::connect_timeout(
        addrs.first().expect("Failed to resolve demo server DNS"),
        Duration::from_secs(5),
    )
    .expect("Failed to open connection to demo server");

    let mut encoded = base64::encode(pub_key);
    encoded.push('\n');
    s.write_all(encoded.as_bytes())
        .expect("Failed to write public key to server");

    let mut bytes = [0u8; 512];
    let len = s.read(&mut bytes).expect("Failed to read from demo server");
    let reply = &std::str::from_utf8(&bytes).unwrap()[..len].trim();
    info!("Demo server gave: {}", reply);

    if !reply.starts_with("OK") {
        return Err(format!("Demo Server returned error {}", reply));
    }
    let parts: Vec<&str> = reply.split(':').collect();
    if parts.len() != 4 {
        return Err(format!(
            "Demo Server returned wrong number of parts. Expected 4 got: {:?}",
            parts
        ));
    }
    let peer_pub = base64::decode(parts[1])
        .map_err(|e| format!("Demo server gave invalid public key: {}", e))?;

    let endpoint_port: u16 = parts[2]
        .parse()
        .map_err(|e| format!("Demo server gave invalid port number: {}", e))?;

    let internal_ip = parts[3];
    let internal_ip: Ipv4Addr = internal_ip.parse().unwrap();

    Ok((
        peer_pub,
        internal_ip,
        SocketAddr::new(addrs[0].ip(), endpoint_port),
    ))
}
