# ChangeLog

This format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org).


## [0.5.0] - 2024-08-10

### Changes

- Fixes compilation failure due to breaking change in winapi. Use windows-sys now that it is the agreed-on crate: https://github.com/nulldotblack/wireguard-nt/pull/15
- Adds a proper error type for this crate: https://github.com/nulldotblack/wireguard-nt/pull/17
- Use `getrandom` over `rand` to reduce dependency tree: https://github.com/nulldotblack/wireguard-nt/pull/16
- Allow creating routes with custom metric: https://github.com/nulldotblack/wireguard-nt/pull/18


### Breaking Changes

- Any function taking in a `wireguard_nt_raw::wireguard`, a newtype wrapper `wireguard_nt::Wireguard` is used instead
- Any function previously returning an `Result<_, Box<dyn std::error::Error>>`, a proper error type is now used across this crate

## [0.4.0] - 2024-04-11

### Fixed

- Correct printing of handshake time when an adapter has not yet completed the handshake in `demo_server` example.

### Breaking Changes

- `last_handshake` in `WireguardPeer` changed from a `std::time::Instant` to a `std::option::Option<std::time::SystemTime>` to reflect non handshake state.

## [0.3.0] - 2021-11-23

### Added

- `get_config` in `Adapter` to obtain the config from an active WireguardNT interface #6
- `set_default_route` in `Adapter` now takes a slice of IpNet addresses to
support multiple addresses as well as hybrid Ipv6/Ipv4 configuration #7
- Added loop that uses `get_config` to print network traffic stats in `demo_server`.

### Breaking Changes

- `set_default_route` Takes a immutable slice of IpNet's instead of a single Ipv4Net #7
- Names of fields inside adapter::WireguardInterface and adapter::WireguardPeer are changed to be snake case
- `adapter::WireguardPeer::last_handshake` is now an instant to simplify use case

## [0.2.2] - 2021-11-14

### Fixed

- Added missing winapi features to fix compilation issue when used as from crates.io

## [0.2.1] - 2021-11-5

### Documented new API for WireguardNT 0.10

## [0.2.0] - 2021-11-4

### Added

- Support for WireguardNT 0.10 #4
- Remove support for versions < WireguardNT 0.10 #3

### Fixed

- `Adapter::set_default_route` doesnt respect allowed ips #2

### Documented

- Updated `demo_server` example accordingly

## [0.1.0] - 2021-09-30

Initial Release

### Added

- Basic API for loading WireguardNT driver dlls, and creating adapters
