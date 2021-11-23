# ChangeLog

This format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org).

## [0.3.0] - 2021-11-23

### Added

- `get_config` in `Adapter` to obtain the config from an active WireguardNT interface #6
- `set_default_route` in `Adapter` now takes a slice of IpNet addresses to
support multiple addresses as well as hybrid Ipv6/Ipv4 configuration #7
- Added loop that uses `get_config` to print network traffic stats in `demo_server`.

### Breaking Changes

- `set_default_route` Takes a immutable slice of IpNet's instead of a single Ipv4Net #7
- Names of fields inside adapter::WireguardInterface and adapter::WireguardPeer are changed to be snake case

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
