#!/bin/bash
bindgen \
--allowlist-function "WireGuard.*" \
--allowlist-type "WIREGUARD_.*" \
--dynamic-loading wireguard \
--dynamic-link-require-all \
wireguard_nt/wireguard_functions.h > src/wireguard_nt_raw.rs
