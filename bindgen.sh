#!/bin/bash
bindgen --allowlist-function "WireGuard.*" --dynamic-loading wireguard wireguard_nt/wireguard.h > src/wireguard_nt_raw.rs
