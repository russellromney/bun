//! Rust bindings for ngtcp2 (vendor build wired up by
//! `scripts/build/deps/ngtcp2.ts`): the IETF QUIC transport library backing
//! the node:quic implementation, built with its BoringSSL crypto backend
//! (`libngtcp2` + `libngtcp2_crypto_boringssl` object files are linked into
//! the final binary by the build graph; no `#[link]` attributes needed).
//!
//! Only the version probe is bound so far; the full API surface lands with
//! the node:quic binding.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
#![warn(unused_must_use)]

use core::ffi::{c_char, c_int};

/// Mirrors `ngtcp2_info` from `ngtcp2/version.h` (age 1 layout).
#[repr(C)]
pub struct ngtcp2_info {
    pub age: c_int,
    pub version_num: c_int,
    pub version_str: *const c_char,
}

unsafe extern "C" {
    /// Returns the library's static version info, or NULL if the linked
    /// library is older than `least_version` (pass 0 to always succeed).
    pub safe fn ngtcp2_version(least_version: c_int) -> *const ngtcp2_info;
}
