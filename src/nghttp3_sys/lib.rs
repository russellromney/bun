//! Rust bindings for nghttp3 (vendor build wired up by
//! `scripts/build/deps/nghttp3.ts`): the HTTP/3 + QPACK library backing the
//! node:quic implementation's HTTP/3 application protocol. The library's
//! object files are linked into the final binary by the build graph; no
//! `#[link]` attributes needed.
//!
//! Only the version probe is bound so far; the full API surface lands with
//! the node:quic binding.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
#![warn(unused_must_use)]

use core::ffi::{c_char, c_int};

/// Mirrors `nghttp3_info` from `nghttp3/version.h` (age 1 layout).
#[repr(C)]
pub struct nghttp3_info {
    pub age: c_int,
    pub version_num: c_int,
    pub version_str: *const c_char,
}

unsafe extern "C" {
    /// Returns the library's static version info, or NULL if the linked
    /// library is older than `least_version` (pass 0 to always succeed).
    pub safe fn nghttp3_version(least_version: c_int) -> *const nghttp3_info;
}
