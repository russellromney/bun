//! Rust bindings for ngtcp2 1.22.1 (vendor build wired up by
//! `scripts/build/deps/ngtcp2.ts`): the IETF QUIC transport library backing
//! the node:quic implementation, built with its BoringSSL crypto backend
//! (`libngtcp2` + `libngtcp2_crypto_boringssl` object files are linked into
//! the final binary by the build graph; no `#[link]` attributes needed).
//!
//! Struct layouts are hand-transcribed from
//! `ngtcp2/ngtcp2.h` / `ngtcp2_crypto.h` at v1.22.1 and must stay
//! field-for-field identical (same order and C types); `repr(C)` then yields
//! the same padding the C compiler produces. Layout is additionally verified
//! at runtime by `debug_assert_layout()` below, which checks values written
//! by `ngtcp2_settings_default` / `ngtcp2_transport_params_default` against
//! the documented defaults.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]
#![warn(unused_must_use)]

use core::ffi::{c_char, c_int, c_void};

/// Mirrors `ngtcp2_info` from `ngtcp2/version.h` (age 1 layout).
#[repr(C)]
pub struct ngtcp2_info {
    pub age: c_int,
    pub version_num: c_int,
    pub version_str: *const c_char,
}

// ── Basic types ────────────────────────────────────────────────────────────

pub type ngtcp2_tstamp = u64;
pub type ngtcp2_duration = u64;
pub type ngtcp2_ssize = isize;
/// `socklen_t` (u32 on every supported platform).
pub type ngtcp2_socklen = u32;

/// Opaque `struct sockaddr`; only ever used behind a pointer.
pub type ngtcp2_sockaddr = c_void;

/// C enums are `int`-sized.
pub type ngtcp2_cc_algo = c_int;
pub const NGTCP2_CC_ALGO_RENO: ngtcp2_cc_algo = 0;
pub const NGTCP2_CC_ALGO_CUBIC: ngtcp2_cc_algo = 1;
pub const NGTCP2_CC_ALGO_BBR: ngtcp2_cc_algo = 2;

pub type ngtcp2_token_type = c_int;
pub const NGTCP2_TOKEN_TYPE_UNKNOWN: ngtcp2_token_type = 0;
pub const NGTCP2_TOKEN_TYPE_RETRY: ngtcp2_token_type = 1;
pub const NGTCP2_TOKEN_TYPE_NEW_TOKEN: ngtcp2_token_type = 2;

pub type ngtcp2_ccerr_type = c_int;
pub const NGTCP2_CCERR_TYPE_TRANSPORT: ngtcp2_ccerr_type = 0;
pub const NGTCP2_CCERR_TYPE_APPLICATION: ngtcp2_ccerr_type = 1;
pub const NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION: ngtcp2_ccerr_type = 2;
pub const NGTCP2_CCERR_TYPE_IDLE_CLOSE: ngtcp2_ccerr_type = 3;
pub const NGTCP2_CCERR_TYPE_DROP_CONN: ngtcp2_ccerr_type = 4;
pub const NGTCP2_CCERR_TYPE_RETRY: ngtcp2_ccerr_type = 5;

pub type ngtcp2_encryption_level = c_int;
pub const NGTCP2_ENCRYPTION_LEVEL_INITIAL: ngtcp2_encryption_level = 0;
pub const NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE: ngtcp2_encryption_level = 1;
pub const NGTCP2_ENCRYPTION_LEVEL_1RTT: ngtcp2_encryption_level = 2;
pub const NGTCP2_ENCRYPTION_LEVEL_0RTT: ngtcp2_encryption_level = 3;

// ── Constants ──────────────────────────────────────────────────────────────

pub const NGTCP2_PROTO_VER_V1: u32 = 0x0000_0001;
pub const NGTCP2_MAX_UDP_PAYLOAD_SIZE: usize = 1200;
pub const NGTCP2_MAX_CIDLEN: usize = 20;
pub const NGTCP2_STATELESS_RESET_TOKENLEN: usize = 16;
pub const NGTCP2_MILLISECONDS: u64 = 1_000_000;
pub const NGTCP2_SECONDS: u64 = 1_000_000_000;

// Struct-version constants (the *_versioned entry points take these).
pub const NGTCP2_PKT_INFO_VERSION: c_int = 1;
pub const NGTCP2_TRANSPORT_PARAMS_VERSION: c_int = 1;
pub const NGTCP2_CONN_INFO_VERSION: c_int = 2;
pub const NGTCP2_SETTINGS_VERSION: c_int = 3;
pub const NGTCP2_CALLBACKS_VERSION: c_int = 3;

// Library error codes (subset used by the binding).
pub const NGTCP2_ERR_CRYPTO: c_int = -213;
pub const NGTCP2_ERR_DRAINING: c_int = -224;
pub const NGTCP2_ERR_WRITE_MORE: c_int = -230;
pub const NGTCP2_ERR_RETRY: c_int = -231;
pub const NGTCP2_ERR_DROP_CONN: c_int = -232;
pub const NGTCP2_ERR_IDLE_CLOSE: c_int = -238;

// `ngtcp2_conn_writev_stream` flags.
pub const NGTCP2_WRITE_STREAM_FLAG_NONE: u32 = 0;
pub const NGTCP2_WRITE_STREAM_FLAG_MORE: u32 = 0x01;
pub const NGTCP2_WRITE_STREAM_FLAG_FIN: u32 = 0x02;

// ── Opaque handles ─────────────────────────────────────────────────────────

#[repr(C)]
pub struct ngtcp2_conn {
    _opaque: [u8; 0],
}
#[repr(C)]
pub struct ngtcp2_mem {
    _opaque: [u8; 0],
}
#[repr(C)]
pub struct ngtcp2_crypto_aead {
    _opaque: [u8; 0],
}
#[repr(C)]
pub struct ngtcp2_crypto_aead_ctx {
    _opaque: [u8; 0],
}
#[repr(C)]
pub struct ngtcp2_crypto_cipher {
    _opaque: [u8; 0],
}
#[repr(C)]
pub struct ngtcp2_crypto_cipher_ctx {
    _opaque: [u8; 0],
}

// ── Value structs (layouts mirror ngtcp2.h v1.22.1) ────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_cid {
    pub datalen: usize,
    pub data: [u8; NGTCP2_MAX_CIDLEN],
}

impl Default for ngtcp2_cid {
    fn default() -> Self {
        Self { datalen: 0, data: [0; NGTCP2_MAX_CIDLEN] }
    }
}

/// `NGTCP2_ALIGN(8)` in C.
#[repr(C, align(8))]
#[derive(Copy, Clone, Default)]
pub struct ngtcp2_pkt_info {
    pub ecn: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_addr {
    pub addr: *mut ngtcp2_sockaddr,
    pub addrlen: ngtcp2_socklen,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_path {
    pub local: ngtcp2_addr,
    pub remote: ngtcp2_addr,
    pub user_data: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_vec {
    pub base: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct ngtcp2_rand_ctx {
    pub native_handle: *mut c_void,
}

/// Layout-compatible `struct sockaddr_in` / `sockaddr_in6` stand-ins. Only
/// embedded by value inside `ngtcp2_preferred_addr` (which this binding never
/// reads field-by-field); sizes match all supported platforms (16 / 28).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_sockaddr_in {
    pub family_port: [u8; 4],
    pub addr: [u8; 4],
    pub zero: [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_sockaddr_in6 {
    pub family_port: [u8; 4],
    pub flowinfo: u32,
    pub addr: [u8; 16],
    pub scope_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_preferred_addr {
    pub cid: ngtcp2_cid,
    pub ipv4: ngtcp2_sockaddr_in,
    pub ipv6: ngtcp2_sockaddr_in6,
    pub ipv4_present: u8,
    pub ipv6_present: u8,
    pub stateless_reset_token: [u8; NGTCP2_STATELESS_RESET_TOKENLEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_version_info {
    pub chosen_version: u32,
    pub available_versions: *const u8,
    pub available_versionslen: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_transport_params {
    pub preferred_addr: ngtcp2_preferred_addr,
    pub original_dcid: ngtcp2_cid,
    pub initial_scid: ngtcp2_cid,
    pub retry_scid: ngtcp2_cid,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_data: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout: ngtcp2_duration,
    pub max_udp_payload_size: u64,
    pub active_connection_id_limit: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: ngtcp2_duration,
    pub max_datagram_frame_size: u64,
    pub stateless_reset_token_present: u8,
    pub disable_active_migration: u8,
    pub original_dcid_present: u8,
    pub initial_scid_present: u8,
    pub retry_scid_present: u8,
    pub preferred_addr_present: u8,
    pub stateless_reset_token: [u8; NGTCP2_STATELESS_RESET_TOKENLEN],
    pub grease_quic_bit: u8,
    pub version_info: ngtcp2_version_info,
    pub version_info_present: u8,
}

pub type ngtcp2_qlog_write = Option<
    unsafe extern "C" fn(user_data: *mut c_void, flags: u32, data: *const c_void, datalen: usize),
>;
pub type ngtcp2_printf =
    Option<unsafe extern "C" fn(user_data: *mut c_void, format: *const c_char, ...)>;

#[repr(C)]
pub struct ngtcp2_settings {
    pub qlog_write: ngtcp2_qlog_write,
    pub cc_algo: ngtcp2_cc_algo,
    pub initial_ts: ngtcp2_tstamp,
    pub initial_rtt: ngtcp2_duration,
    pub log_printf: ngtcp2_printf,
    pub max_tx_udp_payload_size: usize,
    pub token: *const u8,
    pub tokenlen: usize,
    pub token_type: ngtcp2_token_type,
    pub rand_ctx: ngtcp2_rand_ctx,
    pub max_window: u64,
    pub max_stream_window: u64,
    pub ack_thresh: usize,
    pub no_tx_udp_payload_size_shaping: u8,
    pub handshake_timeout: ngtcp2_duration,
    pub preferred_versions: *const u32,
    pub preferred_versionslen: usize,
    pub available_versions: *const u32,
    pub available_versionslen: usize,
    pub original_version: u32,
    pub no_pmtud: u8,
    pub initial_pkt_num: u32,
    pub pmtud_probes: *const u16,
    pub pmtud_probeslen: usize,
    pub glitch_ratelim_burst: u64,
    pub glitch_ratelim_rate: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngtcp2_conn_info {
    pub latest_rtt: ngtcp2_duration,
    pub min_rtt: ngtcp2_duration,
    pub smoothed_rtt: ngtcp2_duration,
    pub rttvar: ngtcp2_duration,
    pub cwnd: u64,
    pub ssthresh: u64,
    pub bytes_in_flight: u64,
    pub pkt_sent: u64,
    pub bytes_sent: u64,
    pub pkt_recv: u64,
    pub bytes_recv: u64,
    pub pkt_lost: u64,
    pub bytes_lost: u64,
    pub ping_recv: u64,
    pub pkt_discarded: u64,
}

impl Default for ngtcp2_conn_info {
    fn default() -> Self {
        // SAFETY: all-zero is a valid bit pattern for this plain-data struct.
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
pub struct ngtcp2_ccerr {
    pub type_: ngtcp2_ccerr_type,
    pub error_code: u64,
    pub frame_type: u64,
    pub reason: *const u8,
    pub reasonlen: usize,
}

#[repr(C)]
pub struct ngtcp2_pkt_hd {
    pub dcid: ngtcp2_cid,
    pub scid: ngtcp2_cid,
    pub pkt_num: i64,
    pub token: *const u8,
    pub tokenlen: usize,
    pub pkt_numlen: usize,
    pub len: usize,
    pub version: u32,
    pub type_: u8,
    pub flags: u8,
}

#[repr(C)]
pub struct ngtcp2_version_cid {
    pub version: u32,
    pub dcid: *const u8,
    pub dcidlen: usize,
    pub scid: *const u8,
    pub scidlen: usize,
}

// ── Callback typedefs (ngtcp2_callbacks fields) ────────────────────────────

pub type ngtcp2_client_initial =
    Option<unsafe extern "C" fn(conn: *mut ngtcp2_conn, user_data: *mut c_void) -> c_int>;
pub type ngtcp2_recv_client_initial = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, dcid: *const ngtcp2_cid, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_recv_crypto_data = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        encryption_level: ngtcp2_encryption_level,
        offset: u64,
        data: *const u8,
        datalen: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_handshake_completed =
    Option<unsafe extern "C" fn(conn: *mut ngtcp2_conn, user_data: *mut c_void) -> c_int>;
pub type ngtcp2_recv_version_negotiation = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        hd: *const ngtcp2_pkt_hd,
        sv: *const u32,
        nsv: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_encrypt = Option<
    unsafe extern "C" fn(
        dest: *mut u8,
        aead: *const ngtcp2_crypto_aead,
        aead_ctx: *const ngtcp2_crypto_aead_ctx,
        plaintext: *const u8,
        plaintextlen: usize,
        nonce: *const u8,
        noncelen: usize,
        aad: *const u8,
        aadlen: usize,
    ) -> c_int,
>;
pub type ngtcp2_decrypt = Option<
    unsafe extern "C" fn(
        dest: *mut u8,
        aead: *const ngtcp2_crypto_aead,
        aead_ctx: *const ngtcp2_crypto_aead_ctx,
        ciphertext: *const u8,
        ciphertextlen: usize,
        nonce: *const u8,
        noncelen: usize,
        aad: *const u8,
        aadlen: usize,
    ) -> c_int,
>;
pub type ngtcp2_hp_mask = Option<
    unsafe extern "C" fn(
        dest: *mut u8,
        hp: *const ngtcp2_crypto_cipher,
        hp_ctx: *const ngtcp2_crypto_cipher_ctx,
        sample: *const u8,
    ) -> c_int,
>;
pub type ngtcp2_recv_stream_data = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        flags: u32,
        stream_id: i64,
        offset: u64,
        data: *const u8,
        datalen: usize,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_acked_stream_data_offset = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        stream_id: i64,
        offset: u64,
        datalen: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_stream_open = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, stream_id: i64, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_stream_close = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        flags: u32,
        stream_id: i64,
        app_error_code: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_recv_stateless_reset = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, sr: *const c_void, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_recv_retry = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, hd: *const ngtcp2_pkt_hd, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_extend_max_streams = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, max_streams: u64, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_rand = Option<
    unsafe extern "C" fn(dest: *mut u8, destlen: usize, rand_ctx: *const ngtcp2_rand_ctx),
>;
pub type ngtcp2_get_new_connection_id = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        cid: *mut ngtcp2_cid,
        token: *mut u8,
        cidlen: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_remove_connection_id = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, cid: *const ngtcp2_cid, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_update_key = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        rx_secret: *mut u8,
        tx_secret: *mut u8,
        rx_aead_ctx: *mut ngtcp2_crypto_aead_ctx,
        rx_iv: *mut u8,
        tx_aead_ctx: *mut ngtcp2_crypto_aead_ctx,
        tx_iv: *mut u8,
        current_rx_secret: *const u8,
        current_tx_secret: *const u8,
        secretlen: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_path_validation = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        flags: u32,
        path: *const ngtcp2_path,
        old_path: *const ngtcp2_path,
        res: c_int,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_select_preferred_addr = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        dest: *mut ngtcp2_path,
        paddr: *const ngtcp2_preferred_addr,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_stream_reset = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        stream_id: i64,
        final_size: u64,
        app_error_code: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_extend_max_stream_data = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        stream_id: i64,
        max_data: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_connection_id_status = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        type_: c_int,
        seq: u64,
        cid: *const ngtcp2_cid,
        token: *const u8,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_handshake_confirmed =
    Option<unsafe extern "C" fn(conn: *mut ngtcp2_conn, user_data: *mut c_void) -> c_int>;
pub type ngtcp2_recv_new_token = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, token: *const u8, tokenlen: usize, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_delete_crypto_aead_ctx = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, aead_ctx: *mut ngtcp2_crypto_aead_ctx, user_data: *mut c_void),
>;
pub type ngtcp2_delete_crypto_cipher_ctx = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, cipher_ctx: *mut ngtcp2_crypto_cipher_ctx, user_data: *mut c_void),
>;
pub type ngtcp2_recv_datagram = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        flags: u32,
        data: *const u8,
        datalen: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_ack_datagram = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, dgram_id: u64, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_lost_datagram = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, dgram_id: u64, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_get_path_challenge_data = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, data: *mut u8, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_stream_stop_sending = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        stream_id: i64,
        app_error_code: u64,
        user_data: *mut c_void,
        stream_user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_version_negotiation = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        version: u32,
        client_dcid: *const ngtcp2_cid,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_recv_key = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, level: ngtcp2_encryption_level, user_data: *mut c_void) -> c_int,
>;
pub type ngtcp2_tls_early_data_rejected =
    Option<unsafe extern "C" fn(conn: *mut ngtcp2_conn, user_data: *mut c_void) -> c_int>;
pub type ngtcp2_begin_path_validation = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        flags: u32,
        path: *const ngtcp2_path,
        fallback_path: *const ngtcp2_path,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_recv_stateless_reset2 = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        path: *const ngtcp2_path,
        sr: *const c_void,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_get_new_connection_id2 = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        cid: *mut ngtcp2_cid,
        token: *mut u8,
        cidlen: usize,
        tokenlen: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_connection_id_status2 = Option<
    unsafe extern "C" fn(
        conn: *mut ngtcp2_conn,
        type_: c_int,
        seq: u64,
        cid: *const ngtcp2_cid,
        token: *const u8,
        tokenlen: usize,
        user_data: *mut c_void,
    ) -> c_int,
>;
pub type ngtcp2_get_path_challenge_data2 = Option<
    unsafe extern "C" fn(conn: *mut ngtcp2_conn, data: *mut u8, datalen: usize, user_data: *mut c_void) -> c_int,
>;

/// `ngtcp2_callbacks` (NGTCP2_CALLBACKS_V3): field order matches ngtcp2.h
/// v1.22.1 exactly.
#[repr(C)]
#[derive(Default)]
pub struct ngtcp2_callbacks {
    pub client_initial: ngtcp2_client_initial,
    pub recv_client_initial: ngtcp2_recv_client_initial,
    pub recv_crypto_data: ngtcp2_recv_crypto_data,
    pub handshake_completed: ngtcp2_handshake_completed,
    pub recv_version_negotiation: ngtcp2_recv_version_negotiation,
    pub encrypt: ngtcp2_encrypt,
    pub decrypt: ngtcp2_decrypt,
    pub hp_mask: ngtcp2_hp_mask,
    pub recv_stream_data: ngtcp2_recv_stream_data,
    pub acked_stream_data_offset: ngtcp2_acked_stream_data_offset,
    pub stream_open: ngtcp2_stream_open,
    pub stream_close: ngtcp2_stream_close,
    pub recv_stateless_reset: ngtcp2_recv_stateless_reset,
    pub recv_retry: ngtcp2_recv_retry,
    pub extend_max_local_streams_bidi: ngtcp2_extend_max_streams,
    pub extend_max_local_streams_uni: ngtcp2_extend_max_streams,
    pub rand: ngtcp2_rand,
    pub get_new_connection_id: ngtcp2_get_new_connection_id,
    pub remove_connection_id: ngtcp2_remove_connection_id,
    pub update_key: ngtcp2_update_key,
    pub path_validation: ngtcp2_path_validation,
    pub select_preferred_addr: ngtcp2_select_preferred_addr,
    pub stream_reset: ngtcp2_stream_reset,
    pub extend_max_remote_streams_bidi: ngtcp2_extend_max_streams,
    pub extend_max_remote_streams_uni: ngtcp2_extend_max_streams,
    pub extend_max_stream_data: ngtcp2_extend_max_stream_data,
    pub dcid_status: ngtcp2_connection_id_status,
    pub handshake_confirmed: ngtcp2_handshake_confirmed,
    pub recv_new_token: ngtcp2_recv_new_token,
    pub delete_crypto_aead_ctx: ngtcp2_delete_crypto_aead_ctx,
    pub delete_crypto_cipher_ctx: ngtcp2_delete_crypto_cipher_ctx,
    pub recv_datagram: ngtcp2_recv_datagram,
    pub ack_datagram: ngtcp2_ack_datagram,
    pub lost_datagram: ngtcp2_lost_datagram,
    pub get_path_challenge_data: ngtcp2_get_path_challenge_data,
    pub stream_stop_sending: ngtcp2_stream_stop_sending,
    pub version_negotiation: ngtcp2_version_negotiation,
    pub recv_rx_key: ngtcp2_recv_key,
    pub recv_tx_key: ngtcp2_recv_key,
    pub tls_early_data_rejected: ngtcp2_tls_early_data_rejected,
    pub begin_path_validation: ngtcp2_begin_path_validation,
    pub recv_stateless_reset2: ngtcp2_recv_stateless_reset2,
    pub get_new_connection_id2: ngtcp2_get_new_connection_id2,
    pub dcid_status2: ngtcp2_connection_id_status2,
    pub get_path_challenge_data2: ngtcp2_get_path_challenge_data2,
}

// ── ngtcp2_crypto: TLS glue (generic + BoringSSL backend) ──────────────────

pub type ngtcp2_crypto_get_conn =
    Option<unsafe extern "C" fn(conn_ref: *mut ngtcp2_crypto_conn_ref) -> *mut ngtcp2_conn>;

/// Stored as the SSL's app data so the BoringSSL QUIC method callbacks can
/// find the owning `ngtcp2_conn`.
#[repr(C)]
pub struct ngtcp2_crypto_conn_ref {
    pub get_conn: ngtcp2_crypto_get_conn,
    pub user_data: *mut c_void,
}

unsafe extern "C" {
    /// Returns the library's static version info, or NULL if the linked
    /// library is older than `least_version` (pass 0 to always succeed).
    pub safe fn ngtcp2_version(least_version: c_int) -> *const ngtcp2_info;

    pub fn ngtcp2_strerror(liberr: c_int) -> *const c_char;
    pub fn ngtcp2_err_is_fatal(liberr: c_int) -> c_int;

    pub fn ngtcp2_settings_default_versioned(settings_version: c_int, settings: *mut ngtcp2_settings);
    pub fn ngtcp2_transport_params_default_versioned(
        transport_params_version: c_int,
        params: *mut ngtcp2_transport_params,
    );
    pub fn ngtcp2_ccerr_default(ccerr: *mut ngtcp2_ccerr);
    pub fn ngtcp2_ccerr_set_application_error(
        ccerr: *mut ngtcp2_ccerr,
        error_code: u64,
        reason: *const u8,
        reasonlen: usize,
    );
    pub fn ngtcp2_ccerr_set_liberr(
        ccerr: *mut ngtcp2_ccerr,
        liberr: c_int,
        reason: *const u8,
        reasonlen: usize,
    );
    pub fn ngtcp2_ccerr_set_tls_alert(
        ccerr: *mut ngtcp2_ccerr,
        tls_alert: u8,
        reason: *const u8,
        reasonlen: usize,
    );
    pub fn ngtcp2_conn_get_tls_alert(conn: *mut ngtcp2_conn) -> u8;

    pub fn ngtcp2_pkt_decode_version_cid(dest: *mut ngtcp2_version_cid, data: *const u8, datalen: usize, short_dcidlen: usize) -> c_int;
    pub fn ngtcp2_accept(dest: *mut ngtcp2_pkt_hd, pkt: *const u8, pktlen: usize) -> c_int;

    pub fn ngtcp2_conn_client_new_versioned(
        pconn: *mut *mut ngtcp2_conn,
        dcid: *const ngtcp2_cid,
        scid: *const ngtcp2_cid,
        path: *const ngtcp2_path,
        client_chosen_version: u32,
        callbacks_version: c_int,
        callbacks: *const ngtcp2_callbacks,
        settings_version: c_int,
        settings: *const ngtcp2_settings,
        transport_params_version: c_int,
        params: *const ngtcp2_transport_params,
        mem: *const ngtcp2_mem,
        user_data: *mut c_void,
    ) -> c_int;

    pub fn ngtcp2_conn_server_new_versioned(
        pconn: *mut *mut ngtcp2_conn,
        dcid: *const ngtcp2_cid,
        scid: *const ngtcp2_cid,
        path: *const ngtcp2_path,
        client_chosen_version: u32,
        callbacks_version: c_int,
        callbacks: *const ngtcp2_callbacks,
        settings_version: c_int,
        settings: *const ngtcp2_settings,
        transport_params_version: c_int,
        params: *const ngtcp2_transport_params,
        mem: *const ngtcp2_mem,
        user_data: *mut c_void,
    ) -> c_int;

    pub fn ngtcp2_conn_del(conn: *mut ngtcp2_conn);

    pub fn ngtcp2_conn_read_pkt_versioned(
        conn: *mut ngtcp2_conn,
        path: *const ngtcp2_path,
        pkt_info_version: c_int,
        pi: *const ngtcp2_pkt_info,
        pkt: *const u8,
        pktlen: usize,
        ts: ngtcp2_tstamp,
    ) -> c_int;

    pub fn ngtcp2_conn_writev_stream_versioned(
        conn: *mut ngtcp2_conn,
        path: *mut ngtcp2_path,
        pkt_info_version: c_int,
        pi: *mut ngtcp2_pkt_info,
        dest: *mut u8,
        destlen: usize,
        pdatalen: *mut ngtcp2_ssize,
        flags: u32,
        stream_id: i64,
        datav: *const ngtcp2_vec,
        datavcnt: usize,
        ts: ngtcp2_tstamp,
    ) -> ngtcp2_ssize;

    pub fn ngtcp2_conn_write_connection_close_versioned(
        conn: *mut ngtcp2_conn,
        path: *mut ngtcp2_path,
        pkt_info_version: c_int,
        pi: *mut ngtcp2_pkt_info,
        dest: *mut u8,
        destlen: usize,
        ccerr: *const ngtcp2_ccerr,
        ts: ngtcp2_tstamp,
    ) -> ngtcp2_ssize;

    pub fn ngtcp2_conn_get_ccerr(conn: *mut ngtcp2_conn) -> *const ngtcp2_ccerr;
    pub fn ngtcp2_conn_get_expiry(conn: *mut ngtcp2_conn) -> ngtcp2_tstamp;
    pub fn ngtcp2_conn_handle_expiry(conn: *mut ngtcp2_conn, ts: ngtcp2_tstamp) -> c_int;
    pub fn ngtcp2_conn_get_handshake_completed(conn: *mut ngtcp2_conn) -> c_int;
    pub fn ngtcp2_conn_get_negotiated_version(conn: *mut ngtcp2_conn) -> u32;
    pub fn ngtcp2_conn_get_max_tx_udp_payload_size(conn: *mut ngtcp2_conn) -> usize;
    pub fn ngtcp2_conn_get_path(conn: *mut ngtcp2_conn) -> *const ngtcp2_path;
    pub fn ngtcp2_conn_in_closing_period(conn: *mut ngtcp2_conn) -> c_int;
    pub fn ngtcp2_conn_in_draining_period(conn: *mut ngtcp2_conn) -> c_int;
    pub fn ngtcp2_conn_get_conn_info_versioned(conn: *mut ngtcp2_conn, conn_info_version: c_int, cinfo: *mut ngtcp2_conn_info);
    pub fn ngtcp2_conn_get_remote_transport_params(conn: *mut ngtcp2_conn) -> *const ngtcp2_transport_params;
    pub fn ngtcp2_conn_get_local_transport_params(conn: *mut ngtcp2_conn) -> *const ngtcp2_transport_params;
    pub fn ngtcp2_conn_get_dcid(conn: *mut ngtcp2_conn) -> *const ngtcp2_cid;
    pub fn ngtcp2_conn_get_client_initial_dcid(conn: *mut ngtcp2_conn) -> *const ngtcp2_cid;
    pub fn ngtcp2_conn_get_scid(conn: *mut ngtcp2_conn, dest: *mut ngtcp2_cid) -> usize;

    // ── ngtcp2_crypto (generic helpers, libngtcp2_crypto_boringssl) ────────
    pub fn ngtcp2_crypto_client_initial_cb(conn: *mut ngtcp2_conn, user_data: *mut c_void) -> c_int;
    pub fn ngtcp2_crypto_recv_client_initial_cb(conn: *mut ngtcp2_conn, dcid: *const ngtcp2_cid, user_data: *mut c_void) -> c_int;
    pub fn ngtcp2_crypto_recv_crypto_data_cb(
        conn: *mut ngtcp2_conn,
        encryption_level: ngtcp2_encryption_level,
        offset: u64,
        data: *const u8,
        datalen: usize,
        user_data: *mut c_void,
    ) -> c_int;
    pub fn ngtcp2_crypto_encrypt_cb(
        dest: *mut u8,
        aead: *const ngtcp2_crypto_aead,
        aead_ctx: *const ngtcp2_crypto_aead_ctx,
        plaintext: *const u8,
        plaintextlen: usize,
        nonce: *const u8,
        noncelen: usize,
        aad: *const u8,
        aadlen: usize,
    ) -> c_int;
    pub fn ngtcp2_crypto_decrypt_cb(
        dest: *mut u8,
        aead: *const ngtcp2_crypto_aead,
        aead_ctx: *const ngtcp2_crypto_aead_ctx,
        ciphertext: *const u8,
        ciphertextlen: usize,
        nonce: *const u8,
        noncelen: usize,
        aad: *const u8,
        aadlen: usize,
    ) -> c_int;
    pub fn ngtcp2_crypto_hp_mask_cb(
        dest: *mut u8,
        hp: *const ngtcp2_crypto_cipher,
        hp_ctx: *const ngtcp2_crypto_cipher_ctx,
        sample: *const u8,
    ) -> c_int;
    pub fn ngtcp2_crypto_recv_retry_cb(conn: *mut ngtcp2_conn, hd: *const ngtcp2_pkt_hd, user_data: *mut c_void) -> c_int;
    pub fn ngtcp2_crypto_update_key_cb(
        conn: *mut ngtcp2_conn,
        rx_secret: *mut u8,
        tx_secret: *mut u8,
        rx_aead_ctx: *mut ngtcp2_crypto_aead_ctx,
        rx_iv: *mut u8,
        tx_aead_ctx: *mut ngtcp2_crypto_aead_ctx,
        tx_iv: *mut u8,
        current_rx_secret: *const u8,
        current_tx_secret: *const u8,
        secretlen: usize,
        user_data: *mut c_void,
    ) -> c_int;
    pub fn ngtcp2_crypto_delete_crypto_aead_ctx_cb(conn: *mut ngtcp2_conn, aead_ctx: *mut ngtcp2_crypto_aead_ctx, user_data: *mut c_void);
    pub fn ngtcp2_crypto_delete_crypto_cipher_ctx_cb(conn: *mut ngtcp2_conn, cipher_ctx: *mut ngtcp2_crypto_cipher_ctx, user_data: *mut c_void);
    pub fn ngtcp2_crypto_get_path_challenge_data_cb(conn: *mut ngtcp2_conn, data: *mut u8, user_data: *mut c_void) -> c_int;
    pub fn ngtcp2_crypto_version_negotiation_cb(
        conn: *mut ngtcp2_conn,
        version: u32,
        client_dcid: *const ngtcp2_cid,
        user_data: *mut c_void,
    ) -> c_int;

    pub fn ngtcp2_conn_set_tls_native_handle(conn: *mut ngtcp2_conn, tls_native_handle: *mut c_void);

    // BoringSSL backend.
    pub fn ngtcp2_crypto_boringssl_configure_client_context(ssl_ctx: *mut c_void) -> c_int;
    pub fn ngtcp2_crypto_boringssl_configure_server_context(ssl_ctx: *mut c_void) -> c_int;
}

/// Convenience wrappers over the `*_versioned` entry points (the C macros are
/// not exported symbols).
#[inline]
pub unsafe fn ngtcp2_settings_default(settings: *mut ngtcp2_settings) {
    unsafe { ngtcp2_settings_default_versioned(NGTCP2_SETTINGS_VERSION, settings) }
}

#[inline]
pub unsafe fn ngtcp2_transport_params_default(params: *mut ngtcp2_transport_params) {
    unsafe { ngtcp2_transport_params_default_versioned(NGTCP2_TRANSPORT_PARAMS_VERSION, params) }
}

/// Validate the hand-transcribed layouts against values the library writes.
/// Debug builds only; called once from the node:quic binding setup.
pub fn debug_assert_layout() {
    if cfg!(debug_assertions) {
        let mut settings = core::mem::MaybeUninit::<ngtcp2_settings>::zeroed();
        // SAFETY: `settings` points to writable memory of the right size; the
        // default initializer fills every field.
        let settings = unsafe {
            ngtcp2_settings_default(settings.as_mut_ptr());
            settings.assume_init()
        };
        // Documented defaults (ngtcp2_settings_default): cc_algo = cubic,
        // initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT (333ms),
        // max_tx_udp_payload_size = 1452, handshake_timeout = UINT64_MAX,
        // ack_thresh = 2.
        debug_assert_eq!(settings.cc_algo, NGTCP2_CC_ALGO_CUBIC, "ngtcp2_settings layout drift (cc_algo)");
        debug_assert_eq!(settings.initial_rtt, 333 * NGTCP2_MILLISECONDS, "ngtcp2_settings layout drift (initial_rtt)");
        debug_assert_eq!(settings.max_tx_udp_payload_size, 1452, "ngtcp2_settings layout drift (max_tx_udp_payload_size)");
        debug_assert_eq!(settings.handshake_timeout, u64::MAX, "ngtcp2_settings layout drift (handshake_timeout)");
        debug_assert_eq!(settings.ack_thresh, 2, "ngtcp2_settings layout drift (ack_thresh)");

        let mut params = core::mem::MaybeUninit::<ngtcp2_transport_params>::zeroed();
        // SAFETY: as above.
        let params = unsafe {
            ngtcp2_transport_params_default(params.as_mut_ptr());
            params.assume_init()
        };
        // Documented defaults: max_udp_payload_size = 65527,
        // ack_delay_exponent = 3, max_ack_delay = 25ms,
        // active_connection_id_limit = 2.
        debug_assert_eq!(params.max_udp_payload_size, 65527, "ngtcp2_transport_params layout drift (max_udp_payload_size)");
        debug_assert_eq!(params.ack_delay_exponent, 3, "ngtcp2_transport_params layout drift (ack_delay_exponent)");
        debug_assert_eq!(params.max_ack_delay, 25 * NGTCP2_MILLISECONDS, "ngtcp2_transport_params layout drift (max_ack_delay)");
        debug_assert_eq!(params.active_connection_id_limit, 2, "ngtcp2_transport_params layout drift (active_connection_id_limit)");
    }
}
