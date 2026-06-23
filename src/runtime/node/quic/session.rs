//! `QuicSession` native handle (Node reference: node/src/quic/session.{h,cc}).
//!
//! A session owns one `ngtcp2_conn` plus its TLS state and is driven entirely
//! from the JS thread: the endpoint feeds it received UDP datagrams, methods
//! called from JS feed it commands, and after every input it runs the ngtcp2
//! write loop to push produced packets back out through the endpoint's UDP
//! socket. ngtcp2's C callbacks never call into JS — JS-visible events
//! (handshake completion, close) are detected by polling connection state
//! after each input, on the JS thread, with the global in hand.

use core::cell::Cell;
use core::ffi::{c_int, c_void};
use core::ptr::{null, null_mut};
use std::collections::HashMap;

use bun_boringssl_sys as ssl;
use bun_jsc::{CallFrame, JSGlobalObject, JSValue, JsCell, JsRef, JsResult, Strong, StringJsc};
use bun_ngtcp2_sys as ngtcp2;

use crate::jsc_hooks::timer_all_mut as timer_all;
use crate::socket::SocketAddress;
use crate::socket::socket_address::inet;
use crate::timer::{EventLoopTimer, EventLoopTimerState, EventLoopTimerTag};

use super::callbacks;
use super::endpoint::QuicEndpoint;
use super::now_ns;
use super::stream::QuicStream;
use super::tls::{TlsConfig, TlsSession};

bun_core::declare_scope!(quic_session, hidden);

/// Stream activity recorded by the ngtcp2 callbacks during packet processing
/// (which must not call into JS) and dispatched afterwards on the JS thread.
enum StreamEvent {
    /// The peer opened a new stream.
    Opened(i64),
    /// Stream data (possibly empty) and/or the FIN flag arrived.
    Data { id: i64, bytes: Vec<u8>, fin: bool },
    /// The stream closed (all data exchanged or an application error).
    Closed { id: i64, code: u64, errored: bool },
    /// The peer abruptly reset its sending side.
    Reset { id: i64, code: u64 },
    /// More stream-level flow-control credit became available.
    Drain(i64),
    /// The stream is blocked on stream-level flow control.
    Blocked(i64),
}

/// Mirrors Node's `Session::State` (`SESSION_STATE` in node/src/quic/session.cc).
/// `IDX_STATE_SESSION_*` binding constants are `offset_of!` values into this.
#[repr(C)]
pub struct SessionState {
    pub listener_flags: u32,
    pub closing: u8,
    pub graceful_close: u8,
    pub silent_close: u8,
    pub stateless_reset: u8,
    pub handshake_completed: u8,
    pub handshake_confirmed: u8,
    pub stream_open_allowed: u8,
    pub priority_supported: u8,
    pub headers_supported: u8,
    pub wrapped: u8,
    pub application_type: u8,
    pub no_error_code: u64,
    pub internal_error_code: u64,
    pub max_datagram_size: u16,
    pub last_datagram_id: u64,
    pub max_pending_datagrams: u16,
}

/// Node's `SESSION_STATS` field names, in declaration order.
pub(crate) const SESSION_STATS_FIELDS: &[&str] = &[
    "CREATED_AT",
    "DESTROYED_AT",
    "CLOSING_AT",
    "HANDSHAKE_COMPLETED_AT",
    "HANDSHAKE_CONFIRMED_AT",
    "BYTES_RECEIVED",
    "BIDI_IN_STREAM_COUNT",
    "BIDI_OUT_STREAM_COUNT",
    "UNI_IN_STREAM_COUNT",
    "UNI_OUT_STREAM_COUNT",
    "MAX_BYTES_IN_FLIGHT",
    "BYTES_IN_FLIGHT",
    "BLOCK_COUNT",
    "CWND",
    "LATEST_RTT",
    "MIN_RTT",
    "RTTVAR",
    "SMOOTHED_RTT",
    "SSTHRESH",
    "PKT_SENT",
    "BYTES_SENT",
    "PKT_RECV",
    "BYTES_RECV",
    "PKT_LOST",
    "BYTES_LOST",
    "PING_RECV",
    "PKT_DISCARDED",
    "DATAGRAMS_RECEIVED",
    "DATAGRAMS_SENT",
    "DATAGRAMS_ACKNOWLEDGED",
    "DATAGRAMS_LOST",
    "STREAMS_IDLE_TIMED_OUT",
];

const IDX_STATS_CREATED_AT: usize = 0;
const IDX_STATS_DESTROYED_AT: usize = 1;
const IDX_STATS_CLOSING_AT: usize = 2;
const IDX_STATS_HANDSHAKE_COMPLETED_AT: usize = 3;
const IDX_STATS_BYTES_RECEIVED: usize = 5;
const IDX_STATS_MAX_BYTES_IN_FLIGHT: usize = 10;
const IDX_STATS_BYTES_IN_FLIGHT: usize = 11;
const IDX_STATS_CWND: usize = 13;
const IDX_STATS_LATEST_RTT: usize = 14;
const IDX_STATS_MIN_RTT: usize = 15;
const IDX_STATS_RTTVAR: usize = 16;
const IDX_STATS_SMOOTHED_RTT: usize = 17;
const IDX_STATS_SSTHRESH: usize = 18;
const IDX_STATS_PKT_SENT: usize = 19;
const IDX_STATS_BYTES_SENT: usize = 20;
const IDX_STATS_PKT_RECV: usize = 21;

/// Our connection IDs are always this long (same as Node's `kCidLen`).
const LOCAL_CID_LEN: usize = 16;
/// Largest UDP payload we ever produce (settings.max_tx_udp_payload_size
/// defaults to 1452 in ngtcp2; allocate a round 1500 to be safe).
const MAX_SEND_PACKET: usize = 1500;

/// A self-contained copy of a socket address (sockaddr_in or sockaddr_in6).
#[derive(Copy, Clone)]
pub(super) struct StoredAddr {
    bytes: [u8; 28],
    len: u32,
}

impl Default for StoredAddr {
    fn default() -> Self {
        StoredAddr { bytes: [0; 28], len: 0 }
    }
}

impl StoredAddr {
    /// Copy from any sockaddr-shaped memory (`len` bytes at `ptr`).
    ///
    /// # Safety
    /// `ptr` must point to at least `len` readable bytes.
    pub(super) unsafe fn from_raw(ptr: *const u8, len: usize) -> StoredAddr {
        let mut out = StoredAddr::default();
        let len = len.min(out.bytes.len());
        // SAFETY: per contract, `ptr` is readable for `len` bytes.
        unsafe { core::ptr::copy_nonoverlapping(ptr, out.bytes.as_mut_ptr(), len) };
        out.len = len as u32;
        out
    }

    pub(super) fn from_socket_address(addr: &SocketAddress) -> StoredAddr {
        // SAFETY: `_addr` is `socklen()` bytes of valid sockaddr data.
        unsafe {
            StoredAddr::from_raw(
                core::ptr::from_ref(&addr._addr).cast::<u8>(),
                addr.socklen() as usize,
            )
        }
    }

    pub(super) fn is_set(&self) -> bool {
        self.len != 0
    }

    pub(super) fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }

    fn ngtcp2_addr(&self) -> ngtcp2::ngtcp2_addr {
        ngtcp2::ngtcp2_addr {
            addr: self.bytes.as_ptr().cast_mut().cast(),
            addrlen: self.len,
        }
    }

    /// Family/port/address triple decoded from the raw sockaddr bytes.
    fn decode(&self) -> Option<(u16, u16, &[u8])> {
        if self.len < 8 {
            return None;
        }
        let family = u16::from_ne_bytes([self.bytes[0], self.bytes[1]]);
        let port = u16::from_be_bytes([self.bytes[2], self.bytes[3]]);
        if family == inet::AF_INET as u16 {
            Some((family, port, &self.bytes[4..8]))
        } else if family == inet::AF_INET6 as u16 && self.len >= 24 {
            Some((family, port, &self.bytes[8..24]))
        } else {
            None
        }
    }

    /// Build a `net.SocketAddress` JS object for this address.
    pub(super) fn to_js_socket_address(&self, global: &JSGlobalObject) -> JSValue {
        let Some((family, port, addr)) = self.decode() else {
            return JSValue::UNDEFINED;
        };
        let socket_address = if family == inet::AF_INET as u16 {
            SocketAddress::init_ipv4([addr[0], addr[1], addr[2], addr[3]], port)
        } else {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(addr);
            SocketAddress::init_ipv6(ip, port, 0, 0)
        };
        crate::generated_classes::js_SocketAddress::to_js(
            bun_core::heap::into_raw(Box::new(socket_address)),
            global,
        )
    }
}

/// `ngtcp2_crypto_conn_ref::get_conn` — the BoringSSL QUIC method callbacks
/// resolve the owning connection through the SSL's app data slot.
unsafe extern "C" fn get_conn_from_ref(
    conn_ref: *mut ngtcp2::ngtcp2_crypto_conn_ref,
) -> *mut ngtcp2::ngtcp2_conn {
    if conn_ref.is_null() {
        return null_mut();
    }
    // SAFETY: `user_data` is the owning QuicSession, alive for as long as its
    // SSL (and therefore this callback) is.
    let session = unsafe { (*conn_ref).user_data.cast::<QuicSession>() };
    if session.is_null() {
        return null_mut();
    }
    // SAFETY: as above.
    unsafe { (*session).conn.get() }
}

/// `ngtcp2_callbacks.rand`.
unsafe extern "C" fn rand_cb(dest: *mut u8, destlen: usize, _rand_ctx: *const ngtcp2::ngtcp2_rand_ctx) {
    if dest.is_null() || destlen == 0 {
        return;
    }
    // SAFETY: ngtcp2 hands us a writable buffer of `destlen` bytes.
    unsafe { ssl::RAND_bytes(dest, destlen) };
}

/// `ngtcp2_callbacks.get_new_connection_id`.
unsafe extern "C" fn get_new_connection_id_cb(
    _conn: *mut ngtcp2::ngtcp2_conn,
    cid: *mut ngtcp2::ngtcp2_cid,
    token: *mut u8,
    cidlen: usize,
    _user_data: *mut c_void,
) -> c_int {
    // SAFETY: ngtcp2 provides a cid out-param and a token buffer of
    // NGTCP2_STATELESS_RESET_TOKENLEN bytes.
    unsafe {
        let cidlen = cidlen.min(ngtcp2::NGTCP2_MAX_CIDLEN);
        if ssl::RAND_bytes((*cid).data.as_mut_ptr(), cidlen) != 1 {
            return -1;
        }
        (*cid).datalen = cidlen;
        if !token.is_null() && ssl::RAND_bytes(token, ngtcp2::NGTCP2_STATELESS_RESET_TOKENLEN) != 1 {
            return -1;
        }
    }
    0
}

/// Push one stream event onto the owning session's queue. Never calls JS —
/// these run inside ngtcp2 packet processing.
fn push_stream_event(user_data: *mut c_void, event: StreamEvent) {
    if user_data.is_null() {
        return;
    }
    // SAFETY: `user_data` is the owning QuicSession (set at conn creation),
    // alive for as long as the conn is.
    let session = unsafe { &*user_data.cast::<QuicSession>() };
    session.stream_events.with_mut(|events| events.push(event));
}

unsafe extern "C" fn stream_open_cb(
    _conn: *mut ngtcp2::ngtcp2_conn,
    stream_id: i64,
    user_data: *mut c_void,
) -> c_int {
    push_stream_event(user_data, StreamEvent::Opened(stream_id));
    0
}

unsafe extern "C" fn recv_stream_data_cb(
    conn: *mut ngtcp2::ngtcp2_conn,
    flags: u32,
    stream_id: i64,
    _offset: u64,
    data: *const u8,
    datalen: usize,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let bytes = if data.is_null() || datalen == 0 {
        Vec::new()
    } else {
        // SAFETY: ngtcp2 hands us `datalen` readable bytes valid only for the
        // duration of this callback; copy what we keep.
        unsafe { core::slice::from_raw_parts(data, datalen) }.to_vec()
    };
    let fin = flags & ngtcp2::NGTCP2_STREAM_DATA_FLAG_FIN != 0;
    push_stream_event(user_data, StreamEvent::Data { id: stream_id, bytes, fin });
    // Connection-level flow control credit is returned immediately; the
    // stream-level credit is granted as the JS reader consumes the data.
    if datalen > 0 {
        // SAFETY: `conn` is the live connection this callback fires for.
        unsafe { ngtcp2::ngtcp2_conn_extend_max_offset(conn, datalen as u64) };
    }
    0
}

unsafe extern "C" fn stream_close_cb(
    _conn: *mut ngtcp2::ngtcp2_conn,
    flags: u32,
    stream_id: i64,
    app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    let errored = flags & ngtcp2::NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET != 0 && app_error_code != 0;
    push_stream_event(
        user_data,
        StreamEvent::Closed { id: stream_id, code: app_error_code, errored },
    );
    0
}

unsafe extern "C" fn stream_reset_cb(
    _conn: *mut ngtcp2::ngtcp2_conn,
    stream_id: i64,
    _final_size: u64,
    app_error_code: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    push_stream_event(user_data, StreamEvent::Reset { id: stream_id, code: app_error_code });
    0
}

unsafe extern "C" fn extend_max_stream_data_cb(
    _conn: *mut ngtcp2::ngtcp2_conn,
    stream_id: i64,
    _max_data: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    push_stream_event(user_data, StreamEvent::Drain(stream_id));
    0
}

unsafe extern "C" fn acked_stream_data_offset_cb(
    _conn: *mut ngtcp2::ngtcp2_conn,
    stream_id: i64,
    offset: u64,
    datalen: u64,
    user_data: *mut c_void,
    _stream_user_data: *mut c_void,
) -> c_int {
    if user_data.is_null() {
        return 0;
    }
    // SAFETY: `user_data` is the owning QuicSession; pure bookkeeping, no JS.
    let session = unsafe { &*user_data.cast::<QuicSession>() };
    if let Some(&stream) = session.streams.get().get(&stream_id) {
        // SAFETY: streams unregister themselves before teardown.
        unsafe { (*stream).on_acked(offset, datalen) };
    }
    0
}

fn build_callbacks(is_server: bool) -> ngtcp2::ngtcp2_callbacks {
    let mut cb = ngtcp2::ngtcp2_callbacks::default();
    if is_server {
        cb.recv_client_initial = Some(ngtcp2::ngtcp2_crypto_recv_client_initial_cb);
    } else {
        cb.client_initial = Some(ngtcp2::ngtcp2_crypto_client_initial_cb);
        cb.recv_retry = Some(ngtcp2::ngtcp2_crypto_recv_retry_cb);
    }
    cb.recv_crypto_data = Some(ngtcp2::ngtcp2_crypto_recv_crypto_data_cb);
    cb.encrypt = Some(ngtcp2::ngtcp2_crypto_encrypt_cb);
    cb.decrypt = Some(ngtcp2::ngtcp2_crypto_decrypt_cb);
    cb.hp_mask = Some(ngtcp2::ngtcp2_crypto_hp_mask_cb);
    cb.update_key = Some(ngtcp2::ngtcp2_crypto_update_key_cb);
    cb.delete_crypto_aead_ctx = Some(ngtcp2::ngtcp2_crypto_delete_crypto_aead_ctx_cb);
    cb.delete_crypto_cipher_ctx = Some(ngtcp2::ngtcp2_crypto_delete_crypto_cipher_ctx_cb);
    cb.get_path_challenge_data = Some(ngtcp2::ngtcp2_crypto_get_path_challenge_data_cb);
    cb.version_negotiation = Some(ngtcp2::ngtcp2_crypto_version_negotiation_cb);
    cb.rand = Some(rand_cb);
    cb.get_new_connection_id = Some(get_new_connection_id_cb);
    cb.stream_open = Some(stream_open_cb);
    cb.recv_stream_data = Some(recv_stream_data_cb);
    cb.stream_close = Some(stream_close_cb);
    cb.stream_reset = Some(stream_reset_cb);
    cb.extend_max_stream_data = Some(extend_max_stream_data_cb);
    cb.acked_stream_data_offset = Some(acked_stream_data_offset_cb);
    cb
}

fn random_cid(len: usize) -> ngtcp2::ngtcp2_cid {
    let mut cid = ngtcp2::ngtcp2_cid::default();
    let len = len.min(ngtcp2::NGTCP2_MAX_CIDLEN);
    // SAFETY: writing `len <= NGTCP2_MAX_CIDLEN` bytes into the cid buffer.
    unsafe { ssl::RAND_bytes(cid.data.as_mut_ptr(), len) };
    cid.datalen = len;
    cid
}

fn read_u64_option(global: &JSGlobalObject, options: JSValue, name: &str) -> JsResult<Option<u64>> {
    if !options.is_object() {
        return Ok(None);
    }
    let Some(value) = options.get(global, name)? else { return Ok(None) };
    if !value.is_number() {
        return Ok(None);
    }
    let n = value.as_number();
    if !n.is_finite() || n < 0.0 {
        return Ok(None);
    }
    Ok(Some(n as u64))
}

pub struct QuicSession {
    conn: Cell<*mut ngtcp2::ngtcp2_conn>,
    tls: JsCell<Option<TlsSession>>,
    /// Boxed so its address is stable; the SSL's app data points at it.
    conn_ref: JsCell<Option<Box<ngtcp2::ngtcp2_crypto_conn_ref>>>,
    /// The owning endpoint. Valid while `endpoint_js` keeps the endpoint's
    /// wrapper (and therefore its native struct) alive.
    endpoint: Cell<*mut QuicEndpoint>,
    endpoint_js: JsCell<Option<Strong>>,
    /// The session handle wrapper; strong while the connection is live.
    this_value: JsCell<JsRef>,
    /// Live views into the wrapper-owned `state`/`stats` ArrayBuffers.
    state: Cell<*mut SessionState>,
    stats: Cell<*mut u64>,
    local_addr: Cell<StoredAddr>,
    remote_addr: Cell<StoredAddr>,
    /// The CID(s) this session is registered under in the endpoint's routing
    /// map, so destroy can unregister them.
    registered_cids: JsCell<Vec<Vec<u8>>>,
    /// Live streams by stream id.
    streams: JsCell<HashMap<i64, *mut QuicStream>>,
    /// Stream activity queued by the ngtcp2 callbacks, dispatched to JS after
    /// the current packet/expiry processing finishes.
    stream_events: JsCell<Vec<StreamEvent>>,
    /// The realm this session was created in (JS-thread only; outlives the
    /// session).
    global: Cell<*const JSGlobalObject>,
    /// Drives ngtcp2's expiry (loss detection, idle/handshake timeouts).
    /// pub(crate): the timer-fire dispatch recovers the session via
    /// `from_field_ptr!`, which needs `offset_of!` visibility.
    pub(crate) event_loop_timer: JsCell<EventLoopTimer>,
    handshake_reported: Cell<bool>,
    close_reported: Cell<bool>,
    /// A JS-initiated close waiting to complete on the next timer fire.
    pending_close: Cell<bool>,
    destroyed: Cell<bool>,
}

bun_event_loop::impl_timer_owner!(QuicSession; from_timer_ptr => event_loop_timer);

impl QuicSession {
    fn state_mut(&self) -> *mut SessionState {
        self.state.get()
    }

    fn write_stat(&self, index: usize, value: u64) {
        let stats = self.stats.get();
        if stats.is_null() {
            return;
        }
        debug_assert!(index < SESSION_STATS_FIELDS.len());
        // SAFETY: in-bounds slot of the wrapper-owned stats buffer; unaligned
        // because ArrayBuffer contents only guarantee byte alignment.
        unsafe { stats.add(index).write_unaligned(value) };
    }

    fn read_stat(&self, index: usize) -> u64 {
        let stats = self.stats.get();
        if stats.is_null() {
            return 0;
        }
        // SAFETY: as in `write_stat`.
        unsafe { stats.add(index).read_unaligned() }
    }

    fn add_stat(&self, index: usize, delta: u64) {
        self.write_stat(index, self.read_stat(index).wrapping_add(delta));
    }

    fn handle(&self) -> JSValue {
        self.this_value.get().get()
    }

    /// Allocate the native struct + JS wrapper and attach the state/stats
    /// buffers. Returns the raw session pointer and its JS handle.
    fn create_shell(
        global: &JSGlobalObject,
        endpoint: *mut QuicEndpoint,
        endpoint_js: JSValue,
        local_addr: StoredAddr,
        remote_addr: StoredAddr,
    ) -> JsResult<(*mut QuicSession, JSValue)> {
        let session = QuicSession {
            conn: Cell::new(null_mut()),
            tls: JsCell::new(None),
            conn_ref: JsCell::new(None),
            endpoint: Cell::new(endpoint),
            endpoint_js: JsCell::new(Some(Strong::create(endpoint_js, global))),
            this_value: JsCell::new(JsRef::empty()),
            state: Cell::new(null_mut()),
            stats: Cell::new(null_mut()),
            local_addr: Cell::new(local_addr),
            remote_addr: Cell::new(remote_addr),
            registered_cids: JsCell::new(Vec::new()),
            streams: JsCell::new(HashMap::new()),
            stream_events: JsCell::new(Vec::new()),
            global: Cell::new(core::ptr::from_ref(global)),
            event_loop_timer: JsCell::new(EventLoopTimer::init_paused(EventLoopTimerTag::QuicSession)),
            handshake_reported: Cell::new(false),
            close_reported: Cell::new(false),
            pending_close: Cell::new(false),
            destroyed: Cell::new(false),
        };
        let raw = bun_core::heap::into_raw(Box::new(session));
        let handle = crate::generated_classes::js_QuicSession::to_js(raw, global);

        // Same shape as Node: `state`/`stats` (+ byte offsets) are own
        // properties of the handle; the JS layer constructs DataView /
        // BigUint64Array over them.
        let state_ptr = super::endpoint::alloc_exposed_array_buffer(
            global,
            handle,
            b"state",
            core::mem::size_of::<SessionState>(),
        )?;
        let stats_ptr = super::endpoint::alloc_exposed_array_buffer(
            global,
            handle,
            b"stats",
            SESSION_STATS_FIELDS.len() * core::mem::size_of::<u64>(),
        )?;
        handle.put(global, b"stateByteOffset", JSValue::js_number(0.0));
        handle.put(global, b"statsByteOffset", JSValue::js_number(0.0));

        // SAFETY: `raw` was just created and is uniquely owned by the wrapper.
        let this = unsafe { &*raw };
        this.state.set(state_ptr.cast::<SessionState>());
        this.stats.set(stats_ptr.cast::<u64>());
        this.write_stat(IDX_STATS_CREATED_AT, now_ns());
        this.this_value.with_mut(|r| r.set_strong(handle, global));
        // SAFETY: state buffer is zero-initialized and live.
        unsafe {
            (*this.state_mut()).max_datagram_size = 1200;
            (*this.state_mut()).max_pending_datagrams = 128;
        }

        Ok((raw, handle))
    }

    /// Apply settings/transport params from the processed session options.
    fn build_settings(
        global: &JSGlobalObject,
        options: JSValue,
        is_server: bool,
    ) -> JsResult<(ngtcp2::ngtcp2_settings, ngtcp2::ngtcp2_transport_params)> {
        let mut settings = core::mem::MaybeUninit::<ngtcp2::ngtcp2_settings>::zeroed();
        // SAFETY: default initializer fills every field.
        let mut settings = unsafe {
            ngtcp2::ngtcp2_settings_default(settings.as_mut_ptr());
            settings.assume_init()
        };
        settings.initial_ts = now_ns();
        // Node: settings.handshake_timeout defaults to 10s (DEFAULT_HANDSHAKE_TIMEOUT).
        settings.handshake_timeout = read_u64_option(global, options, "handshakeTimeout")?
            .map_or(10_000 * ngtcp2::NGTCP2_MILLISECONDS, |ms| ms * ngtcp2::NGTCP2_MILLISECONDS);
        if let Some(rtt) = read_u64_option(global, options, "initialRtt")? {
            settings.initial_rtt = rtt * ngtcp2::NGTCP2_MILLISECONDS;
        }
        if let Some(size) = read_u64_option(global, options, "maxPayloadSize")? {
            settings.max_tx_udp_payload_size = size as usize;
        }
        if let Some(window) = read_u64_option(global, options, "maxWindow")? {
            settings.max_window = window;
        }
        if let Some(window) = read_u64_option(global, options, "maxStreamWindow")? {
            settings.max_stream_window = window;
        }
        if options.is_object() {
            if let Some(cc) = options.get(global, "cc")?.filter(|v| v.is_string()) {
                let cc = bun_core::String::from_js(cc, global)?.to_utf8_bytes();
                settings.cc_algo = match cc.as_slice() {
                    b"reno" => ngtcp2::NGTCP2_CC_ALGO_RENO,
                    b"bbr" => ngtcp2::NGTCP2_CC_ALGO_BBR,
                    _ => ngtcp2::NGTCP2_CC_ALGO_CUBIC,
                };
            }
        }

        let mut params = core::mem::MaybeUninit::<ngtcp2::ngtcp2_transport_params>::zeroed();
        // SAFETY: default initializer fills every field.
        let mut params = unsafe {
            ngtcp2::ngtcp2_transport_params_default(params.as_mut_ptr());
            params.assume_init()
        };
        // Node's defaults (node/src/quic/transportparams.h kDefault*).
        params.initial_max_stream_data_bidi_local = 256 * 1024;
        params.initial_max_stream_data_bidi_remote = 256 * 1024;
        params.initial_max_stream_data_uni = 256 * 1024;
        params.initial_max_data = 1024 * 1024;
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 3;
        params.max_idle_timeout = 10 * ngtcp2::NGTCP2_SECONDS;
        params.active_connection_id_limit = 2;
        if is_server {
            params.initial_max_streams_bidi = 100;
        }

        if options.is_object() {
            if let Some(tp) = options.get(global, "transportParams")?.filter(|v| v.is_object()) {
                if let Some(v) = read_u64_option(global, tp, "initialMaxStreamDataBidiLocal")? {
                    params.initial_max_stream_data_bidi_local = v;
                }
                if let Some(v) = read_u64_option(global, tp, "initialMaxStreamDataBidiRemote")? {
                    params.initial_max_stream_data_bidi_remote = v;
                }
                if let Some(v) = read_u64_option(global, tp, "initialMaxStreamDataUni")? {
                    params.initial_max_stream_data_uni = v;
                }
                if let Some(v) = read_u64_option(global, tp, "initialMaxData")? {
                    params.initial_max_data = v;
                }
                if let Some(v) = read_u64_option(global, tp, "initialMaxStreamsBidi")? {
                    params.initial_max_streams_bidi = v;
                }
                if let Some(v) = read_u64_option(global, tp, "initialMaxStreamsUni")? {
                    params.initial_max_streams_uni = v;
                }
                if let Some(v) = read_u64_option(global, tp, "maxIdleTimeout")? {
                    params.max_idle_timeout = v * ngtcp2::NGTCP2_MILLISECONDS;
                }
                if let Some(v) = read_u64_option(global, tp, "activeConnectionIDLimit")? {
                    params.active_connection_id_limit = v;
                }
                if let Some(v) = read_u64_option(global, tp, "ackDelayExponent")? {
                    params.ack_delay_exponent = v;
                }
                if let Some(v) = read_u64_option(global, tp, "maxAckDelay")? {
                    params.max_ack_delay = v * ngtcp2::NGTCP2_MILLISECONDS;
                }
                if let Some(v) = read_u64_option(global, tp, "maxDatagramFrameSize")? {
                    params.max_datagram_frame_size = v;
                }
            }
        }

        Ok((settings, params))
    }

    /// Create a client session: build TLS + ngtcp2 conn, register routing,
    /// send the initial flight. Returns the JS handle.
    pub(super) fn new_client(
        global: &JSGlobalObject,
        endpoint: *mut QuicEndpoint,
        endpoint_handle: JSValue,
        local_addr: StoredAddr,
        remote_addr: StoredAddr,
        options: JSValue,
    ) -> JsResult<JSValue> {
        let (raw, handle) = Self::create_shell(global, endpoint, endpoint_handle, local_addr, remote_addr)?;
        // SAFETY: freshly created, uniquely referenced here; wrapper owns it.
        let this = unsafe { &*raw };

        let tls_options = if options.is_object() {
            options.get(global, "tls")?.unwrap_or(JSValue::UNDEFINED)
        } else {
            JSValue::UNDEFINED
        };
        let tls_config = TlsConfig::from_js(global, tls_options, false)?;

        let mut conn_ref = Box::new(ngtcp2::ngtcp2_crypto_conn_ref {
            get_conn: Some(get_conn_from_ref),
            user_data: raw.cast(),
        });
        let conn_ref_ptr: *mut ngtcp2::ngtcp2_crypto_conn_ref = &mut *conn_ref;

        let tls = match TlsSession::new(&tls_config, conn_ref_ptr) {
            Ok(tls) => tls,
            Err(message) => {
                this.teardown(global);
                return Err(global.throw(format_args!("Failed to create QUIC TLS session: {message}")));
            }
        };

        let (settings, params) = Self::build_settings(global, options, false)?;
        let callbacks = build_callbacks(false);

        let scid = random_cid(LOCAL_CID_LEN);
        let dcid = random_cid(18);
        // The address copies must outlive the conn_new call below: the path
        // only borrows pointers into them.
        let (path_local, path_remote) = (this.local_addr.get(), this.remote_addr.get());
        let path = ngtcp2::ngtcp2_path {
            local: path_local.ngtcp2_addr(),
            remote: path_remote.ngtcp2_addr(),
            user_data: null_mut(),
        };
        let version = read_u64_option(global, options, "version")?
            .map_or(ngtcp2::NGTCP2_PROTO_VER_V1, |v| v as u32);

        let mut conn: *mut ngtcp2::ngtcp2_conn = null_mut();
        // SAFETY: every pointer argument refers to live stack/heap data; the
        // settings/params/callbacks structs are fully initialized above.
        let rv = unsafe {
            ngtcp2::ngtcp2_conn_client_new_versioned(
                &mut conn,
                &dcid,
                &scid,
                &path,
                version,
                ngtcp2::NGTCP2_CALLBACKS_VERSION,
                &callbacks,
                ngtcp2::NGTCP2_SETTINGS_VERSION,
                &settings,
                ngtcp2::NGTCP2_TRANSPORT_PARAMS_VERSION,
                &params,
                null(),
                raw.cast(),
            )
        };
        if rv != 0 || conn.is_null() {
            this.teardown(global);
            return Err(global.throw(format_args!("Failed to create QUIC client connection ({rv})")));
        }

        // SAFETY: `conn` and `tls.ssl()` are both live; ngtcp2 only stores the
        // pointer.
        unsafe { ngtcp2::ngtcp2_conn_set_tls_native_handle(conn, tls.ssl().cast()) };

        this.conn.set(conn);
        this.tls.set(Some(tls));
        this.conn_ref.set(Some(conn_ref));

        // Incoming packets from the server carry our SCID as their DCID.
        // SAFETY: endpoint pointer is valid (kept alive by endpoint_js Strong).
        unsafe {
            (*endpoint).register_session_cid(&scid.data[..scid.datalen], raw);
        }
        this.registered_cids.with_mut(|cids| cids.push(scid.data[..scid.datalen].to_vec()));

        // Send the client initial flight.
        this.flush(global);
        this.rearm_timer();

        Ok(handle)
    }

    /// Create a server session for a freshly accepted initial packet.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_server(
        global: &JSGlobalObject,
        endpoint: *mut QuicEndpoint,
        endpoint_handle: JSValue,
        local_addr: StoredAddr,
        remote_addr: StoredAddr,
        options: JSValue,
        client_dcid: &[u8],
        client_scid: &[u8],
        version: u32,
    ) -> JsResult<Option<(*mut QuicSession, JSValue)>> {
        let (raw, handle) = Self::create_shell(global, endpoint, endpoint_handle, local_addr, remote_addr)?;
        // SAFETY: freshly created, uniquely referenced here; wrapper owns it.
        let this = unsafe { &*raw };

        let tls_options = if options.is_object() {
            options.get(global, "tls")?.unwrap_or(JSValue::UNDEFINED)
        } else {
            JSValue::UNDEFINED
        };
        let tls_config = TlsConfig::from_js(global, tls_options, true)?;

        let mut conn_ref = Box::new(ngtcp2::ngtcp2_crypto_conn_ref {
            get_conn: Some(get_conn_from_ref),
            user_data: raw.cast(),
        });
        let conn_ref_ptr: *mut ngtcp2::ngtcp2_crypto_conn_ref = &mut *conn_ref;

        let tls = match TlsSession::new(&tls_config, conn_ref_ptr) {
            Ok(tls) => tls,
            Err(_) => {
                this.teardown(global);
                return Ok(None);
            }
        };

        let (mut settings, mut params) = Self::build_settings(global, options, true)?;
        settings.token = null();
        settings.tokenlen = 0;

        // The client's chosen DCID becomes original_dcid; we pick a fresh SCID.
        let mut original_dcid = ngtcp2::ngtcp2_cid::default();
        let len = client_dcid.len().min(ngtcp2::NGTCP2_MAX_CIDLEN);
        original_dcid.data[..len].copy_from_slice(&client_dcid[..len]);
        original_dcid.datalen = len;
        params.original_dcid = original_dcid;
        params.original_dcid_present = 1;

        let mut peer_scid = ngtcp2::ngtcp2_cid::default();
        let len = client_scid.len().min(ngtcp2::NGTCP2_MAX_CIDLEN);
        peer_scid.data[..len].copy_from_slice(&client_scid[..len]);
        peer_scid.datalen = len;

        let scid = random_cid(LOCAL_CID_LEN);
        // The address copies must outlive the conn_new call below: the path
        // only borrows pointers into them.
        let (path_local, path_remote) = (this.local_addr.get(), this.remote_addr.get());
        let path = ngtcp2::ngtcp2_path {
            local: path_local.ngtcp2_addr(),
            remote: path_remote.ngtcp2_addr(),
            user_data: null_mut(),
        };

        let callbacks = build_callbacks(true);
        let mut conn: *mut ngtcp2::ngtcp2_conn = null_mut();
        // SAFETY: as in `new_client`.
        let rv = unsafe {
            ngtcp2::ngtcp2_conn_server_new_versioned(
                &mut conn,
                &peer_scid,
                &scid,
                &path,
                version,
                ngtcp2::NGTCP2_CALLBACKS_VERSION,
                &callbacks,
                ngtcp2::NGTCP2_SETTINGS_VERSION,
                &settings,
                ngtcp2::NGTCP2_TRANSPORT_PARAMS_VERSION,
                &params,
                null(),
                raw.cast(),
            )
        };
        if rv != 0 || conn.is_null() {
            this.teardown(global);
            return Ok(None);
        }
        // SAFETY: both pointers live; ngtcp2 only stores the SSL pointer.
        unsafe { ngtcp2::ngtcp2_conn_set_tls_native_handle(conn, tls.ssl().cast()) };

        this.conn.set(conn);
        this.tls.set(Some(tls));
        this.conn_ref.set(Some(conn_ref));

        // Route both the client-chosen DCID (used until the client learns our
        // SCID) and our SCID to this session.
        // SAFETY: endpoint pointer is valid (kept alive by endpoint_js Strong).
        unsafe {
            (*endpoint).register_session_cid(client_dcid, raw);
            (*endpoint).register_session_cid(&scid.data[..scid.datalen], raw);
        }
        this.registered_cids.with_mut(|cids| {
            cids.push(client_dcid.to_vec());
            cids.push(scid.data[..scid.datalen].to_vec());
        });

        Ok(Some((raw, handle)))
    }

    /// Feed one received UDP datagram into the connection, then drive output.
    pub(super) fn on_packet(&self, global: &JSGlobalObject, data: &[u8], remote: StoredAddr) {
        if self.destroyed.get() || self.conn.get().is_null() {
            return;
        }
        // Keep the remote address from connect/accept. Path migration is not
        // implemented, so a differing source address must not redirect our
        // sends (ngtcp2 validates the path; we keep transmitting to the
        // address the connection was established with).
        if remote.is_set() && !self.remote_addr.get().is_set() {
            self.remote_addr.set(remote);
        }
        // The address copies must outlive the read_pkt call: the path only
        // borrows pointers into them.
        let (path_local, path_remote) = (self.local_addr.get(), self.remote_addr.get());
        let path = ngtcp2::ngtcp2_path {
            local: path_local.ngtcp2_addr(),
            remote: path_remote.ngtcp2_addr(),
            user_data: null_mut(),
        };
        let pi = ngtcp2::ngtcp2_pkt_info::default();
        // SAFETY: `conn` is live; `data` is a live slice for this call.
        let rv = unsafe {
            ngtcp2::ngtcp2_conn_read_pkt_versioned(
                self.conn.get(),
                &path,
                ngtcp2::NGTCP2_PKT_INFO_VERSION,
                &pi,
                data.as_ptr(),
                data.len(),
                now_ns(),
            )
        };
        self.add_stat(IDX_STATS_BYTES_RECEIVED, data.len() as u64);
        self.add_stat(IDX_STATS_PKT_RECV, 1);
        bun_core::scoped_log!(
            quic_session,
            "read_pkt {} bytes rv={} completed={}",
            data.len(),
            rv,
            // SAFETY: `conn` is live.
            unsafe { ngtcp2::ngtcp2_conn_get_handshake_completed(self.conn.get()) }
        );

        if rv != 0 {
            if rv == ngtcp2::NGTCP2_ERR_DRAINING {
                // Peer sent CONNECTION_CLOSE; report and stop.
                self.report_remote_close(global);
                return;
            }
            if rv == ngtcp2::NGTCP2_ERR_CRYPTO || unsafe { ngtcp2::ngtcp2_err_is_fatal(rv) } != 0 {
                self.close_with_local_error(global, rv);
                return;
            }
            // Non-fatal: ignore the packet.
        }

        // Send everything the packet produced (including our final handshake
        // flight) BEFORE reporting handshake completion: the JS callback runs
        // user continuations synchronously (e.g. `await opened` → `close()`),
        // and those must observe a peer that has already received our
        // handshake data.
        self.flush(global);
        if self.destroyed.get() {
            return;
        }
        self.maybe_report_handshake(global);
        if self.destroyed.get() {
            return;
        }
        self.process_stream_events(global);
        self.sync_conn_info_stats();
        self.rearm_timer();
    }

    /// Copy the live congestion/RTT counters from ngtcp2 into the stats
    /// buffer the JS layer reads (cwnd, rtt, bytes in flight, ...).
    fn sync_conn_info_stats(&self) {
        if self.destroyed.get() || self.conn.get().is_null() {
            return;
        }
        let mut info = ngtcp2::ngtcp2_conn_info::default();
        // SAFETY: `conn` is live; `info` is a stack out-param.
        unsafe {
            ngtcp2::ngtcp2_conn_get_conn_info_versioned(
                self.conn.get(),
                ngtcp2::NGTCP2_CONN_INFO_VERSION,
                &mut info,
            );
        }
        self.write_stat(
            IDX_STATS_MAX_BYTES_IN_FLIGHT,
            self.read_stat(IDX_STATS_MAX_BYTES_IN_FLIGHT).max(info.bytes_in_flight),
        );
        self.write_stat(IDX_STATS_BYTES_IN_FLIGHT, info.bytes_in_flight);
        self.write_stat(IDX_STATS_CWND, info.cwnd);
        self.write_stat(IDX_STATS_LATEST_RTT, info.latest_rtt);
        self.write_stat(IDX_STATS_MIN_RTT, info.min_rtt);
        self.write_stat(IDX_STATS_RTTVAR, info.rttvar);
        self.write_stat(IDX_STATS_SMOOTHED_RTT, info.smoothed_rtt);
        self.write_stat(IDX_STATS_SSTHRESH, info.ssthresh);
    }

    /// Dispatch the stream activity queued by the ngtcp2 callbacks during the
    /// last packet/expiry processing pass. Runs on the JS thread with no
    /// ngtcp2 frames on the stack, so callbacks may re-enter the session.
    pub(super) fn process_stream_events(&self, global: &JSGlobalObject) {
        loop {
            let events = self.stream_events.replace(Vec::new());
            if events.is_empty() {
                return;
            }
            // Streams whose readers should be woken once the batch is done:
            // (stream id, fin seen).
            let mut to_wake: Vec<(i64, bool)> = Vec::new();
            for event in events {
                if self.destroyed.get() {
                    return;
                }
                match event {
                    StreamEvent::Opened(id) => {
                        if self.streams.get().contains_key(&id) {
                            continue;
                        }
                        let session_ptr = core::ptr::from_ref(self).cast_mut();
                        let Ok((stream, stream_handle)) =
                            QuicStream::create(global, session_ptr, self.handle(), id)
                        else {
                            continue;
                        };
                        self.streams.with_mut(|map| {
                            map.insert(id, stream);
                        });
                        // Peer-initiated stream direction is derived from the
                        // id: bit 1 set means unidirectional.
                        let direction = if id & 0x2 != 0 { 1.0 } else { 0.0 };
                        if id & 0x2 != 0 {
                            // SAFETY: the stream was created above.
                            unsafe { (*stream).mark_remote_unidirectional() };
                        }
                        if let Some(callback) = callbacks::get(global, "onStreamCreated") {
                            let vm = global.bun_vm().as_mut();
                            vm.event_loop_ref().run_callback(
                                callback,
                                global,
                                self.handle(),
                                &[stream_handle, JSValue::js_number(direction)],
                            );
                        }
                    }
                    StreamEvent::Data { id, bytes, fin } => {
                        let Some(&stream) = self.streams.get().get(&id) else { continue };
                        // SAFETY: streams unregister themselves before teardown.
                        unsafe { (*stream).push_inbound(&bytes, fin) };
                        if let Some(entry) = to_wake.iter_mut().find(|(wid, _)| *wid == id) {
                            entry.1 |= fin;
                        } else {
                            to_wake.push((id, fin));
                        }
                    }
                    StreamEvent::Closed { id, code, errored } => {
                        let Some(&stream) = self.streams.get().get(&id) else { continue };
                        // A clean close also ends the readable side.
                        // SAFETY: as above.
                        unsafe { (*stream).push_inbound(&[], true) };
                        if let Some(entry) = to_wake.iter_mut().find(|(wid, _)| *wid == id) {
                            entry.1 = true;
                        } else {
                            to_wake.push((id, true));
                        }
                        // The error is delivered in QuicError::ToV8Value form:
                        // [type, code, reason, errorName].
                        let error = if errored {
                            JSValue::create_array_from_slice(
                                global,
                                &[
                                    JSValue::js_number(1.0),
                                    JSValue::from_uint64_no_truncate(global, code),
                                ],
                            )
                            .unwrap_or(JSValue::UNDEFINED)
                        } else {
                            JSValue::UNDEFINED
                        };
                        // SAFETY: as above.
                        let stream_handle = unsafe { (*stream).handle() };
                        if let Some(callback) = callbacks::get(global, "onStreamClose") {
                            let vm = global.bun_vm().as_mut();
                            vm.event_loop_ref().run_callback(callback, global, stream_handle, &[error]);
                        }
                    }
                    StreamEvent::Reset { id, code } => {
                        let Some(&stream) = self.streams.get().get(&id) else { continue };
                        // SAFETY: as above.
                        unsafe { (*stream).mark_reset(code) };
                        if let Some(entry) = to_wake.iter_mut().find(|(wid, _)| *wid == id) {
                            entry.1 = true;
                        } else {
                            to_wake.push((id, true));
                        }
                        // The JS layer only registers for the reset event when
                        // an `onreset` callback is installed (wantsReset).
                        // SAFETY: as above.
                        let wants_reset = unsafe { (*(*stream).state_mut()).wants_reset } != 0;
                        if wants_reset {
                            let error = JSValue::create_array_from_slice(
                                global,
                                &[
                                    JSValue::js_number(1.0),
                                    JSValue::from_uint64_no_truncate(global, code),
                                ],
                            )
                            .unwrap_or(JSValue::UNDEFINED);
                            // SAFETY: as above.
                            let stream_handle = unsafe { (*stream).handle() };
                            if let Some(callback) = callbacks::get(global, "onStreamReset") {
                                let vm = global.bun_vm().as_mut();
                                vm.event_loop_ref().run_callback(callback, global, stream_handle, &[error]);
                            }
                        }
                    }
                    StreamEvent::Drain(id) => {
                        let Some(&stream) = self.streams.get().get(&id) else { continue };
                        // SAFETY: as above.
                        if unsafe { (*stream).refresh_write_capacity() } {
                            // SAFETY: as above.
                            let stream_handle = unsafe { (*stream).handle() };
                            if let Some(callback) = callbacks::get(global, "onStreamDrain") {
                                let vm = global.bun_vm().as_mut();
                                vm.event_loop_ref().run_callback(callback, global, stream_handle, &[]);
                            }
                        }
                    }
                    StreamEvent::Blocked(id) => {
                        let Some(&stream) = self.streams.get().get(&id) else { continue };
                        // The JS layer only registers for this when an
                        // `onblocked` callback is installed (wantsBlock).
                        // SAFETY: as above.
                        let wants_block = unsafe { (*(*stream).state_mut()).wants_block } != 0;
                        if wants_block {
                            // SAFETY: as above.
                            let stream_handle = unsafe { (*stream).handle() };
                            if let Some(callback) = callbacks::get(global, "onStreamBlocked") {
                                let vm = global.bun_vm().as_mut();
                                vm.event_loop_ref().run_callback(callback, global, stream_handle, &[]);
                            }
                        }
                    }
                }
            }
            for (id, fin) in to_wake {
                if self.destroyed.get() {
                    return;
                }
                let Some(&stream) = self.streams.get().get(&id) else { continue };
                // SAFETY: as above.
                if unsafe { (*stream).is_destroyed() } {
                    continue;
                }
                // SAFETY: as above.
                if let Some(wakeup) = unsafe { (*stream).take_wakeup() } {
                    let vm = global.bun_vm().as_mut();
                    vm.event_loop_ref().run_callback(
                        wakeup.get(),
                        global,
                        JSValue::UNDEFINED,
                        &[JSValue::js_boolean(fin)],
                    );
                }
            }
            // The JS callbacks above may have produced more events (e.g. a
            // reader pulling data triggers flow-control updates); loop until
            // the queue stays empty.
        }
    }

    /// Run the ngtcp2 write loop, sending every produced packet.
    pub(super) fn flush(&self, global: &JSGlobalObject) {
        if self.destroyed.get() || self.conn.get().is_null() {
            return;
        }
        let endpoint = self.endpoint.get();
        if endpoint.is_null() {
            return;
        }
        let mut buf = [0u8; MAX_SEND_PACKET];
        // The address copies must outlive every writev call in the loop: the
        // path only borrows pointers into them.
        let (path_local, path_remote) = (self.local_addr.get(), self.remote_addr.get());

        // Streams with queued outbound data, visited round-robin; a stream
        // that ngtcp2 reports as blocked is skipped for the rest of this pass.
        let mut pending_streams: Vec<*mut QuicStream> = self
            .streams
            .get()
            .values()
            .copied()
            .filter(|&s| {
                // SAFETY: streams unregister themselves before teardown.
                unsafe { !(*s).is_destroyed() && (*s).has_pending_outbound() }
            })
            .collect();

        loop {
            // Pick the stream (and a stable in-flight chunk of its data) to
            // include in this packet, if any. ngtcp2 keeps the chunk pointer
            // until the bytes are acknowledged, so the chunk is owned by the
            // stream's in-flight list, not this stack frame.
            let (stream_id, chunk_ptr, chunk_len, fin, stream_ptr): (i64, *const u8, usize, bool, *mut QuicStream) =
                match pending_streams.last().copied() {
                    Some(stream) => {
                        // SAFETY: as above.
                        let (ptr, len) = unsafe { (*stream).stage_chunk(MAX_SEND_PACKET) };
                        // SAFETY: as above.
                        let fin = unsafe {
                            (*stream).outbound.get().fin_pending
                                && (*stream).outbound.get().data.len() == len
                        };
                        // SAFETY: as above.
                        let id = unsafe { (*(*stream).state_mut()).id };
                        (id, ptr, len, fin, stream)
                    }
                    None => (-1, null(), 0, false, null_mut()),
                };

            let mut path = ngtcp2::ngtcp2_path {
                local: path_local.ngtcp2_addr(),
                remote: path_remote.ngtcp2_addr(),
                user_data: null_mut(),
            };
            let mut pi = ngtcp2::ngtcp2_pkt_info::default();
            let mut pdatalen: ngtcp2::ngtcp2_ssize = 0;
            let datav = ngtcp2::ngtcp2_vec { base: chunk_ptr, len: chunk_len };
            let flags = if fin { ngtcp2::NGTCP2_WRITE_STREAM_FLAG_FIN } else { ngtcp2::NGTCP2_WRITE_STREAM_FLAG_NONE };
            // SAFETY: `conn` is live; the data vector points into the stream's
            // in-flight chunk, which outlives the connection's use of it.
            let n = unsafe {
                ngtcp2::ngtcp2_conn_writev_stream_versioned(
                    self.conn.get(),
                    &mut path,
                    ngtcp2::NGTCP2_PKT_INFO_VERSION,
                    &mut pi,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut pdatalen,
                    flags,
                    stream_id,
                    if chunk_len == 0 { null() } else { &datav },
                    if chunk_len == 0 { 0 } else { 1 },
                    now_ns(),
                )
            };

            // Settle the staged chunk according to what ngtcp2 accepted.
            let accepted = if pdatalen > 0 { pdatalen as usize } else { 0 };
            if !stream_ptr.is_null() && chunk_len > 0 {
                // SAFETY: as above.
                unsafe { (*stream_ptr).commit_staged(if n >= 0 { accepted } else { 0 }) };
                if accepted > 0 && n >= 0 {
                    // Consuming queued bytes may reopen the writer's window;
                    // the Drain handler refreshes it and notifies JS.
                    // SAFETY: as above.
                    let id = unsafe { (*(*stream_ptr).state_mut()).id };
                    self.stream_events.with_mut(|events| events.push(StreamEvent::Drain(id)));
                }
            }

            if n < 0 {
                let rv = n as c_int;
                match rv {
                    ngtcp2::NGTCP2_ERR_DRAINING => return,
                    ngtcp2::NGTCP2_ERR_STREAM_DATA_BLOCKED
                    | ngtcp2::NGTCP2_ERR_STREAM_SHUT_WR
                    | ngtcp2::NGTCP2_ERR_STREAM_NOT_FOUND => {
                        if rv == ngtcp2::NGTCP2_ERR_STREAM_DATA_BLOCKED && !stream_ptr.is_null() {
                            // SAFETY: as above.
                            let id = unsafe { (*(*stream_ptr).state_mut()).id };
                            self.stream_events.with_mut(|events| events.push(StreamEvent::Blocked(id)));
                        }
                        // This stream cannot make progress right now; move on.
                        pending_streams.pop();
                        continue;
                    }
                    _ => {
                        // SAFETY: plain status query.
                        if unsafe { ngtcp2::ngtcp2_err_is_fatal(rv) } != 0 {
                            self.close_with_local_error(global, rv);
                        }
                        return;
                    }
                }
            }

            if !stream_ptr.is_null() && n > 0 {
                // SAFETY: as above.
                let drained = unsafe { (*stream_ptr).outbound.get().data.is_empty() };
                if fin && pdatalen >= 0 && drained {
                    // SAFETY: as above.
                    unsafe { (*stream_ptr).mark_fin_sent() };
                }
                // SAFETY: as above.
                if unsafe { !(*stream_ptr).has_pending_outbound() } {
                    pending_streams.pop();
                }
            }

            if n == 0 {
                // ngtcp2 has nothing more to send right now (flow control,
                // congestion, or simply done) — stop this pass.
                break;
            }
            let remote = self.remote_addr.get();
            // SAFETY: endpoint stays valid for the duration of this call (the
            // session holds its wrapper strong).
            unsafe { (*endpoint).send_packet(&buf[..n as usize], &remote) };
            self.add_stat(IDX_STATS_PKT_SENT, 1);
            self.add_stat(IDX_STATS_BYTES_SENT, n as u64);
        }
    }

    /// Re-arm (or pause) the expiry timer to ngtcp2's next deadline. Must be
    /// called after every operation that can change the deadline (reads,
    /// writes, expiry handling).
    fn rearm_timer(&self) {
        let timer = self.event_loop_timer.as_ptr();
        if self.destroyed.get() || self.conn.get().is_null() {
            if self.event_loop_timer.get().state == EventLoopTimerState::ACTIVE {
                timer_all().remove(timer);
            }
            return;
        }
        // SAFETY: `conn` is live.
        let expiry = unsafe { ngtcp2::ngtcp2_conn_get_expiry(self.conn.get()) };
        if expiry == u64::MAX {
            if self.event_loop_timer.get().state == EventLoopTimerState::ACTIVE {
                timer_all().remove(timer);
            }
            return;
        }
        let delta_ms = expiry.saturating_sub(now_ns()).div_ceil(ngtcp2::NGTCP2_MILLISECONDS).max(1) as i64;
        let next = bun_core::Timespec::ms_from_now(bun_core::TimespecMockMode::ForceRealTime, delta_ms);
        // SAFETY: `event_loop_timer` is the live inline timer field of this
        // heap-allocated session.
        timer_all().update(timer, &next);
    }

    /// Timer-fire dispatch target: let ngtcp2 handle its expired deadlines
    /// (loss detection, idle/handshake timeouts), then drive output.
    pub(crate) fn on_timer_fire(this: *mut Self) {
        // SAFETY: the timer heap only holds timers of live sessions (teardown
        // removes the timer before the session can be freed).
        let this_ref = unsafe { &*this };
        this_ref
            .event_loop_timer
            .with_mut(|t| t.state = EventLoopTimerState::FIRED);
        if this_ref.destroyed.get() || this_ref.conn.get().is_null() {
            return;
        }
        let global_ptr = this_ref.global.get();
        if global_ptr.is_null() {
            return;
        }
        // SAFETY: sessions only exist on the JS thread of this realm and the
        // realm outlives them.
        let global = unsafe { &*global_ptr };

        // A close requested from JS completes here, one event-loop turn later
        // (Node's close is asynchronous; completing it inside the JS call
        // would let the caller's continuations run before the peer ever gets
        // our final packets).
        if this_ref.pending_close.replace(false) {
            // SAFETY: state buffer is live while the wrapper is.
            let silent = unsafe { (*this_ref.state_mut()).silent_close } != 0;
            if !silent {
                let mut ccerr = core::mem::MaybeUninit::<ngtcp2::ngtcp2_ccerr>::zeroed();
                // SAFETY: ccerr_default fully initializes the struct (NO_ERROR).
                let ccerr = unsafe {
                    ngtcp2::ngtcp2_ccerr_default(ccerr.as_mut_ptr());
                    ccerr.assume_init()
                };
                this_ref.send_connection_close(&ccerr);
            }
            this_ref.report_close(global, 0, 0, None, None);
            return;
        }

        // SAFETY: `conn` is live.
        let rv = unsafe { ngtcp2::ngtcp2_conn_handle_expiry(this_ref.conn.get(), now_ns()) };
        if rv != 0 {
            // Idle timeout, handshake timeout, or another fatal condition.
            this_ref.close_with_local_error(global, rv);
            return;
        }
        this_ref.flush(global);
        if this_ref.destroyed.get() {
            return;
        }
        this_ref.process_stream_events(global);
        this_ref.rearm_timer();
    }

    /// If the TLS handshake just completed, report it to JS.
    fn maybe_report_handshake(&self, global: &JSGlobalObject) {
        if self.handshake_reported.get() || self.destroyed.get() || self.conn.get().is_null() {
            return;
        }
        // SAFETY: `conn` is live.
        if unsafe { ngtcp2::ngtcp2_conn_get_handshake_completed(self.conn.get()) } == 0 {
            return;
        }
        self.handshake_reported.set(true);
        self.write_stat(IDX_STATS_HANDSHAKE_COMPLETED_AT, now_ns());
        // SAFETY: state buffer is live while the wrapper is.
        unsafe {
            (*self.state_mut()).handshake_completed = 1;
            (*self.state_mut()).stream_open_allowed = 1;
        }

        let tls_guard = self.tls.get();
        let Some(tls) = tls_guard.as_ref() else { return };

        let to_js_string = |value: Option<String>| -> JSValue {
            match value {
                Some(s) if !s.is_empty() => bun_core::String::clone_utf8(s.as_bytes())
                    .to_js(global)
                    .unwrap_or(JSValue::UNDEFINED),
                _ => JSValue::UNDEFINED,
            }
        };

        let servername = to_js_string(tls.servername());
        let protocol = to_js_string(tls.alpn_selected().map(|p| String::from_utf8_lossy(&p).into_owned()));
        let cipher = to_js_string(tls.cipher_name());
        let cipher_version = to_js_string(tls.cipher_version());
        let (validation_reason, validation_code) = match tls.validation_error() {
            Some((reason, code)) => (to_js_string(Some(reason)), to_js_string(Some(code))),
            None => (JSValue::UNDEFINED, JSValue::UNDEFINED),
        };

        if let Some(callback) = callbacks::get(global, "onSessionHandshake") {
            let vm = global.bun_vm().as_mut();
            vm.event_loop_ref().run_callback(
                callback,
                global,
                self.handle(),
                &[
                    servername,
                    protocol,
                    cipher,
                    cipher_version,
                    validation_reason,
                    validation_code,
                    JSValue::js_boolean(false),
                    JSValue::js_boolean(false),
                ],
            );
        }
    }

    /// Report a close initiated by the peer (CONNECTION_CLOSE received).
    fn report_remote_close(&self, global: &JSGlobalObject) {
        if self.conn.get().is_null() {
            self.report_close(global, 0, 0, None, None);
            return;
        }
        // SAFETY: `conn` is live.
        let ccerr = unsafe { ngtcp2::ngtcp2_conn_get_ccerr(self.conn.get()) };
        if ccerr.is_null() {
            self.report_close(global, 0, 0, None, None);
            return;
        }
        // SAFETY: ngtcp2 returns a pointer to connection-owned storage, valid
        // while the conn is.
        let (error_type, code, reason) = unsafe {
            let reason = if (*ccerr).reasonlen > 0 && !(*ccerr).reason.is_null() {
                Some(core::slice::from_raw_parts((*ccerr).reason, (*ccerr).reasonlen).to_vec())
            } else {
                None
            };
            ((*ccerr).type_, (*ccerr).error_code, reason)
        };
        self.report_close(global, error_type as i32, code, reason, None);
    }

    /// Close the connection because of a local ngtcp2 error.
    fn close_with_local_error(&self, global: &JSGlobalObject, liberr: c_int) {
        if self.destroyed.get() || self.conn.get().is_null() {
            return;
        }
        let mut ccerr = core::mem::MaybeUninit::<ngtcp2::ngtcp2_ccerr>::zeroed();
        // SAFETY: default + set_liberr/set_tls_alert fully initialize the struct.
        let ccerr = unsafe {
            ngtcp2::ngtcp2_ccerr_default(ccerr.as_mut_ptr());
            if liberr == ngtcp2::NGTCP2_ERR_CRYPTO {
                // A TLS failure closes the connection with CRYPTO_ERROR +
                // alert (e.g. 0x178 for no_application_protocol), which is
                // what the peer (and the JS error code) must observe.
                let alert = ngtcp2::ngtcp2_conn_get_tls_alert(self.conn.get());
                ngtcp2::ngtcp2_ccerr_set_tls_alert(ccerr.as_mut_ptr(), alert, null(), 0);
            } else {
                ngtcp2::ngtcp2_ccerr_set_liberr(ccerr.as_mut_ptr(), liberr, null(), 0);
            }
            ccerr.assume_init()
        };
        self.send_connection_close(&ccerr);
        self.report_close(global, ccerr.type_ as i32, ccerr.error_code, None, None);
    }

    /// Write and transmit a CONNECTION_CLOSE packet for `ccerr`.
    fn send_connection_close(&self, ccerr: &ngtcp2::ngtcp2_ccerr) {
        if self.conn.get().is_null() {
            return;
        }
        let endpoint = self.endpoint.get();
        if endpoint.is_null() {
            return;
        }
        let mut buf = [0u8; MAX_SEND_PACKET];
        // The address copies must outlive the write call: the path only
        // borrows pointers into them.
        let (path_local, path_remote) = (self.local_addr.get(), self.remote_addr.get());
        let mut path = ngtcp2::ngtcp2_path {
            local: path_local.ngtcp2_addr(),
            remote: path_remote.ngtcp2_addr(),
            user_data: null_mut(),
        };
        let mut pi = ngtcp2::ngtcp2_pkt_info::default();
        // SAFETY: `conn` is live; buffers are stack locals.
        let n = unsafe {
            ngtcp2::ngtcp2_conn_write_connection_close_versioned(
                self.conn.get(),
                &mut path,
                ngtcp2::NGTCP2_PKT_INFO_VERSION,
                &mut pi,
                buf.as_mut_ptr(),
                buf.len(),
                ccerr,
                now_ns(),
            )
        };
        if n > 0 {
            let remote = self.remote_addr.get();
            // SAFETY: endpoint outlives the session (held via endpoint_js).
            unsafe { (*endpoint).send_packet(&buf[..n as usize], &remote) };
        }
    }

    /// Invoke `onSessionClose` exactly once.
    fn report_close(
        &self,
        global: &JSGlobalObject,
        error_type: i32,
        code: u64,
        reason: Option<Vec<u8>>,
        error_name: Option<&str>,
    ) {
        if self.close_reported.replace(true) || self.destroyed.get() {
            return;
        }
        self.write_stat(IDX_STATS_CLOSING_AT, now_ns());
        // SAFETY: state buffer is live while the wrapper is.
        unsafe { (*self.state_mut()).closing = 1 };

        let Some(callback) = callbacks::get(global, "onSessionClose") else { return };
        let reason_js = match reason {
            Some(bytes) if !bytes.is_empty() => bun_core::String::clone_utf8(&bytes)
                .to_js(global)
                .unwrap_or(JSValue::UNDEFINED),
            _ => JSValue::UNDEFINED,
        };
        let error_name_js = match error_name {
            Some(name) => bun_core::String::clone_utf8(name.as_bytes())
                .to_js(global)
                .unwrap_or(JSValue::UNDEFINED),
            None => JSValue::UNDEFINED,
        };
        let vm = global.bun_vm().as_mut();
        vm.event_loop_ref().run_callback(
            callback,
            global,
            self.handle(),
            &[
                JSValue::js_number(f64::from(error_type)),
                // The JS layer compares against `0n`: the code is a BigInt.
                JSValue::from_uint64_no_truncate(global, code),
                reason_js,
                error_name_js,
            ],
        );
    }

    /// Release every native resource. Idempotent.
    fn teardown(&self, _global: &JSGlobalObject) {
        if self.destroyed.replace(true) {
            return;
        }
        if self.event_loop_timer.get().state == EventLoopTimerState::ACTIVE {
            timer_all().remove(self.event_loop_timer.as_ptr());
        }
        // Detach every live stream first so nothing keeps pointers into the
        // connection that is about to be freed.
        let live_streams: Vec<*mut QuicStream> = self.streams.get().values().copied().collect();
        for stream in live_streams {
            // SAFETY: pointers in the map are live (streams unregister
            // themselves on teardown, which is idempotent).
            unsafe { (*stream).teardown() };
        }
        self.streams.with_mut(HashMap::clear);
        self.stream_events.with_mut(Vec::clear);
        let endpoint = self.endpoint.get();
        if !endpoint.is_null() {
            self.registered_cids.with_mut(|cids| {
                for cid in cids.drain(..) {
                    // SAFETY: endpoint is alive (endpoint_js Strong still held).
                    unsafe { (*endpoint).unregister_session_cid(&cid) };
                }
            });
        }
        let conn = self.conn.replace(null_mut());
        if !conn.is_null() {
            // SAFETY: `conn` was created by this session and not freed before.
            unsafe { ngtcp2::ngtcp2_conn_del(conn) };
        }
        self.tls.set(None);
        self.conn_ref.set(None);
        self.write_stat(IDX_STATS_DESTROYED_AT, now_ns());
        self.endpoint.set(null_mut());
        self.endpoint_js.set(None);
        self.this_value.with_mut(|r| r.downgrade());
    }

    pub(crate) fn finalize(self: Box<Self>) {
        // The wrapper is only collectable after teardown (the session holds
        // itself strong while the connection is live), so nothing native is
        // left to release here.
        debug_assert!(self.conn.get().is_null());
    }

    // ── JS-visible methods (quic.classes.ts proto) ─────────────────────────

    pub(crate) fn destroy(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        // If the connection is still alive (i.e. JS-initiated destroy rather
        // than the tail end of a close), send CONNECTION_CLOSE first.
        if !self.close_reported.get() && !self.conn.get().is_null() {
            let options = frame.arguments_as_array::<1>()[0];
            let code = read_u64_option(global, options, "code")?.unwrap_or(0);
            let mut ccerr = core::mem::MaybeUninit::<ngtcp2::ngtcp2_ccerr>::zeroed();
            // SAFETY: initialized by ccerr_default / set_application_error.
            let ccerr = unsafe {
                ngtcp2::ngtcp2_ccerr_default(ccerr.as_mut_ptr());
                if code != 0 {
                    ngtcp2::ngtcp2_ccerr_set_application_error(ccerr.as_mut_ptr(), code, null(), 0);
                }
                ccerr.assume_init()
            };
            self.send_connection_close(&ccerr);
        }
        self.teardown(global);
        Ok(JSValue::UNDEFINED)
    }

    /// Schedule the close to complete on the next timer fire.
    fn schedule_close(&self) {
        if self.destroyed.get() || self.close_reported.get() || self.pending_close.replace(true) {
            return;
        }
        let next = bun_core::Timespec::ms_from_now(bun_core::TimespecMockMode::ForceRealTime, 1);
        // SAFETY: `event_loop_timer` is the live inline timer field of this
        // heap-allocated session.
        timer_all().update(self.event_loop_timer.as_ptr(), &next);
    }

    pub(crate) fn graceful_close(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        // SAFETY: state buffer is live while the wrapper is.
        unsafe { (*self.state_mut()).graceful_close = 1 };
        // No streams exist yet, so nothing further to wait for.
        self.schedule_close();
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn silent_close(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        // SAFETY: state buffer is live while the wrapper is.
        unsafe { (*self.state_mut()).silent_close = 1 };
        self.schedule_close();
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn get_remote_address(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() || !self.remote_addr.get().is_set() {
            return Ok(JSValue::UNDEFINED);
        }
        Ok(self.remote_addr.get().to_js_socket_address(global))
    }

    pub(crate) fn get_local_address(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() || !self.local_addr.get().is_set() {
            return Ok(JSValue::UNDEFINED);
        }
        Ok(self.local_addr.get().to_js_socket_address(global))
    }

    pub(crate) fn get_certificate(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn get_ephemeral_key(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn get_peer_certificate(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn update_key(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Err(global.throw(format_args!("QuicSession.updateKey is not implemented yet")))
    }

    /// `openStream(direction, body)` — open a locally-initiated stream.
    /// Returns the stream handle, or undefined when no stream credit is
    /// available (the JS layer reports ERR_QUIC_OPEN_STREAM_FAILED).
    pub(crate) fn open_stream(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() || self.conn.get().is_null() {
            return Ok(JSValue::UNDEFINED);
        }
        let [direction, body] = frame.arguments_as_array::<2>();
        let unidirectional = direction.is_number() && direction.as_number() == 1.0;

        let mut stream_id: i64 = -1;
        // SAFETY: `conn` is live; `stream_id` is a stack out-param.
        let rv = unsafe {
            if unidirectional {
                ngtcp2::ngtcp2_conn_open_uni_stream(self.conn.get(), &mut stream_id, null_mut())
            } else {
                ngtcp2::ngtcp2_conn_open_bidi_stream(self.conn.get(), &mut stream_id, null_mut())
            }
        };
        if rv != 0 {
            // Includes NGTCP2_ERR_STREAM_ID_BLOCKED (no stream credit yet).
            return Ok(JSValue::UNDEFINED);
        }

        let session_ptr = core::ptr::from_ref(self).cast_mut();
        let (stream, handle) = QuicStream::create(global, session_ptr, frame.this(), stream_id)?;
        self.streams.with_mut(|map| {
            map.insert(stream_id, stream);
        });
        if unidirectional {
            // SAFETY: the stream was created above and is registered.
            unsafe { (*stream).mark_local_unidirectional() };
        }

        if !body.is_empty_or_undefined_or_null() {
            if let Some(buf) = body.as_array_buffer(global) {
                let bytes = buf.byte_slice();
                // SAFETY: the stream was created above and is registered.
                unsafe {
                    (*stream).outbound.with_mut(|outbound| {
                        outbound.started = true;
                        outbound.data.extend(bytes.iter().copied());
                        outbound.fin_pending = true;
                    });
                    (*(*stream).state_mut()).has_outbound = 1;
                }
            }
            // Blob / FileHandle / streaming sources are configured by the JS
            // layer through attachSource()/initStreamingSource() afterwards.
        }

        self.flush(global);
        self.schedule_event_dispatch();
        self.rearm_timer();
        Ok(handle)
    }

    /// Detach a stream from the routing map (called from the stream's
    /// teardown).
    pub(super) fn unregister_stream(&self, id: i64) {
        self.streams.with_mut(|map| {
            map.remove(&id);
        });
    }

    /// Grant stream-level flow-control credit back to the peer as the JS
    /// reader consumes data.
    pub(super) fn extend_stream_offset(&self, id: i64, consumed: u64) {
        if self.destroyed.get() || self.conn.get().is_null() || consumed == 0 {
            return;
        }
        // SAFETY: `conn` is live.
        unsafe {
            ngtcp2::ngtcp2_conn_extend_max_stream_offset(self.conn.get(), id, consumed);
        }
    }

    /// Abruptly terminate both sides of a stream (stream.destroy(code)).
    pub(super) fn shutdown_stream(&self, global: &JSGlobalObject, id: i64, code: u64) {
        if self.destroyed.get() || self.conn.get().is_null() {
            return;
        }
        // SAFETY: `conn` is live.
        unsafe {
            ngtcp2::ngtcp2_conn_shutdown_stream_write(self.conn.get(), 0, id, code);
            ngtcp2::ngtcp2_conn_shutdown_stream_read(self.conn.get(), 0, id, code);
        }
        self.flush(global);
        self.schedule_event_dispatch();
        self.rearm_timer();
    }

    /// Ask the peer to stop sending on a stream (STOP_SENDING).
    pub(super) fn stop_sending(&self, global: &JSGlobalObject, id: i64, code: u64) {
        if self.destroyed.get() || self.conn.get().is_null() {
            return;
        }
        // SAFETY: `conn` is live.
        unsafe {
            ngtcp2::ngtcp2_conn_shutdown_stream_read(self.conn.get(), 0, id, code);
        }
        self.flush(global);
        self.schedule_event_dispatch();
        self.rearm_timer();
    }

    /// Abruptly end the local sending side of a stream (RESET_STREAM).
    pub(super) fn reset_stream_write(&self, global: &JSGlobalObject, id: i64, code: u64) {
        if self.destroyed.get() || self.conn.get().is_null() {
            return;
        }
        // SAFETY: `conn` is live.
        unsafe {
            ngtcp2::ngtcp2_conn_shutdown_stream_write(self.conn.get(), 0, id, code);
        }
        self.flush(global);
        self.schedule_event_dispatch();
        self.rearm_timer();
    }

    /// `rearm_timer` for callers outside this module (streams kicking the
    /// session after queueing data).
    pub(super) fn rearm_timer_pub(&self) {
        self.rearm_timer();
    }

    /// Stream events produced while servicing a JS-initiated call (write,
    /// open, shutdown) are not dispatched underneath the caller; deliver them
    /// on the next event-loop turn instead, like Node's deferred callbacks.
    pub(super) fn schedule_event_dispatch(&self) {
        if self.destroyed.get() || self.stream_events.get().is_empty() {
            return;
        }
        let next = bun_core::Timespec::ms_from_now(bun_core::TimespecMockMode::ForceRealTime, 1);
        // SAFETY: `event_loop_timer` is the live inline timer field of this
        // heap-allocated session.
        timer_all().update(self.event_loop_timer.as_ptr(), &next);
    }

    pub(crate) fn send_datagram(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Err(global.throw(format_args!("QuicSession.sendDatagram is not implemented yet")))
    }

    fn transport_params_to_js(
        &self,
        global: &JSGlobalObject,
        params: *const ngtcp2::ngtcp2_transport_params,
    ) -> JsResult<JSValue> {
        if params.is_null() {
            return Ok(JSValue::UNDEFINED);
        }
        let obj = JSValue::create_empty_object(global, 12);
        // SAFETY: ngtcp2 returns a pointer to conn-owned params, valid for the
        // duration of this call.
        let p = unsafe { &*params };
        let put = |name: &str, value: u64| {
            obj.put(global, name.as_bytes(), JSValue::from_uint64_no_truncate(global, value));
        };
        put("initialMaxStreamDataBidiLocal", p.initial_max_stream_data_bidi_local);
        put("initialMaxStreamDataBidiRemote", p.initial_max_stream_data_bidi_remote);
        put("initialMaxStreamDataUni", p.initial_max_stream_data_uni);
        put("initialMaxData", p.initial_max_data);
        put("initialMaxStreamsBidi", p.initial_max_streams_bidi);
        put("initialMaxStreamsUni", p.initial_max_streams_uni);
        put("maxIdleTimeout", p.max_idle_timeout / ngtcp2::NGTCP2_MILLISECONDS);
        put("activeConnectionIDLimit", p.active_connection_id_limit);
        put("ackDelayExponent", p.ack_delay_exponent);
        put("maxAckDelay", p.max_ack_delay / ngtcp2::NGTCP2_MILLISECONDS);
        put("maxDatagramFrameSize", p.max_datagram_frame_size);
        Ok(obj)
    }

    pub(crate) fn local_transport_params(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        if self.conn.get().is_null() {
            return Ok(JSValue::UNDEFINED);
        }
        // SAFETY: `conn` is live.
        let params = unsafe { ngtcp2::ngtcp2_conn_get_local_transport_params(self.conn.get()) };
        self.transport_params_to_js(global, params)
    }

    pub(crate) fn remote_transport_params(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        if self.conn.get().is_null() {
            return Ok(JSValue::UNDEFINED);
        }
        // SAFETY: `conn` is live.
        let params = unsafe { ngtcp2::ngtcp2_conn_get_remote_transport_params(self.conn.get()) };
        self.transport_params_to_js(global, params)
    }

    pub(crate) fn application_options(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Ok(JSValue::create_empty_object(global, 0))
    }
}
