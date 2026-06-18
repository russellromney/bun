//! `QuicEndpoint` native handle — the Bun equivalent of Node's
//! `internalBinding('quic').Endpoint` (node/src/quic/endpoint.{h,cc}).
//!
//! Networking phase 1: the endpoint owns a real uSockets UDP socket (bound
//! lazily on `listen()`, like Node binds on listen/connect), exposes its bound
//! address, and tracks state/stats. QUIC sessions are not implemented yet, so
//! received packets are only counted and `connect()` still fails; that lands
//! with the session/handshake phase.

use core::cell::Cell;
use core::ffi::{c_int, c_void};

use bun_io::KeepAlive;
use bun_jsc::{ArrayBuffer, CallFrame, JSGlobalObject, JSType, JSValue, JsCell, JsRef, JsResult, Strong};
use bun_uws as uws;

use crate::socket::SocketAddress;

use super::callbacks;
use super::now_ns;

/// Mirrors Node's `Endpoint::State` (node/src/quic/endpoint.cc `ENDPOINT_STATE`).
/// The `IDX_STATE_ENDPOINT_*` constants exposed on the binding are
/// `offset_of!` values into this struct, and `QuicEndpoint.state` is an
/// ArrayBuffer over a live instance of it, so the layout can never drift from
/// what JS reads.
#[repr(C)]
pub struct EndpointState {
    pub bound: u8,
    pub receiving: u8,
    pub listening: u8,
    pub closing: u8,
    pub busy: u8,
    pub max_connections_per_host: u16,
    pub max_connections_total: u16,
    pub pending_callbacks: u64,
}

/// Node's `ENDPOINT_STATS` field names, in declaration order. Slot index in
/// the stats buffer == position in this list (node/src/quic/endpoint.cc).
pub(super) const ENDPOINT_STATS_FIELDS: &[&str] = &[
    "CREATED_AT",
    "DESTROYED_AT",
    "BYTES_RECEIVED",
    "BYTES_SENT",
    "PACKETS_RECEIVED",
    "PACKETS_SENT",
    "SERVER_SESSIONS",
    "CLIENT_SESSIONS",
    "SERVER_BUSY_COUNT",
    "RETRY_COUNT",
    "RETRY_RATE_LIMITED",
    "VERSION_NEGOTIATION_COUNT",
    "VERSION_NEGOTIATION_RATE_LIMITED",
    "STATELESS_RESET_COUNT",
    "STATELESS_RESET_RATE_LIMITED",
    "IMMEDIATE_CLOSE_COUNT",
    "IMMEDIATE_CLOSE_RATE_LIMITED",
    "SESSION_CREATION_RATE_LIMITED",
    "PACKETS_BLOCKED",
];

const IDX_STATS_CREATED_AT: usize = 0;
const IDX_STATS_DESTROYED_AT: usize = 1;
const IDX_STATS_BYTES_RECEIVED: usize = 2;
const IDX_STATS_PACKETS_RECEIVED: usize = 4;

/// `CloseContext` values passed to `onEndpointClose` (node/src/quic/endpoint.h).
pub(super) const CLOSECONTEXT_CLOSE: u8 = 0;
pub(super) const CLOSECONTEXT_BIND_FAILURE: u8 = 1;
pub(super) const CLOSECONTEXT_START_FAILURE: u8 = 2;
pub(super) const CLOSECONTEXT_RECEIVE_FAILURE: u8 = 3;
pub(super) const CLOSECONTEXT_SEND_FAILURE: u8 = 4;
pub(super) const CLOSECONTEXT_LISTEN_FAILURE: u8 = 5;

/// Local bind configuration captured from the constructor's processed options.
struct BindConfig {
    /// Presentation-format IP, NUL-terminated for the uSockets call.
    host: Vec<u8>,
    port: u16,
}

impl Default for BindConfig {
    fn default() -> Self {
        // Node's Endpoint::Options default local address is 127.0.0.1:0
        // (node/src/quic/endpoint.h `local_address`).
        BindConfig { host: b"127.0.0.1\0".to_vec(), port: 0 }
    }
}

pub struct QuicEndpoint {
    /// Borrowed view into the JSC-owned ArrayBuffer exposed as the wrapper's
    /// `state` own property. The wrapper owns both that ArrayBuffer (via the
    /// property) and this struct (via finalize), so the pointer is valid for
    /// the life of this struct and is never freed here.
    state: *mut EndpointState,
    /// Same ownership story as `state`; `ENDPOINT_STATS_FIELDS.len()` u64
    /// slots exposed as the wrapper's `stats` own property.
    stats: *mut u64,
    closed: Cell<bool>,

    /// The uSockets UDP socket once bound (lazily, on `listen()`).
    socket: Cell<Option<*mut uws::udp::Socket>>,
    bind_config: JsCell<BindConfig>,
    /// Keeps the event loop alive while the socket is open and receiving.
    poll_ref: JsCell<KeepAlive>,
    /// The JS wrapper; held strong while the UDP socket is open so callbacks
    /// can reach it and GC cannot collect a live endpoint.
    this_value: JsCell<JsRef>,
    /// The processed session options passed to `listen()`, kept alive for the
    /// session phase (TLS configuration for incoming connections).
    listen_options: JsCell<Option<Strong>>,
}

extern "C" fn on_drain(_socket: *mut uws::udp::Socket) {}

extern "C" fn on_close(_socket: *mut uws::udp::Socket) {}

extern "C" fn on_recv_error(_socket: *mut uws::udp::Socket, _errno: c_int) {}

extern "C" fn on_data(socket: *mut uws::udp::Socket, buf: *mut uws::udp::PacketBuffer, packets: c_int) {
    let user = uws::udp::Socket::opaque_mut(socket).user();
    if user.is_null() {
        return;
    }
    // SAFETY: `user` was set to the heap-allocated `QuicEndpoint` at bind time
    // and stays live until `on_close` (uws guarantees no callbacks after
    // close); all mutated fields are `Cell`-based so a shared borrow suffices.
    let this = unsafe { &*user.cast::<QuicEndpoint>() };
    if this.closed.get() {
        return;
    }
    // SAFETY: `buf` is valid for the duration of this callback per uSockets.
    let buf = unsafe { &mut *buf };
    let mut bytes: u64 = 0;
    for i in 0..packets {
        bytes += buf.get_payload(i).len() as u64;
    }
    // No QUIC sessions yet: count traffic, drop payloads. Session routing by
    // DCID lands with the handshake phase.
    this.add_stat(IDX_STATS_PACKETS_RECEIVED, packets.max(0) as u64);
    this.add_stat(IDX_STATS_BYTES_RECEIVED, bytes);
}

/// Create a zero-filled ArrayBuffer of `len` bytes, attach it to `this_value`
/// under `name`, and return the live backing pointer (owned by the JSC
/// ArrayBuffer, which the wrapper keeps alive via the property).
fn alloc_exposed_array_buffer(
    global: &JSGlobalObject,
    this_value: JSValue,
    name: &[u8],
    len: usize,
) -> JsResult<*mut u8> {
    let zeroes = vec![0u8; len];
    let buf = ArrayBuffer::create::<{ JSType::ArrayBuffer }>(global, &zeroes)?;
    let Some(view) = buf.as_array_buffer(global) else {
        return Err(global.throw(format_args!("Failed to allocate QUIC state buffer")));
    };
    this_value.put(global, name, buf);
    Ok(view.ptr)
}

impl QuicEndpoint {
    fn state_mut(&self) -> *mut EndpointState {
        self.state
    }

    fn write_stat(&self, index: usize, value: u64) {
        debug_assert!(index < ENDPOINT_STATS_FIELDS.len());
        // SAFETY: index is in bounds of the stats allocation; unaligned write
        // because ArrayBuffer contents only guarantee byte alignment.
        unsafe { self.stats.add(index).write_unaligned(value) };
    }

    fn read_stat(&self, index: usize) -> u64 {
        debug_assert!(index < ENDPOINT_STATS_FIELDS.len());
        // SAFETY: as in `write_stat`.
        unsafe { self.stats.add(index).read_unaligned() }
    }

    fn add_stat(&self, index: usize, delta: u64) {
        self.write_stat(index, self.read_stat(index).wrapping_add(delta));
    }

    pub(crate) fn constructor(
        global: &JSGlobalObject,
        frame: &CallFrame,
        this_value: JSValue,
    ) -> JsResult<*mut QuicEndpoint> {
        // The processed options object from the JS layer (option validation
        // lives in JS, as in Node). The only field consumed natively so far is
        // `address`, the local SocketAddress to bind to.
        let options = frame.arguments_as_array::<1>()[0];

        let mut bind_config = BindConfig::default();
        if options.is_object() {
            let address = options.get(global, "address")?;
            if let Some(address) = address.filter(|v| !v.is_empty_or_undefined_or_null()) {
                if let Some(addr) = crate::generated_classes::js_SocketAddress::from_js(address) {
                    // SAFETY: `from_js` returned a live SocketAddress owned by
                    // the JS wrapper held in `options`, which outlives this call.
                    let addr = unsafe { addr.as_ref() };
                    let mut host = addr.address().to_utf8_bytes();
                    host.push(0);
                    bind_config = BindConfig { host, port: addr.port() };
                }
            }
        }

        // Same shape as Node: `state` and `stats` are own properties of the
        // handle object (node/src/quic/endpoint.cc JS_DEFINE_READONLY_PROPERTY).
        // They must be real ArrayBuffers — the JS layer constructs DataView /
        // BigUint64Array over them directly.
        let state_ptr = alloc_exposed_array_buffer(
            global,
            this_value,
            b"state",
            core::mem::size_of::<EndpointState>(),
        )?;
        let stats_ptr = alloc_exposed_array_buffer(
            global,
            this_value,
            b"stats",
            ENDPOINT_STATS_FIELDS.len() * core::mem::size_of::<u64>(),
        )?;

        let endpoint = QuicEndpoint {
            state: state_ptr.cast::<EndpointState>(),
            stats: stats_ptr.cast::<u64>(),
            closed: Cell::new(false),
            socket: Cell::new(None),
            bind_config: JsCell::new(bind_config),
            poll_ref: JsCell::new(KeepAlive::init()),
            this_value: JsCell::new(JsRef::empty()),
            listen_options: JsCell::new(None),
        };
        endpoint.write_stat(IDX_STATS_CREATED_AT, now_ns());

        Ok(bun_core::heap::into_raw(Box::new(endpoint)))
    }

    pub(crate) fn finalize(self: Box<Self>) {
        // Reachable only after close (the wrapper is held strong while the UDP
        // socket is open) or for endpoints that never bound; either way there
        // is no socket left to release. The state/stats buffers are owned by
        // the (now unreachable) wrapper.
        debug_assert!(self.socket.get().is_none());
    }

    /// Bind the UDP socket if not already bound. Mirrors Node's lazy bind in
    /// `Endpoint::Listen`/`Endpoint::Connect`.
    fn ensure_bound(&self, global: &JSGlobalObject, this_value: JSValue, this_ptr: *const Self) -> JsResult<()> {
        if self.socket.get().is_some() {
            return Ok(());
        }
        let mut err: c_int = 0;
        let cfg = self.bind_config.get();
        let (host_ptr, port) = (cfg.host.as_ptr(), cfg.port);
        let socket = uws::udp::Socket::create(
            uws::Loop::get(),
            on_data,
            on_drain,
            on_close,
            on_recv_error,
            host_ptr.cast(),
            port,
            0,
            Some(&mut err),
            this_ptr.cast_mut().cast::<c_void>(),
        );
        if socket.is_null() {
            return Err(global.throw(format_args!(
                "Failed to bind QUIC endpoint UDP socket (errno {err})"
            )));
        }
        self.socket.set(Some(socket));

        // Keep the wrapper and the event loop alive while the socket is open.
        self.this_value.with_mut(|r| r.set_strong(this_value, global));
        self.poll_ref.with_mut(|p| p.ref_(bun_io::js_vm_ctx()));

        // SAFETY: see `state` field docs.
        unsafe {
            (*self.state_mut()).bound = 1;
            (*self.state_mut()).receiving = 1;
        }
        Ok(())
    }

    pub(crate) fn listen(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if self.closed.get() {
            return Err(global.throw(format_args!("Endpoint is closed")));
        }
        // SAFETY: see `state` field docs.
        if unsafe { (*self.state_mut()).listening } != 0 {
            return Ok(JSValue::UNDEFINED);
        }
        let options = frame.arguments_as_array::<1>()[0];
        // Keep the processed session options (TLS config for inbound sessions)
        // alive for the session phase.
        if options.is_object() {
            self.listen_options.set(Some(Strong::create(options, global)));
        }
        // `this` is the handle wrapper (the prototype method is invoked on it).
        let this_value = frame.this();
        self.ensure_bound(global, this_value, core::ptr::from_ref(self))?;
        // SAFETY: see `state` field docs.
        unsafe { (*self.state_mut()).listening = 1 };
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn connect(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Err(global.throw(format_args!("QuicEndpoint.connect is not implemented yet")))
    }

    pub(crate) fn set_sni_contexts(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Err(global.throw(format_args!("QuicEndpoint.setSNIContexts is not implemented yet")))
    }

    pub(crate) fn mark_busy(&self, _global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        let busy = frame.arguments_as_array::<1>()[0].to_boolean();
        // SAFETY: see `state` field docs.
        unsafe { (*self.state_mut()).busy = busy as u8 };
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn do_ref(&self, _global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        // Node refs/unrefs the underlying uv handle; map to the event-loop
        // KeepAlive when a socket exists.
        let on = frame.arguments_as_array::<1>()[0].to_boolean();
        if self.socket.get().is_some() && !self.closed.get() {
            let ctx = bun_io::js_vm_ctx();
            self.poll_ref.with_mut(|p| if on { p.ref_(ctx) } else { p.unref(ctx) });
        }
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn address(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        let Some(socket) = self.socket.get() else {
            // Not bound: Node returns undefined.
            return Ok(JSValue::UNDEFINED);
        };
        if self.closed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        let socket = uws::udp::Socket::opaque_mut(socket);
        let port = socket.bound_port();
        if port <= 0 {
            return Ok(JSValue::UNDEFINED);
        }
        let mut ip = [0u8; 16];
        let mut len: i32 = ip.len() as i32;
        socket.bound_ip(ip.as_mut_ptr(), &mut len);
        let addr = match len {
            4 => SocketAddress::init_ipv4([ip[0], ip[1], ip[2], ip[3]], port as u16),
            16 => SocketAddress::init_ipv6(ip, port as u16, 0, 0),
            _ => return Ok(JSValue::UNDEFINED),
        };
        let boxed = SocketAddress::new(addr);
        Ok(crate::generated_classes::js_SocketAddress::to_js(
            bun_core::heap::into_raw(boxed),
            global,
        ))
    }

    pub(crate) fn close_gracefully(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if !self.closed.replace(true) {
            if let Some(socket) = self.socket.take() {
                // Synchronously triggers `on_close`; our handler is a no-op and
                // the user pointer is still valid here.
                uws::udp::Socket::opaque_mut(socket).close();
            }
            self.poll_ref.with_mut(|p| p.disable());
            self.listen_options.set(None);

            // SAFETY: see `state` field docs.
            unsafe {
                let state = self.state_mut();
                (*state).closing = 1;
                (*state).bound = 0;
                (*state).receiving = 0;
                (*state).listening = 0;
            }
            self.write_stat(IDX_STATS_DESTROYED_AT, now_ns());

            // Allow GC of the wrapper again now that the socket is gone.
            self.this_value.with_mut(|r| r.downgrade());

            // Node invokes onEndpointClose(context, status) with the handle as
            // `this` once all pending work is done; with no sessions yet that
            // is immediately.
            if let Some(callback) = callbacks::get(global, "onEndpointClose") {
                let vm = global.bun_vm().as_mut();
                vm.event_loop_ref().run_callback(
                    callback,
                    global,
                    frame.this(),
                    &[JSValue::js_number(f64::from(CLOSECONTEXT_CLOSE)), JSValue::js_number(0.0)],
                );
            }
        }
        Ok(JSValue::UNDEFINED)
    }
}
