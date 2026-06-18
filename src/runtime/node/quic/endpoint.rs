//! `QuicEndpoint` native handle — the Bun equivalent of Node's
//! `internalBinding('quic').Endpoint` (node/src/quic/endpoint.{h,cc}).
//!
//! Skeleton phase: the endpoint owns its `state`/`stats` buffers and basic
//! lifecycle, but no UDP socket or QUIC sessions yet — `listen`/`connect`/
//! `setSNIContexts` fail with a plain error until the networking phase lands.

use core::cell::Cell;

use bun_jsc::{ArrayBuffer, CallFrame, JSGlobalObject, JSType, JSValue, JsResult};

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

/// `CloseContext` values passed to `onEndpointClose` (node/src/quic/endpoint.h).
pub(super) const CLOSECONTEXT_CLOSE: u8 = 0;
pub(super) const CLOSECONTEXT_BIND_FAILURE: u8 = 1;
pub(super) const CLOSECONTEXT_START_FAILURE: u8 = 2;
pub(super) const CLOSECONTEXT_RECEIVE_FAILURE: u8 = 3;
pub(super) const CLOSECONTEXT_SEND_FAILURE: u8 = 4;
pub(super) const CLOSECONTEXT_LISTEN_FAILURE: u8 = 5;

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
}

impl QuicEndpoint {
    fn state(&self) -> &EndpointState {
        // SAFETY: see field docs — the buffer outlives this struct and is only
        // touched from the JS thread.
        unsafe { &*self.state }
    }

    fn state_mut(&self) -> *mut EndpointState {
        self.state
    }

    fn write_stat(&self, index: usize, value: u64) {
        debug_assert!(index < ENDPOINT_STATS_FIELDS.len());
        // SAFETY: index is in bounds of the stats allocation; unaligned write
        // because ArrayBuffer contents only guarantee byte alignment.
        unsafe { self.stats.add(index).write_unaligned(value) };
    }

    pub(crate) fn constructor(
        global: &JSGlobalObject,
        frame: &CallFrame,
        this_value: JSValue,
    ) -> JsResult<*mut QuicEndpoint> {
        // The processed options object from the JS layer. Option validation
        // lives in JS (as in Node); the skeleton does not consume any endpoint
        // options natively yet.
        let _options = frame.arguments_as_array::<1>()[0];

        let state_len = core::mem::size_of::<EndpointState>() as u32;
        let (state_buf, state_bytes) = ArrayBuffer::alloc::<{ JSType::ArrayBuffer }>(global, state_len)?;
        state_bytes.fill(0);

        let stats_len = (ENDPOINT_STATS_FIELDS.len() * core::mem::size_of::<u64>()) as u32;
        let (stats_buf, stats_bytes) = ArrayBuffer::alloc::<{ JSType::ArrayBuffer }>(global, stats_len)?;
        stats_bytes.fill(0);

        // Same shape as Node: `state` and `stats` are own properties of the
        // handle object (node/src/quic/endpoint.cc JS_DEFINE_READONLY_PROPERTY).
        this_value.put(global, b"state", state_buf);
        this_value.put(global, b"stats", stats_buf);

        let endpoint = QuicEndpoint {
            state: state_bytes.as_mut_ptr().cast::<EndpointState>(),
            stats: stats_bytes.as_mut_ptr().cast::<u64>(),
            closed: Cell::new(false),
        };
        endpoint.write_stat(IDX_STATS_CREATED_AT, now_ns());

        Ok(bun_core::heap::into_raw(Box::new(endpoint)))
    }

    pub(crate) fn finalize(self: Box<Self>) {
        // The state/stats buffers are owned by the (now unreachable) wrapper;
        // nothing to release here.
    }

    pub(crate) fn listen(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Err(global.throw(format_args!("QuicEndpoint.listen is not implemented yet")))
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

    pub(crate) fn do_ref(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        // No UDP handle to ref/unref yet.
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn address(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        // Not bound to a UDP socket in the skeleton; Node returns undefined
        // when the endpoint is not bound.
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn close_gracefully(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if !self.closed.replace(true) {
            // SAFETY: see `state` field docs.
            unsafe {
                let state = self.state_mut();
                (*state).closing = 1;
                (*state).bound = 0;
                (*state).receiving = 0;
                (*state).listening = 0;
            }
            let _ = self.state();
            self.write_stat(IDX_STATS_DESTROYED_AT, now_ns());

            // Node invokes onEndpointClose(context, status) with the handle as
            // `this` once all pending work is done; with no networking yet that
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
