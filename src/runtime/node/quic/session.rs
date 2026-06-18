//! `QuicSession` native handle skeleton (Node: node/src/quic/session.{h,cc}).
//! Sessions are created natively (never constructed from JS); no networking
//! exists yet, so instances are never created and every method is a stub.

use bun_jsc::{CallFrame, JSGlobalObject, JSValue, JsResult};

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
pub(super) const SESSION_STATS_FIELDS: &[&str] = &[
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

pub struct QuicSession {
    /// Reserved for the networking phase (ngtcp2 connection state). Keeps the
    /// type non-zero-sized for the C++ wrapper allocation.
    _reserved: u8,
}

macro_rules! stub_method {
    ($($name:ident => $js_name:literal),+ $(,)?) => {
        $(
            pub(crate) fn $name(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
                Err(global.throw(format_args!(concat!("QuicSession.", $js_name, " is not implemented yet"))))
            }
        )+
    };
}

impl QuicSession {
    pub(crate) fn finalize(self: Box<Self>) {}

    pub(crate) fn destroy(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn get_remote_address(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn get_local_address(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Ok(JSValue::UNDEFINED)
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

    stub_method! {
        graceful_close => "gracefulClose",
        silent_close => "silentClose",
        update_key => "updateKey",
        open_stream => "openStream",
        send_datagram => "sendDatagram",
        local_transport_params => "localTransportParams",
        remote_transport_params => "remoteTransportParams",
        application_options => "applicationOptions",
    }
}
