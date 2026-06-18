//! `QuicStream` native handle skeleton (Node: node/src/quic/streams.{h,cc}).
//! Streams are created natively from sessions; with no networking yet,
//! instances are never created and every method is a stub.

use bun_jsc::{CallFrame, JSGlobalObject, JSValue, JsResult};

/// Mirrors Node's `Stream::State` (`STREAM_STATE` in node/src/quic/streams.cc).
/// `IDX_STATE_STREAM_*` binding constants are `offset_of!` values into this.
#[repr(C)]
pub struct StreamState {
    pub id: i64,
    pub pending: u8,
    pub fin_sent: u8,
    pub fin_received: u8,
    pub read_ended: u8,
    pub write_ended: u8,
    pub reset: u8,
    pub reset_code: u64,
    pub has_outbound: u8,
    pub has_reader: u8,
    pub wants_block: u8,
    pub wants_headers: u8,
    pub wants_reset: u8,
    pub wants_trailers: u8,
    pub received_early_data: u8,
    pub write_desired_size: u32,
    pub high_water_mark: u32,
}

/// Node's `STREAM_STATS` field names, in declaration order.
pub(super) const STREAM_STATS_FIELDS: &[&str] = &[
    "CREATED_AT",
    "OPENED_AT",
    "RECEIVED_AT",
    "ACKED_AT",
    "DESTROYED_AT",
    "BYTES_RECEIVED",
    "BYTES_SENT",
    "MAX_OFFSET",
    "MAX_OFFSET_ACK",
    "MAX_OFFSET_RECV",
    "FINAL_SIZE",
    "BYTES_ACCUMULATED",
    "MAX_BYTES_ACCUMULATED",
];

pub struct QuicStream {
    /// Reserved for the networking phase. Keeps the type non-zero-sized for
    /// the C++ wrapper allocation.
    _reserved: u8,
}

macro_rules! stub_method {
    ($($name:ident => $js_name:literal),+ $(,)?) => {
        $(
            pub(crate) fn $name(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
                Err(global.throw(format_args!(concat!("QuicStream.", $js_name, " is not implemented yet"))))
            }
        )+
    };
}

impl QuicStream {
    pub(crate) fn finalize(self: Box<Self>) {}

    pub(crate) fn destroy(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn get_priority(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        // Packed (urgency << 1) | incremental; NGHTTP3 default urgency is 3.
        Ok(JSValue::js_number(f64::from(3u32 << 1)))
    }

    stub_method! {
        attach_source => "attachSource",
        send_headers => "sendHeaders",
        stop_sending => "stopSending",
        reset_stream => "resetStream",
        set_priority => "setPriority",
        get_reader => "getReader",
        init_streaming_source => "initStreamingSource",
        write => "write",
        end_write => "endWrite",
    }
}
