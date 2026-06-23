//! `QuicStream` native handle (Node reference: node/src/quic/streams.{h,cc}).
//!
//! A stream is owned by its session: created locally through
//! `session.openStream(direction, body)` or remotely when ngtcp2 reports a
//! peer-initiated stream. Outbound data lives in a per-stream queue the
//! session's write loop drains into `ngtcp2_conn_writev_stream`; inbound data
//! is appended by the session's packet processing and consumed by the JS
//! layer through the reader protocol (`getReader()` returns this handle,
//! which implements `setWakeup(fn)` / `pull(cb(status, buffer))`).

use core::cell::Cell;
use core::ptr::null_mut;
use std::collections::VecDeque;

use bun_jsc::{ArrayBuffer, CallFrame, JSGlobalObject, JSType, JSValue, JsCell, JsRef, JsResult, Strong};

use super::session::QuicSession;

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
pub(crate) const STREAM_STATS_FIELDS: &[&str] = &[
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

const IDX_STATS_CREATED_AT: usize = 0;
const IDX_STATS_OPENED_AT: usize = 1;
const IDX_STATS_RECEIVED_AT: usize = 2;
const IDX_STATS_DESTROYED_AT: usize = 4;
const IDX_STATS_BYTES_RECEIVED: usize = 5;

/// Default high-water mark for streaming outbound sources (matches the JS
/// layer's kDefaultHighWaterMark).
const DEFAULT_HIGH_WATER_MARK: u32 = 65536;

/// Reader pull statuses (lib/internal/blob.js protocol the JS layer ports).
const PULL_STATUS_EOS: f64 = 0.0;
const PULL_STATUS_DATA: f64 = 1.0;
const PULL_STATUS_BLOCKED: f64 = 2.0;
const PULL_STATUS_ERROR: f64 = -1.0;

/// One chunk of stream data that has been handed to ngtcp2. ngtcp2 keeps the
/// pointer until the bytes are acknowledged, so the allocation must stay
/// alive (and at a stable address) until `acked` covers it.
pub(super) struct InflightChunk {
    pub bytes: Box<[u8]>,
    /// Stream offset of the first byte of `bytes`.
    pub start: u64,
    /// How many bytes of `bytes` ngtcp2 actually accepted.
    pub accepted: usize,
}

/// Outbound body data queued for transmission.
#[derive(Default)]
pub(super) struct Outbound {
    /// Bytes not yet handed to ngtcp2.
    pub data: VecDeque<u8>,
    /// Chunks handed to ngtcp2 that are not yet fully acknowledged.
    pub inflight: Vec<InflightChunk>,
    /// Total bytes accepted by ngtcp2 so far (the next chunk's stream offset).
    pub submitted: u64,
    /// Contiguously acknowledged prefix of the stream.
    pub acked: u64,
    /// The writable side ends once `data` drains.
    pub fin_pending: bool,
    /// `true` once a source was attached or the streaming source started.
    pub started: bool,
}

/// Inbound data received from the peer, waiting for the JS reader.
#[derive(Default)]
pub(super) struct Inbound {
    pub chunks: VecDeque<Vec<u8>>,
    pub ended: bool,
    pub errored: bool,
}

pub struct QuicStream {
    /// The owning session; valid while `session_js` keeps its wrapper alive.
    session: Cell<*mut QuicSession>,
    session_js: JsCell<Option<Strong>>,
    /// The stream handle wrapper; strong while the stream is live.
    this_value: JsCell<JsRef>,
    state: Cell<*mut StreamState>,
    stats: Cell<*mut u64>,
    id: Cell<i64>,
    pub(super) outbound: JsCell<Outbound>,
    pub(super) inbound: JsCell<Inbound>,
    /// JS wakeup callback registered by the reader (`setWakeup`).
    wakeup: JsCell<Option<Strong>>,
    destroyed: Cell<bool>,
}

impl QuicStream {
    pub(super) fn state_mut(&self) -> *mut StreamState {
        self.state.get()
    }

    fn write_stat(&self, index: usize, value: u64) {
        let stats = self.stats.get();
        if stats.is_null() {
            return;
        }
        debug_assert!(index < STREAM_STATS_FIELDS.len());
        // SAFETY: in-bounds slot of the wrapper-owned stats buffer.
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

    pub(super) fn handle(&self) -> JSValue {
        self.this_value.get().get()
    }

    pub(super) fn is_destroyed(&self) -> bool {
        self.destroyed.get()
    }

    /// Create the native struct + JS wrapper with attached state/stats
    /// buffers for a stream with the given id.
    pub(super) fn create(
        global: &JSGlobalObject,
        session: *mut QuicSession,
        session_handle: JSValue,
        id: i64,
    ) -> JsResult<(*mut QuicStream, JSValue)> {
        let stream = QuicStream {
            session: Cell::new(session),
            session_js: JsCell::new(Some(Strong::create(session_handle, global))),
            this_value: JsCell::new(JsRef::empty()),
            state: Cell::new(null_mut()),
            stats: Cell::new(null_mut()),
            id: Cell::new(id),
            outbound: JsCell::new(Outbound::default()),
            inbound: JsCell::new(Inbound::default()),
            wakeup: JsCell::new(None),
            destroyed: Cell::new(false),
        };
        let raw = bun_core::heap::into_raw(Box::new(stream));
        let handle = crate::generated_classes::js_QuicStream::to_js(raw, global);

        let state_ptr = super::endpoint::alloc_exposed_array_buffer(
            global,
            handle,
            b"state",
            core::mem::size_of::<StreamState>(),
        )?;
        let stats_ptr = super::endpoint::alloc_exposed_array_buffer(
            global,
            handle,
            b"stats",
            STREAM_STATS_FIELDS.len() * core::mem::size_of::<u64>(),
        )?;
        handle.put(global, b"stateByteOffset", JSValue::js_number(0.0));
        handle.put(global, b"statsByteOffset", JSValue::js_number(0.0));

        // SAFETY: `raw` was just created and is uniquely owned by the wrapper.
        let this = unsafe { &*raw };
        this.state.set(state_ptr.cast::<StreamState>());
        this.stats.set(stats_ptr.cast::<u64>());
        this.this_value.with_mut(|r| r.set_strong(handle, global));
        let now = super::now_ns();
        this.write_stat(IDX_STATS_CREATED_AT, now);
        this.write_stat(IDX_STATS_OPENED_AT, now);
        // SAFETY: state buffer is zero-initialized and live.
        unsafe {
            (*this.state_mut()).id = id;
            (*this.state_mut()).high_water_mark = DEFAULT_HIGH_WATER_MARK;
        }

        Ok((raw, handle))
    }

    /// Append peer data (and/or the FIN flag) for the JS reader.
    pub(super) fn push_inbound(&self, data: &[u8], fin: bool) {
        if self.destroyed.get() {
            return;
        }
        self.inbound.with_mut(|inbound| {
            if !data.is_empty() {
                inbound.chunks.push_back(data.to_vec());
            }
            if fin {
                inbound.ended = true;
            }
        });
        if !data.is_empty() {
            self.add_stat(IDX_STATS_BYTES_RECEIVED, data.len() as u64);
            self.write_stat(IDX_STATS_RECEIVED_AT, super::now_ns());
        }
        if fin {
            // SAFETY: state buffer is live while the wrapper is.
            unsafe { (*self.state_mut()).fin_received = 1 };
        }
    }

    /// The peer reset the stream: discard pending inbound data and surface the
    /// error through the reader.
    pub(super) fn mark_reset(&self, code: u64) {
        if self.destroyed.get() {
            return;
        }
        self.inbound.with_mut(|inbound| {
            inbound.chunks.clear();
            inbound.errored = true;
            inbound.ended = true;
        });
        // SAFETY: state buffer is live while the wrapper is.
        unsafe {
            (*self.state_mut()).reset = 1;
            (*self.state_mut()).reset_code = code;
            (*self.state_mut()).read_ended = 1;
        }
    }

    /// Take the registered reader wakeup (one-shot per registration).
    pub(super) fn take_wakeup(&self) -> Option<Strong> {
        self.wakeup.replace(None)
    }

    pub(super) fn mark_fin_sent(&self) {
        // SAFETY: state buffer is live while the wrapper is.
        unsafe {
            (*self.state_mut()).fin_sent = 1;
            (*self.state_mut()).write_ended = 1;
        }
    }

    pub(super) fn has_pending_outbound(&self) -> bool {
        let outbound = self.outbound.get();
        // SAFETY: state buffer is live while the wrapper is.
        let fin_sent = unsafe { (*self.state_mut()).fin_sent } != 0;
        !outbound.data.is_empty() || (outbound.fin_pending && !fin_sent)
    }

    /// Move up to `max` queued bytes into a stable in-flight chunk and return
    /// its pointer/length for ngtcp2. The chunk stays owned by the stream
    /// until the peer acknowledges it (`on_acked`).
    pub(super) fn stage_chunk(&self, max: usize) -> (*const u8, usize) {
        self.outbound.with_mut(|outbound| {
            let take = outbound.data.len().min(max);
            if take == 0 {
                return (core::ptr::null(), 0);
            }
            let bytes: Box<[u8]> = outbound.data.iter().copied().take(take).collect();
            let ptr = bytes.as_ptr();
            outbound.inflight.push(InflightChunk { bytes, start: outbound.submitted, accepted: 0 });
            (ptr, take)
        })
    }

    /// Record how much of the most recently staged chunk ngtcp2 accepted.
    /// The unaccepted tail returns to the head of the unsent queue; a chunk
    /// nothing was taken from is dropped again (ngtcp2 retained no pointer).
    pub(super) fn commit_staged(&self, accepted: usize) {
        self.outbound.with_mut(|outbound| {
            let Some(mut chunk) = outbound.inflight.pop() else { return };
            let staged = chunk.bytes.len();
            let accepted = accepted.min(staged);
            // Remove the staged bytes from the unsent queue.
            outbound.data.drain(..staged.min(outbound.data.len()));
            // Anything ngtcp2 did not take goes back to the front, in order.
            for &byte in chunk.bytes[accepted..].iter().rev() {
                outbound.data.push_front(byte);
            }
            if accepted == 0 {
                return;
            }
            chunk.accepted = accepted;
            outbound.submitted += accepted as u64;
            outbound.inflight.push(chunk);
        });
    }

    /// The peer acknowledged stream data up to `offset + datalen`; in-flight
    /// chunks fully covered by the acknowledged prefix can be released.
    pub(super) fn on_acked(&self, offset: u64, datalen: u64) {
        self.outbound.with_mut(|outbound| {
            let acked_to = offset.saturating_add(datalen);
            if acked_to > outbound.acked {
                outbound.acked = acked_to;
            }
            let acked = outbound.acked;
            outbound
                .inflight
                .retain(|chunk| chunk.start + chunk.accepted as u64 > acked);
        });
    }

    /// Refresh the streaming-source backpressure window after the write loop
    /// consumed queued data. Returns true when the JS writer should be told
    /// it can continue (`onStreamDrain`).
    pub(super) fn refresh_write_capacity(&self) -> bool {
        let pending = self.outbound.get().data.len() as u32;
        // SAFETY: state buffer is live while the wrapper is.
        unsafe {
            let state = self.state_mut();
            let was_zero = (*state).write_desired_size == 0;
            (*state).write_desired_size = (*state).high_water_mark.saturating_sub(pending);
            was_zero && (*state).write_desired_size > 0
        }
    }

    /// Release native resources and detach from the session. Idempotent.
    pub(super) fn teardown(&self) {
        if self.destroyed.replace(true) {
            return;
        }
        self.write_stat(IDX_STATS_DESTROYED_AT, super::now_ns());
        let session = self.session.replace(null_mut());
        if !session.is_null() {
            // SAFETY: the session is alive (we hold its wrapper strong until
            // the line after this).
            unsafe { (*session).unregister_stream(self.id.get()) };
        }
        self.outbound.with_mut(|o| {
            o.data.clear();
            o.fin_pending = false;
        });
        self.inbound.with_mut(|i| i.chunks.clear());
        self.wakeup.set(None);
        self.session_js.set(None);
        self.this_value.with_mut(|r| r.downgrade());
    }

    pub(crate) fn finalize(self: Box<Self>) {}

    // ── JS-visible methods (quic.classes.ts proto) ─────────────────────────

    /// Attach a one-shot outbound body (ArrayBuffer / view bytes). The JS
    /// layer has already validated and normalized the source.
    pub(crate) fn attach_source(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        let source = frame.arguments_as_array::<1>()[0];
        let bytes = if source.is_empty_or_undefined_or_null() {
            Vec::new()
        } else if let Some(buf) = source.as_array_buffer(global) {
            buf.byte_slice().to_vec()
        } else {
            return Err(global.throw(format_args!(
                "Unsupported QUIC stream body source (Blob and FileHandle sources are not implemented yet)"
            )));
        };
        self.outbound.with_mut(|outbound| {
            outbound.started = true;
            outbound.data.extend(bytes.iter().copied());
            outbound.fin_pending = true;
        });
        // SAFETY: state buffer is live while the wrapper is.
        unsafe { (*self.state_mut()).has_outbound = 1 };
        self.kick_session(global);
        Ok(JSValue::UNDEFINED)
    }

    /// Begin a streaming outbound source (`write`/`endWrite` follow).
    pub(crate) fn init_streaming_source(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        self.outbound.with_mut(|outbound| {
            outbound.started = true;
        });
        // SAFETY: state buffer is live while the wrapper is.
        unsafe {
            (*self.state_mut()).has_outbound = 1;
            (*self.state_mut()).write_desired_size = (*self.state_mut()).high_water_mark;
        }
        Ok(JSValue::UNDEFINED)
    }

    /// Queue one batch of Uint8Arrays from the streaming source.
    pub(crate) fn write(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        let batch = frame.arguments_as_array::<1>()[0];
        let mut queued: u64 = 0;
        let mut append = |bytes: &[u8]| {
            queued += bytes.len() as u64;
            self.outbound.with_mut(|outbound| {
                outbound.data.extend(bytes.iter().copied());
            });
        };
        if batch.is_array() {
            let len = batch.get_length(global)?;
            for i in 0..len {
                let chunk = batch.get_index(global, i as u32)?;
                if let Some(buf) = chunk.as_array_buffer(global) {
                    append(buf.byte_slice());
                }
            }
        } else if let Some(buf) = batch.as_array_buffer(global) {
            append(buf.byte_slice());
        }
        // Backpressure: report the remaining capacity below the high-water
        // mark; the JS writer waits for onStreamDrain when this reaches 0.
        let pending = self.outbound.get().data.len() as u32;
        // SAFETY: state buffer is live while the wrapper is.
        unsafe {
            let state = self.state_mut();
            (*state).write_desired_size = (*state).high_water_mark.saturating_sub(pending);
        }
        self.kick_session(global);
        Ok(JSValue::js_number(queued as f64))
    }

    /// The streaming source is done; send FIN once the queue drains.
    pub(crate) fn end_write(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        self.outbound.with_mut(|outbound| {
            outbound.started = true;
            outbound.fin_pending = true;
        });
        self.kick_session(global);
        Ok(JSValue::UNDEFINED)
    }

    /// Drive the owning session's write loop after queueing outbound data.
    fn kick_session(&self, global: &JSGlobalObject) {
        let session = self.session.get();
        if session.is_null() {
            return;
        }
        // SAFETY: the session outlives its streams (the stream holds the
        // session wrapper strong while attached).
        unsafe {
            (*session).flush(global);
            (*session).rearm_timer_pub();
        }
    }

    /// The reader protocol: the handle itself is the reader object.
    pub(crate) fn get_reader(&self, _global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        // SAFETY: state buffer is live while the wrapper is.
        unsafe { (*self.state_mut()).has_reader = 1 };
        Ok(frame.this())
    }

    /// `setWakeup(fn | undefined)` — register the one-shot wakeup the reader
    /// awaits while blocked.
    pub(crate) fn set_wakeup(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        let callback = frame.arguments_as_array::<1>()[0];
        if callback.is_empty_or_undefined_or_null() {
            self.wakeup.set(None);
        } else {
            self.wakeup.set(Some(Strong::create(callback, global)));
        }
        Ok(JSValue::UNDEFINED)
    }

    /// `pull(cb)` — synchronously report the next chunk / EOS / blocked.
    pub(crate) fn pull(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        let callback = frame.arguments_as_array::<1>()[0];
        if !callback.is_callable() {
            return Ok(JSValue::UNDEFINED);
        }
        let (status, buffer) = self.inbound.with_mut(|inbound| {
            if inbound.errored {
                (PULL_STATUS_ERROR, None)
            } else if let Some(chunk) = inbound.chunks.pop_front() {
                (PULL_STATUS_DATA, Some(chunk))
            } else if inbound.ended {
                (PULL_STATUS_EOS, None)
            } else {
                (PULL_STATUS_BLOCKED, None)
            }
        });
        let buffer_js = match buffer {
            Some(bytes) => {
                let session = self.session.get();
                if !session.is_null() {
                    // Grant back the consumed flow-control credit.
                    // SAFETY: the session outlives its streams.
                    unsafe { (*session).extend_stream_offset(self.id.get(), bytes.len() as u64) };
                }
                ArrayBuffer::create::<{ JSType::ArrayBuffer }>(global, &bytes)?
            }
            None => JSValue::UNDEFINED,
        };
        let vm = global.bun_vm().as_mut();
        vm.event_loop_ref().run_callback(
            callback,
            global,
            JSValue::UNDEFINED,
            &[JSValue::js_number(status), buffer_js],
        );
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn destroy(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        // An explicit destroy with a code resets the sending side and stops
        // requesting data from the peer, like Node.
        let code = frame.arguments_as_array::<1>()[0];
        let code = if code.is_number() { code.as_number().max(0.0) as u64 } else { 0 };
        let session = self.session.get();
        if !session.is_null() {
            // SAFETY: the session outlives its streams.
            unsafe { (*session).shutdown_stream(global, self.id.get(), code) };
        }
        self.teardown();
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn stop_sending(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        let code = frame.arguments_as_array::<1>()[0];
        let code = if code.is_number() { code.as_number().max(0.0) as u64 } else { 0 };
        let session = self.session.get();
        if !session.is_null() {
            // SAFETY: the session outlives its streams.
            unsafe { (*session).stop_sending(global, self.id.get(), code) };
        }
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn reset_stream(&self, global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSValue> {
        if self.destroyed.get() {
            return Ok(JSValue::UNDEFINED);
        }
        let code = frame.arguments_as_array::<1>()[0];
        let code = if code.is_number() { code.as_number().max(0.0) as u64 } else { 0 };
        // SAFETY: state buffer is live while the wrapper is.
        unsafe { (*self.state_mut()).write_ended = 1 };
        let session = self.session.get();
        if !session.is_null() {
            // SAFETY: the session outlives its streams.
            unsafe { (*session).reset_stream_write(global, self.id.get(), code) };
        }
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn send_headers(&self, global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Err(global.throw(format_args!(
            "QuicStream.sendHeaders requires the HTTP/3 application, which is not implemented yet"
        )))
    }

    pub(crate) fn set_priority(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        Ok(JSValue::UNDEFINED)
    }

    pub(crate) fn get_priority(&self, _global: &JSGlobalObject, _frame: &CallFrame) -> JsResult<JSValue> {
        // Packed (urgency << 1) | incremental; NGHTTP3 default urgency is 3.
        Ok(JSValue::js_number(f64::from(3u32 << 1)))
    }
}
