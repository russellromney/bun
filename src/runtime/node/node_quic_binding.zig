//! Path key for the `$zig("node_quic_binding.zig", ...)` js2native bindings
//! used by `src/js/internal/quic/binding.ts`. The implementation lives in
//! `src/runtime/node/node_quic_binding.rs` (binding object) and
//! `src/runtime/node/quic/` (endpoint/session/stream); this file is never
//! compiled. The name must stay globally unique — `src/uws_sys/quic.zig`
//! already claims `quic.zig`.
