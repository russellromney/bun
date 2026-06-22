//! Per-session TLS state for node:quic (Node reference: src/quic/tlscontext.{h,cc}).
//!
//! Each `Session` owns one `TlsSession`: a BoringSSL `SSL_CTX` + `SSL` pair
//! configured for QUIC through ngtcp2's BoringSSL crypto backend
//! (`ngtcp2_crypto_boringssl_configure_*_context`). The `SSL`'s app data slot
//! (ex_data index 0) holds the session's `ngtcp2_crypto_conn_ref`, which is
//! how the backend's QUIC method callbacks find the owning `ngtcp2_conn`.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr::null_mut;

use bun_boringssl_sys as ssl;
use bun_jsc::{JSGlobalObject, JSValue, JsResult, StringJsc};
use bun_ngtcp2_sys as ngtcp2;

/// `TLSEXT_NAMETYPE_host_name` (`openssl/tls1.h`).
const TLSEXT_NAMETYPE_HOST_NAME: c_int = 0;

/// TLS configuration extracted from the processed `tls` options object the JS
/// layer passes to `Endpoint.connect()` / `Endpoint.listen()`
/// (src/js/internal/quic/quic.ts `processTlsOptions`).
pub(super) struct TlsConfig {
    pub is_server: bool,
    /// ALPN protocol list in wire format (`[len][name]...`); empty means the
    /// caller did not specify one (Node's C++ default is HTTP/3's "h3").
    pub alpn: Vec<u8>,
    /// SNI servername (client) — NUL-terminated when present.
    pub servername: Option<Vec<u8>>,
    /// PEM certificate chains; each entry may contain multiple certificates.
    pub certs_pem: Vec<Vec<u8>>,
    /// PEM private keys (PKCS#8); only the first is used.
    pub keys_pem: Vec<Vec<u8>>,
    /// Additional trusted CA certificates (PEM).
    pub ca_pem: Vec<Vec<u8>>,
    /// `verifyPeer: 'strict'` — fail the handshake on certificate errors.
    pub verify_peer_strict: bool,
    /// Verify the peer certificate's SAN/CN against `servername`.
    pub verify_hostname: bool,
    /// Server: request and verify a client certificate.
    pub verify_client: bool,
}

/// Read a string-or-buffer JS value as bytes (PEM inputs may be strings,
/// ArrayBuffers, or views).
fn value_to_bytes(global: &JSGlobalObject, value: JSValue) -> JsResult<Option<Vec<u8>>> {
    if value.is_empty_or_undefined_or_null() {
        return Ok(None);
    }
    if let Some(buf) = value.as_array_buffer(global) {
        return Ok(Some(buf.byte_slice().to_vec()));
    }
    if value.is_string() {
        return Ok(Some(bun_core::String::from_js(value, global)?.to_utf8_bytes()));
    }
    Ok(None)
}

/// Collect a JS option that may be a single value or an array of values into
/// a list of byte buffers. Non-convertible entries are skipped (the JS layer
/// already validated types).
fn collect_pem_list(global: &JSGlobalObject, value: JSValue) -> JsResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    if value.is_empty_or_undefined_or_null() {
        return Ok(out);
    }
    if value.is_array() {
        let len = value.get_length(global)?;
        for i in 0..len {
            let entry = value.get_index(global, i as u32)?;
            if let Some(bytes) = value_to_bytes(global, entry)? {
                out.push(bytes);
            }
        }
    } else if let Some(bytes) = value_to_bytes(global, value)? {
        out.push(bytes);
    }
    Ok(out)
}

impl TlsConfig {
    /// Extract the fields the handshake needs from the processed options
    /// object (`options.tls`).
    pub(super) fn from_js(global: &JSGlobalObject, tls: JSValue, is_server: bool) -> JsResult<TlsConfig> {
        let mut config = TlsConfig {
            is_server,
            alpn: Vec::new(),
            servername: None,
            certs_pem: Vec::new(),
            keys_pem: Vec::new(),
            ca_pem: Vec::new(),
            verify_peer_strict: false,
            verify_hostname: false,
            verify_client: false,
        };
        if !tls.is_object() {
            return Ok(config);
        }

        if let Some(alpn) = tls.get(global, "alpn")?.filter(|v| v.is_string()) {
            // Already encoded to wire format (latin1) by the JS layer.
            config.alpn = bun_core::String::from_js(alpn, global)?.to_utf8_bytes();
        }
        if let Some(servername) = tls.get(global, "servername")?.filter(|v| v.is_string()) {
            let mut name = bun_core::String::from_js(servername, global)?.to_utf8_bytes();
            if !name.contains(&0) {
                name.push(0);
                config.servername = Some(name);
            }
        }
        if let Some(certs) = tls.get(global, "certs")? {
            config.certs_pem = collect_pem_list(global, certs)?;
        }
        if let Some(keys) = tls.get(global, "keys")? {
            config.keys_pem = collect_pem_list(global, keys)?;
        }
        if let Some(ca) = tls.get(global, "ca")? {
            config.ca_pem = collect_pem_list(global, ca)?;
        }
        if let Some(v) = tls.get(global, "verifyPeerStrict")? {
            config.verify_peer_strict = v.to_boolean();
        }
        if let Some(v) = tls.get(global, "verifyHostname")? {
            config.verify_hostname = v.to_boolean();
        }
        if let Some(v) = tls.get(global, "verifyClient")? {
            config.verify_client = v.to_boolean();
        }
        // Node defaults the servername to "localhost" when none is given
        // (node/src/quic/tlscontext.h TLSContext::Options::servername).
        if config.servername.is_none() {
            config.servername = Some(b"localhost\0".to_vec());
        }
        Ok(config)
    }
}

/// The ALPN wire-format list a server offers; heap-pinned so the
/// `SSL_CTX_set_alpn_select_cb` arg pointer stays valid for the SSL_CTX's
/// lifetime regardless of where the owning `TlsSession` moves.
struct AlpnHolder {
    wire: Vec<u8>,
}

/// Server-side ALPN selection: pick the first server-configured protocol that
/// also appears in the client's list (mirrors `SSL_select_next_proto`
/// server-preference order, which is what Node/nghttp3 use).
unsafe extern "C" fn alpn_select_cb(
    _ssl: *mut ssl::SSL,
    out: *mut *const u8,
    out_len: *mut u8,
    client: *const u8,
    client_len: c_uint,
    arg: *mut c_void,
) -> c_int {
    if arg.is_null() || client.is_null() {
        return ssl::SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    // SAFETY: `arg` is the AlpnHolder owned by the TlsSession that owns this
    // SSL_CTX; it outlives every handshake on it. `client` points to
    // `client_len` bytes valid for the duration of the callback.
    let holder = unsafe { &*arg.cast::<AlpnHolder>() };
    let client = unsafe { core::slice::from_raw_parts(client, client_len as usize) };

    let mut server = holder.wire.as_slice();
    while let Some((&slen, srest)) = server.split_first() {
        let slen = slen as usize;
        if slen == 0 || srest.len() < slen {
            break;
        }
        let sproto = &srest[..slen];

        let mut peer = client;
        while let Some((&plen, prest)) = peer.split_first() {
            let plen = plen as usize;
            if plen == 0 || prest.len() < plen {
                break;
            }
            if &prest[..plen] == sproto {
                // Point into the client's buffer (standard practice: it lives
                // until the handshake message is released, longer than the
                // callback's use of the selection).
                // SAFETY: `prest` is derived from `client`, in bounds.
                unsafe {
                    *out = prest.as_ptr();
                    *out_len = plen as u8;
                }
                return ssl::SSL_TLSEXT_ERR_OK;
            }
            peer = &prest[plen..];
        }
        server = &srest[slen..];
    }
    ssl::SSL_TLSEXT_ERR_ALERT_FATAL
}

/// Owns the per-session `SSL_CTX` + `SSL`.
pub(super) struct TlsSession {
    ctx: *mut ssl::SSL_CTX,
    ssl: *mut ssl::SSL,
    /// Keeps the server ALPN list alive for the `SSL_CTX` callback.
    _alpn: Option<Box<AlpnHolder>>,
}

/// Load every certificate in a PEM blob: the first becomes the leaf, the rest
/// the extra chain.
fn load_cert_chain(ctx: *mut ssl::SSL_CTX, pem: &[u8]) -> Result<(), &'static str> {
    // SAFETY: `pem` is a live byte slice; BIO_new_mem_buf borrows it for the
    // BIO's lifetime, which ends inside this function.
    unsafe {
        let bio = ssl::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as _);
        if bio.is_null() {
            return Err("failed to allocate certificate BIO");
        }
        let mut first = true;
        let mut loaded_any = false;
        loop {
            let x509 = ssl::PEM_read_bio_X509(bio, null_mut(), None, null_mut());
            if x509.is_null() {
                break;
            }
            let ok = if first {
                first = false;
                ssl::SSL_CTX_use_certificate(ctx, x509)
            } else {
                // On success the SSL_CTX takes ownership of `x509`.
                let ok = ssl::SSL_CTX_add_extra_chain_cert(ctx, x509);
                if ok == 1 {
                    loaded_any = true;
                    // add_extra_chain_cert took ownership; keep reading.
                    continue;
                }
                ok
            };
            // use_certificate up-refs; add_extra_chain_cert (failure path) did not.
            ssl::X509_free(x509);
            if ok != 1 {
                ssl::BIO_free(bio);
                return Err("failed to use certificate");
            }
            loaded_any = true;
        }
        ssl::BIO_free(bio);
        if loaded_any { Ok(()) } else { Err("no certificate found in PEM") }
    }
}

fn load_private_key(ctx: *mut ssl::SSL_CTX, pem: &[u8]) -> Result<(), &'static str> {
    // SAFETY: as in `load_cert_chain`.
    unsafe {
        let bio = ssl::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as _);
        if bio.is_null() {
            return Err("failed to allocate key BIO");
        }
        let pkey = ssl::PEM_read_bio_PrivateKey(bio, null_mut(), None, null_mut());
        ssl::BIO_free(bio);
        if pkey.is_null() {
            return Err("failed to parse private key");
        }
        let ok = ssl::SSL_CTX_use_PrivateKey(ctx, pkey);
        // use_PrivateKey up-refs the key; drop our reference either way.
        ssl::EVP_PKEY_free(pkey);
        if ok != 1 {
            return Err("failed to use private key");
        }
        Ok(())
    }
}

/// Build an `X509_STORE` holding the supplied CA certificates.
fn build_ca_store(ca_pem: &[Vec<u8>]) -> Result<*mut ssl::X509_STORE, &'static str> {
    // SAFETY: PEM buffers are live slices; the store owns the certs added to it.
    unsafe {
        let store = ssl::X509_STORE_new();
        if store.is_null() {
            return Err("failed to allocate certificate store");
        }
        for pem in ca_pem {
            let bio = ssl::BIO_new_mem_buf(pem.as_ptr().cast(), pem.len() as _);
            if bio.is_null() {
                ssl::X509_STORE_free(store);
                return Err("failed to allocate CA BIO");
            }
            loop {
                let x509 = ssl::PEM_read_bio_X509(bio, null_mut(), None, null_mut());
                if x509.is_null() {
                    break;
                }
                let ok = ssl::X509_STORE_add_cert(store, x509);
                // add_cert up-refs.
                ssl::X509_free(x509);
                if ok != 1 {
                    ssl::BIO_free(bio);
                    ssl::X509_STORE_free(store);
                    return Err("failed to add CA certificate");
                }
            }
            ssl::BIO_free(bio);
        }
        Ok(store)
    }
}

impl TlsSession {
    /// Create the SSL_CTX/SSL pair for one QUIC session and attach ngtcp2's
    /// BoringSSL QUIC method. `conn_ref` must remain at a stable address for
    /// the lifetime of the returned value (the owning Session boxes it).
    pub(super) fn new(
        config: &TlsConfig,
        conn_ref: *mut ngtcp2::ngtcp2_crypto_conn_ref,
    ) -> Result<TlsSession, &'static str> {
        // SAFETY: plain BoringSSL object construction; every failure path
        // frees what was created before it.
        unsafe {
            let ctx = ssl::SSL_CTX_new(ssl::TLS_method());
            if ctx.is_null() {
                return Err("failed to allocate SSL_CTX");
            }
            let mut this = TlsSession { ctx, ssl: null_mut(), _alpn: None };

            // QUIC requires TLS 1.3.
            if ssl::SSL_CTX_set_min_proto_version(ctx, ssl::TLS1_3_VERSION) != 1
                || ssl::SSL_CTX_set_max_proto_version(ctx, ssl::TLS1_3_VERSION) != 1
            {
                return Err("failed to pin TLS 1.3");
            }

            // Install ngtcp2's SSL_QUIC_METHOD and related configuration.
            let configured = if config.is_server {
                ngtcp2::ngtcp2_crypto_boringssl_configure_server_context(ctx.cast())
            } else {
                ngtcp2::ngtcp2_crypto_boringssl_configure_client_context(ctx.cast())
            };
            if configured != 0 {
                return Err("failed to configure QUIC TLS context");
            }

            // Identity (server always; client only when client certs are used).
            for pem in &config.certs_pem {
                load_cert_chain(ctx, pem)?;
            }
            if let Some(key) = config.keys_pem.first() {
                load_private_key(ctx, key)?;
            }
            if config.is_server && ssl::SSL_CTX_check_private_key(ctx) != 1 && !config.keys_pem.is_empty() {
                return Err("private key does not match certificate");
            }

            // Server ALPN selection over the configured protocol list.
            if config.is_server && !config.alpn.is_empty() {
                let holder = Box::new(AlpnHolder { wire: config.alpn.clone() });
                ssl::SSL_CTX_set_alpn_select_cb(
                    ctx,
                    Some(alpn_select_cb),
                    core::ptr::from_ref::<AlpnHolder>(&*holder).cast_mut().cast(),
                );
                this._alpn = Some(holder);
            }

            let ssl_ptr = ssl::SSL_new(ctx);
            if ssl_ptr.is_null() {
                return Err("failed to allocate SSL");
            }
            this.ssl = ssl_ptr;

            // The crypto backend finds the ngtcp2_conn through the app-data
            // slot (`SSL_get_app_data` == ex_data index 0).
            if ssl::SSL_set_ex_data(ssl_ptr, 0, conn_ref.cast()) != 1 {
                return Err("failed to attach QUIC connection reference");
            }

            if config.is_server {
                ssl::SSL_set_accept_state(ssl_ptr);
                if config.verify_client {
                    ssl::SSL_set_verify(
                        ssl_ptr,
                        ssl::SSL_VERIFY_PEER | ssl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                        None,
                    );
                }
            } else {
                ssl::SSL_set_connect_state(ssl_ptr);

                // Client ALPN offer.
                if !config.alpn.is_empty()
                    && ssl::SSL_set_alpn_protos(ssl_ptr, config.alpn.as_ptr(), config.alpn.len()) != 0
                {
                    return Err("failed to set ALPN protocols");
                }

                if let Some(servername) = &config.servername {
                    // Best effort: a hostname that is not a valid SNI value
                    // (e.g. an IP literal) is simply not sent, like Node.
                    let _ = ssl::SSL_set_tlsext_host_name(ssl_ptr, servername.as_ptr().cast());
                    if config.verify_hostname {
                        let _ = ssl::SSL_set1_host(ssl_ptr, servername.as_ptr().cast());
                    }
                }

                // Peer verification: 'strict' (SSL_VERIFY_PEER) aborts the
                // handshake on a bad certificate. For 'auto'/'manual',
                // BoringSSL clients still verify the chain under
                // SSL_VERIFY_NONE — the mode only stops the failure from
                // aborting the handshake; SSL_get_verify_result() reports it
                // and the JS layer decides (Node's contract for these modes).
                let mode = if config.verify_peer_strict { ssl::SSL_VERIFY_PEER } else { ssl::SSL_VERIFY_NONE };
                ssl::SSL_set_verify(ssl_ptr, mode, None);

                if !config.ca_pem.is_empty() {
                    let store = build_ca_store(&config.ca_pem)?;
                    if ssl::SSL_set0_verify_cert_store(ssl_ptr, store) != 1 {
                        ssl::X509_STORE_free(store);
                        return Err("failed to set CA store");
                    }
                }
            }

            Ok(this)
        }
    }

    pub(super) fn ssl(&self) -> *mut ssl::SSL {
        self.ssl
    }

    /// The negotiated ALPN protocol (without length prefix), if any.
    pub(super) fn alpn_selected(&self) -> Option<Vec<u8>> {
        let mut data: *const u8 = core::ptr::null();
        let mut len: c_uint = 0;
        // SAFETY: `self.ssl` is live; out-params are stack locals.
        unsafe { ssl::SSL_get0_alpn_selected(self.ssl, &mut data, &mut len) };
        if data.is_null() || len == 0 {
            return None;
        }
        // SAFETY: BoringSSL guarantees `data` points to `len` bytes owned by
        // the SSL; copy them out before returning.
        Some(unsafe { core::slice::from_raw_parts(data, len as usize) }.to_vec())
    }

    fn cstr_to_string(ptr: *const c_char) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        // SAFETY: BoringSSL returns NUL-terminated static strings here.
        Some(unsafe { core::ffi::CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
    }

    /// Negotiated cipher suite name (e.g. "TLS_AES_128_GCM_SHA256").
    pub(super) fn cipher_name(&self) -> Option<String> {
        // SAFETY: `self.ssl` is live.
        let cipher = unsafe { ssl::SSL_get_current_cipher(self.ssl) };
        if cipher.is_null() {
            return None;
        }
        // SAFETY: cipher is a static table entry.
        Self::cstr_to_string(unsafe { ssl::SSL_CIPHER_standard_name(cipher) })
    }

    /// Negotiated protocol version string (e.g. "TLSv1.3").
    pub(super) fn cipher_version(&self) -> Option<String> {
        // SAFETY: `self.ssl` is live.
        Self::cstr_to_string(unsafe { ssl::SSL_get_version(self.ssl) })
    }

    /// SNI servername received from the client (server side).
    pub(super) fn servername(&self) -> Option<String> {
        // SAFETY: `self.ssl` is live.
        Self::cstr_to_string(unsafe { ssl::SSL_get_servername(self.ssl, TLSEXT_NAMETYPE_HOST_NAME) })
    }

    /// Peer-certificate validation result as Node-style `(reason, code)`
    /// strings, or `None` when validation succeeded.
    pub(super) fn validation_error(&self) -> Option<(String, String)> {
        // SAFETY: `self.ssl` is live.
        let result = unsafe { ssl::SSL_get_verify_result(self.ssl) };
        if result == ssl::X509_V_OK {
            return None;
        }
        // SAFETY: returns a static string.
        let reason = Self::cstr_to_string(unsafe { ssl::X509_verify_cert_error_string(result) })
            .unwrap_or_else(|| String::from("unknown certificate verification error"));
        // Node's code is the `X509_V_ERR_*` constant name without the prefix
        // (node/src/crypto/crypto_common.cc `GetValidationErrorCode`). Partial
        // table covering the codes the test fixtures can produce; anything
        // else falls back to the generic verification-failure code.
        let code = match result {
            2 => "UNABLE_TO_GET_ISSUER_CERT",
            10 => "CERT_HAS_EXPIRED",
            18 => "DEPTH_ZERO_SELF_SIGNED_CERT",
            19 => "SELF_SIGNED_CERT_IN_CHAIN",
            20 => "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
            21 => "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
            62 => "HOSTNAME_MISMATCH",
            _ => "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        };
        Some((reason, String::from(code)))
    }
}

impl Drop for TlsSession {
    fn drop(&mut self) {
        // SAFETY: pointers were allocated by this struct and not freed elsewhere.
        unsafe {
            if !self.ssl.is_null() {
                ssl::SSL_free(self.ssl);
            }
            if !self.ctx.is_null() {
                ssl::SSL_CTX_free(self.ctx);
            }
        }
    }
}
