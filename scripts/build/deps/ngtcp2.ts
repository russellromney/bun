/**
 * ngtcp2 — IETF QUIC (RFC 9000) transport library. QUIC transport for the
 * node:quic implementation (lsquic stays dedicated to Bun.serve's HTTP/3
 * listener and the HTTP/3 fetch client). Pinned to the same release
 * Node.js v26 vendors (v1.22.1).
 *
 * DirectBuild: lib/*.c plus the TLS crypto helper built against Bun's
 * vendored BoringSSL (crypto/shared.c + crypto/boringssl/boringssl.c).
 * Upstream generates lib/includes/ngtcp2/version.h from version.h.in at
 * configure time; we ship the substituted output as a patch so DirectBuild
 * stays declarative.
 */

import type { Dependency } from "../source.ts";
import { depSourceDir } from "../source.ts";
import { platformDefines, WINDOWS_CONFIG_H } from "./nghttp3.ts";

// v1.22.1
const NGTCP2_COMMIT = "716e64b05f4a3709dfc0b0522cf9fd4456d055e5";

// prettier-ignore
const SOURCES = [
  "ngtcp2_acktr", "ngtcp2_addr", "ngtcp2_balloc", "ngtcp2_bbr", "ngtcp2_buf",
  "ngtcp2_callbacks", "ngtcp2_cc", "ngtcp2_cid", "ngtcp2_conn",
  "ngtcp2_conn_info", "ngtcp2_conv", "ngtcp2_crypto", "ngtcp2_dcidtr",
  "ngtcp2_err", "ngtcp2_frame_chain", "ngtcp2_gaptr", "ngtcp2_idtr",
  "ngtcp2_ksl", "ngtcp2_log", "ngtcp2_map", "ngtcp2_mem", "ngtcp2_objalloc",
  "ngtcp2_opl", "ngtcp2_path", "ngtcp2_pcg", "ngtcp2_pkt", "ngtcp2_pmtud",
  "ngtcp2_ppe", "ngtcp2_pq", "ngtcp2_pv", "ngtcp2_qlog", "ngtcp2_range",
  "ngtcp2_ratelim", "ngtcp2_ringbuf", "ngtcp2_rob", "ngtcp2_rst",
  "ngtcp2_rtb", "ngtcp2_settings", "ngtcp2_str", "ngtcp2_strm",
  "ngtcp2_transport_params", "ngtcp2_unreachable", "ngtcp2_vec",
  "ngtcp2_version", "ngtcp2_window_filter",
];

export const ngtcp2: Dependency = {
  name: "ngtcp2",

  source: () => ({
    kind: "github-archive",
    repo: "ngtcp2/ngtcp2",
    commit: NGTCP2_COMMIT,
  }),

  patches: ["patches/ngtcp2/version-header.patch"],

  fetchDeps: ["boringssl"],

  build: cfg => ({
    kind: "direct",
    sources: [...SOURCES.map(s => `lib/${s}.c`), "crypto/shared.c", "crypto/boringssl/boringssl.c"],
    includes: [
      "lib/includes",
      "crypto/includes",
      "lib",
      "crypto",
      depSourceDir(cfg, "boringssl") + "/include",
    ],
    defines: {
      BUILDING_NGTCP2: true,
      NGTCP2_STATICLIB: true,
      ...platformDefines(cfg),
    },
    ...(cfg.windows && { headers: { "config.h": WINDOWS_CONFIG_H } }),
  }),

  provides: () => ({
    libs: [],
    includes: ["lib/includes", "crypto/includes"],
  }),
};
