/**
 * nghttp3 — HTTP/3 (RFC 9114) and QPACK library from the ngtcp2 project.
 * Application-protocol layer for the node:quic implementation; pairs with
 * ngtcp2 for the QUIC transport. Pinned to the same release Node.js v26
 * vendors (v1.15.0).
 *
 * DirectBuild: lib/*.c plus sfparse, which upstream vendors as a git
 * submodule (lib/sfparse) that GitHub archive tarballs leave empty — it is
 * fetched as its own dependency instead (sfparse.ts). Upstream generates
 * lib/includes/nghttp3/version.h from version.h.in at configure time; we
 * ship the substituted output as a patch so DirectBuild stays declarative.
 */

import type { Config } from "../config.ts";
import type { Dependency } from "../source.ts";
import { depSourceDir } from "../source.ts";

// v1.15.0
const NGHTTP3_COMMIT = "d326f4c1eb3f6a780d77793b30e16756c498f913";

// prettier-ignore
const SOURCES = [
  "nghttp3_balloc", "nghttp3_buf", "nghttp3_callbacks", "nghttp3_conn",
  "nghttp3_conv", "nghttp3_debug", "nghttp3_err", "nghttp3_frame",
  "nghttp3_gaptr", "nghttp3_http", "nghttp3_idtr", "nghttp3_ksl",
  "nghttp3_map", "nghttp3_mem", "nghttp3_objalloc", "nghttp3_opl",
  "nghttp3_pq", "nghttp3_qpack", "nghttp3_qpack_huffman",
  "nghttp3_qpack_huffman_data", "nghttp3_range", "nghttp3_ratelim",
  "nghttp3_rcbuf", "nghttp3_ringbuf", "nghttp3_settings", "nghttp3_str",
  "nghttp3_stream", "nghttp3_tnode", "nghttp3_unreachable", "nghttp3_vec",
  "nghttp3_version",
];

export const nghttp3: Dependency = {
  name: "nghttp3",

  source: () => ({
    kind: "github-archive",
    repo: "ngtcp2/nghttp3",
    commit: NGHTTP3_COMMIT,
  }),

  patches: ["patches/nghttp3/version-header.patch", "patches/nghttp3/sfparse-include.patch"],

  fetchDeps: ["sfparse"],

  build: cfg => ({
    kind: "direct",
    sources: [...SOURCES.map(s => `lib/${s}.c`), depSourceDir(cfg, "sfparse") + "/sfparse.c"],
    includes: ["lib/includes", "lib", depSourceDir(cfg, "sfparse")],
    defines: {
      BUILDING_NGHTTP3: true,
      NGHTTP3_STATICLIB: true,
      ...platformDefines(cfg),
    },
    ...(cfg.windows && { headers: { "config.h": WINDOWS_CONFIG_H } }),
  }),

  provides: () => ({
    libs: [],
    includes: ["lib/includes"],
  }),
};

/**
 * Platform feature defines, mirroring Node.js's deps/ngtcp2/ngtcp2.gyp:
 * non-Windows gets HAVE_UNISTD_H, Linux additionally the byte-order headers,
 * Windows routes through a hand-written config.h (ssize_t + popcount shims).
 * Everything else (HAVE_ENDIAN_H, HAVE_DECL_BSWAP_64, ...) stays undefined and
 * the libraries fall back to their portable byte-swap implementations.
 */
export function platformDefines(cfg: Config): Record<string, string | number | true> {
  if (cfg.windows) {
    return { WIN32: true, _WINDOWS: true, HAVE_CONFIG_H: 1 };
  }
  return {
    HAVE_UNISTD_H: 1,
    ...(cfg.linux && { HAVE_ARPA_INET_H: 1, HAVE_NETINET_IN_H: 1 }),
  };
}

/**
 * Windows config.h shared by nghttp3 and ngtcp2 (same content Node.js uses):
 * MSVC-targeted toolchains lack ssize_t and __builtin_popcount.
 */
export const WINDOWS_CONFIG_H = `#include <stdint.h>

#ifdef _WIN32
#if !defined(_SSIZE_T_) && !defined(_SSIZE_T_DEFINED)
typedef intptr_t ssize_t;
# define _SSIZE_T_
# define _SSIZE_T_DEFINED
#endif
#else  /* !_WIN32 */
# include <sys/types.h>  /* size_t, ssize_t */
#endif  /* _WIN32 */

#ifdef _MSC_VER
#  include <intrin.h>
#  define __builtin_popcount __popcnt
#endif
`;
