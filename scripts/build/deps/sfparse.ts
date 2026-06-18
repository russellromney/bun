/**
 * sfparse — RFC 9651 Structured Field Values parser from the ngtcp2 project.
 * Upstream nghttp3 vendors it as a git submodule (lib/sfparse), which GitHub
 * archive tarballs leave empty, so it is fetched here as its own dependency,
 * pinned to the submodule commit referenced by the vendored nghttp3 release.
 *
 * Header-only here: sfparse.c is compiled by the nghttp3 dep (see nghttp3.ts).
 */

import type { Dependency, DirectBuild } from "../source.ts";

const SFPARSE_COMMIT = "ff7f230e7df2844afef7dc49631cda03a30455f3";

export const sfparse: Dependency = {
  name: "sfparse",

  source: () => ({
    kind: "github-archive",
    repo: "ngtcp2/sfparse",
    commit: SFPARSE_COMMIT,
  }),

  build: cfg => {
    void cfg;
    const spec: DirectBuild = { kind: "direct", sources: [] };
    return spec;
  },

  provides: () => ({
    libs: [],
    includes: ["."],
  }),
};
