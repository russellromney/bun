// Mirrors the module shape of Node's lib/internal/dgram.js. node:dgram keeps its
// per-socket state under this symbol, and vendored Node tests gated on
// `// Flags: --expose-internals` reach it through require("internal/dgram")
// (served via bun:internal-for-testing's exposedInternals).
const kStateSymbol = Symbol("state symbol");

export default {
  kStateSymbol,
};
