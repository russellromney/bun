# rust-argon2 (patched)

Vendored copy of [rust-argon2](https://github.com/sru-systems/rust-argon2) v3.0.0
with one Bun-specific change: `Context::new` no longer rejects `mem_cost < 8 * lanes`.

Upstream rejects a memory cost below `8 * lanes` with `Error::MemoryTooLittle` before
computing anything. Bun releases up through the Zig implementation accepted any
`memoryCost >= 1` for `Bun.password.hash`, so hashes with e.g. `m=5,t=1,p=1` exist in
the wild. Rejecting them during `Bun.password.verify` would lock users out of their own
credentials on upgrade.

The patched `Context::new` allows any `mem_cost >= 1`. The actual number of memory
blocks is still clamped up to `8 * lanes` (as upstream already does immediately after
the removed check), and the raw `mem_cost` value is still fed into H0 per RFC 9106,
so the computed digest matches hashes produced by the prior Zig stdlib implementation.

New hashes cannot be created with `memoryCost < 8`: `Bun.password.hash` validates the
floor in `src/runtime/crypto/PasswordObject.rs` before reaching this crate.

Upstream is otherwise unmodified. See `LICENSE-APACHE` / `LICENSE-MIT`.
