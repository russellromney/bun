import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// https://github.com/oven-sh/bun/issues/30754
// Bun.WebView's runtime exposes goBack()/goForward(); the type declarations
// used to advertise back()/forward(), which never existed at runtime (calling
// the typed name threw TypeError, calling the real name errored in the IDE).
// Pin the declared names so the types can't drift from the runtime again.
//
// This reads packages/bun-types/bun.d.ts directly rather than type-checking
// with tsc: the check is a rename regression, and a plain read runs in
// milliseconds under the debug/ASAN build, whereas spawning tsc there blows
// the default test timeout.

const BUN_DTS = join(import.meta.dir, "..", "..", "..", "packages", "bun-types", "bun.d.ts");

test("Bun.WebView types declare goBack/goForward, not back/forward (#30754)", () => {
  const dts = readFileSync(BUN_DTS, "utf8");

  const classStart = dts.indexOf("class WebView extends EventTarget {");
  expect(classStart).toBeGreaterThan(-1);

  // The class sits at two-space indent inside `declare module "bun"`, so its
  // body ends at the first two-space-indented closing brace.
  const classEnd = dts.indexOf("\n  }", classStart);
  expect(classEnd).toBeGreaterThan(classStart);

  const methods = dts
    .slice(classStart, classEnd)
    .split("\n")
    .map(line => line.trim());

  // Array toContain is an exact-element match, so "goBack(): Promise<void>;"
  // never satisfies a check for "back(): Promise<void>;".
  expect(methods).toContain("goBack(): Promise<void>;");
  expect(methods).toContain("goForward(): Promise<void>;");
  expect(methods).not.toContain("back(): Promise<void>;");
  expect(methods).not.toContain("forward(): Promise<void>;");
});
