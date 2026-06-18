// When only unref'd timers remain but a driver is still spinning the event
// loop waiting on a JS-visible condition (bun:test awaiting a test body,
// wait_for_promise, top-level await in the entrypoint), those drivers hold
// a uSockets-loop ref for their duration so auto_tick takes its active
// branch and parks on the next timer-heap deadline. Without that ref the
// idle branch is a non-blocking pump that busy-spins the driver on POSIX
// and on Windows never runs due timers (uv_run skips them when the loop
// has no ref'd handles).
import { expect, it } from "bun:test";
import { bunEnv, bunExe } from "harness";

// The two in-process tests depend on the bun:test drive loop being the only
// thing refing the loop; keep them sequential so a concurrent test's child
// process doesn't keep an unrelated handle alive and change the code path.
it("unref'd setTimeout fires while the test runner keeps the process alive", async () => {
  const fired = await new Promise(resolve => {
    setTimeout(() => resolve(true), 20).unref();
  });
  expect(fired).toBe(true);
});

it("unref'd setInterval fires while the test runner keeps the process alive", async () => {
  const fired = await new Promise(resolve => {
    const t = setInterval(() => {
      clearInterval(t);
      resolve(true);
    }, 20);
    t.unref();
  });
  expect(fired).toBe(true);
});

it("unref'd setTimeout fires under top-level await", async () => {
  // Node 26 exits early with "Detected unsettled top-level await" (code 13)
  // here; Bun's wait_for_promise refs the loop, so the timer fires instead.
  // Matching Node's early-exit is tracked as issue #14951.
  await using proc = Bun.spawn({
    cmd: [
      bunExe(),
      "-e",
      `const fired = await new Promise(resolve => {
        setTimeout(() => resolve(true), 20).unref();
      });
      console.log(fired ? "fired" : "did not fire");`,
    ],
    env: bunEnv,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);
  expect(stderr).toBe("");
  expect({ stdout: stdout.trim(), exitCode }).toEqual({ stdout: "fired", exitCode: 0 });
});

it("waiting on an unref'd timer parks the event loop instead of spinning", async () => {
  // The child measures CPU consumed across the await only, so slow debug
  // startup doesn't count. Without the driver's loop ref, auto_tick's idle
  // branch returns immediately and the driver busy-spins the whole 2000ms
  // (CPU time tracks wall time); with the ref, the active branch parks on
  // the timer deadline and CPU stays near zero.
  await using proc = Bun.spawn({
    cmd: [
      bunExe(),
      "-e",
      `const cpu0 = process.cpuUsage();
      const fired = await new Promise(resolve => {
        setTimeout(() => resolve(true), 2000).unref();
      });
      const cpu = process.cpuUsage(cpu0);
      console.log(JSON.stringify({ fired, cpuMs: Math.round((cpu.user + cpu.system) / 1000) }));`,
    ],
    env: bunEnv,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);
  expect(stderr).toBe("");
  // `|| "null"` keeps JSON.parse from throwing on empty output so the
  // assertion below reports exitCode instead.
  const output = JSON.parse(stdout.trim() || "null");
  expect({ output, exitCode }).toEqual({
    output: { fired: true, cpuMs: expect.any(Number) },
    exitCode: 0,
  });
  expect(output.cpuMs).toBeLessThan(1000);
});

it("awaiting setImmediate exits promptly with a long unref'd timer pending", async () => {
  // The driver's ref keeps the loop active, so after the setImmediate drops
  // its own ref the active branch is still taken; matches Node and ensures
  // the park doesn't regress to the unref'd-timer deadline on exit.
  const start = Date.now();
  await using proc = Bun.spawn({
    cmd: [
      bunExe(),
      "-e",
      `setTimeout(() => {}, 60000).unref();
      await new Promise(resolve => setImmediate(resolve));`,
    ],
    env: bunEnv,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);
  const wallMs = Date.now() - start;
  expect(stderr).toBe("");
  expect({ stdout, exitCode }).toEqual({ stdout: "", exitCode: 0 });
  expect(wallMs).toBeLessThan(10000);
});
