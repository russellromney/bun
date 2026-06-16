import { describe, expect, it } from "bun:test";
import { isIPv6, isMacOS, isWindows } from "harness";
import * as dgram from "node:dgram";

// https://github.com/nodejs/node/commit/723dd38882584f95b80f53a0baf1b9562bcee28c
describe("Socket.prototype.bindSync", () => {
  it("binds synchronously and returns the resolved address", async () => {
    const { promise, resolve, reject } = Promise.withResolvers();
    const sock = dgram.createSocket("udp4");
    try {
      const addr = sock.bindSync({ address: "127.0.0.1", port: 0 });

      expect(addr.address).toBe("127.0.0.1");
      expect(addr.family).toBe("IPv4");
      expect(typeof addr.port).toBe("number");
      expect(addr.port).toBeGreaterThan(0);

      // address() is valid synchronously and matches the returned address.
      expect(sock.address()).toEqual(addr);

      // The 'listening' event still fires on the next tick.
      sock.on("error", reject);
      sock.on("listening", resolve);
      await promise;
    } finally {
      sock.close();
    }
  });

  it("closing synchronously after bindSync() suppresses the deferred 'listening'", async () => {
    const { promise, resolve, reject } = Promise.withResolvers();
    const sock = dgram.createSocket("udp4");
    try {
      sock.bindSync({ port: 0 });
      sock.on("listening", () => reject(new Error("'listening' should not fire after close()")));
    } finally {
      sock.close(resolve);
    }
    await promise;
  });

  it("defaults the address to the udp4 wildcard when omitted", () => {
    const sock = dgram.createSocket("udp4");
    try {
      const addr = sock.bindSync();
      expect(addr.address).toBe("0.0.0.0");
      expect(addr.port).toBeGreaterThan(0);
    } finally {
      sock.close();
    }
  });

  it("'message' events still flow asynchronously after a synchronous bind", async () => {
    const { promise, resolve, reject } = Promise.withResolvers();
    const receiver = dgram.createSocket("udp4");
    const sender = dgram.createSocket("udp4");
    try {
      receiver.on("error", reject);
      sender.on("error", reject);

      const addr = receiver.bindSync({ address: "127.0.0.1", port: 0 });

      receiver.on("message", msg => {
        try {
          expect(msg.toString()).toBe("hello");
          resolve();
        } catch (e) {
          reject(e);
        }
      });

      sender.send("hello", addr.port, "127.0.0.1");

      await promise;
    } finally {
      receiver.close();
      sender.close();
    }
  });

  // Windows binds the same UDP port twice without error for non-SO_EXCLUSIVEADDRUSE sockets.
  it.skipIf(isWindows)("throws synchronously on EADDRINUSE", () => {
    const first = dgram.createSocket("udp4");
    const second = dgram.createSocket("udp4");
    try {
      const addr = first.bindSync({ address: "127.0.0.1", port: 0 });
      expect(() => second.bindSync({ address: "127.0.0.1", port: addr.port })).toThrow(
        expect.objectContaining({
          code: "EADDRINUSE",
          syscall: "bind",
          address: "127.0.0.1",
          port: addr.port,
          message: `bind EADDRINUSE 127.0.0.1:${addr.port}`,
        }),
      );
    } finally {
      first.close();
      second.close();
    }
  });

  it("throws synchronously on a non-numeric address (no DNS resolution)", () => {
    const sock = dgram.createSocket("udp4");
    try {
      expect(() => sock.bindSync({ address: "localhost", port: 0 })).toThrow(
        expect.objectContaining({ code: "ERR_INVALID_ARG_VALUE", name: "TypeError" }),
      );
    } finally {
      sock.close();
    }
  });

  it("rejects a non-string address", () => {
    const sock = dgram.createSocket("udp4");
    try {
      expect(() => sock.bindSync({ address: 12345 })).toThrow(
        expect.objectContaining({ code: "ERR_INVALID_ARG_TYPE" }),
      );
    } finally {
      sock.close();
    }
  });

  it("a rejected argument leaves the socket unbound and reusable", () => {
    const sock = dgram.createSocket("udp4");
    try {
      expect(() => sock.bindSync({ port: -1 })).toThrow(expect.objectContaining({ code: "ERR_SOCKET_BAD_PORT" }));
      const addr = sock.bindSync({ port: 0 });
      expect(addr.port).toBeGreaterThan(0);
    } finally {
      sock.close();
    }
  });

  it("throws when already bound", () => {
    const sock = dgram.createSocket("udp4");
    try {
      sock.bindSync({ port: 0 });
      expect(() => sock.bindSync({ port: 0 })).toThrow(expect.objectContaining({ code: "ERR_SOCKET_ALREADY_BOUND" }));
    } finally {
      sock.close();
    }
  });

  it("rejects a non-object options argument", () => {
    const sock = dgram.createSocket("udp4");
    try {
      expect(() => sock.bindSync(0)).toThrow(expect.objectContaining({ code: "ERR_INVALID_ARG_TYPE" }));
    } finally {
      sock.close();
    }
  });

  it.skipIf(!isIPv6())("udp6 wildcard default", () => {
    const sock = dgram.createSocket("udp6");
    try {
      const addr = sock.bindSync();
      expect(addr.address).toBe("::");
      expect(addr.family).toBe("IPv6");
      expect(addr.port).toBeGreaterThan(0);
    } finally {
      sock.close();
    }
  });

  it.skipIf(!isIPv6())("udp6 loopback with an OS-assigned ephemeral port, and async 'message' flow", async () => {
    const { promise, resolve, reject } = Promise.withResolvers();
    const receiver = dgram.createSocket("udp6");
    const sender = dgram.createSocket("udp6");
    try {
      receiver.on("error", reject);
      sender.on("error", reject);

      const addr = receiver.bindSync({ address: "::1", port: 0 });
      expect(addr.address).toBe("::1");
      expect(addr.family).toBe("IPv6");
      expect(addr.port).toBeGreaterThan(0);
      expect(receiver.address()).toEqual(addr);

      receiver.on("message", msg => {
        try {
          expect(msg.toString()).toBe("hello");
          resolve();
        } catch (e) {
          reject(e);
        }
      });

      sender.send("hello", addr.port, "::1");

      await promise;
    } finally {
      receiver.close();
      sender.close();
    }
  });

  // With IPV6_V6ONLY set, the v6 socket does not claim the v4 port, so a
  // separate udp4 bind on the same port succeeds. Skipped on Windows where
  // UDP port reuse semantics differ.
  it.skipIf(!isIPv6() || isWindows)("honors the ipv6Only flag", () => {
    const v6 = dgram.createSocket({ type: "udp6", ipv6Only: true });
    const v4 = dgram.createSocket("udp4");
    try {
      const addr6 = v6.bindSync({ address: "::", port: 0 });
      expect(addr6.family).toBe("IPv6");
      const addr4 = v4.bindSync({ address: "127.0.0.1", port: addr6.port });
      expect(addr4.port).toBe(addr6.port);
    } finally {
      v6.close();
      v4.close();
    }
  });
});

describe.skipIf(!isIPv6())("node:dgram", () => {
  it("adds membership successfully (IPv6)", () => {
    const socket = makeSocket6();
    socket.bind(0, () => {
      socket.addMembership("ff01::1", getInterface());
      if (!isMacOS) {
        // macOS seems to be iffy with automatically choosing an interface.
        socket.addMembership("ff02::1");
      }
    });
  });

  it("doesn't add membership given invalid inputs (IPv6)", () => {
    const { promise, resolve, reject } = Promise.withResolvers();
    const socket = makeSocket6();
    socket.bind(0, () => {
      expect(() => {
        // fe00:: is not a valid multicast address
        socket.addMembership("fe00::", getInterface());
        reject();
      }).toThrow();
      expect(() => {
        socket.addMembership("fe00::");
        reject();
      }).toThrow();
      resolve();
    });
    return promise;
  });
});

function makeSocket6() {
  return dgram.createSocket({
    type: "udp6",
    ipv6Only: true,
  });
}

function getInterface() {
  if (isWindows) {
    return "::%1";
  }

  if (isMacOS) {
    return "::%lo0";
  }

  return "::%lo";
}
