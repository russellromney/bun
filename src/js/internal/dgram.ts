// Mirrors the module shape of Node's lib/internal/dgram.js. node:dgram keeps
// its per-socket state under kStateSymbol, and _createSocketHandle/UDP back
// cluster-shared sockets and the udp_wrap internal binding that vendored Node
// tests reach through bun:internal-for-testing's exposedInternals.

const newSocketFd = $newZigFunction("udp_socket.zig", "jsDgramNewSocketFd", 2);
const bindFd = $newZigFunction("udp_socket.zig", "jsDgramBindFd", 4);
const getSockNameFd = $newZigFunction("udp_socket.zig", "jsDgramGetSockNameFd", 1);
const guessHandleTypeFd = $newZigFunction("udp_socket.zig", "jsDgramGuessHandleType", 1);
const closeFd = $newZigFunction("udp_socket.zig", "jsDgramCloseFd", 1);

const kStateSymbol = Symbol("state symbol");

// libuv-style error codes for the raw-descriptor surface. This surface is
// POSIX-only (Windows reports ENOTSUP, like Node's cluster does for shared
// dgram handles), so the POSIX values are the libuv values.
const UV_EBADF = -9;
const UV_EINVAL = -22;

function uvErrno(err, fallback) {
  return typeof err?.errno === "number" && err.errno < 0 ? err.errno : fallback;
}

// A libuv-style UDP handle over a raw datagram descriptor: created/bound (or
// adopted) but never reading. Live node:dgram sockets read through
// Bun.udpSocket; this wrap exists so the cluster primary can hold a shared,
// non-reading handle and so `// Flags: --expose-internals` tests can exercise
// internalBinding('udp_wrap').UDP. Adopting a wrap's fd into a reading socket
// transfers ownership of the descriptor — don't close the wrap afterwards.
class UDP {
  fd = -1;

  bind(address, port, flags) {
    return bindWrap(this, address, port, flags, false);
  }

  bind6(address, port, flags) {
    return bindWrap(this, address, port, flags, true);
  }

  open(fd) {
    if (guessHandleTypeFd(fd) !== "UDP") {
      return UV_EINVAL;
    }
    this.fd = fd;
    return 0;
  }

  getsockname(out) {
    if (this.fd < 0) {
      return UV_EBADF;
    }
    try {
      const { address, port, family } = getSockNameFd(this.fd);
      out.address = address;
      out.port = port;
      out.family = family;
      return 0;
    } catch (err) {
      return uvErrno(err, UV_EBADF);
    }
  }

  close() {
    if (this.fd >= 0) {
      closeFd(this.fd);
      this.fd = -1;
    }
    return 0;
  }

  ref() {}
  unref() {}
  hasRef() {
    return true;
  }
}

function bindWrap(handle, address, port, flags, ipv6) {
  try {
    if (handle.fd < 0) {
      handle.fd = newSocketFd(ipv6, false);
    }
    bindFd(handle.fd, address || (ipv6 ? "::" : "0.0.0.0"), port || 0, flags || 0);
    return 0;
  } catch (err) {
    return uvErrno(err, UV_EINVAL);
  }
}

function isInt32(value) {
  return value === (value | 0);
}

function _createSocketHandle(address, port, addressType, fd, flags) {
  const handle = new UDP();
  let err;

  if (typeof fd === "number" && isInt32(fd) && fd > 0) {
    if (guessHandleTypeFd(fd) !== "UDP") {
      err = UV_EINVAL;
    } else {
      err = handle.open(fd);
    }
  } else if (port || address) {
    err = addressType === "udp6" ? handle.bind6(address, port || 0, flags) : handle.bind(address, port || 0, flags);
  }

  if (err) {
    handle.close();
    return err;
  }

  return handle;
}

function guessHandleType(fd) {
  return guessHandleTypeFd(fd);
}

export default {
  kStateSymbol,
  UDP,
  _createSocketHandle,
  guessHandleType,
};
