"use strict";

const { isNodeStream, isWebStream, isReadableStream, isWritableStream } = require("internal/streams/utils");
const eos = require("internal/streams/end-of-stream");

const SymbolDispose = Symbol.dispose;

let addAbortListener;

// This method is inlined here for readable-stream
// It also does not allow for signal to not exist on the stream
// https://github.com/nodejs/node/pull/36061#discussion_r533718029
const validateAbortSignal = (signal, name) => {
  if (typeof signal !== "object" || !("aborted" in signal)) {
    throw $ERR_INVALID_ARG_TYPE(name, "AbortSignal", signal);
  }
};

function addAbortSignal(signal, stream) {
  validateAbortSignal(signal, "signal");
  if (!isNodeStream(stream) && !isWebStream(stream)) {
    throw $ERR_INVALID_ARG_TYPE("stream", ["ReadableStream", "WritableStream", "Stream"], stream);
  }
  return addAbortSignalNoValidate(signal, stream);
}

// Bun's web streams don't carry Node's kControllerErrorFunction own property;
// error the stream through its controller instead, mirroring controller.error()
// (a no-op once the stream is no longer readable/writable).
function webStreamControllerError(stream, error) {
  if (isWritableStream(stream)) {
    // The slots live on the internal stream object, not the public WritableStream.
    const internalStream = $getInternalWritableStream(stream);
    if ($getByIdDirectPrivate(internalStream, "state") === "writable") {
      $writableStreamDefaultControllerError($getByIdDirectPrivate(internalStream, "controller"), error);
    }
    return;
  }
  if (isReadableStream(stream)) {
    if ($getByIdDirectPrivate(stream, "state") !== $streamReadable) return;
    const controller = $getByIdDirectPrivate(stream, "readableStreamController");
    if (controller == null) return;
    if ($isReadableStreamDefaultController(controller)) {
      $readableStreamDefaultControllerError(controller, error);
    } else {
      $readableByteStreamControllerError(controller, error);
    }
  }
}

function addAbortSignalNoValidate(signal, stream) {
  if (typeof signal !== "object" || !("aborted" in signal)) {
    return stream;
  }
  const onAbort = isNodeStream(stream)
    ? () => {
        stream.destroy($makeAbortError(undefined, { cause: signal.reason }));
      }
    : () => {
        webStreamControllerError(stream, $makeAbortError(undefined, { cause: signal.reason }));
      };
  if (signal.aborted) {
    onAbort();
  } else {
    addAbortListener ??= require("internal/abort_listener").addAbortListener;
    const disposable = addAbortListener(signal, onAbort);
    eos(stream, disposable[SymbolDispose]);
  }
  return stream;
}

export default {
  addAbortSignal,
  addAbortSignalNoValidate,
};
