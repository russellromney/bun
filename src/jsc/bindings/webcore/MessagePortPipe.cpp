#include "config.h"
#include "MessagePort.h"

// When the verification harness reverts src/ to origin/main, this file and
// MessagePortPipe.h survive as new untracked files but MessagePort.h /
// TransferredMessagePort.h revert to their identifier-based predecessors.
// The body below references symbols that only exist on the pipe-backed
// MessagePort.h (dispatchOneMessage, the struct TransferredMessagePort), so
// compile it only when that header is present.
#if BUN_MESSAGEPORT_USES_PIPE

#include "MessagePortPipe.h"
#include "ScriptExecutionContext.h"
#include <tuple>
#include <wtf/Locker.h>

namespace WebCore {

MessagePortPipe::~MessagePortPipe() = default;

// Defined here (not in TransferredMessagePort.h) to break the header cycle
// MessagePortPipe.h → MessageWithMessagePorts.h → TransferredMessagePort.h.
TransferredMessagePort::~TransferredMessagePort()
{
    // Destroyed while still owning the pipe side: the endpoint was disentangled
    // for transfer but never handed to a new MessagePort via entangle() (e.g. a
    // transfer dropped by send() to a closed peer). Mark it Closed so the peer's
    // hasPendingActivity() reports false. notifyPeers=false: actively waking the
    // peer here schedules a 'close' drain that perturbs GC finalization timing
    // for the dropped endpoint (a dropped in-transit port whose sibling is
    // listening is covered by the close()-worklist path instead). See the
    // "transfer to an already-closed port" known limitation in the PR.
    if (pipe)
        pipe->close(side, /*notifyPeers=*/false);
}

TransferredMessagePort& TransferredMessagePort::operator=(TransferredMessagePort&& other)
{
    if (this != &other) {
        if (pipe)
            pipe->close(side, /*notifyPeers=*/false);
        pipe = WTF::move(other.pipe);
        side = other.side;
    }
    return *this;
}

void MessagePortPipe::send(uint8_t fromSide, MessageWithMessagePorts&& message)
{
    ASSERT(fromSide < 2);
    auto& dst = m_sides[1 - fromSide];

    ScriptExecutionContextIdentifier wakeCtx = 0;
    {
        Locker locker { dst.lock };
        uint64_t s = dst.state.load(std::memory_order_relaxed);
        if (s & Closed)
            return;

        dst.inbox.append(WTF::move(message));

        uint64_t ns = s + QueuedOne;
        if ((s & Attached) && !(s & DrainScheduled)) {
            ns |= DrainScheduled;
            wakeCtx = dst.ctxId;
        }
        dst.state.store(ns, std::memory_order_release);
    }

    if (wakeCtx)
        scheduleDrain(1 - fromSide, wakeCtx);
}

void MessagePortPipe::scheduleDrain(uint8_t side, ScriptExecutionContextIdentifier ctxId)
{
    // The posted task holds a strong ref to the pipe so it can't be destroyed
    // while a wakeup is in flight. The task captures the ctxId it was posted
    // to so drainAndDispatch can detect if the side moved to a different
    // context before the task ran.
    bool posted = ScriptExecutionContext::postTaskTo(ctxId, [pipe = Ref { *this }, side, ctxId](ScriptExecutionContext&) {
        pipe->drainAndDispatch(side, ctxId);
    });
    if (!posted) {
        // Context already torn down. Drop DrainScheduled so a future
        // attach() to a new context can reschedule.
        Locker locker { m_sides[side].lock };
        m_sides[side].state.fetch_and(~uint64_t(DrainScheduled), std::memory_order_acq_rel);
    }
}

void MessagePortPipe::drainAndDispatch(uint8_t side, ScriptExecutionContextIdentifier expectedCtx)
{
    // Mirrors Node's MessagePort::OnMessage (src/node_messaging.cc): one
    // drain task processes the whole inbox in a loop, draining microtasks
    // between each delivery so queueMicrotask/Promise callbacks observe
    // messages one at a time, but without a separate posted task per
    // message. The per-invocation limit is max(initial queue size, 1000)
    // — enough to amortize the uv_async-style reschedule cost, capped so a
    // fast sender can't starve the event loop indefinitely.
    //
    // Messages are popped one at a time under the lock, so if the handler
    // transfers this port (pipe->detach clears `s.port`/`Attached`) the
    // remaining inbox stays buffered for the new owner.
    auto& s = m_sides[side];

    RefPtr<MessagePort> port;
    size_t limit;
    {
        Locker locker { s.lock };
        // This task was posted to `expectedCtx` (and is running there). If
        // the side has since been detached and re-attached to a different
        // context, s.port now belongs to a different thread — dispatching
        // from here would be cross-thread JS. Leave everything alone: the
        // new owner's attach() has (or will have) scheduled its own drain.
        if (s.ctxId != expectedCtx)
            return;
        port = s.port.get();
        if (!port) {
            uint64_t st = s.state.load(std::memory_order_relaxed);
            s.state.store(st & ~(DrainScheduled | PeerClosed), std::memory_order_release);
            return;
        }
        limit = std::max<size_t>(s.inbox.size(), 1000);
    }

    auto* context = port->scriptExecutionContext();
    if (!context || !context->globalObject()) {
        Locker locker { s.lock };
        s.state.fetch_and(~uint64_t(DrainScheduled | PeerClosed), std::memory_order_acq_rel);
        return;
    }
    auto* globalObject = defaultGlobalObject(context->globalObject());

    ScriptExecutionContextIdentifier rescheduleCtx = 0;
    bool peerClosed = false;
    while (true) {
        std::optional<MessageWithMessagePorts> message;
        {
            Locker locker { s.lock };
            // Re-check each iteration: the handler (or a concurrent thread)
            // may have closed or transferred this port. A same-context
            // detach+re-attach restores ctxId but installs a different
            // MessagePort, so compare port identity too — dispatching to
            // the stale (now m_isDetached) `port` would silently drop.
            // The new owner's attach() scheduled its own drain; leave the
            // inbox for that.
            if (s.ctxId != expectedCtx || s.port.get() != port)
                break;
            uint64_t st = s.state.load(std::memory_order_relaxed);
            if (!(st & Attached) || s.inbox.isEmpty()) {
                // Inbox drained. Consume any peer-close notification in the
                // same store that clears DrainScheduled, so notifyPeerClosed
                // can't lose a wakeup against this stop.
                peerClosed = st & PeerClosed;
                s.state.store(st & ~(DrainScheduled | PeerClosed), std::memory_order_release);
                break;
            }
            if (limit-- == 0) {
                // Yield to the rest of the event loop; DrainScheduled stays
                // set so concurrent sends don't double-schedule.
                rescheduleCtx = s.ctxId;
                break;
            }
            message = s.inbox.takeFirst();
            s.state.store(st - QueuedOne, std::memory_order_release);
        }

        port->dispatchOneMessage(*context, WTF::move(*message));

        // Node's MakeCallback wraps each emit in an InternalCallbackScope,
        // which drains nextTick + microtasks on exit; match that so
        // queueMicrotask(cb) inside onmessage runs before the next message.
        if (globalObject->drainMicrotasks())
            return; // termination pending
    }

    if (rescheduleCtx)
        scheduleDrain(side, rescheduleCtx);
    else if (peerClosed)
        // Peer closed and our inbox is fully drained: fire 'close' and let the
        // port release the event-loop ref its listener held (ordered after all
        // queued messages, matching Node).
        port->dispatchPeerClosed();
}

std::optional<MessageWithMessagePorts> MessagePortPipe::takeOne(uint8_t side)
{
    ASSERT(side < 2);
    auto& s = m_sides[side];
    Locker locker { s.lock };
    if (s.inbox.isEmpty())
        return std::nullopt;
    s.state.fetch_sub(QueuedOne, std::memory_order_acq_rel);
    return s.inbox.takeFirst();
}

void MessagePortPipe::attach(uint8_t side, ScriptExecutionContextIdentifier ctxId, ThreadSafeWeakPtr<MessagePort> port)
{
    ASSERT(side < 2);
    auto& s = m_sides[side];
    ScriptExecutionContextIdentifier wakeCtx = 0;
    {
        Locker locker { s.lock };
        s.ctxId = ctxId;
        s.port = WTF::move(port);
        uint64_t st = s.state.load(std::memory_order_relaxed);
        uint64_t ns = (st | Attached) & ~Closed;
        // Drain if messages are queued (e.g. after transfer) or the peer closed
        // before this side started listening (PeerClosed set by notifyPeerClosed
        // while unattached) — the latter lets a late listener still get 'close'.
        if ((queuedCount(st) > 0 || (st & PeerClosed)) && !(st & DrainScheduled)) {
            ns |= DrainScheduled;
            wakeCtx = ctxId;
        }
        s.state.store(ns, std::memory_order_release);
    }
    if (wakeCtx)
        scheduleDrain(side, wakeCtx);
}

void MessagePortPipe::detach(uint8_t side)
{
    ASSERT(side < 2);
    auto& s = m_sides[side];
    Locker locker { s.lock };
    s.ctxId = 0;
    s.port = nullptr;
    // Drop Attached and DrainScheduled. A drain task already in flight on
    // the old context can't be recalled, but it captured the old ctxId and
    // drainAndDispatch()'s s.ctxId != expectedCtx check makes it a no-op —
    // even if a new owner attach()es to a different context before it runs.
    // Messages remain queued for the next owner.
    s.state.fetch_and(~uint64_t(Attached | DrainScheduled), std::memory_order_acq_rel);
}

void MessagePortPipe::close(uint8_t side, bool notifyPeers)
{
    ASSERT(side < 2);

    // Dropped messages can carry TransferredMessagePorts, whose destructor
    // calls close() on their pipe. Letting those destruct naturally recurses
    // (close -> ~Deque -> ~TransferredMessagePort -> close -> ...), so a long
    // chain of nested transferred ports overflows the native stack. Drain the
    // cascade iteratively instead: steal transferred pipes from each batch of
    // dropped messages into a stack-local worklist and close them in a loop.
    // The bool is whether to notify that side's peer: notifyPeers for the
    // top-level side, always true for harvested in-transit ports (their channel
    // is dead once the carrier is dropped, regardless of how the carrier died).
    Vector<std::tuple<RefPtr<MessagePortPipe>, uint8_t, bool>> worklist;
    worklist.append({ this, side, notifyPeers });

    while (!worklist.isEmpty()) {
        auto [pipe, sd, notify] = worklist.takeLast();
        auto& s = pipe->m_sides[sd];

        Deque<MessageWithMessagePorts> dropped;
        {
            Locker locker { s.lock };
            s.ctxId = 0;
            s.port = nullptr;
            // Closed is terminal; queued messages are dropped.
            s.state.store(Closed, std::memory_order_release);
            dropped = std::exchange(s.inbox, {});
        }

        // Wake this side's peer (if listening) so it fires 'close' and drops its
        // event-loop ref. Done outside s.lock; notifyPeerClosed takes the peer
        // side's lock, never this one.
        if (notify)
            pipe->notifyPeerClosed(1 - sd);

        // Harvest transferred pipes before `dropped` destructs so their
        // ~TransferredMessagePort sees pipe == nullptr and is a no-op. Their
        // peers are always notified: a dropped in-transit port is undeliverable.
        for (auto& message : dropped) {
            for (auto& tp : message.transferredPorts) {
                if (auto p = std::exchange(tp.pipe, nullptr))
                    worklist.append({ WTF::move(p), tp.side, true });
            }
        }
        // `dropped` (and the RefPtr in the structured binding) destruct
        // outside the lock; they may hold the last ref to pipes whose
        // destructors also take locks.
    }
}

void MessagePortPipe::notifyPeerClosed(uint8_t peerSide)
{
    ASSERT(peerSide < 2);
    auto& s = m_sides[peerSide];

    ScriptExecutionContextIdentifier wakeCtx = 0;
    {
        Locker locker { s.lock };
        uint64_t st = s.state.load(std::memory_order_relaxed);
        // A side that already closed has nothing to observe.
        if (st & Closed)
            return;
        // Record the close even if this side hasn't started listening yet:
        // attach() picks up PeerClosed and schedules the drain, so a listener
        // added after the peer closed still gets 'close'. If it is already
        // attached, wake it now. The bit is consumed by drainAndDispatch under
        // this same lock, so it can't be lost against a concurrent drain.
        uint64_t ns = st | PeerClosed;
        if ((st & Attached) && s.ctxId && !(st & DrainScheduled)) {
            ns |= DrainScheduled;
            wakeCtx = s.ctxId;
        }
        s.state.store(ns, std::memory_order_release);
    }

    if (wakeCtx)
        scheduleDrain(peerSide, wakeCtx);
}

} // namespace WebCore

#endif // BUN_MESSAGEPORT_USES_PIPE
