# `optimize` branch — code-review findings

Scope: master branch as of `d6d72e1`. Goal stated by the user:
> improve performance (don't break protocol), fix any memory leak if there's any, and make sure the app can stay performant for long running session (currently it seems the app stops working after a while)

Approach: first-principles read of the request/response path, then second-order
effects (lifecycle, concurrency, GC, lock contention).

Each finding lists: **what** (the code), **why it matters** (first-order), and
**what else breaks because of it** (second-order). Fixes are landed as one
commit per item so each can be reviewed/reverted independently.

---

## Critical — most plausible causes of the "stops after a while" symptom

### C1 — `client/dial.go::newStrm` recurses without bound

```go
func (c *Client) newStrm() (tnet.Strm, error) {
    conn, err := c.newConn()
    if err != nil {
        flog.Debugf("session creation failed, retrying")
        return c.newStrm()                 // ← recursion, no limit
    }
    strm, err := conn.OpenStrm()
    if err != nil {
        flog.Debugf("failed to open stream, retrying: %v", err)
        return c.newStrm()                 // ← same
    }
    return strm, nil
}
```

**First-order:** any transient failure (carrier drop, KCP timeout, smux session
expiry) causes unbounded tail-recursion. The Go runtime grows the goroutine
stack up to the per-goroutine cap, but more importantly: it's a tight CPU loop
with `c.mu.Lock()` held inside `newConn()`. So a single broken connection wedges
every consumer of the client.

**Second-order:** this is the most plausible cause of the user-reported "stops
working after a while". A single missed KCP ACK during a network blip makes
`Ping` fail in `newConn`, the recovery there is broken (`createConn` failure
returns the *closed* old conn), so every subsequent `newStrm` retries forever.
Symptom from the outside: SOCKS5 / forwarder stops handing out streams; binary
appears hung.

**Fix:** loop with bounded retries + sleep, return error to caller after the
budget is exhausted so the forwarder can drop the inbound connection cleanly.

---

### C2 — `socket/send_handle.go::clientTCPF` map grows forever

```go
type TCPF struct {
    tcpF       iterator.Iterator[conf.TCPF]
    clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
    mu         sync.RWMutex
}

// called from server/handle.go for every connecting client that sends PTCPF
func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
    a := *addr.(*net.UDPAddr)
    h.tcpF.mu.Lock()
    h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
    h.tcpF.mu.Unlock()
}
```

**First-order:** server allocates a map entry per `(clientIP, clientPort)`. There
is no path that ever `delete`s. A long-running server eventually:
- holds N entries proportional to total clients seen (not currently connected)
- pays log(N) lookup on every outbound packet under RLock
- and the lock holds a fresh `iterator.Iterator.Next()` call, which mutates the
  iterator's atomic index under an RLock — that's technically OK because the
  index is `atomic.Uint64`, but the lock semantics are confused.

**Second-order:** on the carrier-rotating-ports setup (where every KCP packet
mints a new source port), the map gets an entry per packet. RAM is the obvious
loser; the real second-order failure is that map growth under a write-lock
stalls the outbound path. Every `setClientTCPF` blocks every `getClientTCPF`
including the legitimate one currently writing the wire.

**Fix:** add an LRU bound (size cap or TTL eviction). For server lifetime
correctness, also delete the entry when the smux session for that peer closes —
hook it into the server's `handleConn` deferred cleanup.

---

### C3 — `socket/recv_handle.go::Read` returns `(nil, nil, nil)` on non-TCP-data packets

```go
func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
    data, _, err := h.handle.ReadPacketData()
    ...
    netLayer := p.NetworkLayer()
    if netLayer == nil {
        return nil, nil, nil           // ← err=nil but payload=nil
    }
    ...
    appLayer := p.ApplicationLayer()
    if appLayer == nil {
        return nil, nil, nil           // ← same
    }
    return appLayer.Payload(), addr, nil
}
```

The caller in `socket.go::ReadFrom`:
```go
payload, addr, err := c.recvHandle.Read()
if err != nil {
    return 0, nil, err
}
n = copy(data, payload)              // n=0 when payload=nil
return n, addr, nil
```

**First-order:** every benign packet that the BPF filter let through but that
isn't a TCP-with-payload (TCP SYN, TCP RST, ICMP that snuck past, malformed
captures, the carrier injecting handshake-only ACKs that have empty payload)
surfaces to KCP as a successful read of zero bytes from a `nil` address.

**Second-order:** `net.PacketConn` callers treat `(n=0, nil-addr, nil-err)` as a
short read from no peer — KCP can interpret this as session shutdown, or just
spin in a hot loop receiving "0 bytes from nothing" if it doesn't. Either way
this is noise the lower stack should swallow, not surface.

**Fix:** loop inside `Read` until we have non-empty payload OR a real error. Add
a per-packet ApplicationLayer length check.

---

## Important — performance + smaller leaks

### I1 — `protocol/protocol.go` uses `gob` with a fresh encoder/decoder per message

```go
func (p *Proto) Read(r io.Reader) error {
    dec := gob.NewDecoder(r)
    return dec.Decode(p)
}

func (p *Proto) Write(w io.Writer) error {
    enc := gob.NewEncoder(w)
    return enc.Encode(p)
}
```

**First-order:** `encoding/gob` runs a type-registration handshake the first
time a type is encoded by an encoder. Creating a new encoder per message means
re-doing the type table on every send. For a 5-message-type protocol with
fixed-size fields, this is hundreds of bytes of overhead per message plus
significant CPU.

**Second-order:** every protocol handshake (PTCP / PUDP / PTCPF / PPING) on the
inner KCP+smux stream becomes a heavy operation. Multiplied by every new TCP
connection going through the SOCKS proxy or forwarder, the per-conn latency
floor is set by gob, not by the network. Hand-rolled binary framing on a fixed
wire format is straightforward (1 byte type + 2-byte length-prefixed addr +
2-byte length-prefixed TCPF count + 1-byte-each TCPF fields).

**Fix:** Wire format:
```
+--------+---------------+---------------+
| type   | addr length   | addr bytes    |
+--------+---------------+---------------+
| TCPF count (u16) | TCPF[] (1 byte each) |
+------------------+----------------------+
```
Preserves on-wire compatibility ONLY if we hard-cut over both ends; gob's
self-describing format makes seamless migration awkward. Acceptable because:
(a) this is the inner stream, behind the same KCP session, and a client and
server roll together; (b) the protocol type byte is the first byte of the gob
stream too, so old/new can be distinguished by the second byte — but cleanest
is just "both ends on the same build". I'll bump a protocol version constant
and gate the new format on that.

### I2 — `pkg/buffer/CopyT` and `CopyU` allocate a new buffer per call

```go
func CopyT(dst io.Writer, src io.Reader) error {
    buf := make([]byte, TPool)
    _, err := io.CopyBuffer(dst, src, buf)
    return err
}
```

**First-order:** 4–8 KiB allocated per TCP/UDP relay invocation, then GC'd.
Each relayed connection has two goroutines (upstream+downstream) so that's
two allocations per connection.

**Second-order:** under a busy SOCKS5 deployment (browser opens 6 parallel TCP
streams per page load), this is GC-pressure that competes with the actual
data path for STW pauses. On constrained edge devices the GC pauses make the
TCP carrier think the proxy died, triggering re-negotiation.

**Fix:** sync.Pool for each size class. Drop into the existing `CopyT/CopyU`
without changing their signatures.

### I3 — `client/dial.go::newConn` holds `c.mu` across slow operations

```go
func (c *Client) newConn() (tnet.Conn, error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    autoExpire := 300
    tc := c.iter.Next()
    go tc.sendTCPF(tc.conn)           // fire-and-forget goroutine
    err := tc.conn.Ping(false)         // can block / fail
    if err != nil {
        ...
        if c, err := tc.createConn(); err == nil {  // can DialContext, ~10s
            tc.conn = c
        }
        tc.expire = time.Now().Add(time.Duration(autoExpire) * time.Second)
    }
    return tc.conn, nil
}
```

**First-order issues:**
- `c.mu` is held across `Ping` and `createConn` — every consumer of the client
  blocks on a single (potentially slow) Ping/Dial.
- `go tc.sendTCPF(tc.conn)` fires off a stream open + protocol write + close on
  every newConn. Concurrent newConn calls each fire one. Under fast retry, a
  flood of these races with each other and with the consumer's actual stream
  opens.
- `autoExpire` is computed and assigned to `tc.expire`, but nothing in the code
  ever reads `tc.expire`. Dead code that obscures intent.
- If `createConn` fails, the OLD (now-Closed) conn stays in `tc.conn` and we
  return it — every subsequent op fails.

**Second-order:** dependent on C1 — if `newConn` returns a broken conn,
`newStrm` recurses forever.

**Fix:** narrow the lock to selection + swap. Do Ping/createConn unlocked
against the chosen `*timedConn` under that conn's own mutex. Remove the dead
`autoExpire`. Stop the fire-and-forget goroutine — `sendTCPF` is only required
once per `timedConn` lifetime (during creation) and `setClientTCPF` is the
server-side state that needs it; re-sending it on every new stream is wasted
work. If we keep periodic refresh, make `ticker.go` actually do it.

### I4 — `client/udp.go::UDP` check-then-act race

```go
c.udpPool.mu.RLock()
if strm, exists := c.udpPool.strms[key]; exists {
    c.udpPool.mu.RUnlock()
    return strm, false, key, nil
}
c.udpPool.mu.RUnlock()
// ... long path: newStrm + protocol header write ...
c.udpPool.mu.Lock()
c.udpPool.strms[key] = strm
c.udpPool.mu.Unlock()
```

**First-order:** two UDP datagrams from the same `(localAddr, targetAddr)`
arriving concurrently both find no strm under RLock, both go through `newStrm`
+ protocol write, then both `strms[key] = ...`. The second write overwrites
the first; the first strm is **leaked** until the smux session GC's it.

**Second-order:** under bursty UDP (DNS rush at browser launch is the obvious
one), we leak streams per burst. Each leaked stream holds an smux buffer.

**Fix:** classic double-check pattern — re-check under WLock before insert; if
another goroutine won the race, close the loser strm and return the winner's.

### I5 — `socket.go::Close` spawns goroutines that race

```go
func (c *PacketConn) Close() error {
    c.cancel()
    if c.sendHandle != nil { go c.sendHandle.Close() }
    if c.recvHandle != nil { go c.recvHandle.Close() }
    return nil
}
```

**First-order:** two reasons to dislike this:
- Multiple Close() calls (which happens normally — `kcp/conn.go::Close` calls
  it, and so does the listener teardown) each spawn fresh goroutines.
- The goroutines have no synchronization; the caller has no way to wait for
  pcap cleanup to actually happen.

**Second-order:** during shutdown the pcap handles can outlive the rest of the
program because nothing waits for the spawned goroutines. On Linux this is
benign (process exit cleans up), on Windows the npcap handle gets stranded and
a restart fails because the interface still has it.

**Fix:** make Close idempotent via `sync.Once`, run handle Close inline (it's
quick), drop the goroutines.

### I6 — `socket.go::Read/Write` deadline pattern is racy and inefficient

```go
var timer *time.Timer
var deadline <-chan time.Time
if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() {
    timer = time.NewTimer(time.Until(d))
    defer timer.Stop()
    deadline = timer.C
}
select {
case <-c.ctx.Done():
    return 0, nil, c.ctx.Err()
case <-deadline:
    return 0, nil, os.ErrDeadlineExceeded
default:
}
payload, addr, err := c.recvHandle.Read()   // blocks indefinitely
```

**First-order:** the deadline is only consulted in the non-blocking select. The
actual `recvHandle.Read()` blocks indefinitely inside pcap and the deadline
goes unused. Plus the timer is allocated per call.

**Second-order:** KCP uses SetReadDeadline as its keepalive mechanism. Every
read from KCP sets a deadline; this socket layer ignores it. The "stops after
a while" symptom can also be triggered if KCP decides the link is dead because
its reads keep blocking past its own deadline.

**Fix:** the real cure is to make `recvHandle.Read` respect a deadline. pcap
has no nice deadline; the practical approach is a per-read context with a
goroutine that calls `recvHandle.handle.SetBPFInstructions(nil)` or closes the
handle. Cleanest: run a single recvLoop goroutine + buffered channel + select
in `ReadFrom`. That's a bigger refactor.

Minimum viable fix: drop the dead `default:` and at least don't allocate a
timer per call when no deadline is set. Document the limitation.

---

## Moderate

### M1 — `client/ticker.go` is dead code

The single-fire timer never resets and the handler body is commented out. The
goroutine just consumes one slot for the lifetime of the client. Delete or
restore. Going with delete for now; the `sendTCPF` refresh idea can come back
as an explicit feature later.

### M2 — `recvHandle.Read` uses `gopacket.NoCopy` and per-packet allocations

`gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)` + a fresh
`&net.UDPAddr{}` on every packet. NoCopy is correct only because the caller
copies the payload immediately. Document the invariant and consider a
`gopacket.DecodingLayerParser` for hot-path decoding (zero-alloc once the
parser is reused across packets).

Not landing this yet — bigger change, want to measure first.

### M3 — `forward/udp.go::handleUDPPacket` allocates per packet

```go
buf := make([]byte, buffer.UPool)
```

Same fix as I2 (sync.Pool). Lower priority because the alloc cost is dwarfed by
the kernel UDP recvmsg cost.

---

## What I'm NOT touching this pass

- **The TCP-payload reflection / pcap-injection wire format** itself. That's a
  protocol concern, user explicitly said don't break protocol.
- **KCP tuning** (`smuxConf`, `aplConf`). Knobs the operator picks, not a code
  bug.
- **The cycle-mode work** on the `tcp-carrier` branch. Out of scope for this
  pass; we're on master.
