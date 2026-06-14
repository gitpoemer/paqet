# Item 10 scope — epoll relay rewrite (deferred from alpha.34)

The alpha.34 plan paired item 9 (TPACKET_V3 recv via afpacket) with
item 10 (single-goroutine epoll fanin for the relay path). Item 9
shipped in alpha.34. Item 10 is **deferred** and this document
explains why.

## What item 10 was supposed to do

Replace the current 1-extra-goroutine-per-stream relay (the BG
`buffer.RelayBidi` goroutine) with a central epoll loop that
multiplexes many streams over one or a few worker goroutines.
Expected win: at 30k users × 50 streams × 4 KB stack = 6 GB just
in BG-goroutine stacks; epoll fanin would cut that to a handful of
worker stacks.

## Why it doesn't ship in alpha.34

The relay shuffles bytes between two endpoints per stream:

- the **target conn** (a `net.TCPConn` to the upstream host on the
  server, or `net.Conn` to the local app on the client)
- the **smux stream** (`*smux.Stream` from
  `github.com/xtaci/smux`)

Epoll only works on file descriptors. The target conn has one — we
can put it in an epoll set. The smux stream does **not**: it's a
channel-backed buffer fed by the smux session's internal recv loop.
There is no FD to register and no exposed non-blocking read on
smux.Stream.

So the relay can't be made fully non-blocking with the current
upstream `xtaci/smux` library. Options:

1. **Fork smux** and add `TryRead` / non-blocking semantics. Real
   work: ~1 week of focused effort plus the ongoing maintenance
   burden of carrying our own fork in sync with upstream.
2. **Half-rewrite**: epoll on the TCP side, keep blocking Read on
   the smux side. Saves one goroutine per stream pair. Modest win,
   modest complexity.
3. **Worker pool with blocking Reads** — looks like fewer goroutines
   but is structurally the same: each worker can only handle one
   blocking Read at a time, so concurrent-stream count still equals
   active-goroutine count. NO actual win; rejected.

(2) is the only path that's worth landing without forking smux. Even
then, it cuts the per-stream BG-goroutine count from 1 to ~0.5 (the
TCP side merges with the inline direction; the smux side is still
its own goroutine). At 30k × 50 = 1.5M streams that's still 6 GB →
3 GB stack memory — meaningful but not the 10× win the original
plan implied.

## Why it isn't urgent

Alpha.33 already capped the dominant memory growth from a different
angle:

- `MaxStreamsPerSession = 4096` per session caps how much one client
  can pin.
- 30s UDP idle timeout reaps inactive UDP streams before they
  accumulate.
- TCP keepalive on outbound dial detects dead targets in ~4.5min.

Under those caps the steady-state active stream count is bounded.
The original 6 GB stack estimate assumed unbounded growth that
alpha.33 prevents.

## Recommendation

Defer item 10 until production telemetry confirms BG-goroutine
stacks are actually the dominant memory cost at your scale. If
they are, the half-rewrite (option 2 above) is a 2-3 day project
and a clean win. If they aren't, forking smux for full epoll fanin
isn't worth the maintenance burden.

When (if) that day comes:

1. Profile a saturated server with `pprof` heap + goroutine.
2. If BG-goroutine stack memory > 1 GB AND there's no clearer hot
   spot, implement option 2 as alpha.35.
3. Re-evaluate option 1 (fork smux) only if option 2 leaves a real
   gap.
