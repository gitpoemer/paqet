# paqet local additions to smux

This is an **in-tree vendored copy** of `github.com/xtaci/smux`
v1.5.57 with a small additive patch applied for paqet's epoll-style
relay (alpha.34 item 10).

Originally added as a git submodule, but the patch commit lived
only in the working tree and CI couldn't fetch it from any remote.
Inlined as plain files instead so the patch lives in paqet's
history directly.

## What's added

Two new public methods on `*Stream` in `stream.go`:

```go
// Non-blocking read. Returns (n, nil) for buffered data, (0,
// ErrWouldBlock) when none is buffered and the stream is open,
// (0, io.EOF) on closed-AND-drained.
func (s *Stream) TryRead(b []byte) (int, error)

// Readability notification channel. Each new arrival wakes any
// selector on this channel exactly once (buffered cap-1).
// Spurious wakeups are allowed.
func (s *Stream) ReadEvents() <-chan struct{}
```

Both delegate to existing internal smux machinery (`tryReadV1`,
`tryReadV2`, `chReaderWakeup`). The original blocking `Read` is
unchanged.

## Why not upstream

paqet's directive was to vendor + patch rather than wait on a PR
review cycle. This local copy is pinned to v1.5.57 and the
`replace github.com/xtaci/smux => ./third_party/smux` directive in
paqet's `go.mod` selects it.

If/when these methods land upstream (the implementation is a few
dozen lines and could plausibly be PR'd back), we drop the replace
directive and consume from origin.

## Sync policy

When upstream tags a new release:

1. `cd third_party/smux && git fetch && git checkout <tag>`
2. Re-apply this patch (the diff lives in this directory's git
   history as a single commit on top of the upstream tag — `git
   log --grep="paqet"`).
3. Run paqet's test suite, including the alpha.34 stealth tests
   and the new alpha.34 relay tests in `internal/server/relay_*`.
4. Bump the require version in paqet's `go.mod` to match.

## Verifying the patch is the only delta

```
cd third_party/smux
git diff v1.5.57 HEAD -- stream.go    # only TryRead + ReadEvents
git status                            # no untracked changes
```
