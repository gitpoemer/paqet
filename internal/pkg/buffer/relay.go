package buffer

import "io"

// RelayBidi runs a bidirectional copy between two ReadWriteClosers using
// two pooled CopyT scratch buffers and exactly two goroutines (caller's
// + one spawned).
//
// Returns (inlineErr, bgErr) where inline is conn→strm (caller's
// goroutine) and bg is strm→conn (spawned). Naming preserves the
// historical pattern from the relay callers this helper consolidates.
//
// Critical invariant: when EITHER direction finishes, BOTH conn AND
// strm are closed so the other goroutine's blocked operation —
// whether Read or Write — unblocks immediately.
//
// The two blocking points per direction:
//   - inline = CopyT(strm, conn): blocks on conn.Read OR strm.Write
//   - bg     = CopyT(conn, strm): blocks on strm.Read OR conn.Write
//
// To unblock inline from outside: close conn (kills its Read) AND/OR
// close strm (kills its Write). To unblock bg: close strm AND/OR
// close conn. So each direction must close BOTH endpoints on exit —
// closing only its own source isn't enough, the partner may be stuck
// on Write instead of Read.
//
// Earlier versions only closed conn after inline returned and nothing
// after bg returned. That meant:
//   - When the LOCAL app closed its TCP conn first (the common case —
//     short HTTP request, browser closes after response), inline's
//     conn.Read returned and we closed conn — but bg was stuck on
//     strm.Read, and closing conn doesn't help that. Bg hung until the
//     smux peer happened to close strm from its end. At ~140 streams/sec
//     arrival, ~30s avg stuck time, this pinned 4k+ goroutines and
//     ~1.9 GB of per-stream smux receive buffers in production.
//
// All Close calls are idempotent. Multiple Close on net.Conn / smux
// stream return nil (or net.ErrClosed) on subsequent calls. Callers
// that keep a defensive `defer conn.Close()` outside RelayBidi are
// safe.
func RelayBidi(conn, strm io.ReadWriteCloser) (inlineErr, bgErr error) {
	errCh := make(chan error, 1)
	go func() {
		err := CopyT(conn, strm)
		// bg done. inline might be blocked on conn.Read or strm.Write
		// — close both to unblock either case.
		strm.Close()
		conn.Close()
		errCh <- err
	}()
	inlineErr = CopyT(strm, conn)
	// inline done. bg might be blocked on strm.Read or conn.Write.
	conn.Close()
	strm.Close()
	bgErr = <-errCh
	return
}
