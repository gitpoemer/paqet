package buffer

import (
	"io"
	"sync"
)

// tcpBufPool reuses TPool-sized scratch buffers for io.CopyBuffer.
//
// OPTIMIZE_NOTES.md I2 — the old code allocated a fresh slice on every CopyT
// invocation, i.e. two allocations per relayed TCP connection. Under a busy
// SOCKS5 deployment that was a steady drip of garbage competing with the
// data path for STW pauses.
var tcpBufPool sync.Pool

// CopyT relays src -> dst using a pooled TPool-sized scratch buffer.
func CopyT(dst io.Writer, src io.Reader) error {
	bufAny := tcpBufPool.Get()
	var buf []byte
	if bufAny == nil || len(bufAny.([]byte)) != TPool {
		// First call, or buffer.Initialize() reconfigured TPool between
		// calls — allocate a fresh slice of the current TPool size; the
		// Pool will keep the new size from here on.
		buf = make([]byte, TPool)
	} else {
		buf = bufAny.([]byte)
	}
	_, err := io.CopyBuffer(dst, src, buf)
	tcpBufPool.Put(buf)
	return err
}
