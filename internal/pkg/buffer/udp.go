package buffer

import (
	"io"
	"sync"
)

// udpBufPool reuses UPool-sized scratch buffers for io.CopyBuffer.
// See OPTIMIZE_NOTES.md I2 for motivation.
var udpBufPool sync.Pool

func CopyU(dst io.Writer, src io.Reader) error {
	bufAny := udpBufPool.Get()
	var buf []byte
	if bufAny == nil || len(bufAny.([]byte)) != UPool {
		buf = make([]byte, UPool)
	} else {
		buf = bufAny.([]byte)
	}
	_, err := io.CopyBuffer(dst, src, buf)
	udpBufPool.Put(buf)
	return err
}
