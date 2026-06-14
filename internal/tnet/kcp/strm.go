package kcp

import (
	"github.com/xtaci/smux"
)

type Strm struct {
	*smux.Stream
}

func (s *Strm) SID() int {
	return int(s.ID())
}

// Unwrap exposes the underlying *smux.Stream so callers (e.g.
// internal/server's coordinator relay path, alpha.34 item 10) can
// reach the new TryRead / ReadEvents methods that the public
// tnet.Strm interface doesn't expose. Returns nil if not wrapping
// a smux stream.
func (s *Strm) Unwrap() *smux.Stream {
	return s.Stream
}
