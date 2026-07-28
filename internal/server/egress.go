package server

import (
	"net"
	"time"
)

// egressDialer builds the net.Dialer used for server-side egress — the
// connections opened to the real target. When mark > 0 it installs a
// Control hook that stamps SO_MARK on the socket so a policy-routing rule
// can steer only this traffic out a WARP/WireGuard interface, leaving the
// tunnel's own control traffic on the default route. mark <= 0 yields a
// plain dialer. On non-Linux platforms the mark is a no-op (see
// egress_other.go); SO_MARK is Linux-only.
func egressDialer(timeout time.Duration, mark int) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if mark > 0 {
		d.Control = markControl(mark)
	}
	return d
}
