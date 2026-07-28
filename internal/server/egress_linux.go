//go:build linux

package server

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// markControl returns a net.Dialer.Control hook that sets SO_MARK on the
// egress socket before connect. Requires CAP_NET_ADMIN — the server
// already runs privileged for pcap (CAP_NET_RAW), so root covers both.
func markControl(mark int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return setErr
	}
}
