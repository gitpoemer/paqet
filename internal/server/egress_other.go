//go:build !linux

package server

import "syscall"

// markControl is a no-op on non-Linux platforms: SO_MARK does not exist.
// Returning nil leaves net.Dialer.Control unset. egressDialer only calls
// this when mark > 0, and paqet's egress-mark/WARP routing is a Linux
// deployment; elsewhere the mark is silently ignored.
func markControl(mark int) func(network, address string, c syscall.RawConn) error {
	return nil
}
