//go:build linux

package socket

import "os"

// getpid returns the current process PID as uint16 input for the
// fanout-group salt. Wraps os.Getpid so the afpacket file doesn't
// have to import os directly (keeps that file's imports focused on
// the packet capture stack).
func getpid() uint16 {
	return uint16(os.Getpid())
}
