package client

import (
	"paqet/internal/flog"
	"paqet/internal/pkg/hash"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
)

// UDP returns the stream that should carry datagrams between (lAddr, tAddr).
// Returns (strm, isNew, key, nil) so the caller can register a per-stream
// reader goroutine exactly once per key.
//
// Closes the check-then-act race in the old code: two datagrams from the
// same (lAddr, tAddr) arriving concurrently both saw "no strm" under RLock,
// both newStrm()'d, and both wrote to the map — second writer silently
// leaked the first stream. Now we re-check under WLock before insert and
// close the loser if we lost the race. See OPTIMIZE_NOTES.md I4.
func (c *Client) UDP(lAddr, tAddr string) (tnet.Strm, bool, uint64, error) {
	key := hash.AddrPair(lAddr, tAddr)

	c.udpPool.mu.RLock()
	if strm, exists := c.udpPool.strms[key]; exists {
		c.udpPool.mu.RUnlock()
		flog.Debugf("reusing UDP stream %d for %s -> %s", strm.SID(), lAddr, tAddr)
		return strm, false, key, nil
	}
	c.udpPool.mu.RUnlock()

	strm, err := c.newStrm()
	if err != nil {
		flog.Debugf("failed to create stream for UDP %s -> %s: %v", lAddr, tAddr, err)
		return nil, false, 0, err
	}

	taddr, err := tnet.NewAddr(tAddr)
	if err != nil {
		flog.Debugf("invalid UDP address %s: %v", tAddr, err)
		strm.Close()
		return nil, false, 0, err
	}
	p := protocol.Proto{Type: protocol.PUDP, Addr: taddr}
	err = p.Write(strm)
	if err != nil {
		flog.Debugf("failed to write UDP protocol header for %s -> %s on stream %d: %v", lAddr, tAddr, strm.SID(), err)
		strm.Close()
		return nil, false, 0, err
	}

	c.udpPool.mu.Lock()
	if winner, exists := c.udpPool.strms[key]; exists {
		// Another goroutine won the race while we were minting our strm.
		c.udpPool.mu.Unlock()
		flog.Debugf("UDP race: discarding our stream %d, reusing %d for %s -> %s", strm.SID(), winner.SID(), lAddr, tAddr)
		strm.Close()
		return winner, false, key, nil
	}
	c.udpPool.strms[key] = strm
	c.udpPool.mu.Unlock()

	flog.Debugf("UDP stream %d created for %s -> %s", strm.SID(), lAddr, tAddr)
	return strm, true, key, nil
}

func (c *Client) CloseUDP(key uint64) error {
	return c.udpPool.delete(key)
}
