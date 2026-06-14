package relay

import (
	smux "github.com/xtaci/smux"
)

func init() {
	ErrWouldBlock = smux.ErrWouldBlock
}
