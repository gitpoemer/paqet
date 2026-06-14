package relay

import (
	"testing"

	smux "github.com/xtaci/smux"
)

// TestSmuxStreamSatisfiesStrm is a compile-time interface assertion:
// if smux.Stream stops satisfying our Strm interface (e.g., upstream
// removes a method or changes a signature, or our vendored patch
// gets reverted), this test won't compile.
//
// At runtime it just confirms the cast works for a nil pointer —
// the assertion is enforced by the compiler before this body runs.
func TestSmuxStreamSatisfiesStrm(t *testing.T) {
	var _ Strm = (*smux.Stream)(nil)
}
