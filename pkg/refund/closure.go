// Package refund identifies the non-interactive refund-without-receiver
// covenant leaf in a VHTLC v2 taptree.
package refund

import (
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/covclaimd/pkg/preimage"
	"github.com/btcsuite/btcd/btcec/v2"
)

// FindRefundClosure returns the nonInteractiveRefundWithoutReceiver leaf.
//
// Type alone is not enough to identify it. refundWithoutReceiver is also a
// CLTVMultisigClosure and carries the same locktime; the two differ only in
// their pubkeys — [sender, server] there, [server, cosigner] here — so
// matching on the SET {server, cosigner} is what tells them apart. Neither
// position in refundWithoutReceiver is cosigner, so there is no ambiguity:
// only the target leaf can ever match.
//
// Matching is order-independent (via preimage.HasExactlyTwoKeys, the same
// helper findClaimClosure uses on the claim side) rather than requiring
// server at PubKeys[0] and cosigner at [1]: which position a key lands in is
// an accident of how the leaf's builder happened to emit it, not a property
// worth depending on. An order-sensitive match would fail closed the wrong
// way if that ever changed — not a build error, not a loud runtime error,
// just "no non-interactive refund-without-receiver leaf in taptree" and a
// refund that silently never gets pushed.
func FindRefundClosure(
	vtxo *script.TapscriptsVtxoScript, server, cosigner *btcec.PublicKey,
) (*script.CLTVMultisigClosure, error) {
	for _, closure := range vtxo.Closures {
		c, ok := closure.(*script.CLTVMultisigClosure)
		if !ok {
			continue
		}
		if preimage.HasExactlyTwoKeys(c.PubKeys, server, cosigner) {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no non-interactive refund-without-receiver leaf in taptree")
}
