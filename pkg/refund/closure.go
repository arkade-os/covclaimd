// Package refund identifies the non-interactive refund-without-receiver
// covenant leaf in a VHTLC v2 taptree.
package refund

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// FindRefundClosure returns the nonInteractiveRefundWithoutReceiver leaf.
//
// Type alone is not enough to identify it. refundWithoutReceiver is also a
// CLTVMultisigClosure and carries the same locktime; the two differ only in
// their second pubkey — the sender's there, the covenant-tweaked emulator key
// here. Matching on the cosigner is what tells them apart.
func FindRefundClosure(
	vtxo *script.TapscriptsVtxoScript, server, cosigner *btcec.PublicKey,
) (*script.CLTVMultisigClosure, error) {
	wantServer := schnorr.SerializePubKey(server)
	wantCosigner := schnorr.SerializePubKey(cosigner)

	for _, closure := range vtxo.Closures {
		c, ok := closure.(*script.CLTVMultisigClosure)
		if !ok || len(c.PubKeys) != 2 {
			continue
		}
		if bytes.Equal(schnorr.SerializePubKey(c.PubKeys[0]), wantServer) &&
			bytes.Equal(schnorr.SerializePubKey(c.PubKeys[1]), wantCosigner) {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no non-interactive refund-without-receiver leaf in taptree")
}
