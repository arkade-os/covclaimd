package preimage

import (
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcec/v2"
)

// BuildPacket returns the extension.Packet the funder must attach to
// the funding transaction (via clientlib.WithExtraPacket or equivalent).
// It encrypts the preimage to covclaimdPubKey and inlines the arkade script
// derived from receiverPkScript.
func BuildPacket(
	preimage []byte,
	covclaimdPubKey *btcec.PublicKey,
	receiverPkScript []byte,
) (extension.Packet, error) {
	if len(preimage) != 32 {
		return nil, fmt.Errorf("preimage must be 32 bytes, got %d", len(preimage))
	}
	if covclaimdPubKey == nil {
		return nil, errors.New("covclaimd pubkey must not be nil")
	}
	arkadeScript, err := EnforcePayTo(receiverPkScript)
	if err != nil {
		return nil, fmt.Errorf("build arkade script: %w", err)
	}
	ciphertext, err := Encrypt(covclaimdPubKey, preimage)
	if err != nil {
		return nil, fmt.Errorf("encrypt preimage: %w", err)
	}
	return (&ClaimPacket{Ciphertext: ciphertext, ArkadeScript: arkadeScript}).ToPacket()
}
