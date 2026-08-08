package preimage

import (
	"errors"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/btcec/v2"
)

func BuildPacket(
	preimage []byte,
	covclaimdPubKey *btcec.PublicKey,
	receiverPkScript []byte,
) (extension.Packet, error) {
	if len(preimage) != preimageSize {
		return nil, fmt.Errorf("preimage must be %d bytes, got %d", preimageSize, len(preimage))
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
