package preimage

import (
	"context"
	"errors"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Recorder validates reveal submissions and records the accepted ones in a
// Registry. It is the write side of the reveal path; the revealPlugin is the
// read side.
type Recorder struct {
	reg       Registry
	secretKey *btcec.PrivateKey
}

func NewRecorder(reg Registry, secretKey *btcec.PrivateKey) (*Recorder, error) {
	if reg == nil {
		return nil, errors.New("registry must not be nil")
	}
	if secretKey == nil {
		return nil, errors.New("secret key must not be nil")
	}
	return &Recorder{reg: reg, secretKey: secretKey}, nil
}

// Submit validates and records a reveal request. swapAddress is the bech32m
// Arkade address of the VHTLC funding output; ciphertext/arkadeScript are the
// ClaimPacket fields. Validation mirrors the encrypted path's packet checks:
// the ciphertext must decrypt to a 32-byte preimage with covclaimd's key and
// the arkade script must be a well-formed EnforcePayTo. The full taptree/closure
// binding is NOT checked here (the taptree only arrives in the funding output);
// the revealPlugin enforces it at claim time. Returns an error suitable for
// returning to the maker as InvalidArgument.
func (r *Recorder) Submit(ctx context.Context, swapAddress string, ciphertext, arkadeScript []byte) error {
	if len(ciphertext) == 0 {
		return errors.New("ciphertext must not be empty")
	}
	if len(arkadeScript) == 0 {
		return errors.New("arkade_script must not be empty")
	}

	// Run the cheap structural checks (address decode, script tokenization)
	// before the expensive ECDH in Decrypt, so junk submissions to this public
	// endpoint are rejected without spending crypto work.
	addr, err := arklib.DecodeAddressV0(swapAddress)
	if err != nil {
		return fmt.Errorf("decode swap address: %w", err)
	}
	pkScript, err := script.P2TRScript(addr.VtxoTapKey)
	if err != nil {
		return fmt.Errorf("derive pkScript from swap address: %w", err)
	}

	if _, err := validatePacket(r.secretKey, &ClaimPacket{
		Ciphertext: ciphertext, ArkadeScript: arkadeScript,
	}); err != nil {
		return err
	}

	return r.reg.Add(ctx, Registration{
		PkScript: pkScript,
		Packet:   ClaimPacket{Ciphertext: ciphertext, ArkadeScript: arkadeScript},
	})
}
