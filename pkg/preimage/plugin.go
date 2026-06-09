package preimage

import (
	"context"
	"errors"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/arkade-os/solver/pkg/executor"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Indexer  indexer.Indexer
	Emulator emulatorclient.TransportClient
	// The secret key used to encrypt and decrypt the packet data encoding the preimage to reveal
	SecretKey *btcec.PrivateKey

	EmulatorPubKey      *btcec.PublicKey
	SignerPubKey        *btcec.PublicKey
	CheckpointTapscript []byte
	Log                 logrus.FieldLogger
}

// NewPlugin builds the encrypted (Arkade extension) preimage executor.Plugin.
// Match decodes a claim from the tx's Arkade extension and gates it on vtxo
// spendability; Solve builds and submits the claim transaction.
func NewPlugin(_ context.Context, cfg Config) (executor.Plugin, error) {
	c, err := newClaimer(cfg)
	if err != nil {
		return nil, err
	}
	return &plugin{c}, nil
}

type plugin struct {
	*claimer
}

// Filter applies no server-side CEL filter: the preimage plugin inspects the
// full tx stream and decides structurally in Match.
func (p *plugin) Filter() string { return "" }

// Match decodes a preimage claim from tx's Arkade extension and confirms the
// funded vtxo is still spendable. Every non-claim tx is a silent miss.
func (p *plugin) Match(ctx context.Context, tx *psbt.Packet) (any, bool) {
	if tx == nil || tx.UnsignedTx == nil {
		return nil, false
	}

	ext, err := extension.NewExtensionFromTx(tx.UnsignedTx)
	if err != nil {
		if !errors.Is(err, extension.ErrExtensionNotFound) {
			p.log.WithError(err).Debug("preimage extension parse failed")
		}
		return nil, false
	}

	claim, ok := p.decode(tx, ext)
	if !ok {
		return nil, false
	}
	return p.gateSpendable(ctx, claim)
}

// Solve builds and submits the claim transaction for a matched intent.
func (p *plugin) Solve(ctx context.Context, intent any) {
	claim, ok := intent.(*MatchedClaim)
	if !ok {
		return
	}
	if err := p.claim(ctx, claim); err != nil {
		p.log.Error(err)
	}
}

// decode extracts a preimage claim from the parsed extension and the matching
// tx output. It returns ok=false (a silent miss) whenever the tx is not a
// well-formed claim addressed to this covclaimd.
func (p *plugin) decode(tx *psbt.Packet, ext extension.Extension) (*MatchedClaim, bool) {
	pkt, err := FindClaim(ext)
	if err != nil {
		p.log.WithError(err).Debug("preimage extension parse failed")
		return nil, false
	}
	if pkt == nil {
		return nil, false
	}
	preimg, ok := p.decodePacket(pkt)
	if !ok {
		return nil, false
	}
	expectedTweaked := emulatorTweakedKey(pkt.ArkadeScript, p.cfg.EmulatorPubKey)
	for i := range tx.UnsignedTx.TxOut {
		if m, ok := p.matchOutput(tx, i, pkt, preimg, expectedTweaked); ok {
			return m, true
		}
	}
	return nil, false
}
