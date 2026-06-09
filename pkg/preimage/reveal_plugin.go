package preimage

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcutil/psbt"

	"github.com/arkade-os/solver/pkg/executor"
)

// revealPlugin claims preimage-gated VTXOs whose ClaimPacket was revealed
// out-of-band (via RevealService) rather than carried in the Arkade extension.
// It rides the same arkd tx stream as the encrypted plugin, but sources packets
// from the Registry keyed by funding-output pkScript, and removes a registration
// once its claim succeeds.
type revealPlugin struct {
	*claimer
	reg Registry
}

// NewRevealPlugin builds the reveal executor.Plugin over the given Registry.
func NewRevealPlugin(cfg Config, reg Registry) (executor.Plugin, error) {
	if reg == nil {
		return nil, errors.New("registry must not be nil")
	}
	c, err := newClaimer(cfg)
	if err != nil {
		return nil, err
	}
	return &revealPlugin{claimer: c, reg: reg}, nil
}

// Filter applies no server-side CEL filter: the reveal plugin inspects the full
// tx stream and matches funding outputs against the registry in Match.
func (p *revealPlugin) Filter() string {
	return ""
}

// Match returns a claim when one of tx's outputs funds a registered swap
// address and the funding output's taptree binds the expected claim closure,
// and the vtxo is still spendable.
func (p *revealPlugin) Match(ctx context.Context, tx *psbt.Packet) (any, bool) {
	matched, ok := p.matchFromRegistry(ctx, tx)
	if !ok {
		return nil, false
	}
	return p.gateSpendable(ctx, matched)
}

// matchFromRegistry is the I/O-free core of Match: it finds the first tx output
// registered in the Registry whose taptree binds the claim closure.
func (p *revealPlugin) matchFromRegistry(ctx context.Context, tx *psbt.Packet) (*MatchedClaim, bool) {
	if tx == nil || tx.UnsignedTx == nil {
		return nil, false
	}
	for i, out := range tx.UnsignedTx.TxOut {
		reg, ok := p.reg.Lookup(ctx, hex.EncodeToString(out.PkScript))
		if !ok {
			continue
		}
		preimg, ok := p.decodePacket(&reg.Packet)
		if !ok {
			continue
		}
		expectedTweaked := emulatorTweakedKey(reg.Packet.ArkadeScript, p.cfg.EmulatorPubKey)
		if m, ok := p.matchOutput(tx, i, &reg.Packet, preimg, expectedTweaked); ok {
			return m, true
		}
	}
	return nil, false
}

// Solve builds and submits the claim, then removes the registration so the bot
// stops watching for it. On claim failure the registration is kept for retry on
// a later streamed tx; the retry is bounded by Match's vtxoSpendable gate, which
// stops re-attempting once the vtxo is no longer spendable (e.g. already claimed).
func (p *revealPlugin) Solve(ctx context.Context, intent any) {
	matched, ok := intent.(*MatchedClaim)
	if !ok {
		return
	}
	if err := p.claim(ctx, matched); err != nil {
		p.log.WithError(err).
			WithField("pk_script_hex", hex.EncodeToString(matched.Credentials.PkScript)).
			Error("reveal claim failed, keeping registration for retry")
		return
	}
	if err := p.reg.Remove(ctx, hex.EncodeToString(matched.Credentials.PkScript)); err != nil {
		p.log.WithError(err).Warn("failed to remove registration after successful claim")
	}
}
