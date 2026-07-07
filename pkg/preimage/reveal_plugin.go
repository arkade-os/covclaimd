package preimage

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

type RevealPlugin struct {
	*claimer
	mu      sync.RWMutex
	packets map[string]ClaimPacket
}

func NewRevealPlugin(cfg Config) (*RevealPlugin, error) {
	c, err := newClaimer(cfg)
	if err != nil {
		return nil, err
	}
	return &RevealPlugin{claimer: c, packets: make(map[string]ClaimPacket)}, nil
}

func (p *RevealPlugin) Submit(ctx context.Context, swapAddress string, ciphertext, arkadeScript []byte) error {
	if len(ciphertext) == 0 {
		return errors.New("ciphertext must not be empty")
	}
	if len(arkadeScript) == 0 {
		return errors.New("arkade_script must not be empty")
	}

	addr, err := arklib.DecodeAddressV0(swapAddress)
	if err != nil {
		return fmt.Errorf("decode swap address: %w", err)
	}
	pkScript, err := script.P2TRScript(addr.VtxoTapKey)
	if err != nil {
		return fmt.Errorf("derive pkScript from swap address: %w", err)
	}

	pkt := ClaimPacket{Ciphertext: ciphertext, ArkadeScript: arkadeScript}
	if _, err := validatePacket(p.cfg.SecretKey, &pkt); err != nil {
		return err
	}

	key := hex.EncodeToString(pkScript)
	p.mu.Lock()
	p.packets[key] = pkt
	p.mu.Unlock()

	p.claimIfAlreadyFunded(ctx, key)
	return nil
}

func (p *RevealPlugin) claimIfAlreadyFunded(ctx context.Context, pkScriptHex string) {
	resp, err := p.cfg.Indexer.GetVtxos(ctx,
		indexer.WithScripts([]string{pkScriptHex}),
		indexer.WithSpendableOnly(),
	)
	if err != nil || len(resp.Vtxos) == 0 {
		return
	}
	txs, err := p.cfg.Indexer.GetVirtualTxs(ctx, []string{resp.Vtxos[0].Txid})
	if err != nil || len(txs.Txs) == 0 {
		p.log.WithError(err).Debug("reveal: failed to fetch funding tx for already-funded swap")
		return
	}
	tx, err := psbt.NewFromRawBytes(strings.NewReader(txs.Txs[0]), true)
	if err != nil {
		p.log.WithError(err).Debug("reveal: failed to parse funding tx")
		return
	}
	if m, ok := p.Match(ctx, tx); ok {
		p.Solve(ctx, m)
	}
}

func (p *RevealPlugin) Filter() string {
	return ""
}

func (p *RevealPlugin) Match(ctx context.Context, tx *psbt.Packet) (any, bool) {
	matched, ok := p.matchRegistered(tx)
	if !ok {
		return nil, false
	}
	return p.gateSpendable(ctx, matched)
}

func (p *RevealPlugin) Solve(ctx context.Context, intent any) {
	matched, ok := intent.(*MatchedClaim)
	if !ok {
		return
	}
	key := hex.EncodeToString(matched.Credentials.PkScript)
	if err := p.claim(ctx, matched); err != nil {
		p.log.WithError(err).
			WithField("pk_script_hex", key).
			Error("reveal claim failed, keeping registration for retry")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.packets, key)
}

func (p *RevealPlugin) matchRegistered(tx *psbt.Packet) (*MatchedClaim, bool) {
	if tx == nil || tx.UnsignedTx == nil {
		return nil, false
	}
	for i, out := range tx.UnsignedTx.TxOut {
		p.mu.RLock()
		pkt, ok := p.packets[hex.EncodeToString(out.PkScript)]
		p.mu.RUnlock()
		if !ok {
			continue
		}
		preimg, ok := p.decodePacket(&pkt)
		if !ok {
			continue
		}
		expectedTweaked := emulatorTweakedKey(pkt.ArkadeScript, p.cfg.EmulatorPubKey)
		if m, ok := p.matchOutput(tx, i, &pkt, preimg, expectedTweaked); ok {
			return m, true
		}
	}
	return nil, false
}
