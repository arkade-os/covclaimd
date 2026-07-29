package preimage

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

var ErrRegistryFull = errors.New("registration capacity reached, retry later")

const (
	maxRegistrations = 10_000
	registrationTTL  = 15 * time.Minute
	claimTimeout     = 2 * time.Minute
)

type RevealPlugin struct {
	*claimer
	mu      sync.RWMutex
	packets map[string]registration
}

type registration struct {
	packet   ClaimPacket
	taptree  []string
	expireAt time.Time
}

func NewRevealPlugin(cfg Config) (*RevealPlugin, error) {
	c, err := newClaimer(cfg)
	if err != nil {
		return nil, err
	}
	return &RevealPlugin{claimer: c, packets: make(map[string]registration)}, nil
}

func (p *RevealPlugin) Submit(
	ctx context.Context, swapAddress arklib.Address,
	taptree txutils.TapTree, pkt ClaimPacket,
) error {
	pkScript, err := swapAddress.GetPkScript()
	if err != nil {
		return fmt.Errorf("derive pkScript from swap address: %w", err)
	}

	preimg, err := pkt.Decrypt(p.cfg.SecretKey)
	if err != nil {
		return err
	}
	if err := p.validateAddress(taptree, pkScript, pkt.ArkadeScript, preimg); err != nil {
		return err
	}

	key := hex.EncodeToString(pkScript)
	if err := p.register(key, pkt, taptree); err != nil {
		return err
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), claimTimeout)
		defer cancel()
		p.claimIfAlreadyFunded(ctx, key)
	}()
	return nil
}

func (p *RevealPlugin) validateAddress(taptree txutils.TapTree, pkScript, arkadeScript, preimage []byte) error {
	vs := &script.TapscriptsVtxoScript{}
	if err := vs.Decode(taptree); err != nil {
		return fmt.Errorf("decode taptree: %w", err)
	}
	tapKey, _, err := vs.TapTree()
	if err != nil {
		return fmt.Errorf("compute taptree: %w", err)
	}
	fromTaptree, err := script.P2TRScript(tapKey)
	if err != nil {
		return fmt.Errorf("derive pkScript from taptree: %w", err)
	}
	if !bytes.Equal(fromTaptree, pkScript) {
		return errors.New("taptree does not hash to the swap address")
	}
	if _, err := findClaimClosure(
		vs, p.cfg.SignerPubKey, emulatorTweakedKey(arkadeScript, p.cfg.EmulatorPubKey), preimage,
	); err != nil {
		return err
	}
	return nil
}

func (p *RevealPlugin) register(key string, pkt ClaimPacket, taptree []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for k, r := range p.packets {
		if now.After(r.expireAt) {
			delete(p.packets, k)
		}
	}
	if _, ok := p.packets[key]; !ok && len(p.packets) >= maxRegistrations {
		return ErrRegistryFull
	}
	p.packets[key] = registration{
		packet: pkt, taptree: taptree, expireAt: now.Add(registrationTTL),
	}
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
		reg, ok := p.packets[hex.EncodeToString(out.PkScript)]
		p.mu.RUnlock()
		if !ok {
			continue
		}
		preimg, ok := p.decodePacket(&reg.packet)
		if !ok {
			continue
		}
		return &MatchedClaim{
			Outpoint: wire.OutPoint{Hash: tx.UnsignedTx.TxHash(), Index: uint32(i)},
			Amount:   uint64(out.Value),
			Credentials: ClaimCredentials{
				Preimage:     preimg,
				ArkadeScript: reg.packet.ArkadeScript,
				Taptree:      reg.taptree,
				PkScript:     out.PkScript,
			},
		}, true
	}
	return nil, false
}
